"""Entry point for the GitHub Action (action.yml).

The composite action passes every input through a PR_VERIFY_* environment
variable; this module turns them into the exact CLI flags of `pr-verify
check`, runs the check, prints the report and writes the outputs
(score, band, requires-review, exit-code) to $GITHUB_OUTPUT. It is started
by run_action.py in isolated mode (`python -I`), so that the pull request's
checkout, which is the working directory, can never supply a module.

`exit-code` is written whichever way the step ends: 0 or 1 with the other
three when a score was worked out, 2 alone when the check could not run (a
check error, an input the CLI refuses, a root that is not a repository), 2
with the other three when the score was worked out but the report could not
be written. A $GITHUB_OUTPUT that cannot be written is a warning, never a
traceback: the verdict is the exit status, and it stands.

Mapping (input -> env var -> CLI flag), kept in INPUTS so the test suite
can assert action.yml and the CLI agree:

    base        PR_VERIFY_BASE        --base        (empty = auto-detect)
    head        PR_VERIFY_HEAD        --head
    format      PR_VERIFY_FORMAT      --format
    fail-on     PR_VERIFY_FAIL_ON     --fail-on
    min-score   PR_VERIFY_MIN_SCORE   --min-score   (empty = use config)
    skip-gates  PR_VERIFY_SKIP_GATES  --skip-gates  ('true' = set)
    root        PR_VERIFY_ROOT        --root        (global flag)
    sarif-file  PR_VERIFY_SARIF_FILE  --sarif-file  (empty = no SARIF file)

Three inputs have no flag; the Action acts on them itself, after the check:

    comment       PR_VERIFY_COMMENT       'true': post (or update) the sticky
                                          pull request comment
    github-token  PR_VERIFY_GITHUB_TOKEN  the token the comment is posted with
    step-summary  PR_VERIFY_STEP_SUMMARY  'true' (default): append the same
                                          markdown to the job summary

The pull request's own facts (labels, author, branch, title, description) are
read from the event payload ($GITHUB_EVENT_PATH, passed as --event-file), so
nothing has to be wired by hand. Posting needs `pull-requests: write` on the
workflow's token; a token that cannot post (a fork's pull request) is a
warning, never a failed check.
"""

from __future__ import annotations

import json
import os
import re
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request

from . import cli
from . import prinfo as prinfo_mod
from . import render as render_mod

#: input name -> (env var, CLI flag, kind). kind: "value" | "flag" | "global".
INPUTS: dict[str, tuple[str, str, str]] = {
    "base": ("PR_VERIFY_BASE", "--base", "value"),
    "head": ("PR_VERIFY_HEAD", "--head", "value"),
    "format": ("PR_VERIFY_FORMAT", "--format", "value"),
    "fail-on": ("PR_VERIFY_FAIL_ON", "--fail-on", "value"),
    "min-score": ("PR_VERIFY_MIN_SCORE", "--min-score", "value"),
    "skip-gates": ("PR_VERIFY_SKIP_GATES", "--skip-gates", "flag"),
    "root": ("PR_VERIFY_ROOT", "--root", "global"),
    "sarif-file": ("PR_VERIFY_SARIF_FILE", "--sarif-file", "value"),
}

#: inputs the Action itself acts on (no CLI flag): name -> env var
ACTION_ONLY: dict[str, str] = {
    "comment": "PR_VERIFY_COMMENT",
    "github-token": "PR_VERIFY_GITHUB_TOKEN",
    "step-summary": "PR_VERIFY_STEP_SUMMARY",
}

OUTPUTS = ("score", "band", "requires-review", "exit-code")

_TRUE = {"1", "true", "yes", "on"}


def build_argv(environ: dict | None = None) -> list[str]:
    """CLI argv for `pr-verify` from the PR_VERIFY_* environment.

    Empty values are omitted so the CLI defaults (and the config's
    risk_threshold for min-score) apply.
    """
    env = os.environ if environ is None else environ
    argv: list[str] = []
    root = env.get(INPUTS["root"][0], "").strip()
    if root:
        argv += ["--root", root]
    argv.append("check")
    for name, (var, flag, kind) in INPUTS.items():
        if kind == "global":
            continue
        raw = env.get(var, "")
        val = raw.strip() if isinstance(raw, str) else ""
        if not val:
            continue
        if kind == "flag":
            if val.lower() in _TRUE:
                argv.append(flag)
        else:
            argv += [flag, val]
    event = env.get("GITHUB_EVENT_PATH", "")
    if isinstance(event, str) and event.strip() and os.path.isfile(event):
        argv += ["--event-file", event]
    if wants_markdown(env):
        argv += ["--comment-file", comment_path(env)]
    return argv


def _true(env, var: str, default: bool = False) -> bool:
    raw = env.get(var, "")
    raw = raw.strip().lower() if isinstance(raw, str) else ""
    return default if not raw else raw in _TRUE


def wants_markdown(env) -> bool:
    return _true(env, ACTION_ONLY["comment"]) or _true(
        env, ACTION_ONLY["step-summary"], default=True)


def comment_path(env) -> str:
    base = env.get("RUNNER_TEMP") or tempfile.gettempdir()
    return os.path.join(base, "pr-verify-comment.md")


def write_outputs(values: dict, path: str | None) -> None:
    """Append name=value lines to $GITHUB_OUTPUT (no-op when unset). A file
    that cannot be written is one warning on stderr: the outputs are lost,
    the verdict (the exit status) is not."""
    if not path:
        return
    try:
        with open(path, "a", encoding="utf-8") as f:
            for key, val in values.items():
                f.write(f"{key}={val}\n")
    except OSError as e:
        cli._eprint(f"warning: could not write the step outputs to "
                    f"$GITHUB_OUTPUT ({path}): {e.strerror or e}")


_REPO_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_LOOPBACK = ("127.0.0.1", "localhost", "::1")


def _api_base(env) -> str | None:
    """GITHUB_API_URL, if it is somewhere the token may go: https, or http to
    this machine (the tests' stand-in server)."""
    url = (env.get("GITHUB_API_URL") or "https://api.github.com").rstrip("/")
    parts = urllib.parse.urlsplit(url)
    if parts.scheme == "https" and parts.hostname:
        return url
    if parts.scheme == "http" and parts.hostname in _LOOPBACK:
        return url
    return None


class _ApiError(Exception):
    def __init__(self, status, detail):
        super().__init__(f"HTTP {status}: {detail}")
        self.status = status


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Never follow a redirect: urllib would send the token to wherever the
    answer points. The GitHub API answers where it was asked."""

    def redirect_request(self, *args, **kwargs):
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)


def _call(method: str, url: str, token: str, body: dict | None = None):
    data = None if body is None else json.dumps(body).encode("utf-8")
    req = urllib.request.Request(url, data=data, method=method, headers={
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "pr-verify",
        **({"Content-Type": "application/json"} if data else {})})
    try:
        with _OPENER.open(req, timeout=20) as resp:
            raw = resp.read(8 * 1024 * 1024)
    except urllib.error.HTTPError as e:
        detail = ""
        try:
            detail = json.loads(e.read(4096).decode("utf-8", "replace")
                                ).get("message", "")
        except (ValueError, AttributeError, OSError):
            pass
        raise _ApiError(e.code, detail or e.reason) from None
    except (urllib.error.URLError, OSError, ValueError) as e:
        raise _ApiError("?", getattr(e, "reason", e)) from None
    try:
        return json.loads(raw.decode("utf-8", "replace")) if raw else None
    except ValueError:
        return None


def post_comment(markdown: str, env) -> str:
    """Create or update the sticky comment on the pull request. Returns what
    happened, in words ("created comment 7", "updated comment 7") or why
    nothing did ("skipped: ..."); never raises for a network or permission
    problem -- the verdict is the check's, not the comment's."""
    token = (env.get(ACTION_ONLY["github-token"]) or "").strip()
    repo = (env.get("GITHUB_REPOSITORY") or "").strip()
    if not token:
        return "skipped: no github-token"
    if not _REPO_RE.match(repo):
        return "skipped: GITHUB_REPOSITORY is not set"
    number = None
    event = env.get("GITHUB_EVENT_PATH") or ""
    if event and os.path.isfile(event):
        try:
            number = prinfo_mod.from_event(event).number
        except (OSError, ValueError):
            number = None
    if number is None:
        m = re.match(r"^refs/pull/(\d+)/", env.get("GITHUB_REF") or "")
        number = int(m.group(1)) if m else None
    if number is None:
        return "skipped: this run is not for a pull request"
    api = _api_base(env)
    if api is None:
        return "skipped: GITHUB_API_URL is not https"
    issue = f"{api}/repos/{repo}/issues/{number}/comments"
    try:
        found = []
        for page in range(1, 11):
            batch = _call("GET", f"{issue}?per_page=100&page={page}", token)
            if not isinstance(batch, list):
                break
            found += [c for c in batch if isinstance(c, dict)
                      and render_mod.STICKY_MARKER in str(c.get("body", ""))
                      and isinstance(c.get("id"), int)]
            if len(batch) < 100:
                break
        # Anyone can paste the marker into a comment of their own. Edit the
        # first one this token is allowed to edit (403/404 means it is not
        # ours, or is gone); if none is, add our own.
        for existing in found[:5]:
            try:
                _call("PATCH", f"{api}/repos/{repo}/issues/comments/"
                      f"{existing['id']}", token, {"body": markdown})
                return f"updated comment {existing['id']}"
            except _ApiError as e:
                if e.status not in (403, 404):
                    raise
        made = _call("POST", issue, token, {"body": markdown})
        return f"created comment {made.get('id') if isinstance(made, dict) else '?'}"
    except _ApiError as e:
        hint = (" (the token needs pull-requests: write; a pull request from "
                "a fork gets a read-only token)" if e.status in (401, 403)
                else "")
        return f"skipped: {e}{hint}"


def publish_markdown(result, env) -> None:
    """After the check: the comment markdown to the job summary and, if
    asked, to the pull request. Warnings only."""
    markdown = render_mod.to_comment(result.payload)
    summary = env.get("GITHUB_STEP_SUMMARY")
    if summary and _true(env, ACTION_ONLY["step-summary"], default=True):
        try:
            with open(summary, "a", encoding="utf-8") as f:
                f.write(markdown + "\n")
        except OSError as e:
            cli._eprint(f"warning: could not write the job summary "
                        f"({summary}): {e.strerror or e}")
    if _true(env, ACTION_ONLY["comment"]):
        outcome = post_comment(markdown, env)
        if outcome.startswith("skipped"):
            cli._eprint(f"warning: pull request comment {outcome}")
        else:
            cli._eprint(f"pull request comment: {outcome}")


def _status(exc: SystemExit) -> int:
    """The exit status a SystemExit stands for: None is 0, a number is
    itself, anything else (a message) is 1, as in Python."""
    if exc.code is None:
        return 0
    return exc.code if isinstance(exc.code, int) else 1


def main(argv: list[str] | None = None, environ: dict | None = None) -> int:
    cli._harden_streams()
    env = os.environ if environ is None else environ
    try:
        args = cli.build_parser().parse_args(
            build_argv(env) if argv is None else argv)
        cli._ensure_repo(args.root)
    except SystemExit as e:
        # argparse (an input the CLI refuses) and _ensure_repo (not a
        # repository, no git) say why on stderr and leave with status 2;
        # the step still sets `exit-code`, as on every other way out
        if _status(e):
            write_outputs({"exit-code": _status(e)}, env.get("GITHUB_OUTPUT"))
        raise
    try:
        result = cli.run_check(args)
    except cli.CHECK_ERRORS as e:
        cli._eprint(f"error: {cli.error_text(e)}")
        write_outputs({"exit-code": 2}, env.get("GITHUB_OUTPUT"))
        return 2
    code = result.code if cli.write_report(result, args.format) else 2
    if not cli.write_extra_files(result, args):
        code = 2
    publish_markdown(result, env)
    outputs = {
        "score": result.breakdown.score,
        "band": result.breakdown.band,
        "requires-review": str(result.breakdown.requires_review).lower(),
        "exit-code": code,
    }
    write_outputs(outputs, env.get("GITHUB_OUTPUT"))
    return code


if __name__ == "__main__":
    sys.exit(main())
