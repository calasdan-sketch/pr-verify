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
"""

from __future__ import annotations

import os
import sys

from . import cli

#: input name -> (env var, CLI flag, kind). kind: "value" | "flag" | "global".
INPUTS: dict[str, tuple[str, str, str]] = {
    "base": ("PR_VERIFY_BASE", "--base", "value"),
    "head": ("PR_VERIFY_HEAD", "--head", "value"),
    "format": ("PR_VERIFY_FORMAT", "--format", "value"),
    "fail-on": ("PR_VERIFY_FAIL_ON", "--fail-on", "value"),
    "min-score": ("PR_VERIFY_MIN_SCORE", "--min-score", "value"),
    "skip-gates": ("PR_VERIFY_SKIP_GATES", "--skip-gates", "flag"),
    "root": ("PR_VERIFY_ROOT", "--root", "global"),
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
    return argv


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
