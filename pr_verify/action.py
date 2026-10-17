"""Entry point for the GitHub Action (action.yml).

The composite action passes every input through a PR_VERIFY_* environment
variable; this module turns them into the exact CLI flags of `pr-verify
check`, runs the check, prints the report and writes the outputs
(score, band, requires-review, exit-code) to $GITHUB_OUTPUT.

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
    """Append name=value lines to $GITHUB_OUTPUT (no-op when unset)."""
    if not path:
        return
    with open(path, "a", encoding="utf-8") as f:
        for key, val in values.items():
            f.write(f"{key}={val}\n")


def main(argv: list[str] | None = None, environ: dict | None = None) -> int:
    cli._harden_streams()
    env = os.environ if environ is None else environ
    args = cli.build_parser().parse_args(build_argv(env) if argv is None else argv)
    cli._ensure_repo(args.root)
    try:
        result = cli.run_check(args)
    except (RuntimeError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
        write_outputs({"exit-code": 2}, env.get("GITHUB_OUTPUT"))
        return 2
    if result.nothing:
        print(result.nothing_message())
        outputs = {"score": 0, "band": "low", "requires-review": "false",
                   "exit-code": 0}
        write_outputs(outputs, env.get("GITHUB_OUTPUT"))
        return 0
    cli.render(result, args.format)
    outputs = {
        "score": result.breakdown.score,
        "band": result.breakdown.band,
        "requires-review": str(result.breakdown.requires_review).lower(),
        "exit-code": result.code,
    }
    write_outputs(outputs, env.get("GITHUB_OUTPUT"))
    return result.code


if __name__ == "__main__":
    sys.exit(main())
