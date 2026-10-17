"""PR Verify: deterministic trust for agent-authored PRs.

Not another AI reviewer — verification, not opinion. For a diff range it
reports: which lines an agent wrote (provenance), what could break
(blast radius), whether policy gates pass, and a deterministic risk score
that tells a senior how deep to review.

  pr-verify check --base main
  pr-verify check --base origin/main --format json --min-score 60
  pr-verify init   # write an example .pr-verify.yaml

Exit status: 1 when the score fails the gate (score >= min-score, see
--min-score / --fail-on) or any policy gate fails; 2 on usage/config
errors; 0 otherwise.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import os
import subprocess
import sys

from . import blastradius as br_mod
from . import config as config_mod
from . import gates as gates_mod
from . import provenance as prov_mod
from . import risk as risk_mod

VERSION = "0.1.0"


def _harden_streams() -> None:
    """Never crash on a console that cannot encode the report (the box
    drawing and ✓/✗ marks are not in cp1252). Python's stderr already
    replaces unencodable characters; make stdout do the same."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None or getattr(stream, "errors", None) != "strict":
            continue
        try:
            reconfigure(errors="replace")
        except (OSError, ValueError):
            pass


def _ensure_repo(root: str) -> None:
    p = subprocess.run(["git", "-C", root, "rev-parse", "--git-dir"],
                       capture_output=True, timeout=15)
    if p.returncode != 0:
        print("error: not a git repo", file=sys.stderr)
        sys.exit(2)


def cmd_init(args) -> int:
    path = os.path.join(args.root, config_mod.CONFIG_FILE)
    if os.path.exists(path) and not args.force:
        print(f"{config_mod.CONFIG_FILE} exists (use --force).")
        return 2
    with open(path, "w", encoding="utf-8") as f:
        f.write(config_mod.example_config())
    print(f"wrote {config_mod.CONFIG_FILE} — tune markers, paths, gates.")
    return 0


def resolve_min_score(fail_on: str, min_score: int | None,
                      cfg_threshold: int) -> int | None:
    """The one gate rule's threshold: None means the score gate is off.

    --fail-on never   -> None (policy gates still fail the run)
    --fail-on any-risk-> 1   (any nonzero score fails)
    --fail-on high    -> --min-score if given, else the config's
                         risk_threshold (default 70)
    """
    if fail_on == "never":
        return None
    if fail_on == "any-risk":
        return 1
    return cfg_threshold if min_score is None else min_score


def _report_human(prov, blast, gate_results, breakdown, min_score) -> None:
    total_added = sum(f.added for f in prov.values())
    agent_added = sum(f.agent_added for f in prov.values())
    print("═" * 56)
    print(f"  PR VERIFY  risk {breakdown.score}/100 "
          f"({breakdown.band.upper()})")
    print("═" * 56)
    print(f"\n  provenance: {agent_added}/{total_added} added lines "
          f"agent-authored")
    for rel in sorted(prov):
        f = prov[rel]
        if f.deleted:
            who = ", ".join(f.deleted_by) or "unknown"
            print(f"    deleted  {rel} (deleted by {who})")
        elif f.added:
            who = ",".join(sorted(f.agents)) if f.agents else "human"
            print(f"    {f.label():6}  {rel} "
                  f"({f.agent_added}/{f.added} agent) [{who}]")
    print("\n  blast radius:")
    ranked = sorted(blast.values(), key=lambda b: b.size, reverse=True)[:8]
    if not ranked:
        print("    no files changed")
    for b in ranked:
        print(f"    {b.file}: {b.size} downstream dependent(s)")
        if b.direct:
            print(f"      direct: {', '.join(b.direct[:5])}"
                  + (" …" if len(b.direct) > 5 else ""))
    print("\n  gates:")
    if not gate_results:
        print("    none configured")
    for g in gate_results:
        mark = "PASS" if g.passed else ("TIMEOUT" if g.timed_out else "FAIL")
        print(f"    [{mark}] {g.command}")
    print("\n  risk factors:")
    for name, fac in breakdown.factors.items():
        print(f"    {fac['points']:>3} pts  {name:12} {fac['detail']}")
    print()
    if min_score is None:
        print(f"  - score {breakdown.score}: score gate disabled "
              "(--fail-on never)")
    elif breakdown.requires_review:
        print(f"  ✗ score {breakdown.score} >= min-score {min_score}: "
              "needs senior review")
    else:
        print(f"  ✓ score {breakdown.score} < min-score {min_score}")
    print("═" * 56)


@dataclasses.dataclass
class CheckResult:
    """Everything one `check` produced, for any renderer (CLI, Action)."""
    code: int                 # exit status
    payload: dict             # the --format json document
    prov: dict
    blast: dict
    gates: list
    breakdown: risk_mod.RiskBreakdown
    min_score: int | None


def run_check(args) -> CheckResult | None:
    """Run the verification. Returns None when there is nothing to verify.
    Raises ValueError/RuntimeError for a bad config at the base ref."""
    root = args.root
    cfg = config_mod.load(root, args.base)
    min_score = resolve_min_score(args.fail_on, args.min_score,
                                  cfg["risk_threshold"])

    # Default head (HEAD) also verifies uncommitted working-tree changes:
    # snapshot them into a synthetic commit so diff/blame see everything.
    # An explicit --head means "committed range only".
    head = args.head
    if head == "HEAD":
        snap = prov_mod.snapshot_worktree(root)
        if snap:
            head = snap
    prov = prov_mod.analyze(root, args.base, head,
                            cfg["agent_markers"])
    if not prov:
        return None
    blast = br_mod.analyze(root, list(prov.keys()))
    gate_results = (gates_mod.run_gates(root, cfg["gates"], cfg["timeout"])
                    if not args.skip_gates else [])
    # requires_review is computed from the SAME threshold the exit code
    # uses (a disabled gate can never require review).
    breakdown = risk_mod.score(prov, blast, gate_results,
                               cfg["sensitive_paths"],
                               101 if min_score is None else min_score)
    payload = {
        "tool": "pr-verify", "version": VERSION,
        "base": args.base, "head": args.head,
        "min_score": min_score,
        "risk": breakdown.as_dict(),
        "files": {
            rel: {"added": f.added, "agent_added": f.agent_added,
                  "label": f.label(), "agents": sorted(f.agents),
                  "deleted": f.deleted, "deleted_by": f.deleted_by}
            for rel, f in prov.items()},
        "blast_radius": {
            rel: {"direct": b.direct, "transitive": b.transitive}
            for rel, b in blast.items()},
        "gates": [g.as_dict() for g in gate_results],
    }
    if any(not g.passed for g in gate_results):
        # A failing policy gate is a failed verification, independent of
        # --fail-on: the tool cannot vouch for this diff.
        code = 1
    elif breakdown.requires_review:
        code = 1
    else:
        code = 0
    return CheckResult(code=code, payload=payload, prov=prov, blast=blast,
                       gates=gate_results, breakdown=breakdown,
                       min_score=min_score)


def render(result: CheckResult, fmt: str) -> None:
    if fmt == "json":
        print(json.dumps(result.payload, indent=2))
    else:
        _report_human(result.prov, result.blast, result.gates,
                      result.breakdown, result.min_score)


def cmd_check(args) -> int:
    _ensure_repo(args.root)
    try:
        result = run_check(args)
    except (RuntimeError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    if result is None:
        print(f"no added lines in {args.base}..{args.head} — nothing to verify")
        return 0
    render(result, args.format)
    return result.code


def _score_arg(value: str) -> int:
    try:
        n = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"expected an integer, got {value!r}")
    if not 0 <= n <= 100:
        raise argparse.ArgumentTypeError("--min-score must be 0..100")
    return n


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="pr-verify", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    p.add_argument("--root", default=os.getcwd(),
                   help="Repo path (default: current directory).")
    sub = p.add_subparsers(dest="cmd", required=True)

    i = sub.add_parser("init", help="Write example .pr-verify.yaml.")
    i.add_argument("--force", action="store_true")

    c = sub.add_parser("check", help="Verify a diff range.")
    c.add_argument("--base", default="main",
                   help="Base ref (default: main).")
    c.add_argument("--head", default="HEAD",
                   help="Head ref (default: HEAD, uncommitted "
                        "working-tree changes included).")
    c.add_argument("--format", choices=["human", "json"], default="human")
    c.add_argument("--fail-on", choices=["high", "any-risk", "never"],
                   default="high",
                   help="high: fail when score >= min-score (default); "
                        "any-risk: fail when score >= 1; never: no score "
                        "gate (policy gates still fail the run).")
    c.add_argument("--min-score", type=_score_arg, default=None,
                   metavar="N",
                   help="Score at which the verification fails (score >= N "
                        "fails, N included). Overrides risk_threshold from "
                        ".pr-verify.yaml (default 70).")
    c.add_argument("--skip-gates", action="store_true",
                   help="Do not run the policy gates from .pr-verify.yaml.")
    return p


def main(argv=None) -> int:
    _harden_streams()
    args = build_parser().parse_args(argv)
    return {"init": cmd_init, "check": cmd_check}[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
