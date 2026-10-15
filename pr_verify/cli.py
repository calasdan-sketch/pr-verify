"""PR Verify: deterministic trust for agent-authored PRs.

Not another AI reviewer — verification, not opinion. For a diff range it
reports: which lines an agent wrote (provenance), what could break
(blast radius), whether policy gates pass, and a deterministic risk score
that tells a senior how deep to review.

  pr-verify check --base main
  pr-verify check --base origin/main --format json --fail-on high
  pr-verify init   # write an example .pr-verify.yaml
"""

from __future__ import annotations

import argparse
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
    with open(path, "w") as f:
        f.write(config_mod.example_config())
    print(f"wrote {config_mod.CONFIG_FILE} — tune markers, paths, gates.")
    return 0


def _report_human(prov, blast, gate_results, breakdown, threshold) -> None:
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
    if breakdown.requires_review:
        print(f"  ✗ score {breakdown.score} >= threshold {threshold}: "
              "needs senior review")
    else:
        print(f"  ✓ score {breakdown.score} < threshold {threshold}")
    print("═" * 56)


def cmd_check(args) -> int:
    root = args.root
    _ensure_repo(root)
    cfg = config_mod.load(root, args.base)

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
        print(f"no added lines in {args.base}..{args.head} — nothing to verify")
        return 0
    blast = br_mod.analyze(root, list(prov.keys()))
    gate_results = (gates_mod.run_gates(root, cfg["gates"], cfg["timeout"])
                    if not args.skip_gates else [])
    breakdown = risk_mod.score(prov, blast, gate_results,
                               cfg["sensitive_paths"],
                               cfg["risk_threshold"])

    if args.format == "json":
        out = {
            "tool": "pr-verify", "version": VERSION,
            "base": args.base, "head": args.head,
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
        print(json.dumps(out, indent=2))
    else:
        _report_human(prov, blast, gate_results, breakdown,
                      cfg["risk_threshold"])

    if any(not g.passed for g in gate_results):
        # A failing policy gate is a failed verification, independent of
        # --fail-on: the tool cannot vouch for this diff.
        return 1
    if args.fail_on == "high" and breakdown.requires_review:
        return 1
    if args.fail_on == "any-risk" and breakdown.score > 0:
        return 1
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="pr-verify", description=__doc__)
    p.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    p.add_argument("--root", default=os.getcwd())
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
                   default="high")
    c.add_argument("--skip-gates", action="store_true")
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    return {"init": cmd_init, "check": cmd_check}[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
