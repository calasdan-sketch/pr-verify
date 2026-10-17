"""PR Verify: deterministic trust for agent-authored PRs.

Not another AI reviewer — verification, not opinion. For a diff range it
reports: which lines an agent wrote (provenance), what could break
(blast radius), whether policy gates pass, and a deterministic risk score
that tells a senior how deep to review.

  pr-verify check                         # base auto-detected
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

#: Tried in order when --base is not given (after origin/HEAD).
BASE_CANDIDATES = ("main", "master", "origin/main", "origin/master")


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
    try:
        p = subprocess.run(["git", "-C", root, "rev-parse", "--git-dir"],
                           capture_output=True, timeout=15)
    except FileNotFoundError:
        print("error: git not found on PATH — pr-verify needs the git "
              "command line tool (https://git-scm.com/downloads)",
              file=sys.stderr)
        sys.exit(2)
    except (OSError, subprocess.SubprocessError) as e:
        print(f"error: could not run git: {e}", file=sys.stderr)
        sys.exit(2)
    if p.returncode != 0:
        print("error: not a git repo", file=sys.stderr)
        sys.exit(2)


def _rev_ok(root: str, rev: str) -> bool:
    p = subprocess.run(["git", "-C", root, "rev-parse", "--verify", "--quiet",
                        rev + "^{commit}"], capture_output=True, timeout=15)
    return p.returncode == 0


def detect_base(root: str) -> str | None:
    """The default branch: origin/HEAD's target, else the first of
    main, master, origin/main, origin/master that exists."""
    p = subprocess.run(["git", "-C", root, "symbolic-ref", "--quiet", "--short",
                        "refs/remotes/origin/HEAD"],
                       capture_output=True, text=True, encoding="utf-8",
                       errors="replace", timeout=15)
    if p.returncode == 0 and p.stdout.strip() and _rev_ok(root, p.stdout.strip()):
        return p.stdout.strip()
    for cand in BASE_CANDIDATES:
        if _rev_ok(root, cand):
            return cand
    return None


def cmd_init(args) -> int:
    path = os.path.join(args.root, config_mod.CONFIG_FILE)
    if os.path.exists(path) and not args.force:
        print(f"{config_mod.CONFIG_FILE} exists (use --force).")
        return 2
    with open(path, "w", encoding="utf-8") as f:
        f.write(config_mod.example_config())
    base = detect_base(args.root) or "your base branch"
    print(f"wrote {config_mod.CONFIG_FILE} — tune markers, paths, gates.")
    print(f"note: the config is read from the base ref, so commit this file "
          f"to {base} for it to take effect (an uncommitted copy does "
          f"nothing and is not scored).")
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


def _report_human(result: "CheckResult") -> None:
    prov, blast, gate_results = result.prov, result.blast, result.gates
    breakdown, min_score = result.breakdown, result.min_score
    total_added = sum(f.added for f in prov.values())
    agent_added = sum(f.agent_added for f in prov.values())
    print("═" * 56)
    print(f"  PR VERIFY  risk {breakdown.score}/100 "
          f"({breakdown.band.upper()})")
    print("═" * 56)
    print(f"\n  base: {result.payload['base']}"
          + ("  (auto-detected)" if result.base_detected else ""))
    for note in result.notes:
        print(f"  note: {note}")
    print(f"\n  provenance: {agent_added}/{total_added} added lines "
          f"agent-authored")
    for rel in sorted(prov):
        f = prov[rel]
        if f.deleted:
            who = ", ".join(f.deleted_by) or "unknown"
            print(f"    deleted  {rel} (deleted by {who})")
        elif f.added:
            who = ", ".join(sorted(f.agents)) if f.agents else "human"
            print(f"    {f.label():6}  {rel} "
                  f"({f.agent_added}/{f.added} agent) [{who}]")
    print("\n  blast radius:")
    ranked = sorted(blast.values(), key=lambda b: b.size, reverse=True)[:8]
    if not ranked:
        print("    no files changed")
    for b in ranked:
        tail = ""
        if b.external_only:
            tail = "  (not in the worktree; nothing in-repo imports it)"
        print(f"    {b.file}: {b.size} downstream dependent(s){tail}")
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
    failed = [g.command for g in gate_results if not g.passed]
    if failed:
        # A failed policy gate fails the verification whatever the score:
        # the verdict line must say so, never end on a green tick.
        print(f"  ✗ policy gate failed: {', '.join(failed)}")
        score_mark = "-"
    elif min_score is None or not breakdown.requires_review:
        score_mark = "✓"
    else:
        score_mark = "✗"
    if min_score is None:
        print(f"  {score_mark} score {breakdown.score}: score gate disabled "
              "(--fail-on never)")
    elif breakdown.requires_review:
        print(f"  {score_mark} score {breakdown.score} >= min-score {min_score}: "
              "needs senior review")
    else:
        print(f"  {score_mark} score {breakdown.score} < min-score {min_score}")
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
    base_detected: bool = False
    notes: list = dataclasses.field(default_factory=list)
    nothing: bool = False     # no added/deleted lines in the range

    def nothing_message(self) -> str:
        base = self.payload["base"]
        msg = (f"no added lines in {base}..{self.payload['head']} — "
               f"nothing to verify")
        for note in self.notes:
            msg += f"\nnote: {note}"
        return msg


def _config_note(root: str, base: str) -> str | None:
    """Say so when the worktree's .pr-verify.yaml is not the one in
    effect (the base ref's copy is)."""
    path = os.path.join(root, config_mod.CONFIG_FILE)
    if not os.path.exists(path):
        return None
    p = subprocess.run(["git", "-C", root, "diff", "--quiet", base, "--",
                        config_mod.CONFIG_FILE],
                       capture_output=True, timeout=15)
    p2 = subprocess.run(["git", "-C", root, "cat-file", "-e",
                         f"{base}:{config_mod.CONFIG_FILE}"],
                        capture_output=True, timeout=15)
    if p2.returncode != 0:
        return (f"{config_mod.CONFIG_FILE} exists in the worktree but not at "
                f"{base}: defaults are in effect — commit it to {base}")
    if p.returncode != 0:
        return (f"{config_mod.CONFIG_FILE} in the worktree differs from "
                f"{base}: the {base} version is in effect — commit it to "
                f"{base}")
    return None


def run_check(args) -> CheckResult:
    """Run the verification. The result's `nothing` is True when the range
    has no added or deleted lines. Raises ValueError/RuntimeError for a
    bad config at the base ref or when no base branch can be found."""
    root = args.root
    base_detected = False
    base = args.base
    if not base:
        base = detect_base(root)
        base_detected = True
        if not base:
            raise RuntimeError(
                "could not detect the base branch (no origin/HEAD, main, "
                "master, origin/main or origin/master) — pass --base <ref>")
    elif not _rev_ok(root, base):
        raise RuntimeError(f"base ref {base!r} does not exist — pass --base "
                           f"<ref> (tried as given; detection would use: "
                           f"{detect_base(root) or 'nothing found'})")
    cfg = config_mod.load(root, base)
    min_score = resolve_min_score(args.fail_on, args.min_score,
                                  cfg["risk_threshold"])
    notes: list[str] = []
    note = _config_note(root, base)
    if note:
        notes.append(note)

    # Default head (HEAD) also verifies uncommitted working-tree changes:
    # snapshot them into a synthetic commit so diff/blame see everything.
    # An explicit --head means "committed range only".
    head = args.head
    untracked_skipped: list[str] = []
    include_untracked = bool(getattr(args, "include_untracked", False))
    if head == "HEAD":
        snap = prov_mod.snapshot_worktree(root, include_untracked=include_untracked)
        if snap:
            head = snap
        if not include_untracked:
            untracked_skipped = [p for p in prov_mod.untracked_files(root)
                                 if p != config_mod.CONFIG_FILE]
            if untracked_skipped:
                shown = ", ".join(untracked_skipped[:5])
                if len(untracked_skipped) > 5:
                    shown += f", … ({len(untracked_skipped)} total)"
                notes.append(f"{len(untracked_skipped)} untracked file(s) not "
                             f"verified ({shown}) — `git add` them or pass "
                             f"--include-untracked")
    prov = prov_mod.analyze(root, base, head, cfg["agent_markers"])
    if not prov:
        empty = risk_mod.score({}, {}, [], [], 101)
        return CheckResult(code=0, prov={}, blast={}, gates=[],
                           breakdown=empty, min_score=min_score,
                           base_detected=base_detected, notes=notes,
                           nothing=True,
                           payload={"tool": "pr-verify", "version": VERSION,
                                    "base": base, "base_detected": base_detected,
                                    "head": args.head, "min_score": min_score,
                                    "notes": notes, "files": {}})
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
        "base": base, "base_detected": base_detected, "head": args.head,
        "min_score": min_score,
        "notes": notes,
        "untracked_skipped": untracked_skipped,
        "risk": breakdown.as_dict(),
        "files": {
            rel: {"added": f.added, "agent_added": f.agent_added,
                  "label": f.label(), "agents": sorted(f.agents),
                  "deleted": f.deleted, "deleted_by": f.deleted_by}
            for rel, f in prov.items()},
        "blast_radius": {
            rel: {"direct": b.direct, "transitive": b.transitive,
                  "external_only": b.external_only}
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
                       min_score=min_score, base_detected=base_detected,
                       notes=notes)


def render(result: CheckResult, fmt: str) -> None:
    if fmt == "json":
        print(json.dumps(result.payload, indent=2))
    else:
        _report_human(result)


def cmd_check(args) -> int:
    _ensure_repo(args.root)
    try:
        result = run_check(args)
    except (RuntimeError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    if result.nothing:
        print(result.nothing_message())
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
    c.add_argument("--base", default=None,
                   help="Base ref (default: auto-detect — origin/HEAD, then "
                        "main, master, origin/main, origin/master; the "
                        "report says which was used).")
    c.add_argument("--head", default="HEAD",
                   help="Head ref (default: HEAD, uncommitted changes to "
                        "tracked files included).")
    c.add_argument("--include-untracked", action="store_true",
                   help="Also verify untracked (not yet `git add`ed) files. "
                        "Off by default: snapshotting writes their content "
                        "into .git/objects (a dangling commit, pruned by gc).")
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
