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
errors; 0 otherwise. A reader that stops early (`| head -1`) cuts the
report short but never changes it.
"""

from __future__ import annotations

import argparse
import contextlib
import dataclasses
import errno
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
        # Both handlers raise UnicodeEncodeError on a character the code
        # page lacks: "strict" (the default) and "surrogateescape" (what a
        # piped stdout reports on Windows 11 / Python 3.11, with cp1252).
        if reconfigure is None or getattr(stream, "errors", None) not in (
                "strict", "surrogateescape"):
            continue
        try:
            reconfigure(errors="replace")
        except (OSError, ValueError):
            pass


def _on_windows() -> bool:
    return os.name == "nt"


def _is_closed_pipe(exc: OSError) -> bool:
    """True when the reader of our output went away (`... | head -1`).

    That is BrokenPipeError (EPIPE) wherever it is reported so. Windows
    reports it differently: with Python 3.11 on Windows 11, print() into a
    pipe whose reader is gone succeeds (it is only buffered), then flush()
    raises a plain OSError, errno EINVAL, no winerror, not a
    BrokenPipeError; unbuffered, the same error comes out of print() itself.
    EINVAL means a closed pipe only there. Anywhere else it is a real error
    and propagates."""
    if isinstance(exc, BrokenPipeError) or exc.errno == errno.EPIPE:
        return True
    return _on_windows() and exc.errno == errno.EINVAL


def _discard(stream) -> None:
    """Point a stream's descriptor at the null device so whatever is still
    buffered flushes harmlessly, now and at exit; otherwise Python reports
    "Exception ignored on flushing sys.stdout" and exits with status 120."""
    try:
        devnull = os.open(os.devnull, os.O_WRONLY)
        try:
            os.dup2(devnull, stream.fileno())
        finally:
            os.close(devnull)
    except (OSError, ValueError, AttributeError):
        pass    # not a real file (captured, replaced): nothing to do


def _flush_stdout() -> None:
    """Flush stdout now, while the verdict is still in hand. Output that
    fits in the buffer fails at its first flush, which is otherwise the one
    the interpreter makes on its way out, where nothing can be done."""
    if sys.stdout is None:
        return
    try:
        sys.stdout.flush()
    except OSError as e:
        if not _is_closed_pipe(e):
            raise
        _discard(sys.stdout)


#: What a terminal acts on, and so is never printed as it is: the C0
#: controls (tab and newline apart), DEL, the C1 controls (U+009B is CSI,
#: one character for ESC [), the Unicode line and paragraph separators and
#: the bidirectional overrides and isolates (they reorder what is on
#: screen). Each is shown as the escape Python writes for it, \x1b for ESC,
#: so the text stays readable and nothing is lost.
_ESCAPES = {
    cp: ("\\x%02x" if cp < 0x100 else "\\u%04x") % cp
    for cp in (*range(0x00, 0x09), *range(0x0B, 0x20), *range(0x7F, 0xA0),
               0x2028, 0x2029, *range(0x202A, 0x202F),
               *range(0x2066, 0x206A))}


def _neutralize(text: str) -> str:
    """text with every character a terminal acts on shown as a visible
    escape (\\x1b for ESC). Tab and newline are text and stay."""
    return text.translate(_ESCAPES)


def _one_line(text: str) -> str:
    """text as ONE line of output. The report is made of names the PR's
    author chose, and a name with a newline in it would start a line of its
    own, which can read as a verdict: the newline is shown as \\x0a. A line
    that starts with :: (after any indentation) is a workflow command in a
    GitHub Actions log -- an annotation, a mask, `stop-commands` -- so its
    first colon is shown as \\x3a."""
    line = _neutralize(text).replace("\n", "\\x0a")
    body = line.lstrip()
    if body.startswith("::"):
        cut = len(line) - len(body)
        line = line[:cut] + "\\x3a" + line[cut + 1:]
    return line


def _out(line: str = "") -> None:
    """Print one line of the report. Everything shown to a person goes
    through here or through _eprint; the JSON document is the exception,
    which json.dumps escapes itself."""
    print(_one_line(line))


def _eprint(message: str) -> None:
    """A message on stderr, whose reader can go away too (`2>&1 | head -1`):
    the exit status that goes with the message (2) must survive that."""
    try:
        print(_one_line(message), file=sys.stderr)
        sys.stderr.flush()
    except OSError as e:
        if not _is_closed_pipe(e):
            raise
        _discard(sys.stderr)


@contextlib.contextmanager
def _stdout_may_close():
    """Wrap the code that prints the report.

    A reader that stops reading (`pr-verify check | head -1`) is not an
    error and must not change the exit status, which is the verdict CI
    acts on. Callers compute the verdict first and return it whatever
    happened to the report, so 0 stays a pass and 1 a fail (a blanket
    exit(1) here would fail every passing check). Only a closed pipe is
    absorbed; any other write error still propagates. The flush is part of
    the guard, also when the body ends in SystemExit (argparse's --help and
    --version), so output that fits in the buffer fails here, where the
    verdict is still in hand, and not at interpreter exit.
    """
    try:
        yield
    except OSError as e:
        if not _is_closed_pipe(e):
            raise
        _discard(sys.stdout)
    finally:
        _flush_stdout()


def _ensure_repo(root: str) -> None:
    try:
        p = subprocess.run(["git", "-C", root, "rev-parse", "--git-dir"],
                           capture_output=True, timeout=15)
    except FileNotFoundError:
        _eprint("error: git not found on PATH — pr-verify needs the git "
                "command line tool (https://git-scm.com/downloads)")
        sys.exit(2)
    except (OSError, subprocess.SubprocessError) as e:
        _eprint(f"error: could not run git: {e}")
        sys.exit(2)
    if p.returncode != 0:
        _eprint("error: not a git repo")
        sys.exit(2)


def repo_root(path: str) -> str:
    """The top level of the repository that contains path.

    Every git path (diff, blame, pathspecs) is relative to the top level,
    and so must be every scan of the worktree, whichever directory
    pr-verify was started in or --root names. Returns path itself when git
    cannot name a top level (not a repository, a bare repository, the .git
    directory)."""
    try:
        p = subprocess.run(["git", "-C", path, "rev-parse", "--show-toplevel"],
                           capture_output=True, timeout=15)
    except (OSError, subprocess.SubprocessError):
        return path
    top = os.fsdecode(p.stdout).rstrip("\r\n") if p.returncode == 0 else ""
    return os.path.normpath(top) if top else path


def _same_dir(a: str, b: str) -> bool:
    try:
        return os.path.samefile(a, b)
    except OSError:
        return (os.path.normcase(os.path.abspath(a))
                == os.path.normcase(os.path.abspath(b)))


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
    # The config is read from the base ref's top level, so that is where it
    # belongs, also when started in (or pointed at) a subdirectory.
    root = repo_root(args.root)
    where = ("" if _same_dir(root, args.root)
             else f" at the repository root ({root})")
    path = os.path.join(root, config_mod.CONFIG_FILE)
    if os.path.exists(path) and not args.force:
        with _stdout_may_close():
            _out(f"{config_mod.CONFIG_FILE} exists{where} (use --force).")
        return 2
    with open(path, "w", encoding="utf-8") as f:
        f.write(config_mod.example_config())
    base = detect_base(root) or "your base branch"
    with _stdout_may_close():
        _out(f"wrote {config_mod.CONFIG_FILE}{where} — tune markers, "
             f"paths, gates.")
        _out(f"note: the config is read from the base ref, so commit this "
             f"file to {base} for it to take effect (an uncommitted copy "
             f"does nothing and is not scored).")
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


def _blast_tail(b: "br_mod.BlastRadius") -> str:
    """Why a changed file shows no dependents, when that is because the
    scan could not see it (a bare "0 downstream dependent(s)" reads as
    "looked, found nothing")."""
    if not b.external_only:
        return ""
    if b.scan == "not_source":
        ext = os.path.splitext(b.file)[1].lower()
        what = f"{ext} files are" if ext else "this file type is"
        return f"  ({what} not scanned for imports)"
    if b.scan == "not_in_worktree":
        why = "not in the worktree"
    elif b.scan == "skipped_dir":
        why = f"in {br_mod.skipped_dir(b.file)}/, which the import scan skips"
    else:
        why = "not reached by the import scan"
    return f"  ({why}; nothing in-repo imports it)"


def _report_human(result: "CheckResult") -> None:
    prov, blast, gate_results = result.prov, result.blast, result.gates
    breakdown, min_score = result.breakdown, result.min_score
    total_added = sum(f.added for f in prov.values())
    agent_added = sum(f.agent_added for f in prov.values())
    _out("═" * 56)
    _out(f"  PR VERIFY  risk {breakdown.score}/100 "
         f"({breakdown.band.upper()})")
    _out("═" * 56)
    _out()
    _out(f"  base: {result.payload['base']}"
         + ("  (auto-detected)" if result.base_detected else ""))
    for note in result.notes:
        _out(f"  note: {note}")
    _out()
    _out(f"  provenance: {agent_added}/{total_added} added lines "
         f"agent-authored")
    for rel in sorted(prov):
        f = prov[rel]
        if f.deleted:
            who = ", ".join(f.deleted_by) or "unknown"
            _out(f"    deleted  {rel} (deleted by {who})")
        elif f.added:
            who = ", ".join(sorted(f.agents)) if f.agents else "human"
            _out(f"    {f.label():6}  {rel} "
                 f"({f.agent_added}/{f.added} agent) [{who}]")
    _out()
    _out("  blast radius:")
    ranked = sorted(blast.values(), key=lambda b: b.size, reverse=True)[:8]
    if not ranked:
        _out("    no files changed")
    for b in ranked:
        tail = _blast_tail(b)
        _out(f"    {b.file}: {b.size} downstream dependent(s){tail}")
        if b.direct:
            _out(f"      direct: {', '.join(b.direct[:5])}"
                 + (" …" if len(b.direct) > 5 else ""))
    _out()
    _out("  gates:")
    if not gate_results:
        _out("    none configured")
    for g in gate_results:
        mark = "PASS" if g.passed else ("TIMEOUT" if g.timed_out else "FAIL")
        _out(f"    [{mark}] {g.command}")
    _out()
    _out("  risk factors:")
    for name, fac in breakdown.factors.items():
        _out(f"    {fac['points']:>3} pts  {name:12} {fac['detail']}")
    _out()
    failed = [g.command for g in gate_results if not g.passed]
    if failed:
        # A failed policy gate fails the verification whatever the score:
        # the verdict line must say so, never end on a green tick.
        _out(f"  ✗ policy gate failed: {', '.join(failed)}")
        score_mark = "-"
    elif min_score is None or not breakdown.requires_review:
        score_mark = "✓"
    else:
        score_mark = "✗"
    if min_score is None:
        _out(f"  {score_mark} score {breakdown.score}: score gate disabled "
             "(--fail-on never)")
    elif breakdown.requires_review:
        _out(f"  {score_mark} score {breakdown.score} >= min-score {min_score}: "
             "needs senior review")
    else:
        _out(f"  {score_mark} score {breakdown.score} < min-score {min_score}")
    _out("═" * 56)


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

    def nothing_lines(self) -> list[str]:
        """What the human report says when there is nothing to verify: one
        sentence, and the notes."""
        lines = [f"no added lines in {self.payload['base']}.."
                 f"{self.payload['head']} — nothing to verify"]
        return lines + [f"note: {note}" for note in self.notes]


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
    root = repo_root(args.root)
    notes: list[str] = []
    if not _same_dir(root, args.root):
        notes.append(f"{args.root} is inside the repository at {root}: the "
                     f"whole repository is verified")
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
    if prov:
        blast = br_mod.analyze(root, list(prov.keys()))
        gate_results = (gates_mod.run_gates(root, cfg["gates"], cfg["timeout"])
                        if not args.skip_gates else [])
        # requires_review is computed from the SAME threshold the exit code
        # uses (a disabled gate can never require review).
        breakdown = risk_mod.score(prov, blast, gate_results,
                                   cfg["sensitive_paths"],
                                   101 if min_score is None else min_score)
    else:
        # Nothing added or deleted: nothing to scan or run, and nothing to
        # review whatever the threshold. The document below still has the
        # shape of every other, for the program that reads it.
        blast, gate_results = {}, []
        breakdown = risk_mod.score({}, {}, [], [], 101)
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
                  "external_only": b.external_only, "scan": b.scan}
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
                       notes=notes, nothing=not prov)


def render(result: CheckResult, fmt: str) -> None:
    if fmt == "json":
        print(json.dumps(result.payload, indent=2))    # exact: JSON escapes
    elif result.nothing:
        for line in result.nothing_lines():
            _out(line)
    else:
        _report_human(result)


def cmd_check(args) -> int:
    _ensure_repo(args.root)
    try:
        result = run_check(args)
    except (RuntimeError, ValueError) as e:
        _eprint(f"error: {e}")
        return 2
    with _stdout_may_close():
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
                   help="Path inside the repository (default: current "
                        "directory). The repository's top level is "
                        "verified, also when this is a subdirectory.")
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
    # --help and --version print here and exit. argparse ignores a failed
    # write, so a closed pipe would only show at the flush on the way out.
    with _stdout_may_close():
        args = build_parser().parse_args(argv)
    return {"init": cmd_init, "check": cmd_check}[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
