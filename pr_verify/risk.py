"""Risk scoring: deterministic, documented, no LLM.

Score 0-100 from eight observable factors. The formula is public so teams
can argue with it and tune it — a black-box score is just another opinion.

  agent_share  40 pts  % of changed lines (added + removed) that an agent
                      wrote or removed (provenance); a whole deleted file
                      is not counted here, see `deletion`
  blast        25 pts  log-scaled transitive dependents: 25 * min(1, log10(1+n)/2)
                      (n=9 -> ~12.5, n=99 -> 25)
  sensitive    20 pts  any changed file under a sensitive_path glob, case
                      ignored (deleted files match like touched files)
  gates        10 pts  any policy gate failed or timed out (0 if no gates)
  no_tests      5 pts  src changed but no test file changed
  deletion     50 pts  agent-attributed deletions: 45 if any deleted file
                      matches a sensitive_path glob (deleting sensitive
                      code, not touching it), else 10 for any agent
                      deletion of tracked files; plus blast-radius-style
                      points for the deleted files' transitive dependents
                      (25 * min(1, log10(1+n)/2)), capped at 50.
                      A pure-deletion PR previously capped at ~50 and could
                      never trip the high threshold; deleting auth.py is at
                      least as scary as rewriting it.

  test_integrity 15 pts  any finding of the test-integrity check (testintegrity.py:
                      an agent deleted, skipped, focused or loosened a test)
  policy       10 pts  any violation of the policy rules in the config
                      (policy.py), which also fails the verification

Bands: 0-29 low · 30-69 medium · 70-100 high — labels only.

THE GATE (one rule, everywhere): the verification fails when
score >= min_score. min_score is --min-score, else the config's
risk_threshold, else 70. A score exactly equal to min_score fails.
requires_review (computed here, in score()) feeds the JSON, the ✗/✓ line
in the human report and the exit code -- one comparison; the band names
never decide pass/fail.

Test files (for no_tests) are recognised by path component -- tests/,
test/, __tests__/, spec/ -- or by filename pattern: test_*.py, *_test.*,
*.test.*, *.spec.*, *Test.java, *Tests.cs, conftest.py. A bare "test"
substring is not enough: latest.py and attestation.py are source.
"""

from __future__ import annotations

import dataclasses
import fnmatch
import math
import os

from . import blastradius as br_mod
from . import gates as gates_mod
from . import provenance as prov_mod


@dataclasses.dataclass
class RiskBreakdown:
    score: int
    band: str
    factors: dict  # name -> {"points": int, "detail": str}
    requires_review: bool

    def as_dict(self) -> dict:
        return {"score": self.score, "band": self.band,
                "factors": self.factors,
                "requires_review": self.requires_review}


DEFAULT_MIN_SCORE = 70

_TEST_DIRS = {"tests", "test", "__tests__", "spec", "specs", "testing"}
_TEST_FILE_GLOBS = ("test_*", "*_test.*", "*.test.*", "*.spec.*",
                    "*Test.java", "*Tests.java", "*Test.kt", "*Tests.cs",
                    "*Test.cs", "*_spec.rb", "conftest.py")


def _is_test_file(rel: str) -> bool:
    parts = rel.replace("\\", "/").split("/")
    if any(p.lower() in _TEST_DIRS for p in parts[:-1]):
        return True
    base = parts[-1]
    return any(fnmatch.fnmatchcase(base, g) or fnmatch.fnmatchcase(base.lower(), g)
               for g in _TEST_FILE_GLOBS)


def _sensitive_candidates(f: str) -> list[str]:
    # Globs are matched against the full repo-relative path AND the
    # bare filename, so a pattern like "*auth*" catches auth.py at the
    # repo root or nested anywhere — not just under matched directories.
    base = os.path.basename(f)
    return [f, "/" + f, base, "/" + base]


def _sensitive_hits(files: list[str], sensitive_paths: list[str]) -> list[str]:
    """The files that match a sensitive glob, ignoring case: Login.tsx and
    PASSWORD.txt are as sensitive as login.tsx (and the file systems of
    Windows and macOS do not tell them apart either)."""
    globs = [p.casefold() for p in sensitive_paths]
    return sorted({f for f in files
                   if any(fnmatch.fnmatchcase(c.casefold(), p)
                          for c in _sensitive_candidates(f)
                          for p in globs)})


def _blast_points(n: int, cap: int) -> int:
    """Log-scaled dependents -> points, shared by blast and deletion."""
    return round(cap * min(1.0, math.log10(1 + n) / 2)) if n else 0


def score(prov: dict[str, prov_mod.FileProvenance],
          blast: dict[str, br_mod.BlastRadius],
          gate_results: list[gates_mod.GateResult],
          sensitive_paths: list[str],
          threshold: int,
          integrity_findings: int = 0,
          policy_violations: int = 0) -> RiskBreakdown:
    factors: dict[str, dict] = {}

    total_added = sum(f.added for f in prov.values())
    agent_added = sum(f.agent_added for f in prov.values())
    total_removed = sum(f.removed for f in prov.values())
    agent_removed = sum(f.agent_removed for f in prov.values())
    total_changed = total_added + total_removed
    share = ((agent_added + agent_removed) / total_changed
             if total_changed else 0.0)
    pts = round(share * 40)
    if total_removed:
        detail = (f"{agent_added + agent_removed}/{total_changed} changed "
                  f"lines agent-authored ({share:.0%}): {agent_added}/"
                  f"{total_added} added, {agent_removed}/{total_removed} "
                  f"removed")
    else:
        detail = (f"{agent_added}/{total_added} added lines agent-authored "
                  f"({share:.0%})")
    factors["agent_share"] = {"points": pts, "detail": detail}

    max_n = max((b.size for b in blast.values()), default=0)
    pts = _blast_points(max_n, 25)
    factors["blast"] = {
        "points": pts,
        "detail": f"largest blast radius: {max_n} downstream dependent(s)"}

    # Deleted files match the sensitive globs like touched files do —
    # deleting auth.py is not a way to dodge the sensitive factor.
    sens_hits = _sensitive_hits(list(prov), sensitive_paths)
    pts = 20 if sens_hits else 0
    factors["sensitive"] = {
        "points": pts,
        "detail": f"sensitive files touched: {', '.join(sens_hits) or 'none'}"}

    failed = [g.command for g in gate_results
              if not g.passed]
    pts = 10 if failed else 0
    factors["gates"] = {
        "points": pts,
        "detail": (f"failed gates: {', '.join(failed)}"
                   if failed else
                   f"{len(gate_results)} gate(s) passed"
                   if gate_results else "no gates configured")}

    src_changed = any(not _is_test_file(f) for f in prov)
    tests_changed = any(_is_test_file(f) for f in prov)
    pts = 5 if (src_changed and not tests_changed) else 0
    factors["no_tests"] = {
        "points": pts,
        "detail": ("source changed with no test changes"
                   if pts else "tests touched or no source changes")}

    # Deletions: pure-deletion PRs contribute ~0 to agent_share (no added
    # lines), so a deletion factor makes sure they can still trip the
    # threshold. Only agent-attributed deletions count — a human deleting
    # a file is their own review problem, not an agent-trust problem.
    # Deleting sensitive code is the worst case (45): unlike a touch, the
    # file can no longer be fixed in place, only restored. Otherwise an
    # agent deleting tracked files at all is worth 10, plus
    # blast-radius-style points for the deleted files' dependents (a
    # deleted import breaks its importers just like a bad edit would).
    agent_deleted = [f for f in prov.values()
                     if f.deleted and f.agents]
    if agent_deleted:
        del_names = [f.file for f in agent_deleted]
        max_dep = max((blast[f].size for f in del_names if f in blast),
                      default=0)
        pts = _blast_points(max_dep, 25)
        if _sensitive_hits(del_names, sensitive_paths):
            pts += 45
        else:
            pts += 10
        pts = min(50, pts)
        factors["deletion"] = {
            "points": pts,
            "detail": (f"agent-deleted: {', '.join(del_names)}; "
                       f"sensitive: "
                       f"{', '.join(_sensitive_hits(del_names, sensitive_paths)) or 'none'}; "
                       f"largest deleted-file dependents: {max_dep}")}
    else:
        factors["deletion"] = {
            "points": 0,
            "detail": "no agent-attributed deletions"}

    factors["test_integrity"] = {
        "points": 15 if integrity_findings else 0,
        "detail": (f"{integrity_findings} test-integrity finding(s)"
                   if integrity_findings else "no test-integrity findings")}
    factors["policy"] = {
        "points": 10 if policy_violations else 0,
        "detail": (f"{policy_violations} policy violation(s)"
                   if policy_violations else "no policy violations")}

    total = min(100, sum(f["points"] for f in factors.values()))
    band = "low" if total < 30 else "medium" if total < 70 else "high"
    # THE gate: one comparison, score >= min_score fails (equal fails).
    return RiskBreakdown(score=total, band=band, factors=factors,
                         requires_review=total >= int(threshold))
