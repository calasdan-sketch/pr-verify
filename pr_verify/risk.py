"""Risk scoring: deterministic, documented, no LLM.

Score 0-100 from six observable factors. The formula is public so teams
can argue with it and tune it — a black-box score is just another opinion.

  agent_share  40 pts  % of added lines written by an agent (provenance)
  blast        25 pts  log-scaled transitive dependents: 25 * min(1, log10(1+n)/2)
                      (n=9 -> ~12.5, n=99 -> 25)
  sensitive    20 pts  any changed file under a sensitive_path glob
                      (deleted files match like touched files)
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

Bands: 0-29 low · 30-69 medium · 70-100 high (needs senior review).
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


def _is_test_file(rel: str) -> bool:
    low = rel.lower()
    return ("test" in low.split("/")[-1] or "/tests/" in low
            or low.startswith("tests/"))


def _sensitive_candidates(f: str) -> list[str]:
    # Globs are matched against the full repo-relative path AND the
    # bare filename, so a pattern like "*auth*" catches auth.py at the
    # repo root or nested anywhere — not just under matched directories.
    base = os.path.basename(f)
    return [f, "/" + f, base, "/" + base]


def _sensitive_hits(files: list[str], sensitive_paths: list[str]) -> list[str]:
    return sorted({f for f in files
                   if any(fnmatch.fnmatchcase(c, p)
                          for c in _sensitive_candidates(f)
                          for p in sensitive_paths)})


def _blast_points(n: int, cap: int) -> int:
    """Log-scaled dependents -> points, shared by blast and deletion."""
    return round(cap * min(1.0, math.log10(1 + n) / 2)) if n else 0


def score(prov: dict[str, prov_mod.FileProvenance],
          blast: dict[str, br_mod.BlastRadius],
          gate_results: list[gates_mod.GateResult],
          sensitive_paths: list[str],
          threshold: int) -> RiskBreakdown:
    factors: dict[str, dict] = {}

    total_added = sum(f.added for f in prov.values())
    agent_added = sum(f.agent_added for f in prov.values())
    share = agent_added / total_added if total_added else 0.0
    pts = round(share * 40)
    factors["agent_share"] = {
        "points": pts,
        "detail": f"{agent_added}/{total_added} added lines agent-authored "
                  f"({share:.0%})"}

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

    total = min(100, sum(f["points"] for f in factors.values()))
    band = "low" if total < 30 else "medium" if total < 70 else "high"
    return RiskBreakdown(score=total, band=band, factors=factors,
                         requires_review=total >= threshold)
