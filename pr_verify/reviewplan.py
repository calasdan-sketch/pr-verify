"""The review plan: how deep to look, who must look, and where to start.

Everything here is derived from facts the tool already has (the score, the
findings, who wrote which line, the blast radius, CODEOWNERS at the base).
Nothing is guessed, and the rule for each answer is the one written below.

depth
  security-review  a critical finding, or two classes at high severity
  deep             the score reached the failing threshold, or any high finding
  standard         the score is 30 or more, or any medium finding
  skim             anything else
suggested reviewers (a floor, not a rule)
  2 for security-review and deep, 1 otherwise; and every code owner of a
  changed file, from CODEOWNERS at the base ref
focus
  where to read first: findings by severity, then the runs of agent-written
  lines in the files with the largest blast radius
"""

from __future__ import annotations

from . import riskclass

MAX_FOCUS = 15


def _ranges(numbers: list[int], gap: int = 2) -> list[tuple[int, int]]:
    out: list[list[int]] = []
    for n in sorted(set(numbers)):
        if out and n - out[-1][1] <= gap:
            out[-1][1] = n
        else:
            out.append([n, n])
    return [(a, b) for a, b in out]


def depth_of(score: int, requires_review: bool, top: dict[str, str]) -> str:
    sev = list(top.values())
    if "critical" in sev or sev.count("high") >= 2:
        return "security-review"
    if requires_review or "high" in sev:
        return "deep"
    if score >= 30 or "medium" in sev:
        return "standard"
    return "skim"


def build(prov: dict, blast: dict, findings: list, top: dict[str, str],
          score: int, requires_review: bool, owners: dict[str, list[str]] | None,
          codeowners_file: str | None, sensitive_hits: list[str]) -> dict:
    depth = depth_of(score, requires_review, top)
    reviewers: dict[str, list[str]] = {}
    for f, who in (owners or {}).items():
        for w in who:
            reviewers.setdefault(w, []).append(f)
    unowned = []
    if codeowners_file:
        risky = set(sensitive_hits) | {fd.file for fd in findings}
        unowned = sorted(f for f in risky if not (owners or {}).get(f))
    focus: list[dict] = []
    ordered = sorted(findings, key=lambda f: (riskclass.SEVERITY_ORDER.index(f.severity),
                                              f.file, f.line))
    for fd in ordered:
        if len(focus) >= MAX_FOCUS:
            break
        focus.append({"file": fd.file, "lines": [fd.line, fd.line] if fd.line else [],
                      "kind": fd.cls, "severity": fd.severity, "why": fd.why})
    agent_files = sorted(
        (p for p in prov.values() if p.agent_lines),
        key=lambda p: (-(blast[p.file].size if p.file in blast else 0),
                       -len(p.agent_lines), p.file))
    for p in agent_files:
        for a, b in _ranges(p.agent_lines):
            if len(focus) >= MAX_FOCUS:
                break
            focus.append({"file": p.file, "lines": [a, b], "kind": "agent_written",
                          "severity": "info",
                          "why": f"{b - a + 1} line(s) written by an agent"
                                 + (f"; {blast[p.file].size} dependent(s)"
                                    if p.file in blast and blast[p.file].size else "")})
    return {
        "depth": depth,
        "suggested_reviewers": 2 if depth in ("security-review", "deep") else 1,
        "code_owners": {w: sorted(fs)[:20] for w, fs in sorted(reviewers.items())},
        "codeowners_file": codeowners_file,
        "risky_files_without_owner": unowned[:50],
        "focus": focus,
    }
