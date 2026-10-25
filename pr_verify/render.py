"""Renderers that work from the --format json document alone: the review
depth, SARIF 2.1.0 and the pull request comment.

Everything here is a pure function of the facts in the payload (the document
`pr-verify check --format json` prints): the same payload always renders to
the same bytes, and nothing is read from git, the network or the clock.

REVIEW DEPTH -- the one-word answer to "how hard should a person look?":

  deep    any of: the score reached min-score (or the band is high), a policy
          gate failed, a policy rule was violated, a test-integrity finding,
          an agent deleted a file, an agent touched a sensitive file
  skim    none of the above, and the score is under 30 (the low band)
  normal  everything else

The reasons are listed with it, in a fixed order, so the word is never a
verdict without a why. The description-vs-diff advisories never change it.
"""

from __future__ import annotations

import hashlib
import json
from urllib.parse import quote

#: the marker a sticky comment is found by (a hidden HTML comment)
STICKY_MARKER = "<!-- pr-verify:sticky -->"
#: GitHub refuses a comment above 65536 characters
MAX_COMMENT_CHARS = 60000
MAX_LISTED = 25

SARIF_SCHEMA = ("https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/"
                "schemas/sarif-schema-2.1.0.json")
INFORMATION_URI = "https://github.com/calasdan-sketch/pr-verify"

_CONTROL = {cp: f"\\x{cp:02x}" for cp in (*range(0, 9), *range(0x0B, 0x20),
                                          0x7F)}


def plain(text) -> str:
    """text with control characters shown as escapes (tab and newline stay)."""
    return str(text).translate(_CONTROL)


# ---------------------------------------------------------------------------
# review depth
# ---------------------------------------------------------------------------

def _agent_files(payload: dict, pred) -> list[str]:
    return sorted(f for f, v in (payload.get("files") or {}).items()
                  if pred(v))


def review_depth(payload: dict) -> dict:
    """{"depth": "skim"|"normal"|"deep", "reasons": [str]} -- see the module
    docstring for the rule. A function of the payload and nothing else."""
    risk = payload.get("risk") or {}
    score = int(risk.get("score") or 0)
    deep: list[str] = []
    if risk.get("requires_review"):
        deep.append(f"the risk score {score} reached the minimum of "
                    f"{payload.get('min_score')}")
    elif risk.get("band") == "high":
        deep.append(f"the risk score {score} is in the high band")
    failed = [g.get("command", "") for g in payload.get("gates") or []
              if not g.get("passed")]
    if failed:
        deep.append(f"{len(failed)} policy gate(s) failed")
    violations = (payload.get("policy") or {}).get("violations") or []
    if violations:
        deep.append(f"{len(violations)} policy rule(s) violated")
    findings = (payload.get("test_integrity") or {}).get("findings") or []
    if findings:
        deep.append(f"{len(findings)} test-integrity finding(s): an agent "
                    f"weakened the tests")
    gone = _agent_files(payload, lambda v: v.get("deleted") and v.get("agents"))
    if gone:
        deep.append(f"an agent deleted {len(gone)} file(s)")
    sens = set(payload.get("sensitive_files") or [])
    touched = [f for f in _agent_files(payload, lambda v: v.get("agents"))
               if f in sens]
    if touched:
        deep.append(f"an agent touched {len(touched)} sensitive file(s)")
    if deep:
        return {"depth": "deep", "reasons": deep}
    if score < 30:
        files = len(payload.get("files") or {})
        why = (f"low risk (score {score}) and no policy, test or gate "
               f"findings")
        return {"depth": "skim",
                "reasons": [why if files else "nothing to verify"]}
    return {"depth": "normal",
            "reasons": [f"the risk score is {score}, under the minimum, "
                        f"with no policy, test or gate findings"]}


# ---------------------------------------------------------------------------
# SARIF 2.1.0
# ---------------------------------------------------------------------------

RULES = [
    ("PRV001", "risk-score", "The risk score reached the minimum",
     "The deterministic 0-100 risk score reached the score that needs senior "
     "review (min-score)."),
    ("PRV002", "policy-violation", "A policy rule from .pr-verify.yaml was violated",
     "The change breaks a protected path, an agent-forbidden path, the change "
     "budget or tests_must_change."),
    ("PRV003", "test-integrity", "An agent weakened the tests",
     "A test was deleted, skipped, focused or its assertion loosened in lines "
     "an agent wrote."),
    ("PRV004", "gate-failed", "A policy gate command failed",
     "A command from `gates` in .pr-verify.yaml failed or timed out."),
    ("PRV005", "sensitive-file", "A sensitive file was changed",
     "The change touches a file matching sensitive_paths."),
    ("PRV006", "description-mismatch", "The description names something the diff does not touch",
     "Advisory: the pull request text mentions a file or symbol that is not "
     "in the change."),
]
_RULE_INDEX = {r[0]: i for i, r in enumerate(RULES)}


def _fingerprint(rule: str, file: str, text: str) -> str:
    return hashlib.sha256("\x00".join((rule, file, text)).encode("utf-8",
                          "replace")).hexdigest()[:32]


def to_sarif(payload: dict) -> dict:
    """The payload as a SARIF 2.1.0 log (one run). Findings with a file get a
    location; the others are attached to the first changed file, since code
    scanning wants a place for every alert. A change with no files has no
    results."""
    files = sorted(payload.get("files") or {})
    anchor = files[0] if files else None
    results: list[dict] = []

    def add(rule, level, text, file=None, line=0):
        file = file or anchor
        if file is None:
            return
        region = {"startLine": line} if line and line > 0 else {"startLine": 1}
        results.append({
            "ruleId": rule,
            "ruleIndex": _RULE_INDEX[rule],
            "level": level,
            "message": {"text": plain(text)},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": quote(plain(file).replace("\\", "/"),
                                                   safe="/"),
                                     "uriBaseId": "%SRCROOT%"},
                "region": region}}],
            "partialFingerprints": {
                "prVerify/v1": _fingerprint(rule, file, text)},
        })

    risk = payload.get("risk") or {}
    if risk.get("requires_review"):
        add("PRV001", "error",
            f"Risk score {risk.get('score')}/100 reached the minimum of "
            f"{payload.get('min_score')}: needs senior review.")
    for v in (payload.get("policy") or {}).get("violations") or []:
        targets = v.get("files") or [None]
        for f in targets[:MAX_LISTED]:
            add("PRV002", "error", v.get("message", v.get("rule", "")), f)
    for fnd in (payload.get("test_integrity") or {}).get("findings") or []:
        add("PRV003", "error" if fnd.get("severity") == "error" else "warning",
            fnd.get("message", ""), fnd.get("file"), fnd.get("line") or 0)
    for g in payload.get("gates") or []:
        if not g.get("passed"):
            how = "timed out" if g.get("timed_out") else "failed"
            add("PRV004", "error", f"Gate {how}: {g.get('command', '')}")
    for f in payload.get("sensitive_files") or []:
        add("PRV005", "warning", f"Sensitive file changed: {f}", f)
    for a in (payload.get("description_check") or {}).get("advisories") or []:
        add("PRV006", "note", a.get("message", ""))
    depth = review_depth(payload)
    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "pr-verify",
                "version": str(payload.get("version", "")),
                "informationUri": INFORMATION_URI,
                "rules": [{
                    "id": rid, "name": name,
                    "shortDescription": {"text": short},
                    "fullDescription": {"text": full},
                    "helpUri": INFORMATION_URI,
                    "defaultConfiguration": {"level": "warning"},
                } for rid, name, short, full in RULES]}},
            "results": results,
            "properties": {"reviewDepth": depth["depth"],
                           "riskScore": risk.get("score"),
                           "riskBand": risk.get("band")},
        }],
    }


# ---------------------------------------------------------------------------
# pull request comment (markdown)
# ---------------------------------------------------------------------------

def md_code(text) -> str:
    """text as an inline code span that nothing inside can break out of: the
    fence is longer than any run of backticks in the text, and control
    characters are shown as escapes. (Inside a code span GitHub does not
    ping an @name, link, or render HTML.)"""
    t = plain(text).replace("\n", "\\n").replace("\r", "\\r")
    longest = run = 0
    for ch in t:
        run = run + 1 if ch == "`" else 0
        longest = max(longest, run)
    fence = "`" * (longest + 1)
    pad = " " if t.startswith("`") or t.endswith("`") else ""
    return f"{fence}{pad}{t}{pad}{fence}"


_MD_SPECIAL = set("\\`*_{}[]<>()#+!|~&")


def md_escape(text) -> str:
    """text as plain markdown prose: nothing in it formats, links, mentions
    (`@name` gets a zero-width space), references (`#12`) or becomes HTML."""
    t = plain(text).replace("\r", " ").replace("\n", " ")
    t = "".join("\\" + c if c in _MD_SPECIAL else c for c in t)
    t = t.replace("@", "@\u200b").replace("://", ":\u200b//")
    return t


def _more(items, shown=MAX_LISTED):
    return max(0, len(items) - shown)


def to_comment(payload: dict) -> str:
    """The sticky pull request comment, markdown. The first line is the
    marker the Action finds it by, the headline is
    `Review depth: skim|normal|deep`."""
    risk = payload.get("risk") or {}
    depth = review_depth(payload)
    out = [STICKY_MARKER, f"## Review depth: {depth['depth']}", ""]
    out += [f"- {md_escape(r)}" for r in depth["reasons"]]
    out.append("")
    score = risk.get("score", 0)
    band = risk.get("band", "low")
    gate = ("score gate off" if payload.get("min_score") is None
            else f"minimum {payload['min_score']}")
    out.append(f"**Risk score {score}/100** ({band}, {gate})")
    files = payload.get("files") or {}
    agent_files = [f for f, v in files.items() if v.get("agents")]
    added = sum(v.get("added", 0) for v in files.values())
    agent_added = sum(v.get("agent_added", 0) for v in files.values())
    out.append(f"{agent_added} of {added} added lines written by an agent "
               f"across {len(files)} changed file(s).")
    out.append("")

    signals = payload.get("agent_signals") or []
    if signals:
        out.append("### Agent signals")
        for s in signals:
            out.append(f"- {md_escape(s.get('kind'))} {md_code(s.get('value'))} "
                       f"matched {md_code(s.get('rule'))}")
        out.append("")

    violations = (payload.get("policy") or {}).get("violations") or []
    failed = [g for g in payload.get("gates") or [] if not g.get("passed")]
    if violations or failed:
        out.append("### Must fix")
        for v in violations:
            out.append(f"- policy {md_code(v.get('rule'))}: "
                       f"{md_escape(v.get('message'))}")
        for g in failed:
            how = "timed out" if g.get("timed_out") else "failed"
            out.append(f"- gate {how}: {md_code(g.get('command'))}")
        out.append("")

    findings = (payload.get("test_integrity") or {}).get("findings") or []
    if findings:
        out.append("### Test integrity")
        for f in findings[:MAX_LISTED]:
            where = f.get("file", "")
            if f.get("line"):
                where += f":{f['line']}"
            snippet = f" {md_code(f['snippet'])}" if f.get("snippet") else ""
            out.append(f"- {md_code(where)} {md_escape(f.get('message'))}"
                       f"{snippet}")
        if _more(findings):
            out.append(f"- ... and {_more(findings)} more")
        out.append("")

    if agent_files:
        out.append("### Agent-written files")
        for f in sorted(agent_files)[:MAX_LISTED]:
            v = files[f]
            who = ", ".join(v.get("agents") or [])
            out.append(f"- {md_code(f)} ({v.get('agent_added', 0)}/"
                       f"{v.get('added', 0)} lines) {md_code(who)}")
        if _more(agent_files):
            out.append(f"- ... and {_more(agent_files)} more")
        out.append("")

    adv = (payload.get("description_check") or {}).get("advisories") or []
    if adv:
        out.append("### Description vs diff (advisory)")
        for a in adv[:MAX_LISTED]:
            out.append(f"- {md_escape(a.get('message'))}")
        if _more(adv):
            out.append(f"- ... and {_more(adv)} more")
        out.append("")

    out.append(f"<sub>pr-verify {md_escape(payload.get('version', ''))}: "
               f"deterministic, no AI review. Same facts, same words.</sub>")
    text = "\n".join(out) + "\n"
    if len(text) > MAX_COMMENT_CHARS:
        text = (text[:MAX_COMMENT_CHARS].rsplit("\n", 1)[0]
                + "\n\n... (shortened: see the check's log)\n")
    return text


def sarif_text(payload: dict) -> str:
    return json.dumps(to_sarif(payload), indent=2) + "\n"
