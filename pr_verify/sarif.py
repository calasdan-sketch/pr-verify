"""SARIF 2.1.0 for GitHub code scanning and any other SARIF reader.

One result per finding and per policy violation, with the file and line, so
they show up as annotations on the pull request's diff. Messages are text
from the pull request and are made safe like every other (control and
direction characters shown as escapes).
"""

from __future__ import annotations

import hashlib
import json
import urllib.parse

from . import textsafe

SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}
SCORE = {"critical": "9.5", "high": "8.0", "medium": "5.0", "low": "2.0"}

RULES = {
    "hidden_text": "Invisible, reordering or look-alike characters",
    "prompt_injection": "Text addressed to an AI reviewer",
    "secret": "Credential or key committed",
    "ci_workflow": "CI workflow change that widens trust",
    "dependency": "Dependency or lockfile change",
    "install_script": "Code that runs at install time",
    "remote_script": "Downloads and runs a script",
    "unsafe_exec": "Evaluates or executes built strings",
    "weak_control": "Security control turned off",
    "weak_crypto": "Weak cryptography",
    "permissions": "Over-broad permissions",
    "destructive_migration": "Migration that drops or empties data",
    "iac": "Infrastructure definition changed",
    "guard_removed": "Authorization or validation call removed",
    "test_weakening": "Tests skipped, removed or made trivial",
    "scan_limit": "Part of the change could not be searched",
}


def _uri(path: str) -> str:
    return urllib.parse.quote(path.replace("\\", "/"), safe="/",
                              errors="surrogateescape")


def build(version: str, findings: list, violations: list, agent_lines: dict | None = None) -> dict:
    agent_lines = agent_lines or {}
    rules = []
    seen: set[str] = set()
    results = []

    top: dict[str, str] = {}      # rule -> highest severity among its findings
    order = ("critical", "high", "medium", "low")
    for fd in findings:
        if fd.cls not in top or order.index(fd.severity) < order.index(top[fd.cls]):
            top[fd.cls] = fd.severity
    nth: dict[tuple, int] = {}

    def rule(rid: str, text: str):
        if rid not in seen:
            seen.add(rid)
            r = {"id": rid, "shortDescription": {"text": text}}
            if rid in top:
                # GitHub reads the security level and the "security" tag from
                # the rule, not from the result
                r["properties"] = {"tags": ["security"],
                                   "security-severity": SCORE.get(top[rid], "5.0")}
            rules.append(r)

    for fd in findings:
        rule(fd.cls, RULES.get(fd.cls, fd.cls))
        res = {
            "ruleId": fd.cls,
            "level": LEVEL.get(fd.severity, "warning"),
            "message": {"text": textsafe.neutralize(fd.why)[:500]},
            "properties": {"severity": fd.severity,
                           "security-severity": SCORE.get(fd.severity, "5.0"),
                           "agentAuthored": fd.line in agent_lines.get(fd.file, ())},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": _uri(fd.file)},
                "region": {"startLine": max(1, fd.line)}}}],
        }
        key = (fd.cls, fd.file, fd.why)
        k = nth[key] = nth.get(key, 0) + 1
        # stable across line shifts: rule, file, reason and which of its kind
        res["partialFingerprints"] = {"prVerify/v1": hashlib.sha256(
            "\x00".join((fd.cls, fd.file, fd.why, str(k))).encode("utf-8", "replace")
        ).hexdigest()[:32]}
        results.append(res)
    for v in violations:
        rid = "policy/" + v.rule
        rule(rid, "Policy rule from .pr-verify.yaml")
        res = {"ruleId": rid, "level": "error",
               "message": {"text": textsafe.neutralize(v.detail)[:500]}}
        if v.file:
            res["locations"] = [{"physicalLocation": {
                "artifactLocation": {"uri": _uri(v.file)},
                "region": {"startLine": max(1, v.line)}}}]
        results.append(res)
    return {
        "$schema": SCHEMA, "version": "2.1.0",
        "runs": [{"tool": {"driver": {
            "name": "pr-verify", "version": version,
            "organization": "Calas Automations Inc.",
            "informationUri": "https://github.com/calasdan-sketch/pr-verify",
            "rules": rules}}, "results": results}],
    }


def dumps(doc: dict) -> str:
    return json.dumps(textsafe.scrub(doc), indent=2)
