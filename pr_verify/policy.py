"""Declarative policy rules: limits and path rules that fail the check.

Gates run YOUR commands. These are rules the tool checks itself, from the
facts it already has (who wrote which line, what class of risk a line
carries, which files changed). Read from the base ref's .pr-verify.yaml like
every other setting:

  policy:
    max_files: 40                    # files changed
    max_changed_lines: 1500          # lines added + removed
    max_agent_lines: 600             # lines an agent added or removed
    require_tests_for_agent_code: true   # an agent changed source, so a test must change too
    agent_deny_paths:                # an agent may not touch these
      - ".github/workflows/**"
      - "**/migrations/**"
    agent_allow_paths:               # if set, an agent may touch only these
      - "src/**"
      - "tests/**"
    deny_classes:                    # a finding of these classes (any author) fails
      - hidden_text
      - secret
    deny_agent_classes:              # a finding on a line an agent wrote fails
      - unsafe_exec
      - weak_control

A violation fails the verification (exit 1) whatever the score. Fail closed:
an unknown key, a wrong type, or an unknown class name is a configuration
error (exit 2), never a rule that silently does nothing.
"""

from __future__ import annotations

import dataclasses

from . import pathglob
from . import riskclass

INT_KEYS = ("max_files", "max_changed_lines", "max_agent_lines")
BOOL_KEYS = ("require_tests_for_agent_code",)
LIST_KEYS = ("agent_deny_paths", "agent_allow_paths", "deny_classes",
             "deny_agent_classes")
KEYS = INT_KEYS + BOOL_KEYS + LIST_KEYS


@dataclasses.dataclass(frozen=True)
class Violation:
    rule: str
    detail: str
    file: str = ""
    line: int = 0

    def as_dict(self) -> dict:
        return dataclasses.asdict(self)


def validate(raw, where: str = ".pr-verify.yaml") -> dict:
    """The policy mapping, checked and normalised; ValueError on anything
    that is not a rule."""
    if raw in (None, "", [], {}):
        return {}
    if not isinstance(raw, dict):
        raise ValueError(f"{where}: policy must be a mapping of rules, got {raw!r}")
    out: dict = {}
    for key, val in raw.items():
        if key not in KEYS:
            raise ValueError(f"{where}: unknown policy rule {key!r} "
                             f"(rules: {', '.join(KEYS)})")
        if key in INT_KEYS:
            if isinstance(val, bool) or val is None:
                raise ValueError(f"{where}: policy.{key} must be a whole number, got {val!r}")
            try:
                n = int(str(val).strip())
            except ValueError:
                raise ValueError(f"{where}: policy.{key} must be a whole number, got {val!r}") from None
            if n < 0:
                raise ValueError(f"{where}: policy.{key} must be 0 or more, got {n}")
            out[key] = n
        elif key in BOOL_KEYS:
            if isinstance(val, bool):
                out[key] = val
            elif str(val).strip().lower() in ("true", "yes", "on", "1"):
                out[key] = True
            elif str(val).strip().lower() in ("false", "no", "off", "0"):
                out[key] = False
            else:
                raise ValueError(f"{where}: policy.{key} must be true or false, got {val!r}")
        else:
            items = [val] if isinstance(val, str) else val
            if not isinstance(items, list) or not items \
                    or not all(isinstance(x, (str, int, float)) and str(x).strip() for x in items):
                raise ValueError(f"{where}: policy.{key} must be a non-empty list of strings, got {val!r}")
            items = [str(x).strip() for x in items]
            if key.endswith("classes"):
                bad = [x for x in items if x not in riskclass.CLASSES]
                if bad:
                    raise ValueError(
                        f"{where}: policy.{key} names unknown class {bad[0]!r} "
                        f"(classes: {', '.join(riskclass.CLASSES)})")
            out[key] = items
    return out


def _is_test(path: str) -> bool:
    return bool(riskclass._TEST.search(path.replace("\\", "/")))


def evaluate(policy: dict, prov: dict, findings: list) -> list[Violation]:
    """Violations of `policy` by this change. prov is file -> FileProvenance."""
    if not policy:
        return []
    out: list[Violation] = []
    live = {f: p for f, p in prov.items() if not p.deleted}
    total_changed = sum(p.changed for p in prov.values())
    agent_lines = sum(p.agent_changed for p in prov.values())
    if "max_files" in policy and len(prov) > policy["max_files"]:
        out.append(Violation("max_files",
                             f"{len(prov)} files changed, the limit is {policy['max_files']}"))
    if "max_changed_lines" in policy and total_changed > policy["max_changed_lines"]:
        out.append(Violation("max_changed_lines",
                             f"{total_changed} lines changed, the limit is {policy['max_changed_lines']}"))
    if "max_agent_lines" in policy and agent_lines > policy["max_agent_lines"]:
        out.append(Violation("max_agent_lines",
                             f"{agent_lines} lines by an agent, the limit is {policy['max_agent_lines']}"))

    touched = sorted(f for f, p in prov.items() if p.agent_changed or (p.deleted and p.agents))
    for pat in policy.get("agent_deny_paths", []):
        for f in touched:
            if pathglob.match(f, pat):
                out.append(Violation("agent_deny_paths",
                                     f"an agent changed a file under the denied path {pat!r}", f))
    allow = policy.get("agent_allow_paths")
    if allow:
        for f in touched:
            if not pathglob.match_any(f, allow):
                out.append(Violation("agent_allow_paths",
                                     "an agent changed a file outside the allowed paths", f))
    if policy.get("require_tests_for_agent_code"):
        agent_src = [f for f in touched if not _is_test(f)
                     and not prov[f].deleted]
        tests_changed = any(_is_test(f) for f in prov)
        if agent_src and not tests_changed:
            out.append(Violation(
                "require_tests_for_agent_code",
                f"an agent changed source ({agent_src[0]}"
                f"{' and ' + str(len(agent_src) - 1) + ' more' if len(agent_src) > 1 else ''}) "
                f"and no test file changed", agent_src[0]))
    agent_set = {f: set(p.agent_lines) for f, p in prov.items() if p.agent_lines}
    deny = set(policy.get("deny_classes", []))
    deny_agent = set(policy.get("deny_agent_classes", []))
    for fd in findings:
        if fd.cls in deny:
            out.append(Violation("deny_classes", f"{fd.cls}: {fd.why}", fd.file, fd.line))
        elif fd.cls in deny_agent:
            p = live.get(fd.file) or prov.get(fd.file)
            if p is not None and (fd.line in agent_set.get(fd.file, ())
                                  or (fd.line == 0 and p.agent_changed)):
                out.append(Violation("deny_agent_classes",
                                     f"{fd.cls} on a line an agent wrote: {fd.why}",
                                     fd.file, fd.line))
    return out[:200]
