"""CODEOWNERS: who GitHub would ask to review each changed file.

Read from the BASE ref (the trusted side), not from the pull request: a PR
that edits CODEOWNERS does not get to choose its own reviewers. The last
matching line wins, as on GitHub. Sections ([Name]) of the GitLab syntax are
skipped and their rules read as ordinary lines.
"""

from __future__ import annotations

import subprocess

from . import pathglob

LOCATIONS = (".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS")
MAX_BYTES = 1_000_000
#: rules x files worked through at most; beyond it owners are not computed
MAX_WORK = 1_000_000


def parse(text: str) -> list[tuple[str, list[str]]]:
    rules: list[tuple[str, list[str]]] = []
    for raw in text.split("\n"):
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith(("[", "^[")):
            continue
        parts = []
        for tok in line.split():
            if tok.startswith("#"):
                break
            parts.append(tok)
        if len(parts) >= 2:
            rules.append((parts[0], parts[1:]))
        elif len(parts) == 1:
            rules.append((parts[0], []))     # a pattern with no owner: unowns
    return rules


def read_base(root: str, base: str) -> tuple[str | None, str]:
    """(location, text) of the CODEOWNERS at <base>, or (None, "")."""
    for loc in LOCATIONS:
        p = subprocess.run(["git", "-C", root, "show", f"{base}:{loc}"],
                           capture_output=True, timeout=15)
        if p.returncode == 0 and len(p.stdout) <= MAX_BYTES:
            return loc, p.stdout.decode("utf-8-sig", errors="replace")
    return None, ""


def owners_of(path: str, rules: list[tuple[str, list[str]]]) -> list[str]:
    owners: list[str] = []
    parts = pathglob.split_path(path)
    for pattern, who in rules:
        if pathglob.match_parts(parts, pattern):
            owners = who
    return owners
