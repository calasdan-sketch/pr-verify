"""Test integrity: did an agent make the tests easier to pass?

An agent that cannot make a test pass has a cheap way out: delete the test,
skip it, mark it as an expected failure, run only one test, or loosen what it
asserts. This reads the diff of the TEST files and reports exactly those
moves, only for lines an agent is credited with (provenance):

  deleted-test-file      a test file the agent removed
  deleted-test           a test function removed and not added back anywhere
                         in the change (a rename or a move is not one)
  removed-assertions     a test file with fewer assertions after the change
  disabled-test          a skip / xfail / ignore / disable marker ADDED
  focused-test           `.only`, `fit`, `fdescribe`: the rest of the file stops
                         running
  loosened-assertion     an assertion replaced in the same hunk by a weaker one
                         (equality -> truthiness, toEqual -> toBeDefined ...)
  tautology-assertion    an assertion that cannot fail was ADDED
                         (`assert True`, `expect(1).toBe(1)`)

Everything is a pattern from the tables below, applied line by line to the
patch: no AST, no guessing. Python and JavaScript/TypeScript are covered in
depth; Go and Ruby also have the test-function shapes, and Java/Kotlin and
Rust the disable markers. A table-driven fixture per row lives in the tests, so
adding a row means adding an example.

How "an agent" is decided: added lines by `git blame` (the line's commit is an
agent's, or the pull request carries an agent signal); removed lines have no
author, so a removal counts when the file lost lines to an agent's commits
(provenance `agent_removed`), and a deleted file when an agent's commit
deleted it. That is approximate for removals and says so in the report.
"""

from __future__ import annotations

import dataclasses
import os
import re

from . import risk as risk_mod


@dataclasses.dataclass
class Finding:
    rule: str
    severity: str          # "error" | "warning"
    file: str
    line: int              # line in the new file; 0 when there is none
    message: str
    snippet: str = ""

    def as_dict(self) -> dict:
        return dataclasses.asdict(self)


@dataclasses.dataclass
class Hunk:
    removed: list          # [(line number in the old file, text)]
    added: list            # [(line number in the new file, text)]
    new_start: int = 0


# ---------------------------------------------------------------------------
# languages
# ---------------------------------------------------------------------------

LANG_BY_EXT = {
    ".py": "python",
    ".js": "js", ".jsx": "js", ".mjs": "js", ".cjs": "js",
    ".ts": "js", ".tsx": "js", ".mts": "js", ".cts": "js",
    ".go": "go", ".java": "java", ".kt": "java", ".kts": "java",
    ".rb": "ruby", ".rs": "rust",
}

_COMMENT = {"python": "#", "ruby": "#", "js": "//", "go": "//", "java": "//",
            "rust": "//"}


def language(path: str) -> str | None:
    return LANG_BY_EXT.get(os.path.splitext(path)[1].lower())


def _is_comment(text: str, lang: str) -> bool:
    t = text.lstrip()
    return bool(t) and t.startswith(_COMMENT[lang]) and not t.startswith("#[")


# ---------------------------------------------------------------------------
# rule tables
# ---------------------------------------------------------------------------

#: (rule id, severity, languages, pattern, what it is). Applied to ADDED lines.
ADDED_RULES = [
    # --- Python
    ("disabled-test", "error", ("python",),
     r"^\s*@pytest\.mark\.skip(?:if)?\b", "a pytest skip marker"),
    ("disabled-test", "error", ("python",),
     r"^\s*@pytest\.mark\.xfail\b", "an expected-failure (xfail) marker"),
    ("disabled-test", "error", ("python",),
     r"^\s*@(?:unittest\.)?(?:skip|skipIf|skipUnless|expectedFailure)\b",
     "a unittest skip / expectedFailure decorator"),
    ("disabled-test", "error", ("python",),
     r"\b(?:pytest\.(?:skip|xfail)|self\.skipTest)\s*\(",
     "a skip or xfail call"),
    ("disabled-test", "error", ("python",),
     r"^\s*pytestmark\s*=.*\b(?:skip|xfail)\b", "a module-wide skip marker"),
    # --- JavaScript / TypeScript
    ("disabled-test", "error", ("js",),
     r"\b(?:it|test|describe|context|suite|specify)\.(?:skip|todo|fixme|skipIf)\b",
     "a skipped test (.skip / .todo / .fixme)"),
    ("disabled-test", "error", ("js",),
     r"(?<![\w.])(?:xit|xtest|xdescribe|xcontext|xspecify)\s*\(",
     "a disabled test (xit / xdescribe)"),
    ("focused-test", "error", ("js",),
     r"\b(?:it|test|describe|context|suite|specify)\.only\b",
     "an .only that stops the other tests from running"),
    ("focused-test", "error", ("js",),
     r"(?<![\w.])(?:fit|fdescribe|fcontext)\s*\(",
     "a focused test (fit / fdescribe) that stops the others from running"),
    # --- Go, Java/Kotlin, Ruby, Rust
    ("disabled-test", "error", ("go",),
     r"\bt\.Skip(?:f|Now)?\s*\(", "a t.Skip call"),
    ("disabled-test", "error", ("java",),
     r"^\s*@(?:Ignore|Disabled)\b", "an @Ignore / @Disabled annotation"),
    ("disabled-test", "error", ("ruby",),
     r"^\s*(?:xit|xdescribe|xcontext|skip|pending)\b(?!\s*[:=])",
     "a skipped or pending example"),
    ("disabled-test", "error", ("rust",),
     r"^\s*#\[ignore\b", "an #[ignore] attribute"),
    # --- an assertion that cannot fail
    ("tautology-assertion", "error", ("python",),
     r"^\s*assert\s+(?:True|1)\s*(?:,.*)?$|\bassertTrue\(\s*True\s*\)",
     "an assertion that is always true"),
    ("tautology-assertion", "error", ("js",),
     r"\bexpect\(\s*(?:true|1)\s*\)\.(?:toBe|toEqual)\(\s*(?:true|1)\s*\)"
     r"|\bassert\.ok\(\s*true\s*\)|\bassert\(\s*true\s*\)",
     "an assertion that is always true"),
]

#: assertion strength per language: (strength, pattern) checked in order, the
#: first hit wins. 3 = exact (equality, a specific error), 2 = a property of
#: the value, 1 = "it is there / truthy". 0 = not an assertion.
ASSERTION_STRENGTH = {
    "python": [
        (1, r"\bassert(?:True|False|IsNotNone|IsNone)\s*\("),
        (3, r"\bassert(?:Equal|Equals|AlmostEqual|DictEqual|ListEqual|"
            r"TupleEqual|SetEqual|SequenceEqual|CountEqual|MultiLineEqual|"
            r"Regex|Is|IsNot|NotEqual|Raises|RaisesRegex|Warns)\s*\("),
        (2, r"\bassert(?:In|NotIn|Greater|GreaterEqual|Less|LessEqual|"
            r"IsInstance|NotIsInstance)\s*\("),
        (3, r"^\s*assert\b.*(?:==|!=)"),
        (2, r"^\s*assert\b.*(?:\bin\b|\bnot in\b|>=|<=|>|<|\bisinstance\b)"),
        (1, r"^\s*assert\b"),
        (3, r"\bpytest\.raises\s*\("),
    ],
    "js": [
        (3, r"\.(?:toBe|toEqual|toStrictEqual|toMatchSnapshot|"
            r"toMatchInlineSnapshot|toHaveBeenCalledWith|"
            r"toHaveBeenCalledTimes|toHaveBeenNthCalledWith|toBeCloseTo|"
            r"toThrowError|toThrow)\s*\(\s*[^)\s]"),
        (3, r"\bassert\.(?:strictEqual|deepEqual|deepStrictEqual|equal|"
            r"notEqual|throws)\s*\("),
        (2, r"\.(?:toContain|toContainEqual|toHaveLength|toMatch|"
            r"toHaveProperty|toBeInstanceOf|toBeGreaterThan|"
            r"toBeGreaterThanOrEqual|toBeLessThan|toBeLessThanOrEqual|"
            r"toMatchObject)\s*\("),
        (1, r"\.(?:toBeTruthy|toBeFalsy|toBeDefined|toBeUndefined|toBeNull|"
            r"toHaveBeenCalled|toThrow)\s*\(\s*\)"),
        (1, r"\bassert\.ok\s*\(|^\s*assert\s*\("),
    ],
}

#: test-function shapes: group "name" is what identifies the test
TEST_DEFS = {
    "python": re.compile(r"^\s*(?:async\s+)?def\s+(?P<name>test\w*)\s*\("),
    "js": re.compile(
        r"""^\s*(?:it|test|specify)(?:\.\w+)*\s*(?:\.each\b[^(]*)?\(\s*"""
        r"""(?P<q>['"`])(?P<name>.+?)(?P=q)"""),
    "go": re.compile(r"^func\s+(?P<name>Test\w*)\s*\("),
    "ruby": re.compile(
        r"""^\s*(?:def\s+(?P<n1>test_\w+)|it\s+(?P<q>['"])(?P<n2>.+?)(?P=q))"""),
}

_COMPILED = [(rid, sev, langs, re.compile(pat), what)
             for rid, sev, langs, pat, what in ADDED_RULES]
_STRENGTH = {lang: [(n, re.compile(p)) for n, p in rows]
             for lang, rows in ASSERTION_STRENGTH.items()}


def assertion_strength(text: str, lang: str) -> int:
    """0 when `text` is no assertion, else 1 (weak) .. 3 (exact)."""
    if lang not in _STRENGTH or _is_comment(text, lang):
        return 0
    for strength, rx in _STRENGTH[lang]:
        if rx.search(text):
            return strength
    return 0


def test_name(text: str, lang: str) -> str | None:
    """The name of the test a line defines, or None. Java/Kotlin and Rust
    mark a test by an annotation on the line before, not by the function line,
    so no test is recognised there (their disable markers still are)."""
    rx = TEST_DEFS.get(lang)
    if rx is None:
        return None
    m = rx.match(text)
    if not m:
        return None
    return m.groupdict().get("name") or m.groupdict().get("n1") \
        or m.groupdict().get("n2")


# ---------------------------------------------------------------------------
# reading the patch
# ---------------------------------------------------------------------------

_HUNK_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


def _path(line: str, side: str) -> str | None:
    from . import provenance as prov_mod
    return prov_mod._header_path(line, side)


def walk_hunks(patch: str) -> dict[str, list[Hunk]]:
    """file -> hunks of a `git diff-tree -p -U0` patch, with the text of every
    changed line. Walks by the line counts of the hunk headers, as
    provenance._walk_patch does, so a file line that looks like a header
    (`+++ b/x`, `-- sql comment`) stays file content."""
    files: dict[str, list[Hunk]] = {}
    cur: str | None = None
    hunk: Hunk | None = None
    old_no = new_no = old_left = new_left = 0
    for line in patch.split("\n"):
        if old_left or new_left:
            mark = line[:1]
            if mark == "-" and old_left:
                old_left -= 1
                if hunk is not None:
                    hunk.removed.append((old_no, line[1:]))
                old_no += 1
                continue
            if mark == "+" and new_left:
                new_left -= 1
                if hunk is not None:
                    hunk.added.append((new_no, line[1:]))
                new_no += 1
                continue
            if (mark == " " or not line) and old_left and new_left:
                old_left -= 1
                new_left -= 1
                old_no += 1
                new_no += 1
                continue
            if mark == "\\":
                continue
            old_left = new_left = 0
        if line.startswith("diff --git "):
            cur, hunk = None, None
        elif line.startswith("--- "):
            pass
        elif line.startswith("+++ "):
            cur = _path(line, "b/")
            if cur is not None:
                files.setdefault(cur, [])
        elif line.startswith("@@") and cur is not None:
            m = _HUNK_RE.match(line)
            if m:
                old_no = int(m.group(1))
                old_left = 1 if m.group(2) is None else int(m.group(2))
                new_no = int(m.group(3))
                new_left = 1 if m.group(4) is None else int(m.group(4))
                hunk = Hunk([], [], new_no)
                files[cur].append(hunk)
    return files


# ---------------------------------------------------------------------------
# the check
# ---------------------------------------------------------------------------

def _snippet(text: str) -> str:
    text = " ".join(text.split())
    return text if len(text) <= 100 else text[:97] + "..."


def analyze(patch: str, prov: dict, test_file=risk_mod._is_test_file
            ) -> list[Finding]:
    """The test-integrity findings of `patch` for the files in `prov`
    (file -> provenance.FileProvenance), in file order."""
    hunks = walk_hunks(patch)
    findings: list[Finding] = []
    # test names added anywhere in the change: a moved test is not deleted
    added_names = set()
    for rel, hs in hunks.items():
        lang = language(rel)
        if lang and test_file(rel):
            for h in hs:
                for _, text in h.added:
                    n = test_name(text, lang)
                    if n:
                        added_names.add(n)
    for rel in sorted(prov):
        fp = prov[rel]
        lang = language(rel)
        if not test_file(rel):
            continue
        if fp.deleted:
            if fp.agents:
                findings.append(Finding(
                    "deleted-test-file", "error", rel, 0,
                    f"an agent deleted the test file {rel}"))
            continue
        if lang is None:
            continue
        agent_lines = set(getattr(fp, "agent_lines", ()))
        agent_removed = fp.agent_removed > 0
        file_hunks = hunks.get(rel, [])
        removed_assertions = added_assertions = 0
        first_removed_line = 0
        for h in file_hunks:
            # added lines: disable markers, focus, tautologies
            for no, text in h.added:
                if no not in agent_lines or _is_comment(text, lang):
                    continue
                for rid, sev, langs, rx, what in _COMPILED:
                    if lang in langs and rx.search(text):
                        findings.append(Finding(
                            rid, sev, rel, no,
                            f"an agent added {what}", _snippet(text)))
                        break
            # assertions removed vs added in this hunk
            r_str = sorted((assertion_strength(t, lang)
                            for _, t in h.removed), reverse=True)
            r_str = [s for s in r_str if s]
            a_pairs = [(no, assertion_strength(t, lang), t)
                       for no, t in h.added]
            a_pairs = [p for p in a_pairs if p[1]]
            removed_assertions += len(r_str)
            added_assertions += len(a_pairs)
            if r_str and not first_removed_line:
                first_removed_line = h.new_start
            if r_str and agent_removed:
                a_sorted = sorted(a_pairs, key=lambda p: -p[1])
                for strong, (no, weak, text) in zip(r_str, a_sorted):
                    if weak < strong and no in agent_lines:
                        findings.append(Finding(
                            "loosened-assertion", "error", rel, no,
                            "an agent replaced an assertion with a weaker "
                            "one", _snippet(text)))
        # a test function that disappeared
        if agent_removed:
            gone = []
            for h in file_hunks:
                lost = []
                for no, text in h.removed:
                    n = test_name(text, lang)
                    if n and n not in added_names and n not in lost:
                        lost.append(n)
                # a hunk that adds as many test definitions as it loses is a
                # rename (def test_a -> def test_b), not a deletion
                made = sum(1 for _, t in h.added if test_name(t, lang))
                if lost and made >= len(lost):
                    continue
                gone.extend(n for n in lost if n not in gone)
            for n in gone:
                findings.append(Finding(
                    "deleted-test", "error", rel, first_removed_line,
                    f"an agent removed the test {n} and nothing in the "
                    f"change adds it back", n))
            if removed_assertions > added_assertions and not gone:
                findings.append(Finding(
                    "removed-assertions", "warning", rel, first_removed_line,
                    f"{rel} has {removed_assertions - added_assertions} "
                    f"fewer assertion(s) after an agent's change"))
    return findings
