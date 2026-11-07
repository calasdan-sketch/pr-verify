"""Text from a pull request, made safe to show.

Shared by the human report (cli.py) and the Markdown report (mdreport.py),
so both escape exactly the same characters.
"""

from __future__ import annotations

import re

#: A byte that was not UTF-8 in a path, kept as a lone surrogate (U+DC80..).
_SURROGATE_RE = re.compile("[\udc80-\udcff]")

#: What a terminal acts on, and so is never printed as it is: the C0
#: controls (tab and newline apart), DEL, the C1 controls (U+009B is CSI,
#: one character for ESC [), the Unicode line and paragraph separators and
#: the bidirectional overrides and isolates (they reorder what is on
#: screen). Each is shown as the escape Python writes for it, \x1b for ESC,
#: so the text stays readable and nothing is lost.
ESCAPES = {
    cp: ("\\x%02x" if cp < 0x100 else "\\u%04x") % cp
    for cp in (*range(0x00, 0x09), *range(0x0B, 0x20), *range(0x7F, 0xA0),
               0x2028, 0x2029, *range(0x202A, 0x202F),
               *range(0x2066, 0x206A))}


def neutralize(text: str) -> str:
    """text with every character a terminal acts on shown as a visible
    escape (\\x1b for ESC). Tab and newline are text and stay."""
    text = text.translate(ESCAPES)
    if _SURROGATE_RE.search(text):
        text = _SURROGATE_RE.sub(lambda m: "\\x%02x" % (ord(m.group()) - 0xDC00), text)
    return text


def scrub(obj):
    """obj (str, list, dict, nested) with every lone surrogate in a string,
    a dict key included, shown as \\xNN. JSON written with such a character
    is rejected by strict parsers, so machine-readable output goes through
    this first."""
    if isinstance(obj, str):
        return _SURROGATE_RE.sub(
            lambda m: "\\x%02x" % (ord(m.group()) - 0xDC00), obj)
    if isinstance(obj, list):
        return [scrub(x) for x in obj]
    if isinstance(obj, tuple):
        return [scrub(x) for x in obj]
    if isinstance(obj, dict):
        return {scrub(k): scrub(v) for k, v in obj.items()}
    return obj
