"""Text from a pull request, made safe to show.

Shared by the human report (cli.py) and the Markdown report (mdreport.py),
so both escape exactly the same characters.
"""

from __future__ import annotations

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
    return text.translate(ESCAPES)
