"""Text that hides from the reader: invisible and reordering characters
("Trojan Source", CVE-2021-42574), look-alike letters, and sentences written
for the review bot instead of for the compiler.

Every function takes one line of ADDED text and returns findings as
(kind, detail) pairs. Pure, no I/O, linear in the length of the line.
"""

from __future__ import annotations

import re
import unicodedata

#: Characters that reorder what is displayed (bidirectional overrides,
#: embeddings, isolates, marks). A source file with one can read differently
#: to a person than to a compiler.
BIDI = frozenset(
    [0x061C, 0x200E, 0x200F, *range(0x202A, 0x202F), *range(0x2066, 0x206A)])

#: Characters that occupy no space on screen but are part of the text.
INVISIBLE = frozenset(
    [0x00AD, 0x034F, 0x115F, 0x1160, 0x17B4, 0x17B5, 0x180E,
     *range(0x200B, 0x2010), 0x2060, 0x2061, 0x2062, 0x2063, 0x2064,
     0x3164, 0xFEFF, 0xFFA0, 0xFFFC])

_TAG_LO, _TAG_HI = 0xE0000, 0xE007F      # "tag" block: ASCII smuggling
_VS_SUP_LO, _VS_SUP_HI = 0xE0100, 0xE01EF  # variation selectors supplement

_HIDDEN_RE = re.compile(
    "[" + "".join(re.escape(chr(c)) for c in sorted(BIDI | INVISIBLE))
    + "\U000E0000-\U000E007F\U000E0100-\U000E01EF" + "]")

_WORD_RE = re.compile(r"[^\W\d]+[\w]*", re.UNICODE)

#: Scripts whose letters are mistaken for Latin ones.
_CONFUSABLE_SCRIPTS = ("CYRILLIC", "GREEK")


def _script(ch: str) -> str:
    try:
        return unicodedata.name(ch).split(" ", 1)[0]
    except ValueError:
        return ""


def hidden_chars(text: str, first_line: bool = False) -> list[tuple[str, str]]:
    """Invisible or reordering characters in text. A byte-order mark at the
    very start of a file is how some editors save UTF-8 and is not reported."""
    out: list[tuple[str, str]] = []
    seen: set[int] = set()
    for i, m in enumerate(_HIDDEN_RE.finditer(text)):
        cp = ord(m.group())
        if cp == 0xFEFF and first_line and m.start() == 0:
            continue
        if cp in seen:
            continue
        seen.add(cp)
        if cp in BIDI:
            kind = "bidi"
        elif _TAG_LO <= cp <= _TAG_HI:
            kind = "tag_chars"
        else:
            kind = "invisible"
        try:
            name = unicodedata.name(chr(cp))
        except ValueError:
            name = "unnamed"
        out.append((kind, f"U+{cp:04X} {name}"))
        if len(out) >= 8:
            break
    return out


def homoglyph_words(text: str) -> list[tuple[str, str]]:
    """Words that mix Latin letters with Cyrillic or Greek ones: `paypal`
    with a Cyrillic `a` is a different identifier that reads the same. A
    word written wholly in Cyrillic or Greek is a word of that language and
    is not reported."""
    if text.isascii():
        return []
    out: list[tuple[str, str]] = []
    for m in _WORD_RE.finditer(text):
        w = m.group()
        if w.isascii():
            continue
        scripts = {_script(c) for c in w if c.isalpha()}
        if "LATIN" in scripts and scripts & set(_CONFUSABLE_SCRIPTS):
            shown = w if len(w) <= 40 else w[:40] + "..."
            out.append(("homoglyph", f"mixed-script word {shown!r}"))
            if len(out) >= 4:
                break
    return out


# --- sentences aimed at an automated reviewer ---------------------------------

_B = r"(?<![A-Za-z])"
_INJECTION = [
    (re.compile(_B + r"(ignore|disregard|forget|override)\s+(all\s+|any\s+|the\s+|your\s+|every\s+)?"
                r"(previous|prior|above|earlier|preceding|system|safety|review)\s+"
                r"(instructions?|prompts?|rules?|guidelines?|checks?)", re.I),
     "tells a model to drop its instructions"),
    (re.compile(_B + r"(note|message|instruction)s?\s+(to|for)\s+(the\s+)?"
                r"(ai|llm|a\.i\.|bot|reviewer|review\s*bot|code\s*review(er)?|assistant|agent|copilot|claude|gpt)\b",
                re.I),
     "addressed to the reviewing AI"),
    (re.compile(_B + r"(ai|llm|bot|assistant|reviewer|copilot)[,:]?\s+(please\s+)?"
                r"(do\s+not|don'?t|never)\s+(flag|report|mention|comment|raise|point\s+out|warn)",
                re.I),
     "tells the reviewer not to report"),
    (re.compile(_B + r"(do\s+not|don'?t|never)\s+(flag|report|mention|raise)\s+"
                r"(this|these|the|any)\b[^.\n]{0,40}\b(issue|vulnerabilit|finding|problem|change|warning)",
                re.I),
     "tells the reviewer not to report"),
    (re.compile(_B + r"(approve|lgtm|mark|label|rate|treat)\s+(this|the)\s+"
                r"(pr|pull\s*request|change|diff|code|commit)\b[^.\n]{0,30}"
                r"\b(as\s+)?(safe|secure|approved|lgtm|trusted|low[\s-]*risk|reviewed)", re.I),
     "asks the reviewer to approve or rate it safe"),
    (re.compile(_B + r"this\s+(pr|pull\s*request|change|code|diff)\s+(has\s+been|was|is)\s+"
                r"(already\s+)?(security[\s-]*)?(reviewed|audited|approved|verified)\s+(and\s+)?"
                r"(is\s+)?(safe|secure|approved|by)?", re.I),
     "claims a review that did not happen"),
    (re.compile(r"(<\s*/?\s*(system|assistant|instructions?)\s*>|\[\s*/?\s*INST\s*\]|"
                r"<\|\s*(im_start|im_end|system)\s*\|>)", re.I),
     "chat-template control tokens"),
    (re.compile(_B + r"you\s+are\s+(now\s+)?(in\s+)?(a|an|the)\s+"
                r"(helpful\s+)?(assistant|ai|language\s+model|code\s+reviewer)\b.{0,60}"
                r"\b(must|should|will|always)\b", re.I),
     "reassigns the reviewer's role"),
    (re.compile(_B + r"(reveal|print|output|show|exfiltrate)\s+(your|the)\s+"
                r"(system\s+prompt|instructions|api\s*keys?|secrets?|environment\s+variables)",
                re.I),
     "asks the reviewer to leak its prompt or secrets"),
]


_INJ_QUICK = re.compile(
    r"instruction|prompt|reviewer|review\s*bot|\bai\b|\bllm\b|\bbot\b|assistant|copilot|"
    r"lgtm|approve|approved|audited|reviewed|verified|flag|report|mention|raise|warn|"
    r"system|\[\s*/?\s*inst|im_start|im_end|reveal|exfiltrate|you\s+are|safe|secure|"
    r"low[\s-]*risk|trusted", re.I)


def injection_phrases(text: str) -> list[tuple[str, str]]:
    """Sentences that talk to an AI reviewer. Matched on added lines of any
    kind, a comment, a string, a docstring or a README line: a model reads
    them all. A hit is a reason for a human to read the line, not a verdict."""
    if len(text) > 4000:
        text = text[:4000]
    if not _INJ_QUICK.search(text):
        return []
    out = []
    for rx, why in _INJECTION:
        if rx.search(text):
            out.append(("prompt_injection", why))
    return out
