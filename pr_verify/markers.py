"""Agent markers: decide whether a commit was written by an agent.

The old rule -- "any marker is a case-insensitive substring of the author
name, email, subject or body" -- labelled a human "Tim Abbott" an agent
(contains "bot"), flagged a human named Claude or Cody, and turned a
subject like "Fix cursor jump" into Cursor's work. The rules below match
on whole words and only where an agent actually leaves its name:

1. Author name, on word boundaries. A bot-shaped name -- one word, or a
   hyphen/underscore/dot handle -- matches when any of its words is a
   marker: `claude-bot`, `Claude`, `copilot-swe-agent`, `aider-ai`.
   A human-shaped name (two or more space-separated words) only matches a
   marker that covers the WHOLE name (`Claude Code` ~ marker "claude
   code") or a bracketed/parenthesised tag anywhere in it
   (`dependabot[bot]`, `Dan Calas (aider)`). So "Claude Dupont",
   "Cody Smith" and "Tim Abbott" are humans; the marker "bot" matches the
   word "bot", never "Abbott".
2. Author email: a marker equal to the whole local part (`cody@...`), to a
   hyphen/underscore-separated word of it (`claude-bot@...`,
   `cursor_agent@...`; dots join human first.last names and are not
   split), or to a domain label (`...@aider.chat`, `...@cursor.com`).
3. Trailers in the body -- `Co-Authored-By:`, `Co-authored-by:`,
   `Generated-by:`, `Signed-off-by:` -- have their name and email parts
   matched with rules 1 and 2 (`Co-Authored-By: Claude
   <noreply@anthropic.com>` matches "claude"). A marker written as
   "co-authored-by: X" in an old config matches X in trailers only.
   Two other lines Claude Code leaves count as trailers too: its footer
   `Generated with [Claude Code](...)` (the text in the brackets is the
   name) and the `Claude-Session:` trailer (the key alone names Claude).
4. A marker with an `@` in it is one exact e-mail address, compared
   whole and without case: `noreply@anthropic.com`. That is how Claude
   Code's trailer is caught whatever model name it carries --
   `Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>` -- while
   other people at anthropic.com stay human. It is never read as a name.
5. A subject PREFIX `marker:` (`aider: fix the tests`). The rest of the
   subject and the body text are never scanned -- prose is not evidence.

`match(...)` returns the marker that matched (shown as `author (marker)`
in the report) or None. Every marker is compared lower-cased.
"""

from __future__ import annotations

import re

#: Body lines whose value names a co-author / generator.
TRAILER_KEYS = ("co-authored-by", "generated-by", "signed-off-by")

_WORD_RE = re.compile(r"[^\W_]+", re.UNICODE)
_TAG_RE = re.compile(r"[\[(]([^\])]*)[\])]")
_TRAILER_RE = re.compile(r"^\s*([A-Za-z-]+):\s*(.+?)\s*$")
_ADDR_RE = re.compile(r"^(.*?)\s*<([^>]*)>\s*$")
#: `<emoji> Generated with [Claude Code](https://claude.com/claude-code)`:
#: the footer Claude Code puts at the end of a commit message. Nothing but
#: decoration may come before "Generated with", so a sentence that merely
#: says so ("I generated this with [Claude Code] ...") is not one.
_FOOTER_RE = re.compile(r"^[^\w\[]*Generated with \[([^\]]+)\]", re.IGNORECASE)
#: Trailer keys that name an agent by themselves, whatever their value:
#: key -> the name it stands for. (`Claude-Session: <url>`)
_AGENT_KEYS = {"claude-session": "Claude"}


def parse_trailer_keys(entries) -> dict[str, str]:
    """Config `agent_trailer_keys` -> {key: name}. Each entry is
    `key: Name` (`claude-session: Claude`); an entry without a name stands
    for the key itself. Keys are compared without case."""
    keys: dict[str, str] = {}
    for entry in entries:
        key, sep, name = str(entry).partition(":")
        key, name = key.strip().lower(), name.strip()
        if key:
            keys[key] = name or key
    return keys


def _words(text: str) -> list[str]:
    return [w.lower() for w in _WORD_RE.findall(text or "")]


def _marker_words(marker: str) -> list[str]:
    return _words(marker)


def _contains_sequence(words: list[str], seq: list[str]) -> bool:
    if not seq or len(seq) > len(words):
        return False
    return any(words[i:i + len(seq)] == seq for i in range(len(words) - len(seq) + 1))


def _split_marker(marker: str) -> tuple[str, bool]:
    """'co-authored-by: claude' -> ('claude', True): trailer-only marker."""
    m = marker.strip().lower()
    for key in TRAILER_KEYS:
        if m.startswith(key + ":"):
            return m[len(key) + 1:].strip(), True
    return m, False


def name_matches(name: str, marker: str) -> bool:
    """Rule 1: author/co-author display name."""
    mw = _marker_words(marker)
    if not mw or not name or "@" in marker:
        return False
    name = name.strip()
    tags = _TAG_RE.findall(name)
    body = _TAG_RE.sub(" ", name).strip()
    human_shaped = len(body.split()) >= 2
    for tag in tags:
        if _contains_sequence(_words(tag), mw):
            return True
    body_words = _words(body)
    if human_shaped:
        return body_words == mw
    return _contains_sequence(body_words, mw)


def email_matches(email: str, marker: str) -> bool:
    """Rule 2: author/co-author email. A marker with an `@` in it is a whole
    address (rule 4)."""
    mw = _marker_words(marker)
    if not mw or not email or "@" not in email:
        return False
    if "@" in marker:
        return email.strip().lower() == marker.strip().lower()
    local, _, domain = email.strip().lower().rpartition("@")
    if _words(local) == mw:
        return True
    # hyphen/underscore/plus-separated words of the local part; dots are
    # left alone (first.last)
    for piece in re.split(r"[-_+]", local):
        if piece and _words(piece) == mw:
            return True
    for label in domain.split("."):
        if _words(label) == mw:
            return True
    return False


def _trailers(body: str, agent_keys: dict[str, str] | None = None
              ) -> list[tuple[str, str]]:
    """(name, email) pairs from trailer lines in the body."""
    agent_keys = _AGENT_KEYS if agent_keys is None else agent_keys
    out: list[tuple[str, str]] = []
    # lines end at "\n", as in git: str.splitlines() would also cut at
    # \x0b \x1e \u2028 ..., so `Co-Authored-By:\x1e Claude <x>` lost its value
    for line in (body or "").split("\n"):
        footer = _FOOTER_RE.match(line)
        if footer:
            out.append((footer.group(1).strip(), ""))
            continue
        m = _TRAILER_RE.match(line)
        if m and m.group(1).lower() in agent_keys:
            out.append((agent_keys[m.group(1).lower()], ""))
            continue
        if not m or m.group(1).lower() not in TRAILER_KEYS:
            continue
        value = m.group(2)
        a = _ADDR_RE.match(value)
        if a:
            out.append((a.group(1).strip(), a.group(2).strip()))
        else:
            out.append((value.strip(), ""))
    return out


def match(name: str, email: str, subject: str, body: str,
          markers: list[str],
          agent_keys: dict[str, str] | None = None) -> str | None:
    """The first marker that identifies this commit as agent-authored,
    or None. Markers are matched in the order given. `agent_keys` are the
    trailer keys that name an agent by themselves (parse_trailer_keys of the
    config's agent_trailer_keys; default: Claude-Session)."""
    trailers = _trailers(body, agent_keys)
    subject_prefix = ""
    if subject and ":" in subject:
        subject_prefix = subject.split(":", 1)[0].strip().lower()
    for raw in markers:
        marker, trailer_only = _split_marker(str(raw))
        if not marker:
            continue
        if not trailer_only:
            if name_matches(name, marker) or email_matches(email, marker):
                return raw
            if (subject_prefix and "@" not in marker
                    and _words(subject_prefix) == _marker_words(marker)):
                return raw
        for t_name, t_email in trailers:
            if name_matches(t_name, marker) or email_matches(t_email, marker):
                return raw
    return None
