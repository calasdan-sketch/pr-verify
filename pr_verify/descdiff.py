"""description-vs-diff: does the pull request's text talk about things the
diff does not touch?

An advisory, nothing more. A description that says "updated `src/auth.py` and
`validate_token()`" over a diff that touches neither is worth a second look:
the text was written for a different change, or the work it describes never
made it in. No LLM, no scoring: file names and code-looking words are pulled
out of the text with patterns and looked for in the diff.

  file     a path-like word (`pkg/mod.py`, `README.md`) that is not one of the
           changed files (a path matches a changed file by its tail either
           way round, so `auth.py` matches `src/app/auth.py`)
  symbol   a backticked identifier that looks like code (`snake_case`,
           `camelCase`, `PascalCase`, `a.b`, `f()`) that appears in no added
           or removed line and in none of the changed files as they are now

Never counted in the score, the exit status or the review depth. Fenced code
blocks, HTML comments and URLs in the text are skipped (PR templates are full
of them), and each kind is cut off at MAX_ADVISORIES.
"""

from __future__ import annotations

import keyword
import re

MAX_ADVISORIES = 20

_FENCE = re.compile(r"```.*?```|~~~.*?~~~", re.DOTALL)
_COMMENT = re.compile(r"<!--.*?-->", re.DOTALL)
_URL = re.compile(r"\b[a-z][a-z0-9+.-]*://\S+|\bwww\.\S+", re.IGNORECASE)
_EXT = ("py|pyi|js|jsx|mjs|cjs|ts|tsx|go|rs|rb|java|kt|kts|swift|c|h|cc|cpp|"
        "hpp|cs|php|sh|bash|md|rst|txt|ya?ml|json|toml|ini|cfg|sql|html|css|"
        "scss|vue|svelte|lock|gradle|xml|proto|tf")
_FILE = (r"(?:\.{0,2}/)?(?:[\w.@-]+/)*[\w.@-]*\w\.(?:" + _EXT + r")")
#: a path with a directory in it, or a directory with a trailing slash
_PATH = re.compile(
    r"(?<![\w/.@~-])((?:\.{0,2}/)?(?:[\w.@-]+/)+[\w.@-]*\w\.(?:" + _EXT +
    r")|(?:[\w.@-]+/)+)(?![\w/-])(?!\.\w)", re.IGNORECASE)
_PATH_EXT = re.compile(r"\.(?:" + _EXT + r")$", re.IGNORECASE)
_BARE_FILE = re.compile(r"^" + _FILE + r"$", re.IGNORECASE)
_TICKED = re.compile(r"`([^`\n]{1,120})`")
_IDENT = re.compile(r"^[A-Za-z_][\w]*(?:\.[A-Za-z_]\w*)*(\(\))?$")
#: words that are code in a sentence but name nothing in the diff
_COMMON = frozenset((
    "true", "false", "none", "null", "undefined", "nan", "self", "this",
    "cls", "args", "kwargs", "async", "await", "string", "number", "object",
    "array", "boolean", "int", "float", "str", "list", "dict", "set", "bool",
    "bytes", "tuple", "main", "init", "e.g", "i.e", "etc"))


def _clean(text: str) -> str:
    return _URL.sub(" ", _COMMENT.sub(" ", _FENCE.sub(" ", text or "")))


def mentioned_paths(text: str) -> list[str]:
    """The files and directories the text names, in order, without repeats:
    a path with a directory in it (`pkg/mod.py`, `docs/`) anywhere, and a bare
    file name (`mod.py`) only inside backticks (otherwise `Node.js` is a
    file)."""
    clean = _clean(text)
    found: list[tuple[int, str]] = []
    for m in _PATH.finditer(clean):
        found.append((m.start(1), m.group(1)))
    for m in _TICKED.finditer(clean):
        word = m.group(1).strip()
        if _BARE_FILE.match(word) and "/" not in word:
            found.append((m.start(1), word))
    seen: list[str] = []
    for _, word in sorted(found):
        word = word[2:] if word.startswith("./") else word
        if word and word not in seen:
            seen.append(word)
    return seen


def _symbol_shaped(word: str) -> bool:
    bare = word[:-2] if word.endswith("()") else word
    if not _IDENT.match(word) or bare.lower() in _COMMON \
            or keyword.iskeyword(bare):
        return False
    if _PATH_EXT.search(bare):
        return False
    if word.endswith("()") or "_" in bare or "." in bare:
        return len(bare) >= 3
    return bool(re.search(r"[a-z][A-Z]", bare)) or (
        bare[:1].isupper() and bool(re.search(r"[A-Z][a-z]+[A-Z]", bare)))


def mentioned_symbols(text: str) -> list[str]:
    """Backticked, code-looking words of the text, in order, without repeats
    (`f()` is kept as `f()`)."""
    seen: list[str] = []
    for m in _TICKED.finditer(_clean(text)):
        word = m.group(1).strip()
        if _symbol_shaped(word) and word not in seen:
            seen.append(word)
    return seen


def _touches(mention: str, changed: list[str]) -> bool:
    m = mention.strip("/").lower()
    for c in changed:
        c = c.lower()
        if c == m or c.endswith("/" + m) or m.endswith("/" + c):
            return True
        if "/" not in m and c.rsplit("/", 1)[-1] == m:
            return True
        if m.endswith("/") or "." not in m.rsplit("/", 1)[-1]:
            # a directory: touched when something changed under it
            if ("/" + c).find("/" + m + "/") != -1:
                return True
    return False


def _in_text(symbol: str, haystacks) -> bool:
    name = symbol[:-2] if symbol.endswith("()") else symbol
    tail = name.rsplit(".", 1)[-1]
    rx = re.compile(r"(?<![\w])" + re.escape(tail) + r"(?![\w])")
    return any(rx.search(h) for h in haystacks)


def advisories(text: str, changed_files: list[str], changed_text: list[str],
               read_file) -> list[dict]:
    """[{"kind": "file"|"symbol", "text", "message"}] for what `text` mentions
    and the change does not touch. `changed_text` are the added and removed
    lines; `read_file(path)` returns a changed file's current content ("" when
    it is gone or unreadable)."""
    out: list[dict] = []
    files = [f for f in mentioned_paths(text) if not _touches(f, changed_files)]
    for f in files[:MAX_ADVISORIES]:
        out.append({"kind": "file", "text": f,
                    "message": f"the description mentions {f}, which this "
                               f"change does not touch"})
    symbols = mentioned_symbols(text)
    if symbols:
        contents = None
        for s in symbols:
            if len([a for a in out if a["kind"] == "symbol"]) >= MAX_ADVISORIES:
                break
            if _in_text(s, changed_text):
                continue
            if contents is None:
                contents = [read_file(f) for f in changed_files]
            if _in_text(s, contents):
                continue
            out.append({"kind": "symbol", "text": s,
                        "message": f"the description mentions {s}, which "
                                   f"is in none of the changed lines or "
                                   f"changed files"})
    return out
