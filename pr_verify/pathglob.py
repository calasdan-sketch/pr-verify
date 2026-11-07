"""Path globs the way .gitignore and CODEOWNERS write them.

`*` matches within one path part, `**` any number of parts, `?` one
character, a leading `/` anchors at the repository root, a pattern with no
`/` matches a name at any depth, a trailing `/` means a directory and
everything below it. A pattern that names a file or directory also matches
everything below it. Paths use `/` (backslashes are turned into it) and are
compared without regard to case, like the file systems of Windows and macOS.

No regular expressions: a path is chosen by the pull request's author, and a
pattern like `**/**/*a*a*b` must not be able to make a regex engine run for
minutes. Parts are matched by dynamic programming, in time proportional to
(pattern parts x path parts) and (pattern length x part length).
"""

from __future__ import annotations

import functools


def _part(pat: str, name: str) -> bool:
    """One path part against one pattern part with * and ?, in O(len*len)."""
    p = n = 0
    star = -1
    mark = 0
    while n < len(name):
        if p < len(pat) and (pat[p] == "?" or pat[p] == name[n]) and pat[p] != "*":
            p += 1
            n += 1
        elif p < len(pat) and pat[p] == "*":
            star = p
            mark = n
            p += 1
        elif star != -1:
            p = star + 1
            mark += 1
            n = mark
        else:
            return False
    while p < len(pat) and pat[p] == "*":
        p += 1
    return p == len(pat)


@functools.lru_cache(maxsize=4096)
def _segments(pattern: str) -> tuple[str, ...]:
    pat = pattern.strip().replace("\\", "/")
    if not pat.strip("/"):
        return ()
    anchored = pat.startswith("/") or "/" in pat.rstrip("/")
    segs = pat.strip("/").split("/")
    segs = ["**" if s == "**" else s.replace("**", "*") for s in segs]
    if not anchored:
        segs = ["**"] + segs
    segs.append("**")           # the thing itself, or anything below it
    return tuple(s.casefold() for s in segs)


def split_path(path: str) -> list[str]:
    return [s.casefold() for s in path.replace("\\", "/").split("/") if s]


def match(path: str, pattern: str) -> bool:
    return match_parts(split_path(path), pattern)


def match_parts(nm: list[str], pattern: str) -> bool:
    """match() for a path already cut into parts by split_path (so one path
    can be tried against thousands of patterns)."""
    pc = _segments(pattern)
    if not pc:
        return False
    if len(pc) == 3 and pc[0] == "**" and pc[2] == "**" and pc[1] != "**":
        # `*.py`, `Makefile`: any part of the path (a directory too)
        return any(_part(pc[1], n) for n in nm)
    head = pc[0]
    # a pattern anchored at the root with a plain first part: one comparison
    if head != "**" and "*" not in head and "?" not in head:
        if not nm or nm[0] != head:
            return False
    # ok[j]: pattern parts [i:] match path parts [j:]
    ok = [False] * (len(nm) + 1)
    ok[len(nm)] = True
    for i in range(len(pc) - 1, -1, -1):
        new = [False] * (len(nm) + 1)
        if pc[i] == "**":
            # zero or more parts
            acc = False
            for j in range(len(nm), -1, -1):
                acc = acc or ok[j]
                new[j] = acc
        else:
            for j in range(len(nm)):
                new[j] = ok[j + 1] and _part(pc[i], nm[j])
        ok = new
    return ok[0]


def match_any(path: str, patterns) -> bool:
    return any(match(path, p) for p in patterns)
