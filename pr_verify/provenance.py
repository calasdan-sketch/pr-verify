"""Provenance: which added lines were written by an agent vs a human.

Method (deterministic, no LLM):
  1. `git diff -U0 base..head` -> added lines per file (hunks).
  2. `git blame --porcelain <head> -- <file>` -> commit per line.
  3. one `git show -s` for all those commits -> author name/email,
     subject, body.
  4. A commit is agent-authored when an agent marker matches its author
     name, author email, a Co-Authored-By/Generated-by trailer, or a
     `marker:` subject prefix -- on whole words (see markers.py). The
     matched marker is kept, so the report can say `author (marker)`.

Non-ASCII paths: git quotes them C-style in diff headers
(`+++ "b/app/\\316\\232...py"`) unless core.quotePath is off. Every git
call here runs with `-c core.quotePath=false`, and a quoted header is
still unescaped defensively, so a Greek or Chinese filename is a file of
its own and never has its hunks appended to the previous file.

Deleted files are reported too: `git diff --diff-filter=D` finds them and
`git log --diff-filter=D` identifies the deleting commit(s), so a deletion
can never slip through as "nothing to verify". For a deleted file the
blast-radius scan matches the file's module names against the imports of
the files still in the worktree.

snapshot_worktree() commits the current index+worktree to a synthetic,
ref-less commit so `check` also sees uncommitted changes. By default only
TRACKED files are snapshotted (`git add -u`): an untracked, not-yet-ignored
`.env.local` must not end up in the object store because someone ran a
check. `include_untracked=True` (--include-untracked) adds them. Either
way the snapshot is a dangling commit object under .git/objects -- never
pushed, unreachable from any ref, removed by `git gc` -- and the user's
index is untouched (staging happens in a temporary GIT_INDEX_FILE).
Uncommitted lines are attributed to a neutral "pr-verify (worktree)"
identity -- counted as human, never as agent -- because there is no commit
authorship to analyze.
"""

from __future__ import annotations

import dataclasses
import os
import re
import subprocess
import tempfile

from . import markers as markers_mod

#: The tool's own config: excluded from provenance (it is not source and
#: the copy in effect is the one at the base ref, see config.py).
CONFIG_FILE = ".pr-verify.yaml"

_GIT_BASE = ["git", "-c", "core.quotePath=false"]


def _git(root: str, *args: str, env: dict | None = None) -> str:
    p = subprocess.run([*_GIT_BASE, "-C", root, *args], capture_output=True,
                       text=True, encoding="utf-8", errors="replace",
                       timeout=60, env=env)
    if p.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)} failed: {p.stderr.strip()[:200]}")
    return p.stdout


def untracked_files(root: str) -> list[str]:
    """Untracked, not-ignored files (repo-relative)."""
    try:
        out = _git(root, "ls-files", "--others", "--exclude-standard")
    except RuntimeError:
        return []
    return sorted(p for p in out.splitlines() if p)


def snapshot_worktree(root: str, include_untracked: bool = False) -> str | None:
    """Synthetic commit of index+worktree (tracked files; untracked too
    when include_untracked).

    Returns the new commit sha, or None when there is nothing to snapshot
    (no HEAD yet, or any git plumbing failure -- callers fall back to the
    plain head ref). Touches no refs and no user-visible index: staging
    happens in a temporary GIT_INDEX_FILE that is removed afterwards.
    """
    try:
        head = _git(root, "rev-parse", "--verify", "HEAD").strip()
    except RuntimeError:
        return None
    env = dict(os.environ)
    env.update({
        "GIT_AUTHOR_NAME": "pr-verify (worktree)",
        "GIT_AUTHOR_EMAIL": "pr-verify@local",
        "GIT_COMMITTER_NAME": "pr-verify (worktree)",
        "GIT_COMMITTER_EMAIL": "pr-verify@local",
    })
    fd, idx = tempfile.mkstemp(prefix="pr-verify-index-")
    os.close(fd)
    env["GIT_INDEX_FILE"] = idx
    add = ["add", "-A"] if include_untracked else ["add", "-u"]
    try:
        for args in (["read-tree", "HEAD"], add):
            p = subprocess.run([*_GIT_BASE, "-C", root, *args], env=env,
                               capture_output=True, timeout=60)
            if p.returncode != 0:
                return None
        p = subprocess.run([*_GIT_BASE, "-C", root, "write-tree"], env=env,
                           capture_output=True, text=True, encoding="utf-8",
                           errors="replace", timeout=60)
        if p.returncode != 0:
            return None
        tree = p.stdout.strip()
        p = subprocess.run(
            [*_GIT_BASE, "-C", root, "commit-tree", tree,
             "-p", head, "-m", "pr-verify: uncommitted worktree snapshot"],
            env=env, capture_output=True, text=True, encoding="utf-8",
            errors="replace", timeout=60)
        if p.returncode != 0:
            return None
        return p.stdout.strip()
    finally:
        try:
            os.unlink(idx)
        except OSError:
            pass


@dataclasses.dataclass
class FileProvenance:
    file: str
    added: int = 0
    agent_added: int = 0
    human_added: int = 0
    agents: set = dataclasses.field(default_factory=set)  # "author (marker)"
    deleted: bool = False
    deleted_by: list = dataclasses.field(default_factory=list)  # author names

    @property
    def agent_share(self) -> float:
        return self.agent_added / self.added if self.added else 0.0

    def label(self) -> str:
        if self.deleted:
            return "deleted"
        if self.added == 0:
            return "untouched"
        if self.agent_added == self.added:
            return "agent"
        if self.agent_added == 0:
            return "human"
        return "mixed"


_DIFF_HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")
_C_ESCAPES = {"n": "\n", "t": "\t", "r": "\r", "\\": "\\", '"': '"',
              "a": "\a", "b": "\b", "f": "\f", "v": "\v"}


def unquote_git_path(s: str) -> str:
    """Undo git's C-style path quoting ("b/app/\\316\\232.py" -> b/app/Κ.py).
    Unquoted input is returned unchanged."""
    if len(s) < 2 or s[0] != '"' or s[-1] != '"':
        return s
    body = s[1:-1]
    out = bytearray()
    i = 0
    while i < len(body):
        ch = body[i]
        if ch != "\\":
            out += ch.encode("utf-8")
            i += 1
            continue
        i += 1
        if i >= len(body):
            break
        esc = body[i]
        if esc in "01234567":
            digits = body[i:i + 3]
            n = 0
            while n < 3 and n < len(digits) and digits[n] in "01234567":
                n += 1
            out.append(int(body[i:i + n], 8) & 0xFF)
            i += n
        else:
            out += _C_ESCAPES.get(esc, esc).encode("utf-8")
            i += 1
    return out.decode("utf-8", "replace")


def _header_path(line: str) -> str | None:
    """Repo-relative path from a `+++ b/...` header (quoted or not), or
    None for `+++ /dev/null`."""
    rest = line[4:].strip()
    rest = unquote_git_path(rest)
    if rest == "/dev/null":
        return None
    if rest.startswith("b/"):
        return rest[2:]
    return rest


def added_lines(root: str, base: str, head: str = "HEAD") -> dict[str, list[int]]:
    """Repo-relative file -> sorted list of added line numbers (at head)."""
    out = _git(root, "diff", "-U0", f"{base}..{head}", "--")
    result: dict[str, list[int]] = {}
    cur_file: str | None = None
    new_line = 0
    for line in out.splitlines():
        if line.startswith("+++ "):
            cur_file = _header_path(line)
            new_line = 0
            if cur_file is not None:
                result.setdefault(cur_file, [])
        elif line.startswith("@@"):
            m = _DIFF_HUNK_RE.match(line)
            if m and cur_file:
                new_line = int(m.group(1))
        elif cur_file and new_line:
            if line.startswith("+") and not line.startswith("+++"):
                result[cur_file].append(new_line)
                new_line += 1
            elif line.startswith("-") and not line.startswith("---"):
                pass  # removed line: doesn't advance new-file numbering
            else:
                new_line += 1
    return {f: sorted(ls) for f, ls in result.items() if ls}


def deleted_files(root: str, base: str, head: str = "HEAD") -> list[str]:
    """Repo-relative paths deleted between base and head."""
    out = _git(root, "diff", "--name-only", "--diff-filter=D",
               f"{base}..{head}", "--")
    return sorted(unquote_git_path(p) for p in out.splitlines() if p)


def _deletion_commits(root: str, base: str, head: str,
                      rel: str) -> list[str]:
    """Commit shas in base..head that deleted rel (oldest first)."""
    out = _git(root, "log", "--format=%H", "--diff-filter=D", "--reverse",
               f"{base}..{head}", "--", rel)
    return [ln for ln in out.splitlines() if ln]


def _blame_authors(root: str, head: str, rel: str) -> dict[int, str]:
    """Line number -> commit sha, for <head> version of file."""
    out = _git(root, "blame", "--porcelain", head, "--", rel)
    authors: dict[int, str] = {}
    sha = ""
    lineno = 0
    for line in out.splitlines():
        if re.match(r"^[0-9a-f]{40} \d+ \d+ \d+$", line):
            parts = line.split()
            sha, lineno = parts[0], int(parts[2])
        elif line.startswith("\t"):
            authors[lineno] = sha
            lineno += 1  # each content line advances within the hunk
    return authors


_REC_SEP = "\x1e"
_FIELD_SEP = "\x00"
#: shas per `git show` call: keeps the command line well under Windows'
#: 8191-character limit (150 * 41 chars).
_SHOW_CHUNK = 150


def _commit_text(root: str, shas: set[str]) -> dict[str, tuple[str, str, str, str]]:
    """sha -> (author name, author email, subject, body), one git call
    per 150 commits instead of one per commit."""
    infos: dict[str, tuple[str, str, str, str]] = {}
    ordered = sorted(shas)
    # git's %x00 / %x1e escapes: a literal NUL cannot travel through argv.
    fmt = "--format=%H%x00%an%x00%ae%x00%s%x00%b%x1e"
    for i in range(0, len(ordered), _SHOW_CHUNK):
        chunk = ordered[i:i + _SHOW_CHUNK]
        out = _git(root, "show", "-s", fmt, *chunk)
        for rec in out.split(_REC_SEP):
            rec = rec.strip("\n")
            if not rec.strip():
                continue
            parts = rec.split(_FIELD_SEP)
            if len(parts) < 5:
                continue
            sha = parts[0].strip()
            infos[sha] = (parts[1], parts[2], parts[3],
                          _FIELD_SEP.join(parts[4:]))
    for sha in shas:
        infos.setdefault(sha, (sha[:7], "", "", ""))
    return infos


def agent_label(name: str, marker: str) -> str:
    return f"{name} ({marker})"


def analyze(root: str, base: str, head: str = "HEAD",
            agent_markers: list[str] | None = None) -> dict[str, FileProvenance]:
    agent_markers = [str(m).lower() for m in (agent_markers or [])]
    added = {rel: lines for rel, lines in added_lines(root, base, head).items()
             if rel != CONFIG_FILE}
    deleted = [rel for rel in deleted_files(root, base, head)
               if rel != CONFIG_FILE]
    result: dict[str, FileProvenance] = {}
    # Batch: collect all shas first, then one `git show` for all of them.
    blame_maps: dict[str, dict[int, str]] = {}
    del_shas: dict[str, list[str]] = {}
    all_shas: set[str] = set()
    for rel in added:
        bm = _blame_authors(root, head, rel)
        blame_maps[rel] = bm
        all_shas.update(bm[ln] for ln in added[rel] if ln in bm)
    for rel in deleted:
        shas = _deletion_commits(root, base, head, rel)
        del_shas[rel] = shas
        all_shas.update(shas)
    texts = _commit_text(root, all_shas)
    matched: dict[str, str] = {}   # sha -> marker that identified it
    for sha, (name, email, subject, body) in texts.items():
        hit = markers_mod.match(name, email, subject, body, agent_markers)
        if hit:
            matched[sha] = hit

    def who(sha: str) -> str:
        return texts.get(sha, (sha[:7], "", "", ""))[0] or sha[:7]

    for rel, linenos in added.items():
        fp = FileProvenance(file=rel)
        bm = blame_maps[rel]
        for ln in linenos:
            fp.added += 1
            sha = bm.get(ln)
            if sha in matched:
                fp.agent_added += 1
                fp.agents.add(agent_label(who(sha), matched[sha]))
            else:
                fp.human_added += 1
        result[rel] = fp
    for rel in deleted:
        fp = FileProvenance(file=rel, deleted=True)
        for sha in del_shas[rel]:
            name = who(sha)
            fp.deleted_by.append(name)
            if sha in matched:
                fp.agents.add(agent_label(name, matched[sha]))
        result[rel] = fp
    return result
