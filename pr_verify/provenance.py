"""Provenance: which added lines were written by an agent vs a human.

Method (deterministic, no LLM):
  1. `git diff-tree -p -U0 -M base head` -> added lines per file (hunks).
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

Everything git prints is parsed as untrusted text: file lines, file names,
commit subjects, bodies and author names all belong to the PR's author, so
nothing inside them may act as a boundary. Output is read as bytes and split
on "\\n" only (str.splitlines() also breaks at \\x0b \\x0c \\x1c-\\x1e \\x85
\\u2028 \\u2029, and text=True turns a lone \\r into \\n), path lists use -z,
the diff is walked by the line counts in its hunk headers (a file line
`++ b/x` is not a `+++` file header), and `git show` is read NUL-framed and
checked against the commits asked for (see _commit_text).

The diff is read the way a machine reads it, not the way a person likes to
see it: with the repository's .gitattributes out of the picture (a PR can
add one that marks a source file `binary`, and git then prints "Binary files
differ" instead of its lines) and through plumbing, which ignores the user's
color, prefix, context and external-diff settings (see _patch).

Deleted files are reported too: `git diff-tree --diff-filter=D` finds them and
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

#: Every git call pins the user's config where it would change the shape of
#: the output: no C-quoting of non-ASCII paths, and no gpg verification
#: chatter (log.showSignature=true prints it to stdout, ahead of each
#: signed commit's record).
_GIT_BASE = ["git", "-c", "core.quotePath=false",
             "-c", "log.showSignature=false"]


def _git_bytes(root: str, *args: str, env: dict | None = None) -> bytes:
    """stdout of `git <args>`, undecoded."""
    p = subprocess.run([*_GIT_BASE, "-C", root, *args], capture_output=True,
                       timeout=60, env=env)
    if p.returncode != 0:
        err = p.stderr.decode("utf-8", "replace").strip()[:200]
        raise RuntimeError(f"git {' '.join(args)} failed: {err}")
    return p.stdout


def _git(root: str, *args: str, env: dict | None = None) -> str:
    """stdout of `git <args>`. Decoded here from the raw bytes: with
    text=True subprocess first turns every lone \\r into \\n, so a file line
    holding one would read like a line break of git's own output."""
    return _git_bytes(root, *args, env=env).decode("utf-8", "replace")


def untracked_files(root: str) -> list[str]:
    """Untracked, not-ignored files (repo-relative)."""
    try:
        out = _git(root, "ls-files", "--others", "--exclude-standard", "-z")
    except RuntimeError:
        return []
    return sorted(p for p in out.split("\0") if p)


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


#: `@@ -a[,b] +c[,d] @@`: groups are b (old lines), c (first new line), d
#: (new lines); an omitted count means 1.
_DIFF_HUNK_RE = re.compile(r"^@@ -\d+(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")
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


#: How a patch is asked for. `git diff` is porcelain: color.ui, diff.noprefix,
#: diff.interHunkContext, diff.submodule, diff.renames ... all reshape its
#: output, GIT_EXTERNAL_DIFF replaces it, and the parser below reads it line
#: by line. Plumbing (`git diff-tree`) takes none of them, so the patch looks
#: the same on every machine. What `git diff` decides for itself is spelled
#: out: rename detection (-M, on by default there). The two --no- options are
#: plumbing's own defaults, stated so that nothing can change them.
_PATCH = ("diff-tree", "-p", "-U0", "-M", "--no-commit-id",
          "--no-ext-diff", "--no-textconv")


def _patch(root: str, base: str, head: str) -> str:
    """The patch from base to head, as the files are and not as the
    repository's .gitattributes would like them shown.

    Attributes steer diff: `-diff` or `binary` turns a file into "Binary
    files differ", `diff` forces text on a real binary, and a `diff=<name>`
    driver can convert the content -- and .gitattributes is in the PR. git
    reads them from the worktree and, failing that, from the index, so this
    runs against an empty work tree and an index that does not exist: git
    finds no attributes and falls back to its own test for a binary (a NUL in
    the first 8000 bytes), which a source file passes and a PNG does not.
    (`--text` would turn the PNG into added lines too.) The repository's
    objects are used as they are: only the work tree and the index are
    replaced."""
    # a directory name is bytes to the file system, not necessarily UTF-8
    gitdir = os.fsdecode(_git_bytes(root, "rev-parse",
                                    "--absolute-git-dir")).rstrip("\r\n")
    with tempfile.TemporaryDirectory(prefix="pr-verify-",
                                     ignore_cleanup_errors=True) as empty:
        env = dict(os.environ)
        env["GIT_INDEX_FILE"] = os.path.join(empty, "index")
        return _git(empty, "--git-dir", gitdir, "--work-tree", empty,
                    *_PATCH, base, head, "--", env=env)


def added_lines(root: str, base: str, head: str = "HEAD") -> dict[str, list[int]]:
    """Repo-relative file -> sorted list of added line numbers (at head)."""
    out = _patch(root, base, head)
    result: dict[str, list[int]] = {}
    cur_file: str | None = None
    new_line = 0
    # A hunk header says how many old (-) and new (+) lines follow it, and a
    # context line counts on both sides (there is none under -U0, but
    # GIT_DIFF_OPTS=-u3 asks for some).
    # Inside a hunk every line is FILE CONTENT, whatever it starts with: the
    # added line `++ /dev/null` reads `+++ /dev/null`, the removed SQL
    # comment `-- x` reads `--- x`, and neither is a file header.
    old_left = new_left = 0
    for line in out.split("\n"):
        if old_left or new_left:
            mark = line[:1]
            if mark == "-" and old_left:
                old_left -= 1
                continue
            if mark == "+" and new_left:
                if cur_file is not None:
                    result[cur_file].append(new_line)
                new_line += 1
                new_left -= 1
                continue
            if (mark == " " or not line) and old_left and new_left:
                old_left -= 1       # an empty line is a blank context line
                new_left -= 1
                new_line += 1
                continue
            if mark == "\\":
                continue  # "\ No newline at end of file": on neither side
            old_left = new_left = 0  # hunk ended early: a header after all
        if line.startswith("+++ "):
            cur_file = _header_path(line)
            if cur_file is not None:
                result.setdefault(cur_file, [])
        elif line.startswith("@@"):
            m = _DIFF_HUNK_RE.match(line)
            if m:
                old_left = 1 if m.group(1) is None else int(m.group(1))
                new_line = int(m.group(2))
                new_left = 1 if m.group(3) is None else int(m.group(3))
    return {f: sorted(ls) for f, ls in result.items() if ls}


def deleted_files(root: str, base: str, head: str = "HEAD") -> list[str]:
    """Repo-relative paths deleted between base and head."""
    out = _git(root, "diff-tree", "-r", "--name-only", "-z", "--diff-filter=D",
               "-M", "--no-commit-id", base, head, "--")
    return sorted(p for p in out.split("\0") if p)


def _deletion_commits(root: str, base: str, head: str,
                      rel: str) -> list[str]:
    """Commit shas in base..head that deleted rel (oldest first)."""
    out = _git(root, "log", "--format=%H", "--diff-filter=D", "--reverse",
               f"{base}..{head}", "--", rel)
    return [ln for ln in out.splitlines() if ln]


def _blame_options(root: str) -> list[str]:
    """Extra `git blame` options. blame.ignoreRevsFile (a setting for
    skipping formatting commits) makes blame look past the commits a file
    lists, and the file is in the PR: it could list the agent's commits, and
    their lines would read as the older, human ones. An empty
    --ignore-revs-file clears the list. Only when the setting exists, so a
    git older than 2.23 (which has neither) is not asked for it."""
    p = subprocess.run([*_GIT_BASE, "-C", root, "config", "--get-all",
                        "blame.ignoreRevsFile"], capture_output=True,
                       timeout=15)
    return ["--ignore-revs-file="] if p.returncode == 0 else []


def _blame_authors(root: str, head: str, rel: str,
                   options: list[str] | tuple = ()) -> dict[int, str]:
    """Line number -> commit sha, for <head> version of file."""
    out = _git(root, "blame", "--porcelain", *options, head, "--", rel)
    authors: dict[int, str] = {}
    sha = ""
    lineno = 0
    for line in out.split("\n"):
        if re.match(r"^[0-9a-f]{40} \d+ \d+ \d+$", line):
            parts = line.split()
            sha, lineno = parts[0], int(parts[2])
        elif line.startswith("\t"):
            authors[lineno] = sha
            lineno += 1  # each content line advances within the hunk
    return authors


#: shas per `git show` call: keeps the command line well under Windows'
#: 8191-character limit (150 * 41 chars).
_SHOW_CHUNK = 150
#: fields `_commit_text` asks git for, per commit
_SHOW_FIELDS = 5
_BAD_SHOW = ("git show returned commit text that does not match the commits "
             "asked for; refusing to guess who wrote them")


def _commit_text(root: str, shas: set[str]) -> dict[str, tuple[str, str, str, str]]:
    """sha -> (author name, author email, subject, body), one git call
    per 150 commits instead of one per commit.

    The text is the PR author's, so it must not shape the parse. Fields are
    NUL-framed -- the one byte that cannot occur inside a commit's text (git
    refuses it in a message and stops at it in a header) -- and the answer
    is checked against the question: exactly 5 fields per commit asked
    for, every sha one we asked for, none twice. Anything else is a
    RuntimeError, never a guess: a record that fails to parse would count
    as human. (The earlier \\x1e record separator is accepted by git in a
    body, a subject and an author name: it cut a Co-Authored-By trailer off
    a body, and dropped the whole record when it sat in the name.)
    """
    infos: dict[str, tuple[str, str, str, str]] = {}
    ordered = sorted(shas)
    # git's %x00 escape: a literal NUL cannot travel through argv.
    fmt = "--format=%H%x00%an%x00%ae%x00%s%x00%b%x00"
    for i in range(0, len(ordered), _SHOW_CHUNK):
        chunk = ordered[i:i + _SHOW_CHUNK]
        # "--": a file named like one of the shas must not make it ambiguous
        out = _git(root, "show", "-s", fmt, *chunk, "--")
        fields = out.split("\x00")
        # what follows the last NUL is only git's own line break
        if fields.pop().strip() or len(fields) != _SHOW_FIELDS * len(chunk):
            raise RuntimeError(_BAD_SHOW)
        for k in range(0, len(fields), _SHOW_FIELDS):
            sha, name, email, subject, body = fields[k:k + _SHOW_FIELDS]
            sha = sha.strip()
            if sha not in chunk or sha in infos:
                raise RuntimeError(_BAD_SHOW)
            body = body.replace("\r\n", "\n").rstrip("\n")
            infos[sha] = (name, email, subject, body)
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
    blame_options = _blame_options(root) if added else []
    for rel in added:
        bm = _blame_authors(root, head, rel, blame_options)
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
