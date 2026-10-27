"""Provenance: which added lines were written by an agent vs a human.

Method (deterministic, no LLM):
  0. The range starts at the MERGE-BASE of base and head, not at base's tip
     (see merge_base): whatever the base branch gained after the PR branched
     is not the PR's change.
  1. `git diff-tree -p -U0 -M base head` -> added lines per file (hunks)
     and how many lines each file lost.
  2. `git blame --porcelain <head> -- <file>` -> commit per added line.
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

A line that was REMOVED is a changed line like an added one, credited to the
commit that removed it: for every file that lost lines, the non-merge commits
of the range that touched it are listed (`git rev-list`), and each one that
is agent-authored is diffed against its parent for the lines it took out.
Only a line the base already had counts: `git blame` of the parent, limited
to the range, says whether each removed line was written inside it (see
_base_lines), and a line the PR added and then took out again, or a human's
new line an agent removes, is no removal at all. What the agent commits took
out of the base's lines, capped at what the range removes from the file in
all, is the agent's share; the rest is human. Two things keep it
approximate: a base line an agent removed and someone put back still counts
for the agent while the file lost other base lines (the cap is per file, not
per line), and a file renamed after the agent's commit hides it from the
per-commit diffs (those removals read as human).

A submodule is a commit id, not a file, so it has no lines to blame: its one
added line is the pointer (`Subproject commit <id>`) and goes to the last
commit of the range that moved it (see _pointer_authors).

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

import contextlib
import dataclasses
import os
import re
import subprocess
import time
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


def merge_base(root: str, base: str, head: str) -> str | None:
    """The commit where `head` left `base` (git merge-base), or None when
    the two share no history: unrelated histories, or a shallow clone that
    does not reach back to the fork point. base and head are commit ids or
    refs that do not start with '-'."""
    p = subprocess.run([*_GIT_BASE, "-C", root, "merge-base", base, head],
                       capture_output=True, timeout=60)
    sha = p.stdout.decode("ascii", "replace").strip()
    if p.returncode == 0 and re.fullmatch(r"[0-9a-f]{40,64}", sha):
        return sha
    if p.returncode == 1 and not p.stderr.strip():
        return None          # git's way to say "no common ancestor"
    err = p.stderr.decode("utf-8", "replace").strip()[:200]
    raise RuntimeError(f"git merge-base failed: {err}")


@dataclasses.dataclass
class FileProvenance:
    file: str
    added: int = 0
    agent_added: int = 0
    human_added: int = 0
    agents: set = dataclasses.field(default_factory=set)  # "author (marker)"
    deleted: bool = False
    deleted_by: list = dataclasses.field(default_factory=list)  # author names
    #: lines taken out of a file that is still there (a file that is gone is
    #: `deleted`, not this), and how many of those an agent's commit removed
    removed: int = 0
    agent_removed: int = 0
    #: the added lines (numbers at head) credited to an agent: what the
    #: test-integrity check looks at, so it only reports an agent's lines
    agent_lines: list = dataclasses.field(default_factory=list)
    #: blame was skipped (file cap or time budget): who wrote the added
    #: lines is not known, so none of them is counted as human or agent
    unverified: bool = False

    @property
    def changed(self) -> int:
        """Lines added plus lines removed."""
        return self.added + self.removed

    @property
    def agent_changed(self) -> int:
        return self.agent_added + self.agent_removed

    @property
    def agent_share(self) -> float:
        return self.agent_changed / self.changed if self.changed else 0.0

    def label(self) -> str:
        if self.deleted:
            return "deleted"
        if self.changed == 0:
            return "untouched"
        if self.agent_changed == self.changed:
            return "agent"
        if self.agent_changed == 0:
            return "human"
        return "mixed"


#: `@@ -a[,b] +c[,d] @@`: groups are a (first old line), b (old lines), c
#: (first new line), d (new lines); an omitted count means 1.
_DIFF_HUNK_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")
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


def _header_path(line: str, side: str = "b/") -> str | None:
    """Repo-relative path from a `+++ b/...` header (or, with side="a/", a
    `--- a/...` one), quoted or not, or None for `/dev/null`."""
    rest = line[4:].strip()
    rest = unquote_git_path(rest)
    if rest == "/dev/null":
        return None
    if rest.startswith(side):
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


@contextlib.contextmanager
def _plumbing_view(root: str):
    """A function that runs `git <args>` against root's objects with an empty
    work tree and no index (see _patch for why), for as many calls as the
    caller makes: the set-up is paid once."""
    # a directory name is bytes to the file system, not necessarily UTF-8
    gitdir = os.fsdecode(_git_bytes(root, "rev-parse",
                                    "--absolute-git-dir")).rstrip("\r\n")
    with tempfile.TemporaryDirectory(prefix="pr-verify-",
                                     ignore_cleanup_errors=True) as empty:
        env = dict(os.environ)
        env["GIT_INDEX_FILE"] = os.path.join(empty, "index")

        def run(*args: str) -> str:
            return _git(empty, "--git-dir", gitdir, "--work-tree", empty,
                        *args, env=env)
        yield run


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
    with _plumbing_view(root) as run:
        return run(*_PATCH, base, head, "--")


def _walk_patch(out: str) -> tuple[dict[str, list[int]],
                                   dict[str, list[int]], dict[str, str]]:
    """(file -> sorted added line numbers at head, file -> sorted numbers of
    the lines removed, in the OLD file, file -> its name in the old tree when
    that differs) of a patch. A file that is gone (`+++ /dev/null`) has no
    entry in any: whole-file deletions are reported as such."""
    result: dict[str, list[int]] = {}
    taken: dict[str, list[int]] = {}
    old_names: dict[str, str] = {}
    cur_file: str | None = None
    old_file: str | None = None
    new_line = old_line = 0
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
                if cur_file is not None:
                    taken.setdefault(cur_file, []).append(old_line)
                old_line += 1
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
                old_line += 1
                new_line += 1
                continue
            if mark == "\\":
                continue  # "\ No newline at end of file": on neither side
            old_left = new_left = 0  # hunk ended early: a header after all
        if line.startswith("diff --git "):
            old_file = None
        elif line.startswith("--- "):
            old_file = _header_path(line, "a/")
        elif line.startswith("+++ "):
            cur_file = _header_path(line)
            if cur_file is not None:
                result.setdefault(cur_file, [])
                if old_file is not None and old_file != cur_file:
                    old_names[cur_file] = old_file
        elif line.startswith("@@"):
            m = _DIFF_HUNK_RE.match(line)
            if m:
                old_line = int(m.group(1))
                old_left = 1 if m.group(2) is None else int(m.group(2))
                new_line = int(m.group(3))
                new_left = 1 if m.group(4) is None else int(m.group(4))
    return ({f: sorted(ls) for f, ls in result.items() if ls},
            {f: ns for f, ns in taken.items() if ns}, old_names)


def _scan_patch(out: str) -> tuple[dict[str, list[int]], dict[str, int]]:
    """(file -> sorted added line numbers at head, file -> number of lines
    removed) of a patch (see _walk_patch)."""
    added, taken, _ = _walk_patch(out)
    return added, {f: len(ns) for f, ns in taken.items()}


def added_lines(root: str, base: str, head: str = "HEAD") -> dict[str, list[int]]:
    """Repo-relative file -> sorted list of added line numbers (at head)."""
    return _scan_patch(_patch(root, base, head))[0]


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


#: characters of pathspecs per `git rev-list` call: well under Windows'
#: 8191-character command line, however long the paths are
_PATHSPEC_BUDGET = 4000


def _commits_touching(root: str, base: str, head: str,
                      paths: list[str]) -> list[tuple[str, str | None]]:
    """(commit, its parent or None) for the non-merge commits in base..head
    that changed any of `paths`, sorted by id.

    `:(literal)` keeps a file called `a[1].py` or `:x` what it is, and
    `--full-history` keeps the default history simplification from skipping
    a side branch whose merge happens to equal one of its parents. The
    parent is the commit's own, from `%P`: with `--parents` git shows the
    parent as the history of `paths` sees it (the nearest commit that
    touched them), so the diff to it would hold other commits' changes, and
    it differs from one batch of paths to the next."""
    found: dict[str, str | None] = {}
    chunk: list[str] = []
    size = 0
    batches = []
    for rel in paths:
        spec = ":(literal)" + rel
        if chunk and size + len(spec) > _PATHSPEC_BUDGET:
            batches.append(chunk)
            chunk, size = [], 0
        chunk.append(spec)
        size += len(spec) + 1
    if chunk:
        batches.append(chunk)
    for specs in batches:
        out = _git(root, "rev-list", "--no-merges", "--full-history",
                   "--format=%P", f"{base}..{head}", "--", *specs)
        sha = None
        for line in out.split("\n"):
            if line.startswith("commit "):      # then a line of parents ...
                sha = line[len("commit "):].strip()
                found[sha] = None               # ... unless it has none
            elif sha is not None:
                parents = line.split()
                if parents:
                    found[sha] = parents[0]
                sha = None
    return sorted(found.items())


#: Whether the installed git takes `blame --no-ignore-revs-file`; None until
#: _git_takes_no_ignore_revs_file() has asked.
_NO_IGNORE_REVS: bool | None = None


def _git_takes_no_ignore_revs_file() -> bool:
    """Whether `git blame` has the negated --no-ignore-revs-file, which
    `git blame -h` lists as --[no-]ignore-revs-file. Found out once: it is
    the same git for every call of the run."""
    global _NO_IGNORE_REVS
    if _NO_IGNORE_REVS is None:
        try:
            p = subprocess.run([*_GIT_BASE, "blame", "-h"],
                               capture_output=True, timeout=15)
            usage = p.stdout + p.stderr       # either one, by git version
        except (OSError, subprocess.SubprocessError):
            usage = b""
        _NO_IGNORE_REVS = b"--[no-]ignore-revs-file" in usage
    return _NO_IGNORE_REVS


def _blame_options(root: str) -> list[str]:
    """Extra `git blame` options. blame.ignoreRevsFile (a setting for
    skipping formatting commits) makes blame look past the commits a file
    lists, and the file is in the PR: it could list the agent's commits, and
    their lines would read as the older, human ones.

    --no-ignore-revs-file drops the configured list before git opens any
    file in it. The empty --ignore-revs-file= (all that older gits have)
    clears it only after git has tried them, so a setting that names a file
    which is not there (copied from another machine) stops every blame with
    "could not open object name list". Only when the setting exists, so a
    git older than 2.23 (which has neither) is not asked for it."""
    p = subprocess.run([*_GIT_BASE, "-C", root, "config", "--get-all",
                        "blame.ignoreRevsFile"], capture_output=True,
                       timeout=15)
    if p.returncode != 0:
        return []
    if _git_takes_no_ignore_revs_file():
        return ["--no-ignore-revs-file"]
    return ["--ignore-revs-file="]


def _is_gitlink(root: str, head: str, rel: str) -> bool:
    """Is rel a submodule at head (tree entry mode 160000)?"""
    return _git_bytes(root, "ls-tree", "-z", head, "--",
                      rel).startswith(b"160000 ")


def _pointer_authors(root: str, base: str, head: str, rel: str,
                     linenos: list[int]) -> dict[int, str]:
    """Line number -> commit for the added lines of a submodule: its pointer.
    The commit that last moved it in base..head wrote it (`git blame` cannot
    say: there is no file to blame)."""
    shas = _git(root, "rev-list", "-1", "--full-history", f"{base}..{head}",
                "--", ":(literal)" + rel).split()
    if not shas:
        raise RuntimeError(f"no commit in {base}..{head} moved the submodule "
                           f"{rel}; refusing to guess who did")
    return {ln: shas[0] for ln in linenos}


def _parse_blame(out: str) -> tuple[dict[int, str], set[str]]:
    """(line number -> commit sha, the shas git marks `boundary`) of `git
    blame --porcelain` output. A boundary commit is one outside the range
    blame was given (`^base head`): a line blamed on it is older than the
    range. Every file line comes tab-prefixed, so no line of the file can
    pass for one of git's own."""
    authors: dict[int, str] = {}
    boundary: set[str] = set()
    sha = ""
    lineno = 0
    for line in out.split("\n"):
        if re.match(r"^[0-9a-f]{40} \d+ \d+ \d+$", line):
            parts = line.split()
            sha, lineno = parts[0], int(parts[2])
        elif line.startswith("\t"):
            authors[lineno] = sha
            lineno += 1  # each content line advances within the hunk
        elif line == "boundary":
            boundary.add(sha)
    return authors, boundary


def _blame_authors(root: str, head: str, rel: str,
                   options: list[str] | tuple = ()) -> dict[int, str]:
    """Line number -> commit sha, for <head> version of file."""
    out = _git(root, "blame", "--porcelain", *options, head, "--", rel)
    return _parse_blame(out)[0]


#: characters of `-L` options per `git blame` call, well under Windows'
#: 8191-character command line. A commit that took lines out of so many
#: places that the ranges do not fit has the whole file blamed instead.
_BLAME_BUDGET = 4000


def _runs(numbers: list[int]) -> list[tuple[int, int]]:
    """Line numbers as (first, last) runs of consecutive lines."""
    runs: list[list[int]] = []
    for n in sorted(numbers):
        if runs and n == runs[-1][1] + 1:
            runs[-1][1] = n
        else:
            runs.append([n, n])
    return [(first, last) for first, last in runs]


def _base_lines(root: str, base: str, parent: str, rel: str,
                numbers: list[int], options: list[str]) -> int:
    """How many of the lines `numbers` of `rel` as it was at `parent` were
    already in the file at `base`, and not written by a commit of the range
    base..parent. `git blame ^base parent` says: it names the commit that
    wrote each line, and marks the ones outside the range as the boundary.
    Blame follows the file through renames (`rel` is its name at `parent`)
    and sees merges for what they are.

    A submodule has one line, its pointer: the base's unless a commit of the
    range moved it. Nothing between the base and the commit (`parent` is
    `base`) needs no question: every line is the base's."""
    if parent == base:
        return len(numbers)
    if _is_gitlink(root, parent, rel):
        moved = _git(root, "rev-list", "-1", "--full-history",
                     f"{base}..{parent}", "--", ":(literal)" + rel).split()
        return 0 if moved else len(numbers)
    ranges = [f"-L{first},{last}" for first, last in _runs(numbers)]
    if sum(len(r) + 1 for r in ranges) > _BLAME_BUDGET:
        ranges = []
    out = _git(root, "blame", "--porcelain", *options, *ranges, f"^{base}",
               parent, "--", rel)
    wrote, boundary = _parse_blame(out)
    found = 0
    for line in sorted(set(numbers)):
        if line not in wrote:
            raise RuntimeError(f"git blame did not name the commit of line "
                               f"{line} of {rel} at {parent[:12]}; refusing "
                               f"to guess who wrote it")
        if wrote[line] in boundary:
            found += 1
    return found


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


#: patchable clock for the blame time budget (tests never wait)
_monotonic = time.monotonic
#: defaults of the blame budget: files blamed and seconds spent
DEFAULT_MAX_BLAME_FILES = 1000
DEFAULT_BLAME_BUDGET = 300.0


def analyze(root: str, base: str, head: str = "HEAD",
            agent_markers: list[str] | None = None,
            pr_signal: str | None = None,
            trailer_keys: dict[str, str] | None = None,
            max_blame_files: int | None = DEFAULT_MAX_BLAME_FILES,
            blame_budget: float | None = DEFAULT_BLAME_BUDGET
            ) -> dict[str, FileProvenance]:
    """Who wrote what between base and head.

    `pr_signal` is the label of an agent signal from the pull request itself
    (prinfo.signal_marker: `branch:claude/fix`): when given, every commit of
    the range counts as an agent's, credited to that signal unless a marker
    matched the commit already. `trailer_keys` are the trailer keys that name
    an agent by themselves (markers.parse_trailer_keys)."""
    agent_markers = [str(m).lower() for m in (agent_markers or [])]
    added, removed = _scan_patch(_patch(root, base, head))
    added = {rel: lines for rel, lines in added.items() if rel != CONFIG_FILE}
    removed = {rel: n for rel, n in removed.items() if rel != CONFIG_FILE}
    deleted = [rel for rel in deleted_files(root, base, head)
               if rel != CONFIG_FILE]
    result: dict[str, FileProvenance] = {}
    # Batch: collect all shas first, then one `git show` for all of them.
    blame_maps: dict[str, dict[int, str]] = {}
    del_shas: dict[str, list[str]] = {}
    all_shas: set[str] = set()
    blame_options = _blame_options(root) if added or removed else []
    unverified: set[str] = set()
    started = _monotonic()
    for n, rel in enumerate(sorted(added)):
        # A huge PR degrades to "unverified" instead of hanging the job.
        if ((max_blame_files and n >= max_blame_files)
                or (blame_budget and _monotonic() - started > blame_budget)):
            unverified.add(rel)
            continue
        try:
            bm = _blame_authors(root, head, rel, blame_options)
        except RuntimeError:
            if not _is_gitlink(root, head, rel):
                raise
            bm = _pointer_authors(root, base, head, rel, added[rel])
        blame_maps[rel] = bm
        all_shas.update(bm[ln] for ln in added[rel] if ln in bm)
    for rel in deleted:
        shas = _deletion_commits(root, base, head, rel)
        del_shas[rel] = shas
        all_shas.update(shas)
    # who took the lines out: the commits of the range that touched them
    removers = (_commits_touching(root, base, head, sorted(removed))
                if removed else [])
    all_shas.update(sha for sha, _ in removers)
    texts = _commit_text(root, all_shas)
    matched: dict[str, str] = {}   # sha -> marker that identified it
    for sha, (name, email, subject, body) in texts.items():
        hit = markers_mod.match(name, email, subject, body, agent_markers,
                                trailer_keys)
        if hit:
            matched[sha] = hit
        elif pr_signal:
            matched[sha] = pr_signal
    # file -> {agent commit: base lines it removed from the file}
    agent_removals: dict[str, dict[str, int]] = {}
    agent_removers = [(sha, parent) for sha, parent in removers
                      if sha in matched and parent]
    if agent_removers:
        with _plumbing_view(root) as run:
            for sha, parent in agent_removers:
                _, taken, old_names = _walk_patch(
                    run(*_PATCH, parent, sha, "--"))
                for rel, numbers in taken.items():
                    if rel not in removed:
                        continue
                    n = _base_lines(root, base, parent,
                                    old_names.get(rel, rel), numbers,
                                    blame_options)
                    if n:
                        agent_removals.setdefault(rel, {})[sha] = n

    def who(sha: str) -> str:
        return texts.get(sha, (sha[:7], "", "", ""))[0] or sha[:7]

    for rel in sorted(set(added) | set(removed)):
        fp = FileProvenance(file=rel)
        bm = blame_maps.get(rel, {})
        if rel in unverified:
            fp.unverified = True
            fp.added = len(added[rel])
        for ln in ([] if rel in unverified else added.get(rel, [])):
            fp.added += 1
            sha = bm.get(ln)
            if sha in matched:
                fp.agent_added += 1
                fp.agent_lines.append(ln)
                fp.agents.add(agent_label(who(sha), matched[sha]))
            else:
                fp.human_added += 1
        fp.removed = removed.get(rel, 0)
        by_agent = agent_removals.get(rel, {})
        fp.agent_removed = min(fp.removed, sum(by_agent.values()))
        if fp.agent_removed:
            for sha in sorted(by_agent):
                fp.agents.add(agent_label(who(sha), matched[sha]))
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
