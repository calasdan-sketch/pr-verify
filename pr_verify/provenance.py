"""Provenance: which added lines were written by an agent vs a human.

Method (deterministic, no LLM):
  1. `git diff -U0 base..head` -> added lines per file (hunks).
  2. `git blame --porcelain <head> -- <file>` -> commit per line.
  3. `git log` for those commits -> author name/email + subject/body.
  4. A commit is agent-authored if any agent_marker substring appears in
     the author name, author email, subject, or body (case-insensitive).

Deleted files are reported too: `git diff --diff-filter=D` finds them and
`git log --diff-filter=D` identifies the deleting commit(s), so a deletion
can never slip through as "nothing to verify". For a deleted file the
blast-radius scan matches the file's module names against the imports of
the files still in the worktree.

snapshot_worktree() commits the current index+worktree (including
untracked files) to a synthetic, ref-less commit so `check` also sees
uncommitted changes. Uncommitted lines are attributed to a neutral
"pr-verify (worktree)" identity — i.e. counted as human, never as agent —
because there is no commit authorship to analyze.
"""

from __future__ import annotations

import dataclasses
import os
import re
import subprocess
import tempfile


def _git(root: str, *args: str, env: dict | None = None) -> str:
    p = subprocess.run(["git", "-C", root, *args], capture_output=True,
                       text=True, encoding="utf-8", errors="replace",
                       timeout=60, env=env)
    if p.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)} failed: {p.stderr.strip()[:200]}")
    return p.stdout


def snapshot_worktree(root: str) -> str | None:
    """Synthetic commit of index+worktree (untracked included).

    Returns the new commit sha, or None when there is nothing to snapshot
    (no HEAD yet, or any git plumbing failure — callers fall back to the
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
    try:
        for args in (["read-tree", "HEAD"], ["add", "-A"]):
            p = subprocess.run(["git", "-C", root, *args], env=env,
                               capture_output=True, timeout=60)
            if p.returncode != 0:
                return None
        p = subprocess.run(["git", "-C", root, "write-tree"], env=env,
                           capture_output=True, text=True, encoding="utf-8",
                           errors="replace", timeout=60)
        if p.returncode != 0:
            return None
        tree = p.stdout.strip()
        p = subprocess.run(
            ["git", "-C", root, "commit-tree", tree,
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
    agents: set = dataclasses.field(default_factory=set)  # author names
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


def added_lines(root: str, base: str, head: str = "HEAD") -> dict[str, list[int]]:
    """Repo-relative file -> sorted list of added line numbers (at head)."""
    out = _git(root, "diff", "-U0", f"{base}..{head}", "--")
    result: dict[str, list[int]] = {}
    cur_file: str | None = None
    new_line = 0
    for line in out.splitlines():
        if line.startswith("+++ b/"):
            cur_file = line[6:]
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
    return sorted(p for p in out.splitlines() if p)


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


def _commit_text(root: str, shas: set[str]) -> dict[str, tuple[str, str]]:
    """sha -> (author name, 'name email subject body' lowercased)."""
    infos: dict[str, tuple[str, str]] = {}
    for sha in shas:
        out = _git(root, "log", "-1", "--format=%an%x00%ae%x00%s%x00%b", sha)
        parts = out.split("\x00")
        name = parts[0] if parts else sha[:7]
        infos[sha] = (name, " ".join(parts).lower())
    return infos


def analyze(root: str, base: str, head: str = "HEAD",
            agent_markers: list[str] | None = None) -> dict[str, FileProvenance]:
    agent_markers = [m.lower() for m in (agent_markers or [])]
    added = added_lines(root, base, head)
    deleted = deleted_files(root, base, head)
    result: dict[str, FileProvenance] = {}
    # Batch: collect all shas first, then one log per sha.
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
    agent_shas = {s for s, (_name, t) in texts.items()
                  if any(m in t for m in agent_markers)}

    for rel, linenos in added.items():
        fp = FileProvenance(file=rel)
        bm = blame_maps[rel]
        for ln in linenos:
            fp.added += 1
            sha = bm.get(ln)
            if sha in agent_shas:
                fp.agent_added += 1
                fp.agents.add(texts[sha][0] or sha[:7])
            else:
                fp.human_added += 1
        result[rel] = fp
    for rel in deleted:
        fp = FileProvenance(file=rel, deleted=True)
        for sha in del_shas[rel]:
            name = texts.get(sha, (sha[:7], ""))[0] or sha[:7]
            fp.deleted_by.append(name)
            if sha in agent_shas:
                fp.agents.add(name)
        result[rel] = fp
    return result
