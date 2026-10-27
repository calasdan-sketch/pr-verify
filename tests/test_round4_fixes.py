"""Panel round 4: regression tests, one class per finding.

R4-1  `--root` from a subdirectory of the repository: paths, blame,
      snapshot, blast radius and gates were computed relative to the
      current directory instead of the repository top level.
R4-2  The "(not in the worktree ...)" label was printed for files that
      are in the worktree (README.md, vendor/x.py ...).
R4-3  miniyaml single-quote escape (`''`): tests live in test_miniyaml.py.
R4-4  Text the PR author controls must not shape the parse of git's
      output: a \\x1e in a commit body, subject or author name cut a
      trailer off or dropped the record (an agent commit read as human);
      a line break git does not honour (\\x0b ... \\u2029, a lone \\r) in a
      file line forged a blame header or a diff file header; a file line
      like `++ /dev/null` did the same with no special character at all.
R4-5  pyproject metadata (SPDX licence, classifiers, URLs).
R4-6  BrokenPipeError (`pr-verify ... | head -1`) must exit quietly and
      keep the verdict.
R4-7  The diff must be read as it is: `binary` or `-diff` in the PR's
      .gitattributes hid source files from the verifier, and a user's git
      settings (color.ui, diff.external, diff.noprefix, diff.interHunkContext
      ...) changed the patch it parses; blame.ignoreRevsFile, a file in the
      PR, could turn agent lines into older, human ones.
R4-8  A closed output pipe is not a BrokenPipeError on Windows: print()
      succeeds, flush() raises OSError(EINVAL), and what was left in the
      buffer failed again at exit (status 120). Also for --help/--version
      and for error messages on stderr.
R4-9  `--format json` with nothing to verify printed a sentence, not JSON.
R4-10 Text the PR's author controls (file names, author names ...) reached
      the terminal with its control characters: an escape sequence, a
      carriage return, a newline that starts a forged report (or GitHub
      Actions workflow-command) line.
R4-11 No invisible or bidirectional-control character in the repository's
      own files.
"""

import ast
import contextlib
import errno
import io
import json
import os
import re
import shlex
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

from pr_verify import action as action_mod
from pr_verify import blastradius as br
from pr_verify import cli as cli_mod
from pr_verify import markers as markers_mod
from pr_verify import provenance as pv

from fixture import (FAIL_GATE, PY, commit_as, commit_at_new_base, git,
                     make_deletion_repo, make_pr_repo, yaml_str)

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _read(name: str) -> str:
    with open(os.path.join(REPO, name), encoding="utf-8") as f:
        return f.read()


# ---------------------------------------------------------------------
# R4-1

@contextlib.contextmanager
def chdir(path):
    old = os.getcwd()
    os.chdir(path)
    try:
        yield
    finally:
        os.chdir(old)


def _main(*argv, cwd=None) -> tuple[int, str, str]:
    """cli.main(argv) -> (exit code, stdout, stderr), optionally with the
    current directory set to cwd (`--root` left to its default)."""
    out, err = io.StringIO(), io.StringIO()
    with contextlib.ExitStack() as stack:
        if cwd:
            stack.enter_context(chdir(cwd))
        stack.enter_context(redirect_stdout(out))
        stack.enter_context(redirect_stderr(err))
        code = cli_mod.main(list(argv))
    return code, out.getvalue(), err.getvalue()


def _json(*argv, cwd=None) -> tuple[int, dict]:
    code, out, err = _main(*argv, "--format", "json", cwd=cwd)
    return code, json.loads(out)


def _same_dir(a: str, b: str) -> bool:
    return os.path.samefile(a, b)


class TestRunFromSubdirectory(unittest.TestCase):
    """Everything is computed from the repository top level, whichever
    directory pr-verify is started in or `--root` points at."""

    #: the parts of the document that must not depend on where we started
    KEYS = ("base", "min_score", "risk", "files", "blast_radius", "gates",
            "untracked_skipped")

    def _same_as_top_level(self, data, top):
        for key in self.KEYS:
            self.assertEqual(data[key], top[key], key)

    def test_current_directory_in_a_subdirectory(self):
        tmp, base = make_pr_repo()
        code, top = _json("--root", tmp, "check", "--base", base,
                          "--skip-gates")
        self.assertEqual(top["risk"]["score"], 57)
        for sub in ("app", "tests"):
            c, data = _json("check", "--base", base, "--skip-gates",
                            cwd=os.path.join(tmp, sub))
            self.assertEqual(c, code, sub)
            self._same_as_top_level(data, top)

    def test_explicit_root_that_is_a_subdirectory(self):
        # decision: --root names a path INSIDE the repository, like
        # `git -C <path>`; the whole repository is verified from its top
        tmp, base = make_pr_repo()
        code, top = _json("--root", tmp, "check", "--base", base,
                          "--skip-gates")
        sub = os.path.join(tmp, "app")
        c, data = _json("--root", sub, "check", "--base", base,
                        "--skip-gates")
        self.assertEqual(c, code)
        self._same_as_top_level(data, top)
        self.assertIn("app/auth.py", data["files"])
        self.assertNotIn("auth.py", data["files"])

    def test_relative_root_and_dotdot(self):
        tmp, base = make_pr_repo()
        code, top = _json("--root", tmp, "check", "--base", base,
                          "--skip-gates")
        c, data = _json("--root", "..", "check", "--base", base,
                        "--skip-gates", cwd=os.path.join(tmp, "app"))
        self.assertEqual(c, code)
        self._same_as_top_level(data, top)
        c, data = _json("--root", ".", "check", "--base", base,
                        "--skip-gates", cwd=os.path.join(tmp, "app"))
        self._same_as_top_level(data, top)

    def test_deletion_is_still_attributed(self):
        # silent wrong answer before the fix: `git log -- app/util.py` run
        # from app/ matched nothing, so the deletion was "by unknown" and
        # the deletion factor (10 pts) vanished: score 23 -> 9
        tmp, base = make_deletion_repo()
        code, top = _json("--root", tmp, "check", "--base", base,
                          "--skip-gates")
        c, data = _json("check", "--base", base, "--skip-gates",
                        cwd=os.path.join(tmp, "app"))
        self.assertEqual(data["files"]["app/util.py"]["deleted_by"],
                         ["claude-bot"])
        self.assertEqual(data["blast_radius"]["app/util.py"]["direct"],
                         ["app/main.py"])
        self.assertEqual(data["risk"]["score"], top["risk"]["score"])
        self.assertEqual(c, code)
        self._same_as_top_level(data, top)

    def test_uncommitted_and_untracked_files_seen_from_a_subdirectory(self):
        tmp, base = make_pr_repo()
        with open(os.path.join(tmp, "app", "core.py"), "a",
                  encoding="utf-8", newline="\n") as f:
            f.write("\n\ndef dirty_wip(x):\n    return x\n")
        # untracked, and outside the directory we start in
        with open(os.path.join(tmp, "tests", "scratch.py"), "w",
                  encoding="utf-8", newline="\n") as f:
            f.write("x = 1\n")
        code, top = _json("--root", tmp, "check", "--base", base,
                          "--skip-gates")
        self.assertEqual(top["files"]["app/core.py"]["added"], 12)
        self.assertEqual(top["untracked_skipped"], ["tests/scratch.py"])
        c, data = _json("check", "--base", base, "--skip-gates",
                        cwd=os.path.join(tmp, "app"))
        self._same_as_top_level(data, top)
        c, data = _json("check", "--base", base, "--skip-gates",
                        "--include-untracked", cwd=os.path.join(tmp, "app"))
        self.assertIn("tests/scratch.py", data["files"])

    def test_gates_run_in_the_top_level(self):
        tmp, old_base = make_pr_repo()
        rec = os.path.join(tempfile.mkdtemp(), "cwd.txt")
        code_ = ("import os, sys; "
                 "open(sys.argv[1], 'w', encoding='utf-8').write(os.getcwd())")
        base = commit_at_new_base(tmp, old_base, {".pr-verify.yaml": (
            "gates:\n"
            f"  - [{yaml_str(PY)}, \"-c\", {yaml_str(code_)}, "
            f"{yaml_str(rec)}]\n")})
        _json("check", "--base", base, cwd=os.path.join(tmp, "app"))
        with open(rec, encoding="utf-8") as f:
            self.assertTrue(_same_dir(f.read(), tmp))

    def test_config_notes_still_work_from_a_subdirectory(self):
        tmp, old_base = make_pr_repo()
        base = commit_at_new_base(tmp, old_base,
                                  {".pr-verify.yaml": "risk_threshold: 80\n"})
        with open(os.path.join(tmp, ".pr-verify.yaml"), "w",
                  encoding="utf-8") as f:
            f.write("risk_threshold: 10\n")
        c, data = _json("check", "--base", base, "--skip-gates",
                        cwd=os.path.join(tmp, "app"))
        self.assertEqual(data["min_score"], 80)     # the base copy rules
        self.assertTrue(any("differs from" in n for n in data["notes"]),
                        data["notes"])

    def test_report_says_which_repository_was_used(self):
        tmp, base = make_pr_repo()
        _, top = _json("--root", tmp, "check", "--base", base,
                       "--skip-gates")
        self.assertFalse([n for n in top["notes"] if "inside the repository" in n])
        _, data = _json("check", "--base", base, "--skip-gates",
                        cwd=os.path.join(tmp, "app"))
        notes = [n for n in data["notes"] if "inside the repository" in n]
        self.assertEqual(len(notes), 1, data["notes"])
        self.assertIn("the whole repository is verified", notes[0])
        code, out, _ = _main("check", "--base", base, "--skip-gates",
                             cwd=os.path.join(tmp, "app"))
        self.assertIn("note: ", out)
        self.assertIn("inside the repository at", out)

    def test_init_writes_the_config_at_the_top_level(self):
        # the config is read from the base ref's TOP LEVEL; a copy in a
        # subdirectory would never take effect
        tmp, base = make_pr_repo()
        code, out, _ = _main("init", cwd=os.path.join(tmp, "app"))
        self.assertEqual(code, 0)
        self.assertTrue(os.path.isfile(os.path.join(tmp, ".pr-verify.yaml")))
        self.assertFalse(os.path.exists(
            os.path.join(tmp, "app", ".pr-verify.yaml")))
        self.assertIn("repository root", out)
        code, out, _ = _main("--root", os.path.join(tmp, "tests"), "init")
        self.assertEqual(code, 2)          # exists at the top level already
        self.assertFalse(os.path.exists(
            os.path.join(tmp, "tests", ".pr-verify.yaml")))

    def test_outside_a_repository_is_still_a_clean_error(self):
        tmp = tempfile.mkdtemp()
        # _ensure_repo exits via SystemExit(2) with a one-line message
        for kwargs, argv in (({"cwd": tmp}, ("check",)),
                             ({}, ("--root", tmp, "check"))):
            err = io.StringIO()
            with contextlib.ExitStack() as stack:
                if "cwd" in kwargs:
                    stack.enter_context(chdir(kwargs["cwd"]))
                stack.enter_context(redirect_stderr(err))
                with self.assertRaises(SystemExit) as cm:
                    cli_mod.main(list(argv))
            self.assertEqual(cm.exception.code, 2)
            self.assertEqual(err.getvalue().strip(), "error: not a git repo")

    def test_init_outside_a_repository_still_writes_in_place(self):
        tmp = tempfile.mkdtemp()
        code, out, _ = _main("init", cwd=tmp)
        self.assertEqual(code, 0)
        self.assertTrue(os.path.isfile(os.path.join(tmp, ".pr-verify.yaml")))

    def test_bare_repository_keeps_working(self):
        # no work tree, so no top level to resolve to: the path is used as is
        tmp, base = make_pr_repo()
        bare = os.path.join(tempfile.mkdtemp(), "bare.git")
        git(tmp, "clone", "-q", "--bare", tmp, bare)
        self.assertEqual(cli_mod.repo_root(bare), bare)
        code, data = _json("--root", bare, "check", "--base", base,
                           "--skip-gates")
        self.assertIn(code, (0, 1))
        self.assertEqual(data["files"]["app/auth.py"]["label"], "agent")

    def test_repo_root_resolution(self):
        tmp, base = make_pr_repo()
        self.assertTrue(_same_dir(cli_mod.repo_root(tmp), tmp))
        self.assertTrue(_same_dir(cli_mod.repo_root(os.path.join(tmp, "app")),
                                  tmp))
        # a path that is not in a repository comes back unchanged
        plain = tempfile.mkdtemp()
        self.assertEqual(cli_mod.repo_root(plain), plain)

    def test_real_process_started_in_a_subdirectory(self):
        tmp, base = make_pr_repo()
        env = dict(os.environ)
        env["PYTHONPATH"] = os.pathsep.join(
            p for p in (REPO, env.get("PYTHONPATH")) if p)
        p = subprocess.run(
            [sys.executable, "-m", "pr_verify", "check", "--base", base,
             "--skip-gates", "--format", "json"],
            cwd=os.path.join(tmp, "app"), env=env, capture_output=True,
            text=True, encoding="utf-8", timeout=120)
        self.assertEqual(p.returncode, 0, p.stderr)
        data = json.loads(p.stdout)
        self.assertEqual(data["risk"]["score"], 57)
        self.assertIn("app/core.py", data["blast_radius"])
        self.assertEqual(data["blast_radius"]["app/core.py"]["direct"],
                         ["app/views.py"])


# ---------------------------------------------------------------------
# R4-2

def _sha(tmp: str, rev: str = "HEAD") -> str:
    return subprocess.run(["git", "-C", tmp, "rev-parse", rev],
                          capture_output=True, text=True, encoding="utf-8",
                          check=True).stdout.strip()


def _write(tmp: str, files: dict[str, str]) -> None:
    for rel, content in files.items():
        p = os.path.join(tmp, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w", encoding="utf-8", newline="\n") as f:
            f.write(content)


def make_label_repo() -> tuple[str, str]:
    """Returns (tmp, base_sha). One agent commit then touches eight files
    the blast-radius scan treats differently:

      README.md, config.yaml   in the worktree, not a source type
      trace.log                in the worktree, not a source type, tracked
                               although *.log is git-ignored
      vendor/lib.py            in the worktree, a skipped directory
      app/core.py              in the import graph (app/user.py imports it)
      app/old_helper.py        deleted, still imported by app/user.py
      app/dead.py              deleted, imported by nobody
      docs/notes.md            deleted, not a source type
    """
    tmp = tempfile.mkdtemp()
    git(tmp, "init", "-qb", "main")
    commit_as(tmp, "Dan Calas", "dan@example.com", "base", {
        ".gitignore": "*.log\n",
        "README.md": "# hi\n",
        "config.yaml": "a: 1\n",
        "vendor/lib.py": "def v():\n    return 1\n",
        "app/core.py": "def calc(x):\n    return x\n",
        "app/user.py": "from app.core import calc\n"
                       "from app.old_helper import h\n",
        "app/old_helper.py": "def h():\n    return 2\n",
        "app/dead.py": "def dead():\n    return 0\n",
        "docs/notes.md": "notes\n",
    })
    base = _sha(tmp)
    for rel in ("app/old_helper.py", "app/dead.py", "docs/notes.md"):
        os.remove(os.path.join(tmp, rel))
    _write(tmp, {
        "README.md": "# hi\nmore\n",
        "config.yaml": "a: 1\nb: 2\n",
        "vendor/lib.py": "def v():\n    return 1\n\n\ndef v2():\n    return 2\n",
        "app/core.py": "def calc(x):\n    return x\n\n\ndef c2():\n    return 2\n",
        "trace.log": "log line\n",
    })
    git(tmp, "add", "-A")
    git(tmp, "add", "-f", "trace.log")
    git(tmp, "-c", "user.name=claude-bot", "-c", "user.email=cb@example.com",
        "commit", "-qm", "big change\n\nCo-Authored-By: Claude")
    return tmp, base


def _blast_lines(out: str) -> dict[str, str]:
    """file -> its whole line in the report's blast-radius section."""
    section = out.split("blast radius:")[1].split("gates:")[0]
    lines = {}
    for ln in section.splitlines():
        s = ln.strip()
        if ": " in s and "downstream dependent(s)" in s:
            lines[s.split(": ", 1)[0]] = s
    return lines


class TestWorktreeLabel(unittest.TestCase):
    """"(not in the worktree ...)" was printed for every changed file the
    import graph did not contain - including files that are in the
    worktree. Each label now says what is true of that file."""

    def setUp(self):
        self.tmp, self.base = make_label_repo()
        _, self.data = _json("--root", self.tmp, "check", "--base",
                             self.base, "--skip-gates")
        _, self.out, _ = _main("--root", self.tmp, "check", "--base",
                               self.base, "--skip-gates")
        self.lines = _blast_lines(self.out)
        self.radius = self.data["blast_radius"]

    def test_scan_code_per_file(self):
        scan = {rel: b["scan"] for rel, b in self.radius.items()}
        self.assertEqual(scan, {
            "README.md": "not_source", "config.yaml": "not_source",
            "trace.log": "not_source", "docs/notes.md": "not_source",
            "vendor/lib.py": "skipped_dir",
            "app/core.py": "graph",
            "app/old_helper.py": "not_in_worktree",
            "app/dead.py": "not_in_worktree"})

    def test_files_that_exist_are_not_called_missing(self):
        for rel in ("README.md", "config.yaml", "trace.log", "vendor/lib.py"):
            self.assertTrue(os.path.exists(os.path.join(self.tmp, rel)), rel)
            self.assertNotIn("not in the worktree", self.lines[rel], rel)

    def test_non_source_file_says_imports_are_not_scanned(self):
        self.assertTrue(self.lines["README.md"].endswith(
            "(.md files are not scanned for imports)"), self.lines["README.md"])
        self.assertIn(".yaml files are not scanned for imports",
                      self.lines["config.yaml"])
        self.assertIn(".log files are not scanned for imports",
                      self.lines["trace.log"])

    def test_skipped_directory_is_named(self):
        self.assertTrue(self.lines["vendor/lib.py"].endswith(
            "(in vendor/, which the import scan skips; "
            "nothing in-repo imports it)"), self.lines["vendor/lib.py"])

    def test_deleted_source_file_nobody_imports_is_not_in_the_worktree(self):
        self.assertFalse(os.path.exists(os.path.join(self.tmp, "app/dead.py")))
        self.assertTrue(self.lines["app/dead.py"].endswith(
            "(not in the worktree; nothing in-repo imports it)"))
        self.assertTrue(self.radius["app/dead.py"]["external_only"])

    def test_deleted_non_source_file_does_not_claim_imports(self):
        self.assertFalse(os.path.exists(os.path.join(self.tmp, "docs/notes.md")))
        self.assertTrue(self.lines["docs/notes.md"].endswith(
            "(.md files are not scanned for imports)"))

    def test_files_with_dependents_or_in_the_graph_need_no_label(self):
        self.assertTrue(self.lines["app/core.py"].endswith(
            "1 downstream dependent(s)"), self.lines["app/core.py"])
        self.assertTrue(self.lines["app/old_helper.py"].endswith(
            "1 downstream dependent(s)"), self.lines["app/old_helper.py"])
        self.assertEqual(self.radius["app/core.py"]["direct"], ["app/user.py"])
        # deleted but still imported: its dependents are still found
        self.assertEqual(self.radius["app/old_helper.py"]["direct"],
                         ["app/user.py"])
        self.assertFalse(self.radius["app/old_helper.py"]["external_only"])

    def test_file_type_without_extension(self):
        radii = br.analyze(self.tmp, ["Makefile", "LICENSE"])
        self.assertEqual(radii["Makefile"].scan, "not_source")

    def test_scan_codes_straight_from_analyze(self):
        tmp = tempfile.mkdtemp()
        _write(tmp, {"a.py": "import b\n", "b.py": "x = 1\n", "doc.md": "hi\n",
                     "node_modules/pkg/index.js": "x\n",
                     "deep/vendor/x.py": "x = 1\n"})
        radii = br.analyze(tmp, ["b.py", "doc.md", "node_modules/pkg/index.js",
                                 "deep/vendor/x.py", "gone.py", "gone.md"])
        self.assertEqual({k: v.scan for k, v in radii.items()}, {
            "b.py": "graph", "doc.md": "not_source",
            "node_modules/pkg/index.js": "skipped_dir",
            "deep/vendor/x.py": "skipped_dir",
            "gone.py": "not_in_worktree", "gone.md": "not_source"})
        self.assertEqual(br.skipped_dir("deep/vendor/x.py"), "vendor")
        self.assertIsNone(br.skipped_dir("app/x.py"))

    def test_a_vendored_file_that_is_imported_by_name_keeps_its_dependents(self):
        tmp = tempfile.mkdtemp()
        _write(tmp, {"app/main.py": "import lib\n", "vendor/lib.py": "x = 1\n"})
        r = br.analyze(tmp, ["vendor/lib.py"])["vendor/lib.py"]
        self.assertEqual((r.scan, r.direct, r.external_only),
                         ("skipped_dir", ["app/main.py"], False))

    def test_non_source_files_are_not_matched_by_module_name(self):
        # config.yaml is not the module `config`: editing it used to make
        # every file that does `import config` a "dependent"
        tmp = tempfile.mkdtemp()
        git(tmp, "init", "-qb", "main")
        commit_as(tmp, "Dan Calas", "dan@example.com", "base", {
            "config.py": "DEBUG = False\n", "config.yaml": "a: 1\n",
            "app/main.py": "import config\n"})
        base = _sha(tmp)
        commit_as(tmp, "claude-bot", "cb@example.com",
                  "edit yaml\n\nCo-Authored-By: Claude",
                  {"config.yaml": "a: 1\nb: 2\n"})
        _, data = _json("--root", tmp, "check", "--base", base,
                        "--skip-gates")
        b = data["blast_radius"]["config.yaml"]
        self.assertEqual((b["direct"], b["transitive"], b["scan"]),
                         ([], [], "not_source"))
        self.assertEqual(data["risk"]["factors"]["blast"]["points"], 0)

    def test_explicit_head_not_checked_out(self):
        # blast radius reads the worktree, so a file that exists only on
        # --head really is not in the worktree
        tmp, base = make_pr_repo()
        git(tmp, "checkout", "-qb", "feature")
        commit_as(tmp, "claude-bot", "cb@example.com",
                  "feat\n\nCo-Authored-By: Claude",
                  {"app/feature_only.py": "x = 1\n"})
        git(tmp, "checkout", "-q", "main")
        _, data = _json("--root", tmp, "check", "--base", "main", "--head",
                        "feature", "--skip-gates")
        b = data["blast_radius"]["app/feature_only.py"]
        self.assertEqual(b["scan"], "not_in_worktree")
        _, out, _ = _main("--root", tmp, "check", "--base", "main", "--head",
                          "feature", "--skip-gates")
        self.assertIn("(not in the worktree; nothing in-repo imports it)", out)

    def test_untracked_files_included_on_request(self):
        tmp, base = make_pr_repo()
        _write(tmp, {"app/brand_new.py": "x = 1\n", "notes.txt": "hi\n"})
        _, data = _json("--root", tmp, "check", "--base", base,
                        "--skip-gates", "--include-untracked")
        radius = data["blast_radius"]
        self.assertEqual(radius["app/brand_new.py"]["scan"], "graph")
        self.assertEqual(radius["notes.txt"]["scan"], "not_source")

    def test_renamed_file_is_in_the_graph(self):
        tmp = tempfile.mkdtemp()
        git(tmp, "init", "-qb", "main")
        commit_as(tmp, "Dan Calas", "dan@example.com", "base",
                  {"app/old_name.py": "def old():\n    return 1\n" * 4})
        base = _sha(tmp)
        git(tmp, "mv", "app/old_name.py", "app/new_name.py")
        _write(tmp, {"app/new_name.py":
                     "def old():\n    return 1\n" * 4 + "def extra():\n    return 2\n"})
        git(tmp, "add", "-A")
        git(tmp, "-c", "user.name=claude-bot", "-c", "user.email=cb@example.com",
            "commit", "-qm", "rename\n\nCo-Authored-By: Claude")
        _, data = _json("--root", tmp, "check", "--base", base,
                        "--skip-gates")
        self.assertEqual(data["blast_radius"]["app/new_name.py"]["scan"],
                         "graph")
        _, out, _ = _main("--root", tmp, "check", "--base", base,
                          "--skip-gates")
        self.assertNotIn("not in the worktree", out)

    def test_readme_documents_the_labels(self):
        readme = _read("README.md")
        for code in ("not_in_worktree", "not_source", "skipped_dir", "graph"):
            self.assertTrue(code in readme, code)
        self.assertTrue("not scanned for imports" in readme)


# ---------------------------------------------------------------------
# R4-4

AGENT_TRAILER = "Co-Authored-By: Claude <noreply@anthropic.com>"
AGENT_MARKERS = ["claude"]
#: what str.splitlines() ends a line at, besides "\n", and git does not
LINE_BREAKS = ("\x0b", "\x0c", "\x1c", "\x1d", "\x1e", "\x85", "\u2028",
               "\u2029", "\r")


def _range_with_commit(name, email, message, files, base_files=None):
    """(tmp, base_sha): a human base commit, then ONE commit by name/email
    -- the shape of an agent PR."""
    tmp = tempfile.mkdtemp()
    git(tmp, "init", "-qb", "main")
    commit_as(tmp, "Dan Calas", "dan@example.com", "base",
              base_files or {"app/a.py": "x = 1\n"})
    base = _sha(tmp)
    commit_as(tmp, name, email, message, files)
    return tmp, base


def _signed_commit(tmp, name, email, message):
    """Commit the index as a child of HEAD, with a `gpgsig` header (not a
    real signature: enough for git to try to verify it)."""
    tree = subprocess.run(["git", "-C", tmp, "write-tree"],
                          capture_output=True, text=True, encoding="utf-8",
                          check=True).stdout.strip()
    raw = (f"tree {tree}\nparent {_sha(tmp)}\n"
           f"author {name} <{email}> 1700000000 +0000\n"
           f"committer {name} <{email}> 1700000000 +0000\n"
           "gpgsig -----BEGIN PGP SIGNATURE-----\n \n iQEzBAABCAAdFiEEfake\n"
           " =abcd\n -----END PGP SIGNATURE-----\n"
           f"\n{message}\n")
    sha = subprocess.run(
        ["git", "-C", tmp, "hash-object", "-t", "commit", "-w", "--stdin"],
        input=raw.encode("utf-8"), capture_output=True,
        check=True).stdout.decode("ascii").strip()
    git(tmp, "update-ref", "HEAD", sha)
    return sha


class TestForgedCommitRecords(unittest.TestCase):
    """Commit text is the PR author's. git accepts \\x1e (the old record
    separator) in a body, a subject and an author name, and never emits a
    NUL, so NUL frames the fields."""

    def _analyzed(self, name, email, message):
        tmp, base = _range_with_commit(
            name, email, message, {"app/a.py": "x = 1\ny = 2\nz = 3\n"})
        head = _sha(tmp)
        fp = pv.analyze(tmp, base, "HEAD", AGENT_MARKERS)["app/a.py"]
        return tmp, head, fp

    def test_separator_in_the_body_cannot_hide_the_trailer(self):
        message = "Add feature\n\nnotes\x1e\n\n" + AGENT_TRAILER
        tmp, head, fp = self._analyzed("Dan Calas", "dan@example.com",
                                       message)
        self.assertIn(AGENT_TRAILER, pv._commit_text(tmp, {head})[head][3])
        self.assertEqual((fp.label(), fp.agent_added, fp.added),
                         ("agent", 2, 2))

    def test_separator_in_the_subject_keeps_the_record(self):
        subject = "claude: Add\x1e feature"
        tmp, head, fp = self._analyzed("claude-bot", "bot@example.com",
                                       subject)
        self.assertEqual(pv._commit_text(tmp, {head})[head][2], subject)
        self.assertEqual((fp.label(), fp.agent_added), ("agent", 2))

    def test_separator_in_the_author_name_keeps_the_record(self):
        name = "claude-bot [\x1e]"
        tmp, head, fp = self._analyzed(name, "bot@example.com", "Add")
        self.assertEqual(pv._commit_text(tmp, {head})[head][0], name)
        self.assertEqual((fp.label(), fp.agent_added), ("agent", 2))

    def test_forged_records_in_the_stream_are_refused(self):
        # git cannot emit a NUL inside a commit's text, so a stream that
        # carries extra fields, unrequested or repeated shas is not
        # git's answer to the question: refuse it, never guess a record
        a, b, c = "a" * 40, "b" * 40, "c" * 40

        def rec(sha, body="body"):
            return "\x00".join([sha, "Dan", "dan@example.com", "subject",
                                body]) + "\x00\n"

        good = rec(a) + rec(b)
        forged = {
            "an extra record": good + rec(c),
            "a record for a sha nobody asked for": rec(a) + rec(c),
            "the same record twice": rec(a) + rec(a),
            "fields forged inside a body":
                rec(a, "x\x00" + c + "\x00claude\x00bot@x\x00s\x00b") + rec(b),
            "a truncated stream": good[:-20],
            "no output": "",
        }
        for label, stream in forged.items():
            with self.subTest(label), \
                    mock.patch.object(pv, "_git", return_value=stream):
                with self.assertRaises(RuntimeError):
                    pv._commit_text("ignored", {a, b})
        with mock.patch.object(pv, "_git", return_value=good):
            texts = pv._commit_text("ignored", {a, b})
        self.assertEqual(texts[a],
                         ("Dan", "dan@example.com", "subject", "body"))
        self.assertEqual(set(texts), {a, b})

    def test_a_file_named_like_a_commit_does_not_break_the_lookup(self):
        tmp, base = make_pr_repo()
        head = _sha(tmp)
        _write(tmp, {head: "decoy\n"})   # makes a bare `git show <sha>` ambiguous
        self.assertEqual(pv._commit_text(tmp, {head})[head][0], "claude-bot")

    def test_log_showsignature_config_does_not_pollute_the_records(self):
        # with log.showSignature=true git prints gpg's verdict on stdout,
        # ahead of each signed commit: the sha field came out as
        # "gpg: ...<sha>", the record was lost and the commit read as human
        tmp = tempfile.mkdtemp()
        git(tmp, "init", "-qb", "main")
        commit_as(tmp, "Dan Calas", "dan@example.com", "base",
                  {"app/a.py": "x = 1\n", "app/old.py": "y = 1\n"})
        base = _sha(tmp)
        os.remove(os.path.join(tmp, "app/old.py"))
        _write(tmp, {"app/a.py": "x = 1\nz = 2\n"})
        git(tmp, "add", "-A")
        head = _signed_commit(tmp, "claude-bot", "claude-bot@example.com",
                              "agent\n\n" + AGENT_TRAILER)
        git(tmp, "config", "log.showSignature", "true")
        self.assertEqual(pv._commit_text(tmp, {head})[head][0], "claude-bot")
        prov = pv.analyze(tmp, base, "HEAD", AGENT_MARKERS)
        self.assertEqual(prov["app/a.py"].label(), "agent")
        self.assertEqual(prov["app/old.py"].label(), "deleted")
        self.assertEqual(prov["app/old.py"].deleted_by, ["claude-bot"])


class TestForgedFileContent(unittest.TestCase):
    """File lines and names are the PR author's too: a line break that git
    does not honour must not start a record in its blame or diff output,
    and neither may a line that merely looks like a header."""

    def _added(self, files, base_files):
        tmp, base = _range_with_commit("claude-bot", "claude-bot@example.com",
                                       "agent", files, base_files)
        return pv.added_lines(tmp, base, "HEAD")

    def test_line_break_cannot_forge_a_blame_header(self):
        tmp = tempfile.mkdtemp()
        git(tmp, "init", "-qb", "main")
        commit_as(tmp, "Dan Calas", "dan@example.com", "base",
                  {"README.md": "hi\n"})
        base = _sha(tmp)
        commit_as(tmp, "Dan Calas", "dan@example.com", "human tweak",
                  {"docs.txt": "h\n"})
        human = _sha(tmp)
        # line 1 smuggles "<human sha> 1 2 1": a blame header that would
        # hand lines 2.. to the human commit
        files = {f"app/f{i}.py":
                 f"# note{sep}{human} 1 2 1\na = 1\nb = 2\nc = 3\nd = 4\n"
                 for i, sep in enumerate(LINE_BREAKS)}
        commit_as(tmp, "claude-bot", "claude-bot@example.com",
                  "agent work\n\n" + AGENT_TRAILER, files)
        prov = pv.analyze(tmp, base, "HEAD", AGENT_MARKERS)
        for i, sep in enumerate(LINE_BREAKS):
            fp = prov[f"app/f{i}.py"]
            self.assertEqual((fp.label(), fp.agent_added, fp.added),
                             ("agent", 5, 5), repr(sep))

    def test_line_break_cannot_forge_a_diff_header(self):
        # "+++ /dev/null" after a line break would end the file's hunks
        old = "x = 1\nm = 1\nn = 1\n"
        base_files = {f"app/f{i}.py": old for i in range(len(LINE_BREAKS))}
        files = {f"app/f{i}.py": "x = 1\nfoo = 1" + sep + "+++ /dev/null\n"
                 "m = 1\nnew1 = 1\nn = 1\nnew2 = 2\n"
                 for i, sep in enumerate(LINE_BREAKS)}
        added = self._added(files, base_files)
        for i, sep in enumerate(LINE_BREAKS):
            self.assertEqual(added.get(f"app/f{i}.py"), [2, 4, 6], repr(sep))

    def test_added_line_that_reads_like_a_file_header(self):
        # "++ /dev/null" is `+++ /dev/null` in the diff: it dropped every
        # added line after it, the whole change to the file with it
        self.assertEqual(
            self._added({"app/a.py": "x = 1\n++ /dev/null\nl0 = 0\nz = 0\n"},
                        {"app/a.py": "x = 1\n"}),
            {"app/a.py": [2, 3, 4]})
        # ... and "++ b/app/b.py" moved the rest to another file
        added = self._added(
            {"app/a.py": "x = 1\n++ b/app/b.py\nl0 = 0\nl1 = 1\n"},
            {"app/a.py": "x = 1\n", "app/b.py": "y = 1\n"})
        self.assertEqual(added, {"app/a.py": [2, 3, 4]})

    def test_added_line_starting_with_two_plus_signs_is_counted(self):
        self.assertEqual(
            self._added({"c.txt": "a\n++i;\nb\n"}, {"c.txt": "a\n"}),
            {"c.txt": [2, 3]})

    def test_removed_line_starting_with_two_dashes_does_not_shift_lines(self):
        # a removed SQL comment reads `--- old comment` in the diff
        self.assertEqual(
            self._added({"q.sql": "select 1;\nselect 3;\nselect 2;\n"},
                        {"q.sql": "select 1;\n-- old comment\nselect 2;\n"}),
            {"q.sql": [2]})

    def test_no_newline_marker_does_not_shift_lines(self):
        # "\ No newline at end of file" is no line of either side
        self.assertEqual(
            self._added({"n.txt": "a\nb\nc\nd\n"}, {"n.txt": "a\nb"}),
            {"n.txt": [2, 3, 4]})

    def test_unicode_line_separators_in_file_names(self):
        names = ["app/a\u2028b.py", "app/c\u2029d.py"]
        tmp = tempfile.mkdtemp()
        git(tmp, "init", "-qb", "main")
        commit_as(tmp, "Dan Calas", "dan@example.com", "base",
                  {n: "x = 1\n" for n in names})
        base = _sha(tmp)
        for n in names:
            os.remove(os.path.join(tmp, n))
        git(tmp, "add", "-A")
        git(tmp, "-c", "user.name=claude-bot",
            "-c", "user.email=claude-bot@example.com", "commit", "-qm",
            "agent deletes\n\n" + AGENT_TRAILER)
        self.assertEqual(pv.deleted_files(tmp, base, "HEAD"), sorted(names))
        prov = pv.analyze(tmp, base, "HEAD", AGENT_MARKERS)
        self.assertEqual(sorted(prov), sorted(names))
        self.assertTrue(all(fp.deleted for fp in prov.values()))
        _write(tmp, {n: "y = 2\n" for n in names})
        self.assertEqual(pv.untracked_files(tmp), sorted(names))


class TestTrailerLineBreaks(unittest.TestCase):
    """A trailer is a line of the body, and a line ends at "\\n" -- as git
    sees it. `Co-Authored-By:\\x1e Claude <...>` used to be cut in two by
    str.splitlines() and counted as no agent at all."""

    def _match(self, body):
        return markers_mod.match("Dan Calas", "dan@example.com", "Add", body,
                                 AGENT_MARKERS)

    def test_odd_whitespace_after_the_key_does_not_hide_a_trailer(self):
        for sep in LINE_BREAKS:
            with self.subTest(sep=repr(sep)):
                body = f"Add\n\nCo-Authored-By:{sep} Claude <noreply@anthropic.com>"
                self.assertEqual(self._match(body), "claude")

    def test_ordinary_trailers_still_match(self):
        for body in ("Add\n\n" + AGENT_TRAILER,
                     "Add\r\n\r\n" + AGENT_TRAILER + "\r\n",
                     AGENT_TRAILER,
                     "Add\n\nSigned-off-by: Dan <d@example.com>\n"
                     + AGENT_TRAILER + "\nmore text\n"):
            with self.subTest(body=body):
                self.assertEqual(self._match(body), "claude")
        self.assertIsNone(self._match("Add\n\nclaude said hello"))

    def test_end_to_end_with_a_real_commit(self):
        message = "Add feature\n\nCo-Authored-By:\x1e Claude <noreply@anthropic.com>"
        tmp, base = _range_with_commit(
            "Dan Calas", "dan@example.com", message,
            {"app/a.py": "x = 1\ny = 2\n"})
        fp = pv.analyze(tmp, base, "HEAD", AGENT_MARKERS)["app/a.py"]
        self.assertEqual((fp.label(), fp.agent_added), ("agent", 1))


# ---------------------------------------------------------------------
# R4-5

class TestPyprojectMetadata(unittest.TestCase):
    """pyproject.toml is read as text: tomllib only exists on 3.11+."""

    def setUp(self):
        self.text = _read("pyproject.toml")

    def test_license_is_the_one_in_the_license_file(self):
        self.assertTrue(_read("LICENSE").startswith("MIT License"))
        self.assertRegex(self.text, r'(?m)^license = "MIT"$')
        self.assertRegex(self.text, r'(?m)^license-files = \["LICENSE"\]$')

    def test_spdx_license_needs_setuptools_77(self):
        # PEP 639 `license = "<SPDX>"` is only understood from setuptools 77
        self.assertRegex(self.text, r'(?m)^requires = \["setuptools>=77"\]$')

    def test_no_legacy_license_classifier(self):
        # setuptools >= 77 rejects `License ::` classifiers next to an
        # SPDX `license` expression
        self.assertNotIn("License ::", self.text)

    def test_classifiers(self):
        for c in ("Development Status :: 4 - Beta",
                  "Environment :: Console",
                  "Intended Audience :: Developers",
                  "Operating System :: OS Independent",
                  "Programming Language :: Python :: 3",
                  "Programming Language :: Python :: 3.10",
                  "Programming Language :: Python :: 3.11",
                  "Programming Language :: Python :: 3.12",
                  "Programming Language :: Python :: 3.13",
                  "Topic :: Software Development :: Quality Assurance"):
            self.assertIn(f'"{c}"', self.text, c)

    def test_python_classifiers_match_requires_python(self):
        self.assertIn('requires-python = ">=3.10"', self.text)
        versions = re.findall(r'"Programming Language :: Python :: (3\.\d+)"',
                              self.text)
        self.assertTrue(versions)
        self.assertEqual(min(versions, key=lambda v: int(v.split(".")[1])),
                         "3.10")

    def test_keywords_and_urls(self):
        self.assertRegex(self.text, r"(?m)^keywords = \[")
        self.assertRegex(
            self.text,
            r'(?m)^Homepage = "https://github\.com/calasdan-sketch/pr-verify"$')
        self.assertRegex(
            self.text,
            r'(?m)^Issues = "https://github\.com/calasdan-sketch/pr-verify/issues"$')
        self.assertIn("[project.urls]", self.text)


# ---------------------------------------------------------------------
# R4-6

@contextlib.contextmanager
def closed_pipe_stdout(line_buffered: bool):
    """sys.stdout is a real pipe whose reader is already gone (`| head -1`).
    Line-buffered, the first print fails (what an unbuffered or tty stdout
    does); block-buffered, nothing fails until the flush the interpreter
    does at exit, which is replayed here after the body."""
    r, w = os.pipe()
    os.close(r)
    out = os.fdopen(w, "w", buffering=1 if line_buffered else -1,
                    encoding="utf-8", errors="strict")
    try:
        with redirect_stdout(out):
            yield out
        out.flush()          # the interpreter's exit-time flush
    finally:
        try:
            out.close()
        except OSError:
            pass             # only reachable when the body already failed


def _check(tmp, base, *extra, fmt="human", line_buffered=True):
    """pr-verify check on a closed stdout -> (exit code, stderr text)."""
    err = io.StringIO()
    with closed_pipe_stdout(line_buffered), redirect_stderr(err):
        code = cli_mod.main(["--root", tmp, "check", "--base", base,
                             "--skip-gates", "--format", fmt, *extra])
    return code, err.getvalue()


class TestBrokenPipe(unittest.TestCase):
    """`pr-verify check | head -1`: the reader leaving is not an error and
    must not change the exit status, which is the verdict CI acts on."""

    def test_verdict_survives_a_closed_pipe(self):
        tmp, base = make_pr_repo()          # scores 57
        for line_buffered in (True, False):
            for fmt in ("human", "json"):
                with self.subTest(line_buffered=line_buffered, fmt=fmt):
                    kw = dict(fmt=fmt, line_buffered=line_buffered)
                    self.assertEqual(_check(tmp, base, **kw), (0, ""))
                    # 57 >= 10 and 57 >= 57 (equal fails): the pipe must
                    # not turn a failing verdict into a pass
                    self.assertEqual(
                        _check(tmp, base, "--min-score", "10", **kw), (1, ""))
                    self.assertEqual(
                        _check(tmp, base, "--min-score", "57", **kw), (1, ""))

    def test_failing_gate_verdict_survives_a_closed_pipe(self):
        tmp, old_base = make_pr_repo()
        base = commit_at_new_base(
            tmp, old_base,
            {".pr-verify.yaml": f"gates:\n  - {yaml_str(FAIL_GATE)}\n"})
        for line_buffered in (True, False):
            err = io.StringIO()
            with closed_pipe_stdout(line_buffered), redirect_stderr(err):
                code = cli_mod.main(["--root", tmp, "check", "--base", base])
            self.assertEqual((code, err.getvalue()), (1, ""), line_buffered)

    def test_nothing_to_verify_on_a_closed_pipe(self):
        tmp, base = make_pr_repo()
        for line_buffered in (True, False):
            self.assertEqual(
                _check(tmp, "HEAD", line_buffered=line_buffered), (0, ""))

    def test_init_on_a_closed_pipe(self):
        for line_buffered in (True, False):
            tmp = tempfile.mkdtemp()
            err = io.StringIO()
            with closed_pipe_stdout(line_buffered), redirect_stderr(err):
                code = cli_mod.main(["--root", tmp, "init"])
            self.assertEqual((code, err.getvalue()), (0, ""), line_buffered)
            self.assertTrue(
                os.path.isfile(os.path.join(tmp, ".pr-verify.yaml")))

    def test_action_still_writes_its_outputs(self):
        tmp, base = make_pr_repo()
        for line_buffered in (True, False):
            out_file = os.path.join(tempfile.mkdtemp(), "gh_output")
            env = {"PR_VERIFY_ROOT": tmp, "PR_VERIFY_BASE": base,
                   "PR_VERIFY_SKIP_GATES": "true",
                   "PR_VERIFY_MIN_SCORE": "57", "GITHUB_OUTPUT": out_file}
            err = io.StringIO()
            with closed_pipe_stdout(line_buffered), redirect_stderr(err):
                code = action_mod.main(environ=env)
            self.assertEqual((code, err.getvalue()), (1, ""), line_buffered)
            with open(out_file, encoding="utf-8") as f:
                outputs = dict(line.rstrip("\n").split("=", 1)
                               for line in f if line.strip())
            self.assertEqual(outputs, {"score": "57", "band": "medium",
                                       "requires-review": "true",
                                       "exit-code": "1"})

    def test_other_write_errors_are_not_swallowed(self):
        # not swallowed like a closed pipe, whose reader just went away and
        # which leaves the verdict alone: a report that cannot be written is
        # an error (round 7: one line and exit 2; it used to be a traceback)
        class DiskFull(io.StringIO):
            def write(self, s):
                raise OSError(errno.ENOSPC, "No space left on device")

        tmp, base = make_pr_repo()
        err = io.StringIO()
        with redirect_stdout(DiskFull()), redirect_stderr(err):
            code = cli_mod.main(["--root", tmp, "check", "--base", base,
                                 "--skip-gates"])
        self.assertEqual(code, 2)
        self.assertEqual(err.getvalue().strip(),
                         "error: could not write the report: "
                         "No space left on device")

    def test_closed_pipe_errno_per_platform(self):
        epipe = BrokenPipeError(errno.EPIPE, "Broken pipe")
        einval = OSError(errno.EINVAL, "Invalid argument")
        enospc = OSError(errno.ENOSPC, "No space left on device")
        self.assertTrue(cli_mod._is_closed_pipe(epipe))
        self.assertFalse(cli_mod._is_closed_pipe(enospc))
        # a write to a closed pipe can fail with EINVAL on Windows
        with mock.patch.object(os, "name", "nt"):
            self.assertTrue(cli_mod._is_closed_pipe(einval))
            self.assertFalse(cli_mod._is_closed_pipe(enospc))
        with mock.patch.object(os, "name", "posix"):
            self.assertFalse(cli_mod._is_closed_pipe(einval))

    def test_real_process_whose_reader_is_gone(self):
        # The real thing: a child process, a real pipe, the read end closed
        # before the child prints a byte. Buffered stdout fails at the
        # exit-time flush (status 120 and "Exception ignored" without the
        # fix), unbuffered stdout fails inside print().
        tmp, base = make_pr_repo()
        for unbuffered in (False, True):
            for extra, verdict in (((), 0), (("--min-score", "10"), 1)):
                with self.subTest(unbuffered=unbuffered, extra=extra):
                    env = dict(os.environ)
                    env["PYTHONPATH"] = os.pathsep.join(
                        p for p in (REPO, env.get("PYTHONPATH")) if p)
                    env.pop("PYTHONUNBUFFERED", None)
                    if unbuffered:
                        env["PYTHONUNBUFFERED"] = "1"
                    p = subprocess.Popen(
                        [sys.executable, "-m", "pr_verify", "--root", tmp,
                         "check", "--base", base, "--skip-gates", *extra],
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                        env=env)
                    p.stdout.close()
                    err = p.stderr.read().decode("utf-8", "replace")
                    code = p.wait(timeout=120)
                    p.stderr.close()
                    self.assertEqual(err, "")
                    self.assertEqual(code, verdict)


# ---------------------------------------------------------------------
# R4-7

PNG = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR" + bytes(range(256)) * 4

#: A program for git's own shell to run (a textconv driver, an external
#: diff tool) that exists on every platform and prints nothing.
SILENT_PROGRAM = shlex.quote(PY.replace("\\", "/")) + " -c pass"


def _attr_repo(attributes, attributes_path=".gitattributes", where=None):
    """(tmp, base). The base has app/a.py and a real binary, logo.png. One
    agent commit then adds lines 2 and 3 to app/a.py, changes the PNG and
    writes the attributes (when given)."""
    tmp = where or tempfile.mkdtemp()
    git(tmp, "init", "-qb", "main")
    with open(os.path.join(tmp, "logo.png"), "wb") as f:
        f.write(PNG)
    commit_as(tmp, "Dan Calas", "dan@example.com", "base",
              {"app/a.py": "x = 1\n"})
    base = _sha(tmp)
    with open(os.path.join(tmp, "logo.png"), "wb") as f:
        f.write(PNG + b"\x01\x02")
    files = {"app/a.py": "x = 1\ny = 2\nz = 3\n"}
    if attributes is not None:
        files[attributes_path] = attributes
    commit_as(tmp, "claude-bot", "claude-bot@example.com",
              "Agent change\n\n" + AGENT_TRAILER, files)
    return tmp, base


class TestGitAttributes(unittest.TestCase):
    """`*.py -diff` or `binary` in a .gitattributes -- a file the PR itself
    can add -- makes `git diff` print "Binary files differ" for the files it
    names, and the verifier read that as "no added lines": a rewritten
    source file went unscored. `diff` (set) goes the other way and makes
    git diff a real binary as text."""

    VARIANTS = (
        ("-diff", "*.py -diff\n"),
        ("binary", "*.py binary\n"),
        ("one file by name", "app/a.py -diff\n"),
        ("everything binary", "* binary\n"),
        ("everything -diff", "* -diff\n"),
        ("-diff after diff", "*.py diff\n*.py -diff\n"),
        ("-diff and linguist-generated",
         "*.py linguist-generated=true -diff\n"),
        ("-text", "*.py -text\n"),
        ("diff=somedriver", "*.py diff=somedriver\n"),
        ("diff=python", "*.py diff=python\n"),
        ("linguist-generated", "*.py linguist-generated\n"),
        ("text eol=crlf", "*.py text eol=crlf\n"),
    )

    def assertLinesSeen(self, root, base):
        added = pv.added_lines(root, base, "HEAD")
        self.assertEqual(added.get("app/a.py"), [2, 3])
        self.assertNotIn("logo.png", added)     # a real binary stays binary

    def test_attributes_cannot_hide_a_source_file(self):
        for label, attributes in self.VARIANTS:
            with self.subTest(label):
                tmp, base = _attr_repo(attributes)
                self.assertLinesSeen(tmp, base)

    def test_attributes_in_a_subdirectory(self):
        tmp, base = _attr_repo("*.py -diff\n", "app/.gitattributes")
        self.assertLinesSeen(tmp, base)

    def test_attributes_that_are_not_committed(self):
        # git reads the worktree's (then the index's) .gitattributes, not
        # the range's: neither may change what the range contains
        tmp, base = _attr_repo(None)
        with open(os.path.join(tmp, ".gitattributes"), "w",
                  encoding="utf-8", newline="\n") as f:
            f.write("*.py -diff\n")
        self.assertLinesSeen(tmp, base)         # in the worktree only
        git(tmp, "add", ".gitattributes")
        self.assertLinesSeen(tmp, base)         # staged

    def test_a_real_binary_stays_binary_whatever_the_attributes_say(self):
        # `diff` forces text: the PNG would become a pile of added lines
        for attributes in (None, "*.png -diff\n", "*.png diff\n", "* diff\n"):
            with self.subTest(attributes):
                tmp, base = _attr_repo(attributes)
                self.assertLinesSeen(tmp, base)

    def test_every_repository_layout(self):
        tmp, base = _attr_repo("*.py -diff\n")
        linked = os.path.join(tempfile.mkdtemp(), "linked")
        git(tmp, "worktree", "add", "-q", "--detach", linked, "HEAD")
        bare = os.path.join(tempfile.mkdtemp(), "bare.git")
        git(tmp, "clone", "-q", "--bare", tmp, bare)
        for label, root in (("top level", tmp),
                            ("subdirectory", os.path.join(tmp, "app")),
                            ("linked worktree", linked),
                            ("bare repository", bare)):
            with self.subTest(label):
                self.assertLinesSeen(root, base)

    @unittest.skipIf(os.name == "nt" or sys.platform == "darwin",
                     "needs a file system that keeps any bytes in a name")
    def test_a_directory_name_that_is_not_utf8(self):
        # the repository's own path is handed to git as it is, not as the
        # text git's output decodes to
        odd = os.path.join(os.fsencode(tempfile.mkdtemp()), b"caf\xe9")
        try:
            os.mkdir(odd)
        except OSError:
            self.skipTest("this file system refuses the name")
        tmp, base = _attr_repo("*.py -diff\n", where=os.fsdecode(odd))
        self.assertLinesSeen(tmp, base)

    def test_the_repository_is_left_alone(self):
        tmp, base = _attr_repo("*.py -diff\n")
        index = os.path.join(tmp, ".git", "index")
        with open(index, "rb") as f:
            before = f.read()

        # a private temp dir: other processes (a parallel test run, another
        # pr-verify) also create and remove scratch files in the shared one
        private = tempfile.mkdtemp()
        with mock.patch.object(tempfile, "tempdir", private):
            self.assertLinesSeen(tmp, base)
        with open(index, "rb") as f:
            self.assertEqual(f.read(), before)
        self.assertEqual(os.listdir(private), [])

    def test_the_whole_check_sees_the_lines(self):
        tmp, base = _attr_repo("*.py -diff\n")
        code, payload = _json("--root", tmp, "check", "--base", base,
                              "--skip-gates")
        self.assertIn("app/a.py", payload["files"])
        f = payload["files"]["app/a.py"]
        self.assertEqual((f["added"], f["agent_added"], f["label"]),
                         (2, 2, "agent"))
        self.assertNotIn("logo.png", payload["files"])

    def test_a_textconv_driver_cannot_change_the_lines(self):
        # a driver the user configured, named by the PR's attributes: this
        # one converts every file to nothing, so the diff of it is empty
        tmp, base = _attr_repo("*.py diff=squash\n")
        git(tmp, "config", "diff.squash.textconv", SILENT_PROGRAM)
        self.assertLinesSeen(tmp, base)


def _shape_repo():
    """A range with something in it for each setting that reshapes
    `git diff`: two hunks two lines apart (app/a.py), blank context lines
    (app/blank.py), a directory called b (b/c.py), a rename with an edit
    (app/old.py -> app/new.py)."""
    tmp = tempfile.mkdtemp()
    git(tmp, "init", "-qb", "main")
    ten = "".join(f"line {i}\n" for i in range(10))
    commit_as(tmp, "Dan Calas", "dan@example.com", "base",
              {"app/a.py": "a\nb\nc\nd\ne\nf\n",
               "app/blank.py": "x\n\ny\nz\n",
               "b/c.py": "q = 1\n",
               "app/old.py": ten})
    base = _sha(tmp)
    os.remove(os.path.join(tmp, "app", "old.py"))
    commit_as(tmp, "claude-bot", "claude-bot@example.com",
              "Agent change\n\n" + AGENT_TRAILER,
              {"app/a.py": "a\nB\nc\nd\nE\nf\n",
               "app/blank.py": "X\n\ny\nZ\n",
               "b/c.py": "q = 1\nr = 2\n",
               "app/new.py": ten + "line 10\n"})
    return tmp, base


SHAPE_ADDED = {"app/a.py": [2, 5], "app/blank.py": [1, 4], "b/c.py": [2],
               "app/new.py": [11]}


class TestUserConfigDoesNotShapeTheDiff(unittest.TestCase):
    """The patch is read line by line, so it has to look the same on every
    machine: the colors, prefixes, context or external diff tool a user has
    set up must not change what the verifier sees. `git diff` honours all of
    them; the plumbing `git diff-tree` does not."""

    CONFIGS = (
        ("color.ui", {"color.ui": "always"}, {}),
        ("color.diff", {"color.diff": "always"}, {}),
        ("diff.noprefix", {"diff.noprefix": "true"}, {}),
        ("diff.interHunkContext", {"diff.interHunkContext": "5"}, {}),
        ("diff.interHunkContext and blank lines",
         {"diff.interHunkContext": "5", "diff.suppressBlankEmpty": "true"},
         {}),
        ("diff.renames", {"diff.renames": "false"}, {}),
        ("diff.external", {"diff.external": SILENT_PROGRAM}, {}),
        ("GIT_EXTERNAL_DIFF", {}, {"GIT_EXTERNAL_DIFF": SILENT_PROGRAM}),
        ("GIT_DIFF_OPTS", {}, {"GIT_DIFF_OPTS": "-u3"}),
    )

    def test_the_patch_looks_the_same_with_any_configuration(self):
        for label, config, env in self.CONFIGS:
            with self.subTest(label):
                tmp, base = _shape_repo()
                for key, value in config.items():
                    git(tmp, "config", key, value)
                with mock.patch.dict(os.environ, env):
                    self.assertEqual(pv.added_lines(tmp, base, "HEAD"),
                                     SHAPE_ADDED)
                    self.assertEqual(pv.deleted_files(tmp, base, "HEAD"), [])

    def test_a_submodule_bump_is_not_hidden(self):
        # diff.submodule rewrites, and diff.ignoreSubmodules drops, the
        # lines `git diff` prints for a submodule
        for key, value in (("diff.submodule", "log"),
                           ("diff.submodule", "diff"),
                           ("diff.ignoreSubmodules", "all")):
            with self.subTest(key=key, value=value):
                tmp = tempfile.mkdtemp()
                git(tmp, "init", "-qb", "main")
                # an unpopulated submodule: an empty directory at the path
                os.makedirs(os.path.join(tmp, "vendor", "lib"))
                git(tmp, "update-index", "--add", "--cacheinfo",
                    f"160000,{'1' * 40},vendor/lib")
                commit_as(tmp, "Dan Calas", "dan@example.com", "base",
                          {"app/a.py": "x = 1\n"})
                base = _sha(tmp)
                git(tmp, "update-index", "--cacheinfo",
                    f"160000,{'2' * 40},vendor/lib")
                commit_as(tmp, "claude-bot", "claude-bot@example.com",
                          "bump\n\n" + AGENT_TRAILER, {})
                git(tmp, "config", key, value)
                self.assertEqual(pv.added_lines(tmp, base, "HEAD"),
                                 {"vendor/lib": [1]})


class TestPatchParser(unittest.TestCase):
    """Whatever the options, a hunk is walked by the counts in its header:
    context lines (a `-U3`, an inter-hunk context) are file content that
    was not added, and an added line that reads like a file header is still
    an added line."""

    PATCH = "\n".join([
        "diff --git a/app/a.py b/app/a.py",
        "index 1111111..2222222 100644",
        "--- a/app/a.py",
        "+++ b/app/a.py",
        "@@ -2,5 +2,6 @@ def f():",
        "-b",
        "+B",
        " c",
        "",                 # a blank context line, as diff.suppressBlankEmpty
        " d",               # prints it
        "-e",
        "+E",
        "++++ x",           # the added line "+++ x"
        "diff --git a/b.py b/b.py",
        "--- a/b.py",
        "+++ b/b.py",
        "@@ -1 +1,2 @@",
        " keep",
        "+new",
        "\\ No newline at end of file",
        ""])

    def test_context_lines_are_not_added_lines(self):
        with mock.patch.object(pv, "_patch", return_value=self.PATCH):
            self.assertEqual(pv.added_lines("ignored", "base", "head"),
                             {"app/a.py": [2, 6, 7], "b.py": [2]})


class TestBlameIgnoreRevs(unittest.TestCase):
    """blame.ignoreRevsFile (a user's setting, for formatting commits) makes
    blame look past the commits a file lists. The file is in the PR: it
    could list the agent's commits, and their lines would read as the
    older, human ones."""

    def test_a_commit_the_pr_lists_still_owns_its_lines(self):
        tmp = tempfile.mkdtemp()
        git(tmp, "init", "-qb", "main")
        commit_as(tmp, "Dan Calas", "dan@example.com", "base",
                  {"app/a.py": "def f():\n    return 1\n",
                   ".git-blame-ignore-revs": "# none\n"})
        base = _sha(tmp)
        commit_as(tmp, "claude-bot", "claude-bot@example.com",
                  "Agent change\n\n" + AGENT_TRAILER,
                  {"app/a.py": "def f():\n    return 2\n"})
        agent = _sha(tmp)
        git(tmp, "config", "blame.ignoreRevsFile", ".git-blame-ignore-revs")
        commit_as(tmp, "Dan Calas", "dan@example.com", "tidy",
                  {".git-blame-ignore-revs": f"# none\n{agent}\n"})
        got = pv.analyze(tmp, base, "HEAD", ["claude"])["app/a.py"]
        self.assertEqual((got.added, got.agent_added), (1, 1))


# ---------------------------------------------------------------------
# R4-8

class WindowsClosedPipe:
    """A stream whose reader is gone, with errors reported the way Windows
    reports them (measured: Windows 11, Python 3.11). The pipe is real, its
    read end closed. A write that reaches it fails with a plain OSError,
    errno EINVAL, not a BrokenPipeError. print() into the stream succeeds
    (it is only buffered) and flush() raises; `unbuffered` is `python -u`,
    where the write itself fails. Whatever failed stays pending, as in a
    BufferedWriter, until a flush gets through."""

    def __init__(self, unbuffered=False):
        r, self.fd = os.pipe()
        os.close(r)
        self.unbuffered = unbuffered
        self.pending = []

    def _push(self):
        if not self.pending:
            return
        try:
            os.write(self.fd, "".join(self.pending).encode("utf-8"))
        except BrokenPipeError:
            raise OSError(errno.EINVAL, "Invalid argument") from None
        self.pending.clear()

    def write(self, s):
        self.pending.append(s)
        if self.unbuffered:
            self._push()
        return len(s)

    def flush(self):
        self._push()

    def fileno(self):
        return self.fd

    def close(self):
        os.close(self.fd)


class TestClosedPipeOnWindows(unittest.TestCase):
    """After `pr-verify check | head -1` print() still succeeds on Windows
    and the failure turns up at the flush, as an OSError with errno 22. If
    nothing catches it the interpreter's own flush on the way out fails
    again ("Exception ignored", exit status 120), and the verdict is lost.
    Faked here on every platform: the stream is a real pipe with no reader
    that reports its errors the Windows way, and cli._on_windows() says so."""

    def setUp(self):
        self.tmp, self.base = make_pr_repo()       # scores 57

    def pipe(self, unbuffered=False):
        pipe = WindowsClosedPipe(unbuffered)
        self.addCleanup(pipe.close)
        return pipe

    def run_main(self, argv, stdout=None, stderr=None, windows=True):
        with contextlib.ExitStack() as stack:
            stack.enter_context(mock.patch.object(
                cli_mod, "_on_windows", return_value=windows))
            if stdout is not None:
                stack.enter_context(redirect_stdout(stdout))
            if stderr is not None:
                stack.enter_context(redirect_stderr(stderr))
            return cli_mod.main(argv)

    def assertSettled(self, pipe):
        """What the interpreter does on its way out cannot fail any more:
        its flush gets through, and the descriptor leads to the null
        device (a write to it would fail if it still led to the pipe)."""
        pipe.flush()
        os.write(pipe.fd, b"x")

    def test_verdict_survives_a_flush_that_fails_with_einval(self):
        for unbuffered in (False, True):
            for fmt in ("human", "json"):
                for extra, verdict in (((), 0), (("--min-score", "10"), 1),
                                       (("--min-score", "57"), 1)):
                    with self.subTest(unbuffered=unbuffered, fmt=fmt,
                                      extra=extra):
                        pipe = self.pipe(unbuffered)
                        code = self.run_main(
                            ["--root", self.tmp, "check", "--base", self.base,
                             "--skip-gates", "--format", fmt, *extra], pipe)
                        self.assertEqual(code, verdict)
                        self.assertSettled(pipe)

    def test_failing_gate_verdict_survives(self):
        base = commit_at_new_base(
            self.tmp, self.base,
            {".pr-verify.yaml": f"gates:\n  - {yaml_str(FAIL_GATE)}\n"})
        for unbuffered in (False, True):
            pipe = self.pipe(unbuffered)
            code = self.run_main(["--root", self.tmp, "check", "--base", base],
                                 pipe)
            self.assertEqual(code, 1, unbuffered)
            self.assertSettled(pipe)

    def test_nothing_to_verify_and_init(self):
        for unbuffered in (False, True):
            pipe = self.pipe(unbuffered)
            code = self.run_main(["--root", self.tmp, "check", "--base",
                                  "HEAD"], pipe)
            self.assertEqual(code, 0, unbuffered)
            self.assertSettled(pipe)
            fresh = tempfile.mkdtemp()
            pipe = self.pipe(unbuffered)
            code = self.run_main(["--root", fresh, "init"], pipe)
            self.assertEqual(code, 0, unbuffered)
            self.assertTrue(
                os.path.isfile(os.path.join(fresh, ".pr-verify.yaml")))
            self.assertSettled(pipe)

    def test_action_writes_its_outputs(self):
        for unbuffered in (False, True):
            out_file = os.path.join(tempfile.mkdtemp(), "gh_output")
            env = {"PR_VERIFY_ROOT": self.tmp, "PR_VERIFY_BASE": self.base,
                   "PR_VERIFY_SKIP_GATES": "true",
                   "PR_VERIFY_MIN_SCORE": "57", "GITHUB_OUTPUT": out_file}
            pipe = self.pipe(unbuffered)
            with mock.patch.object(cli_mod, "_on_windows",
                                   return_value=True), redirect_stdout(pipe):
                code = action_mod.main(environ=env)
            self.assertEqual(code, 1, unbuffered)
            with open(out_file, encoding="utf-8") as f:
                self.assertIn("exit-code=1\n", f.read())
            self.assertSettled(pipe)

    def test_einval_is_a_real_error_anywhere_else(self):
        # not a closed pipe, so not absorbed: reported, and exit 2 (round 7;
        # it used to be an OSError that ended the run in a traceback)
        for unbuffered in (False, True):
            pipe = self.pipe(unbuffered)
            with self.subTest(unbuffered=unbuffered):
                err = io.StringIO()
                code = self.run_main(["--root", self.tmp, "check", "--base",
                                      self.base, "--skip-gates"], pipe, err,
                                     windows=False)
                self.assertEqual(code, 2)
                self.assertEqual(err.getvalue().strip(),
                                 "error: could not write the report: "
                                 "Invalid argument")

    def test_help_and_version(self):
        # argparse ignores a failed write and exits: the flush that fails
        # is the one on the way out
        for argv in (["--help"], ["--version"], ["check", "--help"],
                     ["init", "--help"]):
            for unbuffered in (False, True):
                with self.subTest(argv=argv, unbuffered=unbuffered):
                    pipe = self.pipe(unbuffered)
                    with self.assertRaises(SystemExit) as cm:
                        self.run_main(argv, pipe)
                    self.assertEqual(cm.exception.code, 0)
                    self.assertSettled(pipe)

    def test_error_messages_on_a_closed_stderr(self):
        notrepo = tempfile.mkdtemp()
        for unbuffered in (False, True):
            with self.subTest(unbuffered=unbuffered):
                err = self.pipe(unbuffered)
                with self.assertRaises(SystemExit) as cm:
                    self.run_main(["--root", notrepo, "check"],
                                  io.StringIO(), err)
                self.assertEqual(cm.exception.code, 2)
                self.assertSettled(err)
                err = self.pipe(unbuffered)
                code = self.run_main(["--root", self.tmp, "check", "--base",
                                      "no-such-ref"], io.StringIO(), err)
                self.assertEqual(code, 2)
                self.assertSettled(err)
                err = self.pipe(unbuffered)
                env = {"PR_VERIFY_ROOT": self.tmp,
                       "PR_VERIFY_BASE": "no-such-ref"}
                with mock.patch.object(cli_mod, "_on_windows",
                                       return_value=True), \
                        redirect_stderr(err):
                    self.assertEqual(action_mod.main(environ=env), 2)
                self.assertSettled(err)

    def test_closed_pipe_by_errno(self):
        class Odd(OSError):     # keeps its errno: not mapped to a subclass
            pass

        einval = OSError(errno.EINVAL, "Invalid argument")
        self.assertTrue(cli_mod._is_closed_pipe(
            Odd(errno.EPIPE, "Broken pipe")))
        self.assertTrue(cli_mod._is_closed_pipe(
            BrokenPipeError(errno.EPIPE, "Broken pipe")))
        for windows, closed in ((True, True), (False, False)):
            with mock.patch.object(cli_mod, "_on_windows",
                                   return_value=windows):
                self.assertEqual(cli_mod._is_closed_pipe(einval), closed)
                for number in (errno.ENOSPC, errno.EACCES, errno.EIO):
                    self.assertFalse(cli_mod._is_closed_pipe(
                        OSError(number, "other")))

    def test_real_process_help_and_errors_with_the_reader_gone(self):
        # The real thing on this platform, for the paths the stdout test
        # above does not take: --help and --version leave through
        # SystemExit, and an error message goes to stderr.
        notrepo = tempfile.mkdtemp()
        cases = (("--help", ["--help"], "stdout", 0),
                 ("--version", ["--version"], "stdout", 0),
                 ("error message", ["--root", notrepo, "check"], "stderr", 2))
        for unbuffered in (False, True):
            for label, argv, gone, want in cases:
                with self.subTest(label, unbuffered=unbuffered):
                    env = dict(os.environ)
                    env["PYTHONPATH"] = os.pathsep.join(
                        p for p in (REPO, env.get("PYTHONPATH")) if p)
                    env.pop("PYTHONUNBUFFERED", None)
                    if unbuffered:
                        env["PYTHONUNBUFFERED"] = "1"
                    p = subprocess.Popen(
                        [sys.executable, "-m", "pr_verify", *argv],
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                        env=env)
                    closed, other = ((p.stdout, p.stderr) if gone == "stdout"
                                     else (p.stderr, p.stdout))
                    closed.close()
                    rest = other.read().decode("utf-8", "replace")
                    code = p.wait(timeout=120)
                    other.close()
                    self.assertEqual(rest, "")
                    self.assertEqual(code, want)


# ---------------------------------------------------------------------
# R4-9

class TestNothingToVerifyJson(unittest.TestCase):
    """`--format json` is for a program to read. A range with nothing to
    verify printed the sentence meant for people, and json.loads() failed
    on it."""

    def test_the_document_has_the_shape_of_every_other(self):
        tmp, base = make_pr_repo()
        for extra in ((), ("--fail-on", "never"), ("--fail-on", "any-risk"),
                      ("--min-score", "0")):
            with self.subTest(extra=extra):
                code, nothing = _json("--root", tmp, "check", "--base",
                                      "HEAD", "--skip-gates", *extra)
                _, full = _json("--root", tmp, "check", "--base", base,
                                "--skip-gates", *extra)
                self.assertEqual(code, 0)       # nothing to verify passes
                self.assertEqual(list(nothing), list(full))   # keys, in order
                self.assertEqual(list(nothing["risk"]), list(full["risk"]))
                self.assertEqual(list(nothing["risk"]["factors"]),
                                 list(full["risk"]["factors"]))
                self.assertEqual(nothing["min_score"], full["min_score"])
                self.assertEqual(nothing["version"], full["version"])

    def test_it_is_empty_and_it_passes(self):
        tmp, base = make_pr_repo()
        code, doc = _json("--root", tmp, "check", "--base", "HEAD",
                          "--skip-gates")
        self.assertEqual(code, 0)
        self.assertEqual((doc["tool"], doc["base"], doc["head"]),
                         ("pr-verify", "HEAD", "HEAD"))
        self.assertEqual((doc["files"], doc["blast_radius"], doc["gates"]),
                         ({}, {}, []))
        risk = doc["risk"]
        self.assertEqual((risk["score"], risk["band"], risk["requires_review"]),
                         (0, "low", False))
        self.assertEqual({f["points"] for f in risk["factors"].values()}, {0})

    def test_no_gate_runs_when_there_is_nothing_to_verify(self):
        tmp, base = make_pr_repo()
        commit_as(tmp, "Dan Calas", "dan@example.com", "gate",
                  {".pr-verify.yaml": f"gates:\n  - {yaml_str(FAIL_GATE)}\n"})
        code, doc = _json("--root", tmp, "check", "--base", "HEAD")
        self.assertEqual((code, doc["gates"]), (0, []))

    def test_notes_and_skipped_files_are_in_it(self):
        tmp, base = make_pr_repo()
        with open(os.path.join(tmp, "new.txt"), "w", encoding="utf-8") as f:
            f.write("x\n")                                   # untracked
        code, doc = _json("--root", tmp, "check", "--base", "HEAD",
                          "--skip-gates")
        self.assertEqual(doc["untracked_skipped"], ["new.txt"])
        self.assertTrue(any("untracked" in n for n in doc["notes"]),
                        doc["notes"])

    def test_the_human_report_still_says_it_in_words(self):
        tmp, base = make_pr_repo()
        code, out, err = _main("--root", tmp, "check", "--base", "HEAD",
                               "--skip-gates")
        self.assertEqual(code, 0)
        self.assertIn("nothing to verify", out)
        with self.assertRaises(ValueError):
            json.loads(out)

    def test_the_action_prints_the_same_document(self):
        tmp, base = make_pr_repo()
        out_file = os.path.join(tempfile.mkdtemp(), "gh_output")
        env = {"PR_VERIFY_ROOT": tmp, "PR_VERIFY_BASE": "HEAD",
               "PR_VERIFY_FORMAT": "json", "PR_VERIFY_SKIP_GATES": "true",
               "GITHUB_OUTPUT": out_file}
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = action_mod.main(environ=env)
        self.assertEqual(code, 0)
        doc = json.loads(buf.getvalue())
        self.assertEqual((doc["files"], doc["risk"]["score"]), ({}, 0))
        with open(out_file, encoding="utf-8") as f:
            self.assertEqual(f.read().splitlines(),
                             ["score=0", "band=low", "requires-review=false",
                              "exit-code=0"])


# ---------------------------------------------------------------------
# R4-10

ESC = "\x1b"
CSI = "\x9b"           # a C1 control: the one-character form of ESC [
BS = chr(92)           # a backslash


def _acted_on(text: str) -> list[str]:
    """What a terminal (or a log reader) would act on in text: C0 and C1
    controls and DEL apart from tab and newline, the Unicode line and
    paragraph separators, the bidirectional overrides and isolates."""
    return sorted({f"U+{ord(c):04X}" for c in text
                   if (ord(c) < 0x20 and c not in "\t\n")
                   or 0x7F <= ord(c) <= 0x9F
                   or ord(c) in (0x2028, 0x2029)
                   or 0x202A <= ord(c) <= 0x202E
                   or 0x2066 <= ord(c) <= 0x2069})


class TestNeutralize(unittest.TestCase):
    """The two functions every printed line passes through."""

    def test_the_escapes(self):
        n = cli_mod._neutralize
        self.assertEqual(n("a" + ESC + "[31mb"), "a\\x1b[31mb")
        self.assertEqual(n("\x00\x07\x08\x0b\x0c\r\x7f"),
                         "\\x00\\x07\\x08\\x0b\\x0c\\x0d\\x7f")
        self.assertEqual(n(CSI + "\x85\x80\x9f"), "\\x9b\\x85\\x80\\x9f")
        self.assertEqual(
            n(chr(0x2028) + chr(0x2029) + chr(0x202A) + chr(0x202E)
              + chr(0x2066) + chr(0x2069)),
            BS + "u2028" + BS + "u2029" + BS + "u202a" + BS + "u202e"
            + BS + "u2066" + BS + "u2069")

    def test_text_is_left_alone(self):
        text = ("a\tb\nc caf" + chr(0xE9) + " " + chr(0x39A) + chr(0x3B1)
                + " " + chr(0x4E2D) + chr(0x6587) + " " + chr(0x2713)
                + chr(0x2717) + " " + chr(0x2550) + chr(0x2026) + chr(0x2014)
                + " " + chr(0x1F600) + " " + chr(0xA0) + chr(0xA1) + chr(0xFF)
                + chr(0x200C) + chr(0x200D) + chr(0x200E) + chr(0xFEFF))
        self.assertEqual(cli_mod._neutralize(text), text)

    def test_exactly_what_a_terminal_acts_on_is_escaped(self):
        n = cli_mod._neutralize
        for cp in [*range(0x10000), 0x1F600, 0xE0001, 0x10FFFF]:
            ch = chr(cp)
            shown = n(ch)
            if _acted_on(ch):
                self.assertNotEqual(shown, ch, hex(cp))
                self.assertTrue(shown.isascii() and shown.isprintable(),
                                hex(cp))
            else:
                self.assertEqual(shown, ch, hex(cp))

    def test_one_line(self):
        one = cli_mod._one_line
        self.assertEqual(one("a\nb\tc" + ESC), "a\\x0ab\tc\\x1b")
        self.assertEqual(one("x" + chr(0x2028) + "y"), "x" + BS + "u2028y")
        # GitHub Actions reads a line that starts with :: (after any
        # indentation) as a workflow command
        self.assertEqual(one("::error::x"), "\\x3a:error::x")
        self.assertEqual(one("  ::error::x"), "  \\x3a:error::x")
        self.assertEqual(one("\n::error::x"), "\\x0a::error::x")
        self.assertEqual(one("a ::error::x"), "a ::error::x")


def _hostile_repo(path="app/x.py", author=None):
    """A PR from an agent whose name (and, when given, whose file name)
    carries terminal control characters."""
    return _range_with_commit(
        author or "claude" + ESC + "[31m-bot" + CSI, "claude-bot@example.com",
        "Agent change\n\n" + AGENT_TRAILER, {path: "a = 1\nb = 2\n"},
        base_files={"app/keep.py": "k = 1\n"})


class TestTerminalSafety(unittest.TestCase):
    """The report prints names the PR's author chose. A terminal acts on
    escape sequences in them (recolor, move the cursor, rewrite the line
    with a carriage return); a newline starts a line of its own, which can
    forge a verdict, or in a GitHub Actions log a `::command::`. The
    terminal sees them escaped; the JSON keeps the exact text."""

    def human(self, tmp, base, *extra):
        code, out, err = _main("--root", tmp, "check", "--base", base,
                               "--skip-gates", *extra)
        self.assertEqual(err, "")
        return code, out

    def assertTidy(self, out):
        """Nothing a terminal acts on, and no line that an Actions log would
        read as a workflow command."""
        self.assertEqual(_acted_on(out), [])
        self.assertEqual([ln for ln in out.split("\n")
                          if ln.lstrip().startswith("::")], [])

    def test_author_names_in_the_report(self):
        tmp, base = _hostile_repo()
        code, out = self.human(tmp, base)
        self.assertTidy(out)
        self.assertIn("[claude\\x1b[31m-bot\\x9b (claude)]", out)
        # the exact text is in the JSON, which json.dumps escapes itself
        code, doc = _json("--root", tmp, "check", "--base", base,
                          "--skip-gates")
        self.assertEqual(doc["files"]["app/x.py"]["agents"],
                         ["claude" + ESC + "[31m-bot" + CSI + " (claude)"])

    @unittest.skipIf(os.name == "nt", "Windows file names cannot hold these")
    def test_file_names_cannot_forge_report_lines(self):
        name = ("app/x" + ESC + "[2J\n::error::forged\n"
                "  OK score 1 < min-score 70\r.py")
        tmp, base = _hostile_repo(name)
        twin, twin_base = _hostile_repo()
        code, out = self.human(tmp, base)
        _, plain = self.human(twin, twin_base)
        self.assertTidy(out)
        # the report has the lines of the one for a tame name: the name
        # did not add any
        self.assertEqual(len(out.split("\n")), len(plain.split("\n")))
        self.assertIn("app/x\\x1b[2J\\x0a::error::forged\\x0a  OK score 1 "
                      "< min-score 70\\x0d.py", out)
        code, doc = _json("--root", tmp, "check", "--base", base,
                          "--skip-gates")
        self.assertIn(name, doc["files"])                   # exact
        self.assertIn(name, doc["blast_radius"])

    @unittest.skipIf(os.name == "nt", "Windows file names cannot hold these")
    def test_a_name_that_starts_with_colons(self):
        # the blast-radius line starts with the file's name
        tmp, base = _hostile_repo("::error::boom.py")
        code, out = self.human(tmp, base)
        self.assertTidy(out)
        self.assertIn("    \\x3a:error::boom.py: 0 downstream", out)
        code, doc = _json("--root", tmp, "check", "--base", base,
                          "--skip-gates")
        self.assertIn("::error::boom.py", doc["blast_radius"])

    @unittest.skipIf(os.name == "nt", "Windows file names cannot hold these")
    def test_deleted_and_untracked_names(self):
        gone = "gone" + ESC + "[31m\n::notice::x.py"
        new = "new" + ESC + "[2J\n::warning::y.txt"
        tmp = tempfile.mkdtemp()
        git(tmp, "init", "-qb", "main")
        commit_as(tmp, "Dan Calas", "dan@example.com", "base",
                  {gone: "g = 1\n", "app/keep.py": "k = 1\n"})
        base = _sha(tmp)
        os.remove(os.path.join(tmp, gone))
        git(tmp, "add", "-A")
        git(tmp, "-c", "user.name=claude-bot",
            "-c", "user.email=claude-bot@example.com",
            "commit", "-qm", "Drop it\n\n" + AGENT_TRAILER)
        with open(os.path.join(tmp, new), "w", encoding="utf-8") as f:
            f.write("y\n")                                   # untracked
        code, out = self.human(tmp, base)
        self.assertTidy(out)
        self.assertIn("deleted  gone\\x1b[31m\\x0a::notice::x.py "
                      "(deleted by claude-bot)", out)
        self.assertIn("not verified (new\\x1b[2J\\x0a::warning::y.txt)", out)

    @unittest.skipIf(os.name == "nt", "Windows file names cannot hold these")
    def test_the_nothing_to_verify_report(self):
        tmp, base = make_pr_repo()
        with open(os.path.join(tmp, "new" + ESC + "[2J\n::notice::x.txt"),
                  "w", encoding="utf-8") as f:
            f.write("x\n")                                   # untracked
        code, out = self.human(tmp, "HEAD")
        self.assertEqual(code, 0)
        self.assertIn("nothing to verify", out)
        self.assertTidy(out)
        self.assertIn("(new\\x1b[2J\\x0a::notice::x.txt)", out)

    @unittest.skipIf(os.name == "nt", "Windows file names cannot hold these")
    def test_the_branch_a_clone_names_as_the_base(self):
        # origin/HEAD names the remote's default branch, a name the remote
        # chose (git allows C1 controls and bidi overrides in ref names)
        tmp, base = _hostile_repo()
        ref = "refs/remotes/origin/trunk" + CSI + chr(0x202E)
        git(tmp, "update-ref", ref, base)
        git(tmp, "symbolic-ref", "refs/remotes/origin/HEAD", ref)
        code, out, err = _main("--root", tmp, "check", "--skip-gates")
        self.assertTidy(out)
        self.assertIn("base: origin/trunk\\x9b" + BS + "u202e  (auto-detected)",
                      out)

    @unittest.skipIf(os.name == "nt", "Windows file names cannot hold these")
    def test_init_names_the_directory_it_wrote_to(self):
        tmp = tempfile.mkdtemp(suffix=ESC + "[2J")
        git(tmp, "init", "-qb", "main")
        os.mkdir(os.path.join(tmp, "sub"))
        code, out, err = _main("--root", os.path.join(tmp, "sub"), "init")
        self.assertEqual(code, 0)
        self.assertTidy(out)
        self.assertIn("at the repository root (", out)
        self.assertIn("\\x1b[2J)", out)

    def test_gate_commands(self):
        command = FAIL_GATE + " " + shlex.quote(ESC + "[31m")
        tmp, old_base = make_pr_repo()
        base = commit_at_new_base(
            tmp, old_base,
            {".pr-verify.yaml": f"gates:\n  - {yaml_str(command)}\n"})
        code, out, err = _main("--root", tmp, "check", "--base", base)
        self.assertEqual(code, 1)
        self.assertTidy(out)
        self.assertIn("[FAIL] ", out)
        self.assertIn("\\x1b[31m", out)              # the command, visibly

    def test_the_action_prints_the_same(self):
        tmp, base = _hostile_repo()
        env = {"PR_VERIFY_ROOT": tmp, "PR_VERIFY_BASE": base,
               "PR_VERIFY_SKIP_GATES": "true"}
        buf = io.StringIO()
        with redirect_stdout(buf):
            action_mod.main(environ=env)
        self.assertTidy(buf.getvalue())
        self.assertIn("[claude\\x1b[31m-bot\\x9b (claude)]", buf.getvalue())

    def test_error_messages(self):
        err = io.StringIO()
        with redirect_stderr(err):
            cli_mod._eprint("error: x" + ESC + "[2J\n::error::y" + CSI)
        self.assertEqual(err.getvalue(),
                         "error: x\\x1b[2J\\x0a::error::y\\x9b\n")

    def test_every_print_is_neutralised_or_json(self):
        # cli._out and cli._eprint are the ways onto the terminal; the JSON
        # document is the one thing printed as it is. A bare print()
        # somewhere else would skip the escaping.
        allowed = {("cli.py", "_out"), ("cli.py", "_eprint"),
                   ("cli.py", "render"), ("cli.py", "cmd_trend")}  # JSON
        stray = []

        def walk(node, module, func):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                func = node.name
            if (isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Name)
                    and node.func.id == "print"
                    and (module, func) not in allowed):
                stray.append(f"{module}:{node.lineno} in {func}()")
            for child in ast.iter_child_nodes(node):
                walk(child, module, func)

        package = os.path.join(REPO, "pr_verify")
        for module in sorted(os.listdir(package)):
            if module.endswith(".py"):
                with open(os.path.join(package, module), "rb") as f:
                    walk(ast.parse(f.read()), module, None)
        self.assertEqual(stray, [])


# ---------------------------------------------------------------------
# R4-11

class TestNoInvisibleCharacters(unittest.TestCase):
    """A verifier's own files must read as they are: a bidirectional
    override or a zero-width character can hide what a line does."""

    INVISIBLE = {0xFEFF, 0x2028, 0x2029, 0x2060, 0x061C, 0x180E,
                 *range(0x200B, 0x2010), *range(0x202A, 0x202F),
                 *range(0x2061, 0x2065), *range(0x2066, 0x206A)}

    def test_repository_files(self):
        # the files that are in the repository or would be: not whatever
        # else is lying in the checkout (a virtualenv, a build directory)
        p = subprocess.run(["git", "-C", REPO, "ls-files", "-z", "--cached",
                            "--others", "--exclude-standard"],
                           capture_output=True)
        if p.returncode != 0:
            self.skipTest("not a git checkout")
        found, scanned = [], []
        for raw in filter(None, p.stdout.split(b"\0")):
            rel = os.fsdecode(raw)
            try:
                with open(os.path.join(REPO, rel), "rb") as f:
                    text = f.read().decode("utf-8")
            except (UnicodeDecodeError, OSError):
                continue                       # not text, or not there
            scanned.append(rel)
            for number, line in enumerate(text.split("\n"), 1):
                for ch in line:
                    if ord(ch) in self.INVISIBLE:
                        found.append(f"{rel}:{number}: U+{ord(ch):04X}")
        self.assertIn("pr_verify/cli.py", scanned)       # it did look
        self.assertEqual(found, [])


if __name__ == "__main__":
    unittest.main()
