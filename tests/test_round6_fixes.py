"""Round-6 panel regressions (second verification panel, 2026-10-18).

V1  A human's removed lines were credited to the agent whenever an agent
    commit also took out lines the PR itself had added: the agent's removals
    were capped at what the file lost in all, and its own churn filled the
    cap.

V2  A UTF-8 byte-order mark in .pr-verify.yaml (PowerShell's
    `Set-Content -Encoding utf8`) was read as part of the first key; UTF-16
    text (PowerShell's `>`) gave a screenful of NULs; a list at the indent of
    its key gave "list item inside mapping" without saying what to change;
    and a config that is a bare list ended in a traceback, exit 1.

V3  A blame.ignoreRevsFile in the git configuration that names a file which
    is not there (a setting copied from another machine) stopped every check
    with exit 2 ("could not open object name list"), `--ignore-revs-file=`
    notwithstanding: that option is applied after git has opened the
    configured files. `--no-ignore-revs-file` drops the list first.

V4  The Action documents an `exit-code` output (0 pass, 1 fail, 2 error)
    but wrote it only when the check itself ran: an input the CLI refuses
    (--fail-on, --min-score, --format) and a root that is not a repository
    left through argparse's or the repository check's exit 2 with the output
    file untouched, and a GITHUB_OUTPUT that could not be written ended in a
    traceback and exit 1, the code for a failed check.

V5  (found while reading the same code) A file or process error that stopped
    `check` (a full disk under the snapshot of uncommitted changes, a git
    that could not be started) or `init` (a read-only repository) ended in a
    traceback and exit 1, the code for a failed verification; it is a run
    that could not verify: one `error:` line and exit 2.

Fixtures are throwaway git repos (see fixture.py); nothing touches the
network, HOME or the real git configuration.
"""

import builtins
import contextlib
import errno
import io
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

from pr_verify import action as action_mod
from pr_verify import cli as cli_mod
from pr_verify import config as config_mod
from pr_verify import provenance as pv

from fixture import commit_as, git

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
AGENT = ("claude-bot", "claude-bot@example.com")
HUMAN = ("Dan Calas", "dan@example.com")
IDENTITY = ("-c", "user.name=Dan Calas", "-c", "user.email=dan@example.com")

_TEMP_DIRS: list[str] = []


def _new_dir(prefix: str = "prv-r6-") -> str:
    """A temp directory that tearDownModule removes again."""
    path = tempfile.mkdtemp(prefix=prefix)
    _TEMP_DIRS.append(path)
    return path


def tearDownModule():
    for path in _TEMP_DIRS:
        # git's object files are read-only, which Windows will not delete
        for dirpath, _dirs, names in os.walk(path):
            for name in names:
                with contextlib.suppress(OSError):
                    os.chmod(os.path.join(dirpath, name),
                             stat.S_IWRITE | stat.S_IREAD)
        shutil.rmtree(path, ignore_errors=True)
    del _TEMP_DIRS[:]


def rev(tmp, ref="HEAD") -> str:
    return subprocess.run(["git", "-C", tmp, "rev-parse", ref], check=True,
                          capture_output=True, text=True,
                          encoding="utf-8").stdout.strip()


def main(*argv, cwd=None):
    """cli.main(argv) in this process: (exit code, stdout, stderr)."""
    out, err = io.StringIO(), io.StringIO()
    with contextlib.ExitStack() as stack:
        if cwd:
            old = os.getcwd()
            os.chdir(cwd)
            stack.callback(os.chdir, old)
        stack.enter_context(redirect_stdout(out))
        stack.enter_context(redirect_stderr(err))
        code = cli_mod.main(list(argv))
    return code, out.getvalue(), err.getvalue()


def check_json(tmp, *extra):
    code, out, err = main("--root", tmp, "check", "--skip-gates",
                          "--format", "json", *extra)
    return code, json.loads(out), err


def lines(*numbers, prefix="line"):
    return "".join(f"{prefix}_{n} = {n}\n" for n in numbers)


def agent_commit(tmp, files, message="Tidy"):
    commit_as(tmp, *AGENT, message + "\n\nCo-authored-by: Claude", files)


def human_commit(tmp, files, message="Tidy by hand"):
    commit_as(tmp, *HUMAN, message, files)


# ---------------------------------------------------------------------
# V1 - an agent is credited only for lines the base had

MOD = "lib/mod.py"
BASE100 = lines(*range(100))
#: the base without its first ten lines
TAIL90 = lines(*range(10, 100))


def make_mod_repo(history=True):
    """main: lib/mod.py with 100 lines. HEAD is a branch `pr` that leaves
    main at that commit. Returns (tmp, base).

    The base is not the repository's first commit, as it never is in a real
    one, and the file's lines come from the base and from a commit before it
    that is no root commit either. (Git marks the lines of a root commit as
    older than the range even without being told where the range starts; it
    is with a base that has history that the range has to be told.)
    `history=False` is the other case, a base that is the first commit."""
    tmp = _new_dir()
    git(tmp, "init", "-qb", "main")
    if history:
        commit_as(tmp, *HUMAN, "first", {"README.md": "# lib\n"})
        commit_as(tmp, *HUMAN, "second", {MOD: lines(*range(70))})
    commit_as(tmp, *HUMAN, "base", {MOD: BASE100, "lib/util.py": "u = 1\n"})
    base = rev(tmp)
    git(tmp, "checkout", "-q", "-b", "pr")
    return tmp, base


def entry(tmp, *extra, path=MOD):
    return check_json(tmp, *extra)[1]["files"][path]


def removal_blames(tmp, base):
    """(the file's entry, the arguments of each `git blame` that asks who
    wrote lines a commit removed: the ones with the range's `^base`)."""
    seen = []
    real = pv._git

    def spy(root, *args, **kw):
        if args[0] == "blame" and f"^{base}" in args:
            seen.append(args)
        return real(root, *args, **kw)
    with mock.patch.object(pv, "_git", spy):
        f = entry(tmp, "--base", base)
    return f, seen


class TestAgentIsCreditedForTheBasesLinesOnly(unittest.TestCase):
    """A human removed ten lines; an agent added twenty of its own and a
    later commit of its took them out again. The file lost ten lines in all
    and the agent's commit removed twenty, so the ten were credited to the
    agent: 10/10 agent, score 45 instead of 5."""

    def test_the_panels_repro_scores_like_the_human_only_control(self):
        control, base = make_mod_repo()
        human_commit(control, {MOD: TAIL90}, "drop 10 old lines")
        _, want, _ = check_json(control, "--base", base)

        tmp, base = make_mod_repo()
        human_commit(tmp, {MOD: TAIL90}, "drop 10 old lines")
        agent_commit(tmp, {MOD: TAIL90 + lines(*range(20), prefix="agent")},
                     "add feature")
        agent_commit(tmp, {MOD: TAIL90}, "tidy up")
        _, got, _ = check_json(tmp, "--base", base)
        f = got["files"][MOD]
        self.assertEqual((f["removed"], f["agent_removed"], f["label"]),
                         (10, 0, "human"))
        self.assertEqual(f["agents"], [])
        self.assertEqual(got["files"], want["files"])
        self.assertEqual(got["risk"], want["risk"])
        self.assertEqual(got["risk"]["factors"]["agent_share"]["points"], 0)

    def test_a_base_that_is_the_first_commit_works_too(self):
        # the same two cases when the base has no history
        tmp, base = make_mod_repo(history=False)
        human_commit(tmp, {MOD: TAIL90}, "drop 10 old lines")
        agent_commit(tmp, {MOD: TAIL90 + lines(*range(20), prefix="agent")},
                     "add feature")
        agent_commit(tmp, {MOD: lines(*range(10, 50), *range(55, 100))},
                     "tidy up")
        f = entry(tmp, "--base", base)
        self.assertEqual((f["removed"], f["agent_removed"]), (15, 5))

    def test_a_base_line_counts_wherever_it_came_from(self):
        # lines of the first commit, of one in between (an agent's) and of
        # the base itself are all the base's: whoever wrote them
        tmp = _new_dir()
        git(tmp, "init", "-qb", "main")
        commit_as(tmp, *HUMAN, "first", {MOD: lines(*range(30))})
        agent_commit(tmp, {MOD: lines(*range(60))}, "second")
        commit_as(tmp, *HUMAN, "base", {MOD: lines(*range(90))})
        base = rev(tmp)
        git(tmp, "checkout", "-q", "-b", "pr")
        human_commit(tmp, {MOD: lines(*range(90))
                           + lines(*range(3), prefix="h")}, "add three")
        agent_commit(tmp, {MOD: lines(*range(5), *range(10, 35),
                                      *range(40, 65), *range(70, 90))
                           + lines(*range(3), prefix="h")}, "tidy up")
        f = entry(tmp, "--base", base)
        # 5..9 (the first commit's), 35..39 (the agent's own, earlier),
        # 65..69 (the base's)
        self.assertEqual((f["removed"], f["agent_removed"]), (15, 15))

    def test_the_agents_own_removal_next_to_the_churn_is_still_counted(self):
        tmp, base = make_mod_repo()
        human_commit(tmp, {MOD: TAIL90}, "drop 10 old lines")
        agent_commit(tmp, {MOD: TAIL90 + lines(*range(20), prefix="agent")},
                     "add feature")
        # takes its own twenty lines out again and five of the base's
        agent_commit(tmp, {MOD: lines(*range(10, 50), *range(55, 100))},
                     "tidy up")
        f = entry(tmp, "--base", base)
        self.assertEqual((f["removed"], f["agent_removed"], f["label"]),
                         (15, 5, "mixed"))
        self.assertEqual(f["agents"], ["claude-bot (claude)"])

    def test_the_other_order_is_the_same(self):
        # the agent churns first, the human removes afterwards
        tmp, base = make_mod_repo()
        agent_commit(tmp, {MOD: BASE100 + lines(*range(20), prefix="agent")},
                     "add feature")
        agent_commit(tmp, {MOD: lines(*range(5), *range(10, 100))},
                     "tidy up")                      # drops base 5..9 only
        human_commit(tmp, {MOD: lines(*range(10, 100))}, "drop 5 more")
        f = entry(tmp, "--base", base)
        self.assertEqual((f["removed"], f["agent_removed"]), (10, 5))

    def test_an_agent_taking_out_a_humans_new_lines_removes_nothing(self):
        tmp, base = make_mod_repo()
        human_commit(tmp, {MOD: TAIL90}, "drop 10 old lines")
        human_commit(tmp, {MOD: TAIL90 + lines(*range(5), prefix="human")},
                     "add five")
        agent_commit(tmp, {MOD: TAIL90}, "revert the five")
        f = entry(tmp, "--base", base)
        self.assertEqual((f["added"], f["removed"], f["agent_removed"],
                          f["label"]), (0, 10, 0, "human"))

    def test_a_line_a_human_rewrote_was_taken_out_by_the_human(self):
        # the base's line_3 is gone because the human changed it; the agent
        # changed the human's version, which is not a base line
        tmp, base = make_mod_repo()
        human_commit(tmp, {MOD: BASE100.replace("line_3 = 3\n",
                                                "line_3 = 33\n")}, "tweak")
        agent_commit(tmp, {MOD: BASE100.replace("line_3 = 3\n",
                                                "line_3 = 333\n")}, "tweak")
        f = entry(tmp, "--base", base)
        self.assertEqual((f["added"], f["agent_added"]), (1, 1))
        self.assertEqual((f["removed"], f["agent_removed"]), (1, 0))

    def test_a_line_the_agent_rewrote_twice_is_one_removal(self):
        tmp, base = make_mod_repo()
        agent_commit(tmp, {MOD: BASE100.replace("line_3 = 3\n",
                                                "line_3 = 33\n")}, "tweak")
        agent_commit(tmp, {MOD: BASE100.replace("line_3 = 3\n",
                                                "line_3 = 333\n")}, "again")
        f = entry(tmp, "--base", base)
        self.assertEqual((f["added"], f["agent_added"]), (1, 1))
        self.assertEqual((f["removed"], f["agent_removed"]), (1, 1))

    def test_the_right_lines_are_looked_at(self):
        # lines shift when something is inserted: a removal must be judged
        # by where the line was, not by where it is now
        tmp, base = make_mod_repo()
        dropped = {"line_10 = 10\n", "line_11 = 11\n", "line_12 = 12\n"}
        mine = lines(*range(3), prefix="h") + "".join(
            ln for ln in BASE100.splitlines(True) if ln not in dropped)
        human_commit(tmp, {MOD: mine},
                     "three of the base's lines out, three of its own in")
        # the agent takes out one of the human's new lines and three of the
        # base's: the first, one in the middle and the last
        gone = {"h_1 = 1\n", "line_0 = 0\n", "line_50 = 50\n",
                "line_99 = 99\n"}
        agent_commit(tmp, {MOD: "".join(ln for ln in mine.splitlines(True)
                                        if ln not in gone)}, "tidy up")
        f = entry(tmp, "--base", base)
        self.assertEqual((f["added"], f["agent_added"]), (2, 0))
        self.assertEqual(f["removed"], 6)
        self.assertEqual(f["agent_removed"], 3)

    def test_a_base_that_moved_on_changes_nothing(self):
        tmp, base = make_mod_repo()
        human_commit(tmp, {MOD: TAIL90}, "drop 10 old lines")
        agent_commit(tmp, {MOD: TAIL90 + lines(*range(20), prefix="agent")},
                     "add feature")
        agent_commit(tmp, {MOD: TAIL90}, "tidy up")
        git(tmp, "checkout", "-q", "main")
        human_commit(tmp, {"lib/util.py": "u = 1\nv = 2\n"}, "main moves on")
        git(tmp, "checkout", "-q", "pr")
        code, data, _ = check_json(tmp, "--base", "main")
        self.assertEqual(data["merge_base"], base)
        f = data["files"][MOD]
        self.assertEqual((f["removed"], f["agent_removed"]), (10, 0))
        self.assertEqual(list(data["files"]), [MOD])

    def test_a_merged_side_branch(self):
        tmp, base = make_mod_repo()
        git(tmp, "checkout", "-q", "-b", "side", base)
        agent_commit(tmp, {MOD: BASE100 + lines(*range(4), prefix="agent")},
                     "add four")
        agent_commit(tmp, {MOD: lines(*range(50), *range(55, 100))},
                     "tidy up")                   # its own four and base 50..54
        git(tmp, "checkout", "-q", "pr")
        human_commit(tmp, {MOD: TAIL90}, "drop 10 old lines")
        git(tmp, *IDENTITY, "merge", "-q", "--no-ff", "-m", "Merge side",
            "side")
        f = entry(tmp, "--base", base)
        self.assertEqual((f["removed"], f["agent_removed"]), (15, 5))

    def test_a_renamed_file_is_followed(self):
        old, new = "app/old.py", "app/new.py"
        text = lines(*range(30))
        kept = lines(*range(8), *range(13, 30))      # five lines out
        # renamed by a human first, the agent removes afterwards ...
        tmp = _new_dir()
        git(tmp, "init", "-qb", "main")
        commit_as(tmp, *HUMAN, "base", {old: text})
        base = rev(tmp)
        git(tmp, "mv", old, new)
        human_commit(tmp, {}, "rename")
        agent_commit(tmp, {new: kept}, "remove five")
        f = entry(tmp, "--base", base, path=new)
        self.assertEqual((f["removed"], f["agent_removed"]), (5, 5))
        # ... or in the very commit that renames it, with something in
        # between that the file's old name has to be looked up behind
        tmp = _new_dir()
        git(tmp, "init", "-qb", "main")
        commit_as(tmp, *HUMAN, "base", {old: text})
        base = rev(tmp)
        human_commit(tmp, {"app/other.py": "o = 1\n"}, "something else")
        git(tmp, "mv", old, new)
        agent_commit(tmp, {new: kept}, "rename and remove five")
        f = entry(tmp, "--base", base, path=new)
        self.assertEqual((f["removed"], f["agent_removed"]), (5, 5))

    def test_a_submodule_pointer_a_human_moved_is_not_the_agents(self):
        tmp, base = make_submodule_repo((HUMAN, "2"), (AGENT, "3"))
        f = entry(tmp, "--base", base, path="vendor/lib")
        self.assertEqual((f["added"], f["agent_added"]), (1, 1))
        self.assertEqual((f["removed"], f["agent_removed"]), (1, 0))

    def test_a_submodule_pointer_the_agent_moves_twice_is_one_removal(self):
        tmp, base = make_submodule_repo((AGENT, "2"), (AGENT, "3"))
        f = entry(tmp, "--base", base, path="vendor/lib")
        self.assertEqual((f["removed"], f["agent_removed"]), (1, 1))

    def test_more_hunks_than_a_command_line_holds(self):
        # the ranges of one commit go on the command line (8191 characters on
        # Windows); when they do not fit, the whole file is blamed. A tiny
        # budget forces that here
        base_text = lines(*range(200))
        tmp = _new_dir()
        git(tmp, "init", "-qb", "main")
        commit_as(tmp, *HUMAN, "base", {MOD: base_text})
        base = rev(tmp)
        human_commit(tmp, {MOD: lines(*range(2, 200))}, "drop two")
        agent_commit(tmp, {MOD: lines(*range(2, 200)) + lines(*range(10),
                                                               prefix="own")},
                     "add ten")
        # takes the ten out and every fifth base line (hunks far apart)
        every_fifth = lines(*(n for n in range(2, 200) if n % 5))
        agent_commit(tmp, {MOD: every_fifth}, "tidy up")
        want = len([n for n in range(2, 200) if n % 5 == 0])
        with mock.patch.object(pv, "_BLAME_BUDGET", 12):
            f, blames = removal_blames(tmp, base)
        self.assertEqual((f["removed"], f["agent_removed"]), (2 + want, want))
        self.assertEqual(len(blames), 1)
        self.assertEqual([a for a in blames[0] if a.startswith("-L")], [])

    def test_blame_is_asked_about_the_removed_lines_only(self):
        tmp, base = make_mod_repo()
        human_commit(tmp, {MOD: TAIL90}, "drop 10 old lines")
        # the base's line_n is line n-9 of TAIL90: the agent takes out
        # line_30..32 and line_60
        agent_commit(tmp, {MOD: lines(*range(10, 30), *range(33, 60),
                                      *range(61, 100))}, "tidy up")
        f, blames = removal_blames(tmp, base)
        self.assertEqual((f["removed"], f["agent_removed"]), (14, 4))
        self.assertEqual(len(blames), 1)
        self.assertEqual([a for a in blames[0] if a.startswith("-L")],
                         ["-L21,23", "-L51,51"])

    def test_blame_that_leaves_a_line_out_is_an_error_not_a_guess(self):
        tmp, base = make_mod_repo()
        human_commit(tmp, {MOD: TAIL90}, "drop 10 old lines")
        agent_commit(tmp, {MOD: lines(*range(10, 50), *range(55, 100))},
                     "drop five")
        with mock.patch.object(pv, "_parse_blame",
                               lambda out: ({}, set())):
            code, out, err = main("--root", tmp, "check", "--skip-gates",
                                  "--base", base)
        self.assertEqual(code, 2, err)
        one_error_line(self, err, "git blame did not name the commit of line",
                       MOD, "refusing to guess")

    def test_a_commit_on_the_merge_base_asks_nothing_of_blame(self):
        # nothing lies between the base and the commit: every line it takes
        # out is the base's, and git is not asked
        tmp, base = make_mod_repo()
        agent_commit(tmp, {MOD: lines(*range(10, 100))}, "drop ten")
        seen = []
        real = pv._git

        def spy(root, *args, **kw):
            seen.append(args[0])
            return real(root, *args, **kw)
        with mock.patch.object(pv, "_git", spy):
            f = entry(tmp, "--base", base)
        self.assertEqual((f["removed"], f["agent_removed"]), (10, 10))
        self.assertNotIn("blame", seen)

    def test_one_blame_per_file_and_commit_that_needs_one(self):
        tmp, base = make_mod_repo()
        human_commit(tmp, {MOD: TAIL90}, "drop 10 old lines")
        agent_commit(tmp, {MOD: TAIL90 + lines(*range(20), prefix="agent")},
                     "add feature")
        agent_commit(tmp, {MOD: TAIL90}, "tidy up")
        seen = []
        real = pv._git

        def spy(root, *args, **kw):
            seen.append(args[0])
            return real(root, *args, **kw)
        with mock.patch.object(pv, "_git", spy):
            entry(tmp, "--base", base)
        # the second agent commit's parent is not the base: one blame; the
        # first agent commit removed nothing
        self.assertEqual(seen.count("blame"), 1)

    # `git rev-list --parents -- <paths>` shows a commit's parent as seen by
    # the history of those paths: the nearest commit that touched them, not
    # the commit before it. What the agent commit changed is what it changed
    # to its real parent's version.

    def test_a_removal_that_came_before_the_agents_rename_is_not_the_agents(
            self):
        old, new = "app/old.py", "app/new.py"
        tmp = _new_dir()
        git(tmp, "init", "-qb", "main")
        commit_as(tmp, *HUMAN, "base", {old: lines(*range(30))})
        base = rev(tmp)
        # a human takes three lines out of the old name (the history of the
        # new name does not see this commit) ...
        human_commit(tmp, {old: lines(*range(3), *range(6, 30))}, "drop 3")
        # ... and the agent renames the file and takes two more out
        git(tmp, "mv", old, new)
        agent_commit(tmp, {new: lines(*range(3), *range(6, 20),
                                      *range(22, 30))},
                     "rename and drop 2")
        f = entry(tmp, "--base", base, path=new)
        self.assertEqual((f["removed"], f["agent_removed"], f["label"]),
                         (5, 2, "mixed"))

    def test_a_file_whose_other_files_fall_into_other_batches(self):
        # many files with removals are asked about in batches; the answer for
        # one commit must not depend on which batch came last
        tmp = _new_dir()
        git(tmp, "init", "-qb", "main")
        a, b = "lib/a.py", "lib/b.py"
        commit_as(tmp, *HUMAN, "base", {a: lines(*range(30)),
                                        b: lines(*range(30))})
        base = rev(tmp)
        human_commit(tmp, {a: lines(*range(3), *range(6, 30))}, "drop 3 of a")
        agent_commit(tmp, {a: lines(*range(3), *range(6, 20),
                                    *range(22, 30)),
                           b: lines(*range(10), *range(12, 30))},
                     "drop 2 of a and 2 of b")
        with mock.patch.object(pv, "_PATHSPEC_BUDGET", 10):
            got = check_json(tmp, "--base", base)[1]["files"]
        self.assertEqual((got[a]["removed"], got[a]["agent_removed"]), (5, 2))
        self.assertEqual((got[b]["removed"], got[b]["agent_removed"]), (2, 2))

    def test_the_commits_come_with_their_own_parents(self):
        # two histories of their own, joined by a merge and unrelated to the
        # base. For a commit that has no parent git prints no line of
        # parents: the header of the next commit must not swallow it. The
        # dates put one such commit between the others.
        tmp = _new_dir()
        git(tmp, "init", "-qb", "main")
        commit_as(tmp, *HUMAN, "base", {"a.py": "a = 1\n"})
        base = rev(tmp)
        made = {}

        def at(day, name, text):
            stamp = f"2020-01-0{day}T00:00:00+0000"
            with mock.patch.dict(os.environ, {"GIT_AUTHOR_DATE": stamp,
                                              "GIT_COMMITTER_DATE": stamp}):
                human_commit(tmp, {"f.py": text}, name)
            made[name] = rev(tmp)

        git(tmp, "checkout", "-q", "--orphan", "x")
        git(tmp, "rm", "-rfq", ".")
        at(1, "x1", "x = 1\n")
        at(4, "x2", "x = 2\n")
        git(tmp, "checkout", "-q", "--orphan", "y")
        git(tmp, "rm", "-rfq", ".")
        at(2, "y1", "y = 1\n")
        at(3, "y2", "y = 2\n")
        git(tmp, *IDENTITY, "merge", "-q", "--allow-unrelated-histories",
            "-s", "ours", "x", "-m", "join")
        self.assertEqual(
            pv._commits_touching(tmp, base, "HEAD", ["f.py"]),
            sorted([(made["x1"], None), (made["x2"], made["x1"]),
                    (made["y1"], None), (made["y2"], made["y1"])]))


class TestWhatTheReadmeCallsApproximate(unittest.TestCase):
    """The README names two things that stay approximate. They are pinned
    here, so the sentence and the behaviour change together."""

    def test_a_base_line_put_back_still_counts_for_the_agent(self):
        tmp, base = make_mod_repo()
        agent_commit(tmp, {MOD: lines(*range(50), *range(55, 100))},
                     "drop five")
        human_commit(tmp, {MOD: BASE100}, "put them back")
        human_commit(tmp, {MOD: TAIL90}, "drop ten")
        f = entry(tmp, "--base", base)
        self.assertEqual(f["removed"], 10)          # the ten, all the human's
        self.assertEqual(f["agent_removed"], 5)     # the cap is per file

    def test_removals_from_a_file_renamed_later_read_as_human(self):
        old, new = "app/old.py", "app/new.py"
        tmp = _new_dir()
        git(tmp, "init", "-qb", "main")
        commit_as(tmp, *HUMAN, "base", {old: lines(*range(30))})
        base = rev(tmp)
        agent_commit(tmp, {old: lines(*range(8), *range(13, 30))},
                     "remove five")
        git(tmp, "mv", old, new)
        human_commit(tmp, {}, "rename")
        f = entry(tmp, "--base", base, path=new)
        self.assertEqual((f["removed"], f["agent_removed"]), (5, 0))

    def test_the_readme_says_both(self):
        with open(os.path.join(REPO, "README.md"), encoding="utf-8") as f:
            readme = " ".join(f.read().split())
        self.assertIn("Only a line the base already had counts", readme)
        self.assertIn("a base line an agent removed and someone put back "
                      "still counts for the agent", readme)
        self.assertIn("removals from a file that is renamed later in the PR "
                      "read as human", readme)
        # the Limitations list says the same, and not the older "agent
        # commits that remove each other's lines" (they earn nothing now)
        self.assertIn("can still count for the agent, so the agent's "
                      "removal count is an upper bound", readme)
        self.assertNotIn("remove each other's lines", readme)


def make_submodule_repo(*bumps):
    """main: a human commit with app/a.py and a submodule at vendor/lib (not
    populated: an empty directory, the pointer set by hand). Then one commit
    per (author, digit) in `bumps`, each moving the pointer to <digit> * 40.
    Returns (tmp, base)."""
    tmp = _new_dir()
    git(tmp, "init", "-qb", "main")
    os.makedirs(os.path.join(tmp, "vendor", "lib"))
    git(tmp, "update-index", "--add", "--cacheinfo",
        f"160000,{'1' * 40},vendor/lib")
    commit_as(tmp, *HUMAN, "base", {"app/a.py": "x = 1\n"})
    base = rev(tmp)
    for who, digit in bumps:
        git(tmp, "update-index", "--cacheinfo",
            f"160000,{digit * 40},vendor/lib")
        message = "Bump vendor/lib"
        if who == AGENT:
            message += "\n\nCo-authored-by: Claude"
        commit_as(tmp, *who, message, {})
    return tmp, base


# ---------------------------------------------------------------------
# V2 - the config file: BOM, UTF-16, the list layout, a file that is a list

def repo_with_config(raw: bytes):
    """A repository whose base commit holds .pr-verify.yaml with exactly
    these bytes, and a branch `pr` that adds a line. Returns (tmp, base)."""
    tmp = _new_dir()
    git(tmp, "init", "-qb", "main")
    with open(os.path.join(tmp, ".pr-verify.yaml"), "wb") as f:
        f.write(raw)
    commit_as(tmp, *HUMAN, "base", {"app.py": "x = 1\n"})
    base = rev(tmp)
    git(tmp, "checkout", "-q", "-b", "pr")
    commit_as(tmp, *HUMAN, "more", {"app.py": "x = 1\ny = 2\n"})
    return tmp, base


def check_config(raw: bytes, *extra):
    tmp, base = repo_with_config(raw)
    return main("--root", tmp, "check", "--base", base, "--skip-gates",
                "--format", "json", *extra)


BOM = b"\xef\xbb\xbf"


class TestTheConfigFileIsReadAsItWasSaved(unittest.TestCase):
    def test_a_utf8_byte_order_mark_is_not_part_of_the_first_key(self):
        for raw in (BOM + b"risk_threshold: 50\n",
                    BOM + b"risk_threshold: 50\r\nagent_markers:\r\n"
                          b"  - mybot\r\n"):
            with self.subTest(raw):
                tmp, base = repo_with_config(raw)
                cfg = config_mod.load(tmp, base)
                self.assertEqual(cfg["risk_threshold"], 50)
        self.assertEqual(cfg["agent_markers"], ["mybot"])

    def test_a_check_applies_a_config_that_starts_with_a_mark(self):
        # score 5 (no tests) against a threshold of 1: the gate trips, so
        # the exit code shows the file was read (it was exit 2)
        code, out, err = check_config(BOM + b"risk_threshold: 1\n")
        self.assertEqual(code, 1, (out, err))
        self.assertEqual(err, "")
        code, out, err = check_config(b"risk_threshold: 1\n")
        self.assertEqual(code, 1, (out, err))

    def test_a_file_that_is_only_a_mark_or_only_comments_is_the_defaults(self):
        for raw in (BOM, BOM + b"# nothing here\n", b"", b"# just a note\n",
                    b"\n\n"):
            with self.subTest(raw):
                tmp, base = repo_with_config(raw)
                self.assertEqual(config_mod.load(tmp, base),
                                 config_mod.DEFAULTS)

    def test_utf16_text_is_refused_and_says_so(self):
        text = "risk_threshold: 50\r\n"
        for name, raw in (("utf-16 LE", text.encode("utf-16")),
                          ("utf-16 BE", b"\xfe\xff" + text.encode("utf-16-be"))):
            with self.subTest(name):
                code, out, err = check_config(raw)
                self.assertEqual(code, 2, (out, err))
                self.assertEqual(out, "")
                self.assertEqual(len(err.strip().splitlines()), 1, err)
                self.assertIn("error: invalid .pr-verify.yaml at ", err)
                self.assertIn("UTF-16", err)
                self.assertIn("save it as UTF-8", err)
                self.assertNotIn("\x00", err)

    def test_a_list_at_the_indent_of_its_key_says_what_to_change(self):
        code, out, err = check_config(
            b"agent_markers:\n- mybot\n- other\nrisk_threshold: 50\n")
        self.assertEqual(code, 2, (out, err))
        self.assertEqual(len(err.strip().splitlines()), 1, err)
        self.assertIn("list item inside mapping", err)
        self.assertIn("(line 2)", err)
        self.assertIn("indent the list items under their key", err)

    def test_the_indented_list_is_read(self):
        tmp, base = repo_with_config(
            b"agent_markers:\n  - mybot\n  - other\nrisk_threshold: 50\n")
        cfg = config_mod.load(tmp, base)
        self.assertEqual(cfg["agent_markers"], ["mybot", "other"])
        self.assertEqual(cfg["risk_threshold"], 50)

    def test_other_yaml_the_reader_does_not_know_keeps_its_old_hint(self):
        code, out, err = check_config(b"gates: &g []\n")
        self.assertEqual(code, 2, (out, err))
        self.assertIn("anchors", err)
        self.assertIn("supported: plain mappings/lists/scalars", err)
        self.assertNotIn("indent the list items", err)

    def test_a_config_that_is_a_list_is_exit_2_not_a_traceback(self):
        for raw in (b"- a\n- b\n", b"- risk_threshold: 50\n"):
            with self.subTest(raw):
                code, out, err = check_config(raw)
                self.assertEqual(code, 2, (out, err))
                self.assertEqual(out, "")
                lines_ = err.strip().splitlines()
                self.assertEqual(len(lines_), 1, err)
                self.assertIn("error: invalid .pr-verify.yaml at ", err)
                self.assertIn("must be a mapping of settings", err)
                self.assertIn("a list", err)
                self.assertNotIn("Traceback", err)

    def test_the_readme_names_the_encoding_and_the_list_layout(self):
        with open(os.path.join(REPO, "README.md"), encoding="utf-8") as f:
            readme = " ".join(f.read().split())
        for text in (
                "`.pr-verify.yaml` is read as UTF-8",
                "a byte-order mark",
                "UTF-16 text (what PowerShell's `>` writes) is refused",
                "list items are indented under their key",
                "`agent_markers:` and then `- claude` at the same indent",
                "is refused with that hint"):
            self.assertIn(text, readme)


# ---------------------------------------------------------------------
# V3 - a blame.ignoreRevsFile that names a file that is not there

def repo_with_one_agent_line():
    """main: lib/mod.py with two human lines. Branch pr: an agent commit
    adds a third. Returns (tmp, base)."""
    tmp = _new_dir()
    git(tmp, "init", "-qb", "main")
    commit_as(tmp, *HUMAN, "base", {MOD: lines(0, 1)})
    base = rev(tmp)
    git(tmp, "checkout", "-q", "-b", "pr")
    agent_commit(tmp, {MOD: lines(0, 1, 2)}, "add a line")
    return tmp, base


def counts(tmp, base):
    """(exit code, (added, agent_added) of the file or None, stderr)."""
    code, out, err = main("--root", tmp, "check", "--skip-gates",
                          "--format", "json", "--base", base)
    if not out.strip():
        return code, None, err
    f = json.loads(out)["files"][MOD]
    return code, (f["added"], f["agent_added"]), err


USAGE_WITH = (b"usage: git blame [<options>] [<rev-opts>] [<rev>] [--] "
              b"<file>\n\n    --[no-]ignore-revs-file <file>\n"
              b"                          ignore revisions from <file>\n")
USAGE_WITHOUT = (b"usage: git blame [<options>] [<rev-opts>] [<rev>] [--] "
                 b"<file>\n\n    --ignore-revs-file <file>\n"
                 b"                          ignore revisions from <file>\n")


class TestABlameIgnoreFileThatIsNotThere(unittest.TestCase):
    """`git config blame.ignoreRevsFile no-such-file` made every check
    exit 2, whatever the tool passed: git opens the files the configuration
    lists before it looks at --ignore-revs-file=."""

    def test_the_setting_in_the_repository_config(self):
        tmp, base = repo_with_one_agent_line()
        git(tmp, "config", "blame.ignoreRevsFile", "no-such-file")
        code, got, err = counts(tmp, base)
        self.assertEqual((code, got, err), (0, (1, 1), ""))

    def test_the_setting_in_the_global_config(self):
        tmp, base = repo_with_one_agent_line()
        fd, path = tempfile.mkstemp(prefix="prv-gitconfig-")
        os.close(fd)
        self.addCleanup(os.remove, path)
        with open(path, "w", encoding="utf-8", newline="\n") as f:
            f.write("[init]\n\tdefaultBranch = main\n"
                    "[blame]\n\tignoreRevsFile = ~/no/such/file\n")
        with mock.patch.dict(os.environ, {"GIT_CONFIG_GLOBAL": path}):
            code, got, err = counts(tmp, base)
        self.assertEqual((code, got, err), (0, (1, 1), ""))

    def test_a_missing_file_and_a_second_one_that_is_there(self):
        tmp, base = repo_with_one_agent_line()
        commit_as(tmp, *HUMAN, "ignore list", {".git-blame-ignore-revs": ""})
        git(tmp, "config", "blame.ignoreRevsFile", "no-such-file")
        git(tmp, "config", "--add", "blame.ignoreRevsFile",
            ".git-blame-ignore-revs")
        code, got, err = counts(tmp, base)
        self.assertEqual((code, got, err), (0, (1, 1), ""))

    def test_the_file_the_pr_ships_still_cannot_hide_the_agent(self):
        # the point of the option: an ignore list that is in the PR names the
        # agent's commit; its lines must not read as the older, human ones
        tmp, base = repo_with_one_agent_line()
        agent = rev(tmp)
        git(tmp, "config", "blame.ignoreRevsFile", ".git-blame-ignore-revs")
        human_commit(tmp, {".git-blame-ignore-revs": f"# none\n{agent}\n"},
                     "tidy")
        code, got, err = counts(tmp, base)
        self.assertEqual((code, got, err), (0, (1, 1), ""))

    def test_the_removal_blame_ignores_the_ignore_file_too(self):
        # V1's churn scenario with an ignore list in the PR that names the
        # commit that added the churn: were blame to look past it, the
        # agent's own twenty lines would read as the base's
        tmp, base = make_mod_repo()
        human_commit(tmp, {MOD: TAIL90}, "drop 10 old lines")
        agent_commit(tmp, {MOD: TAIL90 + lines(*range(20), prefix="agent")},
                     "add feature")
        churn = rev(tmp)
        agent_commit(tmp, {MOD: TAIL90}, "tidy up")
        git(tmp, "config", "blame.ignoreRevsFile", ".git-blame-ignore-revs")
        human_commit(tmp, {".git-blame-ignore-revs": f"# none\n{churn}\n"},
                     "tidy")
        f = entry(tmp, "--base", base)
        self.assertEqual((f["removed"], f["agent_removed"]), (10, 0))

    def test_without_the_setting_blame_gets_no_extra_option(self):
        tmp, _ = repo_with_one_agent_line()
        self.assertEqual(pv._blame_options(tmp), [])

    def test_the_readme_says_so(self):
        with open(os.path.join(REPO, "README.md"), encoding="utf-8") as f:
            readme = " ".join(f.read().split())
        self.assertIn("also one that names a file that is not there "
                      "(`--no-ignore-revs-file`; a git without that option "
                      "may still stop on such a setting", readme)


class TestTheNegatedOptionIsUsedWhenGitHasIt(unittest.TestCase):
    """`--no-ignore-revs-file` only where `git blame -h` lists it; the old
    spelling otherwise. Asked once per run."""

    def setUp(self):
        self.addCleanup(setattr, pv, "_NO_IGNORE_REVS",
                        getattr(pv, "_NO_IGNORE_REVS", None))
        pv._NO_IGNORE_REVS = None
        self.asked = []

    def fake_git(self, usage=USAGE_WITH, configured=True, usage_error=None):
        def fake(cmd, *args, **kw):
            self.asked.append(cmd)
            if "config" in cmd:
                return subprocess.CompletedProcess(
                    cmd, 0 if configured else 1,
                    b"no-such-file\n" if configured else b"", b"")
            if usage_error is not None:
                raise usage_error
            return subprocess.CompletedProcess(cmd, 129, b"", usage)
        return mock.patch.object(pv.subprocess, "run", side_effect=fake)

    def usage_calls(self):
        return [c for c in self.asked if "blame" in c and "-h" in c]

    def test_git_that_lists_the_negated_form(self):
        with self.fake_git(USAGE_WITH):
            self.assertEqual(pv._blame_options("."), ["--no-ignore-revs-file"])

    def test_git_that_does_not(self):
        with self.fake_git(USAGE_WITHOUT):
            self.assertEqual(pv._blame_options("."), ["--ignore-revs-file="])

    def test_the_usage_may_come_on_either_stream(self):
        def fake(cmd, *args, **kw):
            if "config" in cmd:
                return subprocess.CompletedProcess(cmd, 0, b"x\n", b"")
            return subprocess.CompletedProcess(cmd, 129, USAGE_WITH, b"")
        with mock.patch.object(pv.subprocess, "run", side_effect=fake):
            self.assertEqual(pv._blame_options("."), ["--no-ignore-revs-file"])

    def test_git_that_cannot_be_asked_gets_the_old_spelling(self):
        for error in (OSError("no git"), subprocess.TimeoutExpired("git", 15)):
            with self.subTest(error):
                pv._NO_IGNORE_REVS = None
                with self.fake_git(usage_error=error):
                    self.assertEqual(pv._blame_options("."),
                                     ["--ignore-revs-file="])

    def test_git_is_asked_once(self):
        with self.fake_git(USAGE_WITH):
            for _ in range(3):
                pv._blame_options(".")
        self.assertEqual(len(self.usage_calls()), 1)

    def test_git_is_not_asked_without_the_setting(self):
        with self.fake_git(configured=False):
            self.assertEqual(pv._blame_options("."), [])
        self.assertEqual(self.usage_calls(), [])

    def test_the_answer_matches_what_the_installed_git_accepts(self):
        # `blame -h` is how it is told; the proof is that git takes the
        # option (a usage error, exit 129, is "unknown option")
        tmp, _ = repo_with_one_agent_line()
        p = subprocess.run(["git", "-C", tmp, "blame",
                            "--no-ignore-revs-file", "--", "no-such-path"],
                           capture_output=True)
        self.assertEqual(pv._git_takes_no_ignore_revs_file(),
                         p.returncode != 129)

    def test_the_old_spelling_still_hides_an_ignore_list_from_git(self):
        # what an old git gets: with the setting naming a file that exists
        tmp, base = repo_with_one_agent_line()
        agent = rev(tmp)
        git(tmp, "config", "blame.ignoreRevsFile", ".git-blame-ignore-revs")
        human_commit(tmp, {".git-blame-ignore-revs": f"# none\n{agent}\n"},
                     "tidy")
        pv._NO_IGNORE_REVS = False
        code, got, err = counts(tmp, base)
        self.assertEqual((code, got, err), (0, (1, 1), ""))


# ---------------------------------------------------------------------
# V4 - the Action sets `exit-code` whichever way it ends

class TestTheActionSetsExitCodeOnEveryPath(unittest.TestCase):
    def setUp(self):
        self.out_dir = _new_dir("prv-gho-")
        self.out_file = os.path.join(self.out_dir, "github_output")
        with open(self.out_file, "w", encoding="utf-8", newline="\n") as f:
            f.write("earlier=step\n")        # other steps write here too
        self.tmp, self.base = repo_with_one_agent_line()

    def step(self, output="file", **inputs):
        """Run the Action in this process the way the step does, from the
        PR_VERIFY_* variables. Returns (exit status, the lines it appended
        to $GITHUB_OUTPUT as a dict, stdout, stderr)."""
        env = {"PR_VERIFY_ROOT": self.tmp, "PR_VERIFY_BASE": self.base,
               "PR_VERIFY_SKIP_GATES": "true"}
        env.update(inputs)
        if output == "file":
            env["GITHUB_OUTPUT"] = self.out_file
        elif output:
            env["GITHUB_OUTPUT"] = output
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            try:
                status = action_mod.main(environ=env)
            except SystemExit as e:
                status = e.code
        return status, self.outputs(), out.getvalue(), err.getvalue()

    def outputs(self):
        with open(self.out_file, encoding="utf-8") as f:
            written = [ln.rstrip("\n") for ln in f if ln.strip()]
        assert written[0] == "earlier=step", written       # appended, not replaced
        return dict(ln.split("=", 1) for ln in written[1:])

    def test_a_value_the_cli_refuses(self):
        for name, value, why in (
                ("PR_VERIFY_FAIL_ON", "bogus", "invalid choice"),
                ("PR_VERIFY_MIN_SCORE", "abc", "expected an integer"),
                ("PR_VERIFY_MIN_SCORE", "101", "0..100"),
                ("PR_VERIFY_MIN_SCORE", "-1", "0..100"),
                ("PR_VERIFY_FORMAT", "xml", "invalid choice")):
            with self.subTest(name=name, value=value):
                # fresh file for each: the next case must not see this one
                with open(self.out_file, "w", encoding="utf-8",
                          newline="\n") as f:
                    f.write("earlier=step\n")
                status, outputs, out, err = self.step(**{name: value})
                self.assertEqual(status, 2)
                self.assertEqual(outputs, {"exit-code": "2"})
                self.assertIn(why, err)
                self.assertEqual(out, "")

    def test_a_root_that_is_not_a_repository(self):
        plain = _new_dir("prv-plain-")
        status, outputs, out, err = self.step(PR_VERIFY_ROOT=plain,
                                              PR_VERIFY_BASE="")
        self.assertEqual(status, 2)
        self.assertEqual(outputs, {"exit-code": "2"})
        self.assertIn("not a git repo", err)

    def test_git_that_is_not_installed(self):
        with mock.patch.object(cli_mod.subprocess, "run",
                               side_effect=FileNotFoundError("git")):
            status, outputs, out, err = self.step()
        self.assertEqual(status, 2)
        self.assertEqual(outputs, {"exit-code": "2"})
        self.assertIn("git not found", err)

    def test_the_ways_out_that_already_wrote_it_still_do(self):
        status, outputs, out, err = self.step(PR_VERIFY_HEAD="no-such-ref")
        self.assertEqual((status, outputs), (2, {"exit-code": "2"}))
        self.assertIn("does not exist", err)

    def test_a_check_that_ran_writes_all_four(self):
        status, outputs, out, err = self.step(PR_VERIFY_FORMAT="json")
        self.assertEqual(status, 0)
        self.assertEqual(set(outputs), set(action_mod.OUTPUTS))
        self.assertEqual(outputs["exit-code"], "0")
        status, outputs, out, err = self.step(PR_VERIFY_MIN_SCORE="1")
        self.assertEqual(status, 1)
        self.assertEqual(outputs["exit-code"], "1")
        self.assertEqual(set(outputs), set(action_mod.OUTPUTS))

    def test_no_output_file_is_no_trouble_on_any_path(self):
        for inputs in ({"PR_VERIFY_FAIL_ON": "bogus"}, {}, {"PR_VERIFY_HEAD":
                                                               "no-such-ref"}):
            with self.subTest(inputs):
                status, _, out, err = self.step(output=None, **inputs)
                self.assertIn(status, (0, 2))
                self.assertNotIn("Traceback", err)

    def test_help_is_not_an_outcome(self):
        # `--help` leaves through SystemExit(0) and says nothing about a check
        out, err = io.StringIO(), io.StringIO()
        env = {"GITHUB_OUTPUT": self.out_file}
        with redirect_stdout(out), redirect_stderr(err):
            with self.assertRaises(SystemExit) as ctx:
                action_mod.main(argv=["--help"], environ=env)
        self.assertEqual(ctx.exception.code, 0)
        self.assertEqual(self.outputs(), {})

    def test_an_output_file_that_cannot_be_written_is_a_warning(self):
        missing = os.path.join(self.out_dir, "no", "such", "dir", "out")
        for inputs, want in (({}, 0), ({"PR_VERIFY_MIN_SCORE": "1"}, 1),
                             ({"PR_VERIFY_FAIL_ON": "bogus"}, 2),
                             ({"PR_VERIFY_HEAD": "no-such-ref"}, 2)):
            with self.subTest(inputs):
                status, _, out, err = self.step(output=missing, **inputs)
                self.assertEqual(status, want)    # the verdict stands
                self.assertNotIn("Traceback", err)
                warned = [ln for ln in err.splitlines()
                          if ln.startswith("warning: could not write")]
                self.assertEqual(len(warned), 1, err)
                self.assertIn("GITHUB_OUTPUT", warned[0])

    def test_an_output_path_that_is_a_directory(self):
        status, _, out, err = self.step(output=self.out_dir)
        self.assertEqual(status, 0)
        self.assertIn("warning: could not write", err)
        self.assertNotIn("Traceback", err)

    def test_the_step_as_written_does_the_same(self):
        env = {k: v for k, v in os.environ.items()
               if k != "PYTHONUNBUFFERED" and not k.startswith("PR_VERIFY_")}
        env.update({"PR_VERIFY_ROOT": self.tmp, "PR_VERIFY_BASE": self.base,
                    "PR_VERIFY_FAIL_ON": "bogus",
                    "GITHUB_OUTPUT": self.out_file})
        p = subprocess.run([sys.executable, "-I",
                            os.path.join(REPO, "run_action.py")], env=env,
                           capture_output=True, text=True, encoding="utf-8",
                           cwd=self.tmp, timeout=120)
        self.assertEqual(p.returncode, 2, p.stderr)
        self.assertEqual(self.outputs(), {"exit-code": "2"})
        self.assertIn("invalid choice", p.stderr)

    def test_the_readme_and_action_yml_say_it(self):
        with open(os.path.join(REPO, "README.md"), encoding="utf-8") as f:
            readme = " ".join(f.read().split())
        self.assertIn("`exit-code` is always set", readme)
        self.assertIn("the other three only when a score was worked out",
                      readme)
        with open(os.path.join(REPO, "action.yml"), encoding="utf-8") as f:
            yml = " ".join(f.read().split())
        self.assertIn("Exit status of pr-verify check (0 pass, 1 fail, 2 "
                      "error); set on every path, also when the inputs are "
                      "refused", yml)


# ---------------------------------------------------------------------
# V5 - a file or process error is exit 2 and one line, never a traceback

def one_error_line(test, err, *mentions):
    got = err.strip().splitlines()
    test.assertEqual(len(got), 1, err)
    test.assertTrue(got[0].startswith("error: "), err)
    test.assertNotIn("Traceback", err)
    for text in mentions:
        test.assertIn(text, got[0].replace("\\", "/"))


class TestAnOsErrorThatStopsACheckIsExit2(unittest.TestCase):
    def test_a_full_disk_under_the_snapshot_of_uncommitted_changes(self):
        tmp, base = repo_with_one_agent_line()
        full = OSError(errno.ENOSPC, "No space left on device")
        with mock.patch.object(pv, "snapshot_worktree", side_effect=full):
            code, out, err = main("--root", tmp, "check", "--base", base,
                                  "--skip-gates")
        self.assertEqual(code, 2, (out, err))
        self.assertEqual(out, "")
        one_error_line(self, err, "No space left on device")

    def test_a_file_that_cannot_be_read(self):
        tmp, base = repo_with_one_agent_line()
        refused = PermissionError(errno.EACCES, "Permission denied",
                                  os.path.join(tmp, MOD))
        with mock.patch.object(cli_mod, "run_check", side_effect=refused):
            code, out, err = main("--root", tmp, "check", "--base", base)
        self.assertEqual(code, 2, (out, err))
        one_error_line(self, err, "Permission denied", MOD)

    def test_git_that_cannot_be_started_halfway(self):
        # the repository check passes; the next git call fails to start
        tmp, base = repo_with_one_agent_line()
        real = subprocess.run
        calls = []

        def run(cmd, *args, **kw):
            calls.append(cmd)
            if len(calls) > 3:
                raise PermissionError(errno.EACCES, "Permission denied", "git")
            return real(cmd, *args, **kw)
        with mock.patch.object(subprocess, "run", side_effect=run):
            code, out, err = main("--root", tmp, "check", "--base", base,
                                  "--skip-gates")
        self.assertEqual(code, 2, (out, err))
        one_error_line(self, err, "Permission denied")

    def test_the_action_sets_the_exit_code_too(self):
        tmp, base = repo_with_one_agent_line()
        out_file = os.path.join(_new_dir("prv-gho-"), "out")
        env = {"PR_VERIFY_ROOT": tmp, "PR_VERIFY_BASE": base,
               "GITHUB_OUTPUT": out_file}
        err = io.StringIO()
        with mock.patch.object(cli_mod, "run_check",
                               side_effect=OSError(errno.EIO, "I/O error")):
            with redirect_stderr(err):
                status = action_mod.main(environ=env)
        self.assertEqual(status, 2)
        one_error_line(self, err.getvalue(), "I/O error")
        with open(out_file, encoding="utf-8") as f:
            self.assertEqual(f.read(), "exit-code=2\n")

    def test_a_verdict_is_still_a_verdict(self):
        # the net does not turn a failed verification into an error
        tmp, base = repo_with_one_agent_line()
        code, out, err = main("--root", tmp, "check", "--base", base,
                              "--skip-gates", "--min-score", "1")
        self.assertEqual(code, 1, (out, err))


class TestInitThatCannotWriteIsExit2(unittest.TestCase):
    def repo(self):
        tmp = _new_dir("prv-init-")
        git(tmp, "init", "-qb", "main")
        return tmp

    def test_a_folder_where_the_file_belongs(self):
        tmp = self.repo()
        os.makedirs(os.path.join(tmp, ".pr-verify.yaml"))
        code, out, err = main("--root", tmp, "init", "--force")
        self.assertEqual(code, 2, (out, err))
        self.assertEqual(out, "")
        one_error_line(self, err, "could not write", ".pr-verify.yaml")

    def test_a_write_that_is_refused(self):
        tmp = self.repo()
        real = builtins.open

        def refusing(path, *args, **kw):
            if os.path.basename(str(path)) == ".pr-verify.yaml":
                raise PermissionError(errno.EACCES, "Permission denied",
                                      str(path))
            return real(path, *args, **kw)
        with mock.patch.object(builtins, "open", side_effect=refusing):
            code, out, err = main("--root", tmp, "init")
        self.assertEqual(code, 2, (out, err))
        one_error_line(self, err, "could not write", "Permission denied")
        self.assertFalse(os.path.exists(os.path.join(tmp, ".pr-verify.yaml")))

    @unittest.skipIf(os.name == "nt" or (hasattr(os, "geteuid")
                                         and os.geteuid() == 0),
                     "needs a folder that its owner cannot write to")
    def test_a_read_only_repository(self):
        tmp = self.repo()
        os.chmod(tmp, 0o555)
        self.addCleanup(os.chmod, tmp, 0o755)
        code, out, err = main("--root", tmp, "init")
        self.assertEqual(code, 2, (out, err))
        one_error_line(self, err, "could not write", "Permission denied")

    def test_init_in_a_folder_that_works_is_unchanged(self):
        tmp = self.repo()
        code, out, err = main("--root", tmp, "init")
        self.assertEqual((code, err), (0, ""))
        self.assertIn("wrote .pr-verify.yaml", out)
        with open(os.path.join(tmp, ".pr-verify.yaml"),
                  encoding="utf-8") as f:
            self.assertEqual(f.read(), config_mod.example_config())
        code, out, err = main("--root", tmp, "init")       # and it exists
        self.assertEqual(code, 2)
        self.assertIn("exists", out)


class TestTheReadmeNamesTheFileErrors(unittest.TestCase):
    def test_exit_2_covers_a_file_that_cannot_be_read_or_written(self):
        with open(os.path.join(REPO, "README.md"), encoding="utf-8") as f:
            readme = " ".join(f.read().split())
        self.assertIn("So does a file that cannot be read or written (a full "
                      "disk, a read-only repository for `init`)", readme)


# ---------------------------------------------------------------------
# Release 0.1.2: the package and the command line name the same version

class TestVersionsAgree(unittest.TestCase):
    def test_the_package_and_the_cli_name_the_same_version(self):
        with open(os.path.join(REPO, "pyproject.toml"),
                  encoding="utf-8") as f:
            found = re.search(r'^version\s*=\s*"([^"]+)"', f.read(), re.M)
        self.assertIsNotNone(found)
        self.assertEqual(found.group(1), cli_mod.VERSION)


if __name__ == "__main__":
    unittest.main()
