"""Round-5 panel regressions (final verification panel, 2026-10-17).

V1  A base branch that moved on after the PR branched was diffed from its
    tip: everything the base gained since showed up as part of the PR
    (as reverted changes), diluting the agent's share.
V2  Claude Code's own trailer, `Co-Authored-By: Claude Sonnet 5.5
    <noreply@anthropic.com>`, read as a human commit.
V3  Deleted lines were not scored: an agent removing four lines of auth.py
    was "nothing to verify".
V4  The GitHub Action ran `python -m pr_verify.action` with the PR's own
    checkout first on sys.path: a PR could ship an `argparse.py`.
V5  `--help` / `--version` into a closed pipe crashed on Python 3.10/3.11.
V6  `init` wrote 4 of the 32 default sensitive globs and 6 of the 11 default
    markers, and globs were case-sensitive.
V7  Odd repository content and odd arguments aborted the run: a submodule
    bump, a symlink to /dev/zero, a git call that takes over a minute,
    `--head=--output=FILE`.
V8  Every deleted file re-parsed the whole worktree.

Fixtures are throwaway git repos (see fixture.py); nothing touches the
network, HOME or the real git configuration.
"""

import ast
import contextlib
import errno
import io
import json
import os
import re
import runpy
import shlex
import string
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

from pr_verify import action as action_mod
from pr_verify import blastradius as br
from pr_verify import cli as cli_mod
from pr_verify import config as config_mod
from pr_verify import markers as markers_mod
from pr_verify import miniyaml
from pr_verify import provenance as pv
from pr_verify import risk as risk_mod

try:
    import resource
except ImportError:         # Windows
    resource = None

from fixture import (PY, commit_as, commit_at_new_base, git, make_pr_repo)

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

AGENT = ("claude-bot", "claude-bot@example.com")
HUMAN = ("Dan Calas", "dan@example.com")


def _read(name: str) -> str:
    with open(os.path.join(REPO, name), encoding="utf-8") as f:
        return f.read()


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


# ---------------------------------------------------------------------
# V1 - the base moved on

LEGACY_OLD = "".join(f"old_{i} = {i}\n" for i in range(300))
LEGACY_NEW = "".join(f"NEW_{i} = {i}\n" for i in range(300))
AUTH_BASE = "def login(u, p):\n    return True\n"
AUTH_AGENT = AUTH_BASE + "".join(
    f"\n\ndef step_{i}(t):\n    return t\n" for i in range(2))   # 8 lines


def make_moved_base_repo():
    """main: c0 (auth.py, legacy.py with 300 lines). Branch `feature` leaves
    c0 and gets ONE agent commit adding 8 lines to auth.py. Then main moves
    on: a human commit rewrites all 300 lines of legacy.py. HEAD = feature.
    Returns (tmp, c0, main_tip)."""
    tmp = tempfile.mkdtemp()
    git(tmp, "init", "-qb", "main")
    commit_as(tmp, *HUMAN, "base",
              {"app/auth.py": AUTH_BASE, "app/legacy.py": LEGACY_OLD})
    c0 = rev(tmp)
    git(tmp, "checkout", "-q", "-b", "feature")
    commit_as(tmp, *AGENT, "Add steps\n\nCo-authored-by: Claude",
              {"app/auth.py": AUTH_AGENT})
    git(tmp, "checkout", "-q", "main")
    commit_as(tmp, *HUMAN, "reformat legacy", {"app/legacy.py": LEGACY_NEW})
    main_tip = rev(tmp)
    git(tmp, "checkout", "-q", "feature")
    return tmp, c0, main_tip


class TestBaseThatMovedOn(unittest.TestCase):
    """The panel's repro: 8 agent lines, then a 300-line human reformat
    lands on main; `check --base main --min-score 60` scored 30 and exited
    0, `--base $(git merge-base main HEAD)` scored 69 and exited 1."""

    def test_only_the_branchs_own_changes_are_in_the_range(self):
        tmp, c0, _ = make_moved_base_repo()
        code, data, _ = check_json(tmp, "--base", "main", "--min-score", "60")
        self.assertEqual(list(data["files"]), ["app/auth.py"])
        self.assertEqual(data["files"]["app/auth.py"]["added"], 8)
        self.assertEqual(data["files"]["app/auth.py"]["agent_added"], 8)
        self.assertEqual(data["risk"]["score"], 65)   # 40 + 20 + 5
        self.assertEqual(code, 1)

    def test_same_verdict_as_naming_the_merge_base_yourself(self):
        tmp, c0, _ = make_moved_base_repo()
        via_branch = check_json(tmp, "--base", "main", "--min-score", "60")
        via_sha = check_json(tmp, "--base", c0, "--min-score", "60")
        self.assertEqual(via_branch[0], via_sha[0])
        for key in ("files", "risk", "blast_radius", "min_score"):
            self.assertEqual(via_branch[1][key], via_sha[1][key], key)

    def test_the_json_says_which_commit_the_diff_started_from(self):
        tmp, c0, main_tip = make_moved_base_repo()
        _, data, _ = check_json(tmp, "--base", "main")
        self.assertEqual(data["base"], "main")
        self.assertEqual(data["merge_base"], c0)
        self.assertNotEqual(data["merge_base"], main_tip)

    def test_a_base_that_has_not_moved_is_its_own_merge_base(self):
        tmp, base = make_pr_repo()
        _, data, _ = check_json(tmp, "--base", base)
        self.assertEqual(data["merge_base"], rev(tmp, base))
        self.assertFalse([n for n in data["notes"] if "merge-base" in n],
                         data["notes"])

    def test_the_report_says_so_when_the_base_moved(self):
        tmp, c0, _ = make_moved_base_repo()
        code, out, err = main("--root", tmp, "check", "--base", "main",
                              "--skip-gates")
        self.assertIn(f"merge-base {c0[:12]}", out)
        self.assertIn("1 commit(s) ahead", out)
        self.assertNotIn("legacy.py", out)

    def test_uncommitted_changes_are_still_seen_on_top(self):
        tmp, c0, _ = make_moved_base_repo()
        with open(os.path.join(tmp, "app", "auth.py"), "a", encoding="utf-8",
                  newline="\n") as f:
            f.write("\n\ndef wip(t):\n    return t\n")
        _, data, _ = check_json(tmp, "--base", "main")
        self.assertEqual(list(data["files"]), ["app/auth.py"])
        self.assertEqual(data["files"]["app/auth.py"]["added"], 12)
        self.assertEqual(data["files"]["app/auth.py"]["agent_added"], 8)

    def test_an_explicit_head_uses_the_merge_base_too(self):
        tmp, c0, _ = make_moved_base_repo()
        git(tmp, "checkout", "-q", "main")
        _, data, _ = check_json(tmp, "--base", "main", "--head", "feature")
        self.assertEqual(list(data["files"]), ["app/auth.py"])
        self.assertEqual(data["merge_base"], c0)

    def test_unrelated_histories_fall_back_to_the_base_and_say_so(self):
        tmp, _, _ = make_moved_base_repo()
        git(tmp, "checkout", "-q", "--orphan", "island")
        git(tmp, "rm", "-rfq", ".")
        commit_as(tmp, *AGENT, "island\n\nCo-authored-by: Claude",
                  {"app/island.py": "x = 1\n"})
        code, data, _ = check_json(tmp, "--base", "main")
        self.assertIsNone(data["merge_base"])
        self.assertTrue(any("no common ancestor" in n for n in data["notes"]),
                        data["notes"])
        self.assertIn("app/island.py", data["files"])
        # not a crash, not a silent pass: the whole difference is scored
        self.assertIn(code, (0, 1))

    def test_merge_base_helper(self):
        tmp, c0, main_tip = make_moved_base_repo()
        self.assertEqual(pv.merge_base(tmp, main_tip, rev(tmp, "feature")), c0)
        self.assertEqual(pv.merge_base(tmp, c0, rev(tmp, "feature")), c0)
        git(tmp, "checkout", "-q", "--orphan", "island")
        git(tmp, "rm", "-rfq", ".")
        commit_as(tmp, *HUMAN, "island", {"x.py": "x = 1\n"})
        self.assertIsNone(pv.merge_base(tmp, main_tip, rev(tmp, "island")))


# ---------------------------------------------------------------------
# V2 - Claude Code's own trailer

ROBOT = "\U0001F916"
#: what Claude Code (and the harness around it) really leaves in a commit
CLAUDE_TRAILERS = {
    "current model": "Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>",
    "older, bare name": "Co-Authored-By: Claude <noreply@anthropic.com>",
    "another model": "Co-Authored-By: Claude Opus 4.1 <noreply@anthropic.com>",
    "lower-case key": "Co-authored-by: Claude Haiku 4.5 <noreply@anthropic.com>",
    "a name nobody has heard of":
        "Co-Authored-By: Some Future Model 9 <noreply@anthropic.com>",
    "address in capitals":
        "Co-Authored-By: Claude Sonnet 5.5 <NoReply@Anthropic.com>",
}
CLAUDE_FOOTERS = {
    "generated with":
        ROBOT + " Generated with [Claude Code](https://claude.com/claude-code)",
    "generated with, no emoji":
        "Generated with [Claude Code](https://claude.com/claude-code)",
    "session trailer":
        "Claude-Session: https://claude.ai/code/session_019ComBdpPqFWgzKZ3JGWdXX",
}
#: text that merely mentions Claude or Anthropic: still human
NOT_AGENT = {
    "an Anthropic employee, no trailer":
        ("Alice Smith", "alice@anthropic.com", "Fix the build", ""),
    "an Anthropic employee as co-author":
        ("Dan Calas", "dan@example.com", "Fix",
         "Co-Authored-By: Alice Smith <alice@anthropic.com>"),
    "the address in prose":
        ("Dan Calas", "dan@example.com", "Fix",
         "Paired with Claude Sonnet 5.5 <noreply@anthropic.com> on this."),
    "the address in a sentence":
        ("Dan Calas", "dan@example.com", "Fix",
         "Questions: write to noreply@anthropic.com"),
    "a look-alike domain":
        ("Dan Calas", "dan@example.com", "Fix",
         "Co-Authored-By: Alice Smith <noreply@anthropic.com.example.org>"),
    "a look-alike local part":
        ("Dan Calas", "dan@example.com", "Fix",
         "Co-Authored-By: Alice Smith <no-reply@anthropic.com>"),
    "generated-with in prose":
        ("Dan Calas", "dan@example.com", "Fix",
         "I generated this with [Claude Code] yesterday, then rewrote it."),
    "generated-with in the subject":
        ("Dan Calas", "dan@example.com",
         ROBOT + " Generated with [Claude Code]", ""),
    "a human called Claude Sonnet":
        ("Claude Sonnet", "cs@example.com", "Fix", ""),
}


def default_markers():
    return list(config_mod.DEFAULTS["agent_markers"])


class TestClaudeCodeTrailer(unittest.TestCase):
    """`Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>` is what
    Claude Code writes; only the bare names `Claude` / `Claude Code` matched,
    so the commits of the tool this is built for read as human."""

    def _match(self, name, email, subject, body):
        return markers_mod.match(name, email, subject, body, default_markers())

    def test_every_form_of_the_trailer_is_an_agent(self):
        for label, trailer in CLAUDE_TRAILERS.items():
            with self.subTest(label):
                body = f"Adds the thing.\n\n{trailer}"
                self.assertIsNotNone(
                    self._match("Dan Calas", "dan@example.com", "Add", body))

    def test_the_footer_and_the_session_trailer_are_agents(self):
        for label, line in CLAUDE_FOOTERS.items():
            with self.subTest(label):
                body = f"Adds the thing.\n\n{line}\n"
                self.assertIsNotNone(
                    self._match("Dan Calas", "dan@example.com", "Add", body))

    def test_the_whole_message_as_claude_code_writes_it(self):
        body = ("Add the thing\n\n" + CLAUDE_FOOTERS["generated with"] + "\n\n"
                + CLAUDE_TRAILERS["current model"] + "\n"
                + CLAUDE_FOOTERS["session trailer"])
        self.assertIsNotNone(
            self._match("Dan Calas", "dan@example.com", "Add the thing", body))

    def test_mentions_and_look_alikes_stay_human(self):
        for label, (name, email, subject, body) in NOT_AGENT.items():
            with self.subTest(label):
                self.assertIsNone(self._match(name, email, subject, body))

    def test_an_address_marker_is_that_exact_address(self):
        marker = "noreply@anthropic.com"
        self.assertTrue(markers_mod.email_matches("NoReply@Anthropic.com",
                                                  marker))
        self.assertFalse(markers_mod.email_matches("alice@anthropic.com",
                                                   marker))
        self.assertFalse(markers_mod.email_matches("noreply@anthropic.com.au",
                                                   marker))
        # it is never read as a name ...
        self.assertFalse(markers_mod.name_matches("noreply anthropic com",
                                                  marker))
        # ... and, written without the trailer prefix, it also applies to the
        # author's own address
        self.assertEqual(markers_mod.match("Bot Two", "noreply@anthropic.com",
                                           "Fix", "", [marker]), marker)
        self.assertIsNone(markers_mod.match("Dan", "dan@anthropic.com",
                                            "Fix", "", [marker]))
        self.assertIsNone(markers_mod.match(
            "Dan", "dan@example.com", "noreply anthropic com: fix", "",
            [marker]))

    def test_the_label_names_the_marker_that_matched(self):
        hit = self._match("Dan Calas", "dan@example.com", "Add",
                          CLAUDE_TRAILERS["current model"])
        self.assertEqual(hit, "co-authored-by: noreply@anthropic.com")
        hit = self._match("Dan Calas", "dan@example.com", "Add",
                          CLAUDE_FOOTERS["generated with"])
        self.assertEqual(hit, "claude code")

    def _repo_with(self, body):
        tmp = tempfile.mkdtemp()
        git(tmp, "init", "-qb", "main")
        commit_as(tmp, *HUMAN, "base", {"app/core.py": "x = 1\n"})
        base = rev(tmp)
        commit_as(tmp, *HUMAN, "Add the thing\n\n" + body,
                  {"app/core.py": "x = 1\ny = 2\nz = 3\n"})
        return tmp, base

    def test_end_to_end_a_human_identity_with_the_trailer_is_agent_work(self):
        for label, trailer in CLAUDE_TRAILERS.items():
            with self.subTest(label):
                tmp, base = self._repo_with(trailer)
                _, data, _ = check_json(tmp, "--base", base)
                f = data["files"]["app/core.py"]
                self.assertEqual((f["label"], f["agent_added"], f["added"]),
                                 ("agent", 2, 2))
                self.assertTrue(f["agents"], f)
                self.assertGreater(data["risk"]["factors"]["agent_share"]
                                   ["points"], 0)

    def test_end_to_end_a_plain_human_commit_is_still_human(self):
        tmp, base = self._repo_with("Paired with Claude Sonnet 5.5 "
                                    "<noreply@anthropic.com> on this.")
        _, data, _ = check_json(tmp, "--base", base)
        f = data["files"]["app/core.py"]
        self.assertEqual((f["label"], f["agent_added"]), ("human", 0))

    def test_the_default_list_is_what_the_readme_and_init_say(self):
        self.assertIn("co-authored-by: noreply@anthropic.com",
                      default_markers())
        self.assertIn("noreply@anthropic.com", _read("README.md"))


# ---------------------------------------------------------------------
# V3 - deleted lines

def lines(*numbers, prefix="line"):
    return "".join(f"{prefix}_{n} = {n}\n" for n in numbers)


AUTH10 = lines(*range(10))


def make_lines_repo(content=AUTH10, path="app/auth.py"):
    """A repo whose base commit has `path` with `content` and one more
    file. Returns (tmp, base)."""
    tmp = tempfile.mkdtemp()
    git(tmp, "init", "-qb", "main")
    commit_as(tmp, *HUMAN, "base", {path: content, "app/util.py": "u = 1\n"})
    return tmp, rev(tmp)


def agent_commit(tmp, files, message="Tidy"):
    commit_as(tmp, *AGENT, message + "\n\nCo-authored-by: Claude", files)


def human_commit(tmp, files, message="Tidy by hand"):
    commit_as(tmp, *HUMAN, message, files)


class TestDeletedLines(unittest.TestCase):
    """An agent removing four lines of auth.py was `nothing to verify`,
    exit 0: only added lines were looked at. A removed line is now a
    changed line, credited to the commit that removed it."""

    def test_the_panels_repro_is_not_nothing_to_verify(self):
        tmp, base = make_lines_repo()
        agent_commit(tmp, {"app/auth.py": lines(0, 1, 6, 7, 8, 9)})
        code, out, err = main("--root", tmp, "check", "--base", base,
                              "--skip-gates", "--min-score", "60")
        self.assertNotIn("nothing to verify", out)
        self.assertIn("app/auth.py", out)
        self.assertIn("4/4 removed", out)
        self.assertEqual(code, 1, out)       # 40 + 20 sensitive + 5 no_tests

    def test_json_counts_removed_lines_per_file(self):
        tmp, base = make_lines_repo()
        agent_commit(tmp, {"app/auth.py": lines(0, 1, 6, 7, 8, 9)})
        code, data, _ = check_json(tmp, "--base", base)
        f = data["files"]["app/auth.py"]
        self.assertEqual((f["added"], f["agent_added"]), (0, 0))
        self.assertEqual((f["removed"], f["agent_removed"]), (4, 4))
        self.assertEqual(f["label"], "agent")
        self.assertEqual(f["agents"], ["claude-bot (claude)"])
        self.assertEqual(data["risk"]["score"], 65)
        self.assertEqual(data["risk"]["factors"]["agent_share"]["points"], 40)
        self.assertEqual(data["risk"]["factors"]["sensitive"]["points"], 20)

    def test_every_entry_has_the_keys_even_with_nothing_removed(self):
        tmp, base = make_pr_repo()
        _, data, _ = check_json(tmp, "--base", base)
        for rel, f in data["files"].items():
            self.assertEqual((f["removed"], f["agent_removed"]), (0, 0), rel)

    def test_a_human_removing_lines_is_human(self):
        tmp, base = make_lines_repo()
        human_commit(tmp, {"app/auth.py": lines(0, 1, 6, 7, 8, 9)})
        code, data, _ = check_json(tmp, "--base", base, "--min-score", "60")
        f = data["files"]["app/auth.py"]
        self.assertEqual((f["removed"], f["agent_removed"], f["label"]),
                         (4, 0, "human"))
        self.assertEqual(data["risk"]["factors"]["agent_share"]["points"], 0)
        self.assertEqual(code, 0)

    def test_each_removal_goes_to_the_commit_that_made_it(self):
        tmp, base = make_lines_repo()
        human_commit(tmp, {"app/auth.py": lines(0, 1, 2, 3, 4, 5, 6, 7)})  # -2
        agent_commit(tmp, {"app/auth.py": lines(0, 1, 5, 6, 7)})           # -3
        _, data, _ = check_json(tmp, "--base", base)
        f = data["files"]["app/auth.py"]
        self.assertEqual((f["removed"], f["agent_removed"], f["label"]),
                         (5, 3, "mixed"))
        self.assertEqual(data["risk"]["factors"]["agent_share"]["points"], 24)

    def test_added_and_removed_lines_are_one_percentage(self):
        tmp, base = make_lines_repo()
        # agent replaces two lines: +2 -2; a human then adds four
        agent_commit(tmp, {"app/auth.py": lines(0, 1, 2, 3, 4, 5, 6, 7)
                           + lines(80, 81)})
        human_commit(tmp, {"app/auth.py": lines(0, 1, 2, 3, 4, 5, 6, 7)
                           + lines(80, 81) + lines(90, 91, 92, 93)})
        _, data, _ = check_json(tmp, "--base", base)
        f = data["files"]["app/auth.py"]
        self.assertEqual((f["added"], f["agent_added"]), (6, 2))
        self.assertEqual((f["removed"], f["agent_removed"]), (2, 2))
        share = data["risk"]["factors"]["agent_share"]
        self.assertEqual(share["points"], 20)           # 4 of 8 changed lines
        self.assertIn("4/8 changed lines", share["detail"])

    def test_a_pr_without_removals_scores_exactly_as_before(self):
        tmp, base = make_pr_repo()
        _, data, _ = check_json(tmp, "--base", base)
        self.assertEqual(data["risk"]["score"], 57)
        self.assertIn("9/13 added lines agent-authored (69%)",
                      data["risk"]["factors"]["agent_share"]["detail"])

    def test_lines_added_and_removed_again_inside_the_pr_cancel_out(self):
        tmp, base = make_lines_repo()
        agent_commit(tmp, {"app/auth.py": AUTH10 + lines(80, 81, 82)})
        agent_commit(tmp, {"app/auth.py": AUTH10})
        code, out, _ = main("--root", tmp, "check", "--base", base,
                            "--skip-gates")
        self.assertIn("nothing to verify", out)
        self.assertEqual(code, 0)

    def test_the_agents_share_never_exceeds_what_the_pr_removes(self):
        tmp, base = make_lines_repo()
        agent_commit(tmp, {"app/auth.py": AUTH10 + lines(80, 81, 82)})
        # six lines removed by this commit: its three own and three more
        agent_commit(tmp, {"app/auth.py": lines(0, 1, 2, 3, 4, 5, 6)})
        _, data, _ = check_json(tmp, "--base", base)
        f = data["files"]["app/auth.py"]
        self.assertEqual((f["added"], f["removed"]), (0, 3))
        self.assertEqual(f["agent_removed"], 3)

    def test_uncommitted_removals_count_and_are_not_agent_work(self):
        tmp, base = make_lines_repo()
        agent_commit(tmp, {"app/util.py": "u = 1\nv = 2\n"})
        with open(os.path.join(tmp, "app", "auth.py"), "w", encoding="utf-8",
                  newline="\n") as f:
            f.write(lines(0, 1, 2, 3))
        _, data, _ = check_json(tmp, "--base", base)
        f = data["files"]["app/auth.py"]
        self.assertEqual((f["removed"], f["agent_removed"], f["label"]),
                         (6, 0, "human"))

    def test_a_removed_file_is_still_one_deleted_file_not_removed_lines(self):
        tmp, base = make_lines_repo()
        os.remove(os.path.join(tmp, "app", "auth.py"))
        git(tmp, "add", "-A")
        git(tmp, "-c", "user.name=claude-bot",
            "-c", "user.email=claude-bot@example.com", "commit", "-qm",
            "Drop auth\n\nCo-authored-by: Claude")
        _, data, _ = check_json(tmp, "--base", base)
        f = data["files"]["app/auth.py"]
        self.assertEqual((f["label"], f["deleted"], f["removed"]),
                         ("deleted", True, 0))

    def test_removals_before_the_fork_are_not_the_prs(self):
        tmp, c0, _ = make_moved_base_repo()
        git(tmp, "checkout", "-q", "main")
        human_commit(tmp, {"app/auth.py": ""}, "empty auth on main")
        git(tmp, "checkout", "-q", "feature")
        _, data, _ = check_json(tmp, "--base", "main")
        self.assertEqual(data["files"]["app/auth.py"]["removed"], 0)

    def test_file_provenance_label_and_totals_for_removals(self):
        fp = pv.FileProvenance(file="a.py")
        fp.removed, fp.agent_removed = 4, 4
        self.assertEqual(fp.label(), "agent")
        fp.agent_removed = 0
        self.assertEqual(fp.label(), "human")
        fp.agent_removed = 1
        self.assertEqual(fp.label(), "mixed")
        self.assertEqual((fp.changed, fp.agent_changed), (4, 1))
        self.assertEqual(pv.FileProvenance(file="b.py").label(), "untouched")

    def test_score_uses_changed_lines(self):
        fp = pv.FileProvenance(file="app/x.py")
        fp.added, fp.agent_added, fp.removed, fp.agent_removed = 2, 2, 6, 0
        b = risk_mod.score({"app/x.py": fp}, {}, [], [], 70)
        self.assertEqual(b.factors["agent_share"]["points"], 10)   # 2 of 8


# ---------------------------------------------------------------------
# V4 - the Action must never run code from the PR's checkout

ACTION_YML = os.path.join(REPO, "action.yml")
LAUNCHER = os.path.join(REPO, "run_action.py")

#: A module that writes its name to $SHADOW_MARKER and stops the process:
#: whatever imports it has run code from the checkout.
SHADOW_MODULE = (
    "import os\n"
    "with open(os.environ['SHADOW_MARKER'], 'a') as f:\n"
    "    f.write(__name__ + '\\n')\n"
    "raise SystemExit(99)\n")
SHADOWED = ("argparse.py", "json.py", "subprocess.py", "dataclasses.py",
            "pr_verify/__init__.py")


def load_action():
    with open(ACTION_YML, encoding="utf-8") as f:
        return miniyaml.safe_load(f.read())


def step_environment(action, overrides):
    """The environment GitHub gives the step: each `${{ inputs.x }}` is the
    input's default unless `overrides` has the variable."""
    env = {}
    for var, value in action["runs"]["steps"][0]["env"].items():
        m = re.fullmatch(r"\$\{\{ inputs\.([a-z-]+) \}\}", value)
        assert m, f"unexpected env expression {value!r}"
        env[var] = str(action["inputs"][m.group(1)].get("default", ""))
    env.update(overrides)
    return env


def step_command(action, env):
    """argv of the step's `run:` line, which must be ONE python command:
    split like bash would, `$VAR` filled in from env, python replaced by the
    interpreter running the tests."""
    run = action["runs"]["steps"][0]["run"].strip()
    assert "\n" not in run and "&&" not in run and ";" not in run, run
    words = shlex.split(run)
    assert words[0] == "python", run
    return [sys.executable] + [string.Template(w).safe_substitute(env)
                               for w in words[1:]]


class TestActionNeverRunsCheckoutCode(unittest.TestCase):
    """A composite step starts in the PR's checkout. `python -m
    pr_verify.action` puts that directory first on sys.path, so a PR that
    adds an `argparse.py` (or a `pr_verify/` package) had the job run it."""

    def setUp(self):
        self.action = load_action()
        self.tmp, self.base = make_pr_repo()
        commit_as(self.tmp, *HUMAN, "innocent looking change",
                  {name: SHADOW_MODULE for name in SHADOWED})
        self.marker = os.path.join(tempfile.mkdtemp(), "ran")
        self.out_file = os.path.join(tempfile.mkdtemp(), "gh_output")
        self.env = {k: v for k, v in os.environ.items()
                    if k != "PYTHONUNBUFFERED" and not k.startswith("PYTHON")}
        self.env.update(step_environment(self.action, {
            "PR_VERIFY_BASE": self.base, "PR_VERIFY_FORMAT": "json",
            "PR_VERIFY_SKIP_GATES": "true"}))
        self.env.update({"GITHUB_ACTION_PATH": REPO,
                         "GITHUB_OUTPUT": self.out_file,
                         "SHADOW_MARKER": self.marker})

    def _run(self, argv, env=None):
        return subprocess.run(argv, cwd=self.tmp, env=env or self.env,
                              capture_output=True, text=True,
                              encoding="utf-8", timeout=120)

    def _marker(self):
        if not os.path.exists(self.marker):
            return []
        with open(self.marker, encoding="utf-8") as f:
            return f.read().split()

    def test_control_the_old_command_runs_the_checkouts_code(self):
        # without this the test below would prove nothing: the very same
        # checkout DOES hijack the command the action used to run
        p = self._run([sys.executable, "-m", "pr_verify.action"])
        self.assertEqual(p.returncode, 99, p.stderr)
        self.assertTrue(self._marker(), "the shadow module never ran")

    def test_the_step_as_written_never_imports_from_the_checkout(self):
        argv = step_command(self.action, self.env)
        p = self._run(argv)
        self.assertEqual(self._marker(), [], "checkout code was imported")
        self.assertIn(p.returncode, (0, 1), p.stderr)
        data = json.loads(p.stdout)
        # the checkout is data: its files were analysed ...
        self.assertIn("argparse.py", data["files"])
        # ... and the real verdict came out: the one an in-process run gives
        _, direct, _ = check_json(self.tmp, "--base", self.base)
        self.assertEqual(data["risk"], direct["risk"])
        with open(self.out_file, encoding="utf-8") as f:
            self.assertIn("score=", f.read())

    def test_not_even_a_hostile_pythonpath_changes_that(self):
        env = dict(self.env, PYTHONPATH=self.tmp, PYTHONSTARTUP=os.path.join(
            self.tmp, "argparse.py"), PYTHONHOME="")
        p = self._run(step_command(self.action, env), env)
        self.assertEqual(self._marker(), [], "PYTHONPATH reached the import")
        self.assertIn(p.returncode, (0, 1), p.stderr)

    def test_the_run_line_is_isolated_python_and_nothing_else(self):
        run = self.action["runs"]["steps"][0]["run"]
        words = shlex.split(run)
        self.assertEqual(words[:2], ["python", "-I"], run)
        self.assertTrue(words[2].startswith("$GITHUB_ACTION_PATH/"), run)
        self.assertTrue(os.path.isfile(
            os.path.join(REPO, words[2].split("/", 1)[1])), run)
        self.assertNotIn("pip", run)

    def test_no_expression_is_interpolated_into_a_script(self):
        for step in self.action["runs"]["steps"]:
            self.assertNotIn("${{", step["run"], step["run"])

    def test_the_launcher_adds_only_its_own_directory(self):
        before = list(sys.path)
        with mock.patch.dict(os.environ):
            os.environ.pop("NoDefaultCurrentDirectoryInExePath", None)
            try:
                ns = runpy.run_path(LAUNCHER, run_name="launcher_under_test")
                self.assertEqual(sys.path[0], REPO)
                self.assertEqual(sys.path[1:], before)
                # Windows looks in the working directory for `git` first
                self.assertEqual(
                    os.environ["NoDefaultCurrentDirectoryInExePath"], "1")
            finally:
                sys.path[:] = before
        self.assertTrue(callable(ns["main"]))

    def test_readme_says_how_the_step_runs(self):
        readme = _read("README.md")
        self.assertTrue("python -I" in readme, "README: how the step runs")
        self.assertFalse("with pip and runs" in readme, "README: stale")


# ---------------------------------------------------------------------
# V5 - --help / --version into a pipe nobody reads, on Python 3.10

class _GoneReader:
    """A stream whose reader has quit: every write is a broken pipe."""
    def write(self, text):
        raise BrokenPipeError(errno.EPIPE, "Broken pipe")

    def flush(self):
        pass


class TestArgparseOutputIntoAClosedPipe(unittest.TestCase):
    """Python 3.12 ignores a failed write when argparse prints help, usage
    or the version; 3.10 lets the OSError out of parse_args, where the
    closed-pipe guard absorbed it and `args` was never assigned
    (UnboundLocalError, exit 1, a traceback on stderr)."""

    def test_help_and_version_still_exit_0(self):
        for argv in (["--help"], ["--version"], ["check", "--help"],
                     ["init", "--help"]):
            with self.subTest(argv):
                with redirect_stdout(_GoneReader()):
                    with self.assertRaises(SystemExit) as cm:
                        cli_mod.build_parser().parse_args(argv)
                self.assertEqual(cm.exception.code, 0)

    def test_a_usage_error_still_exits_2(self):
        for argv in (["--bogus"], ["check", "--min-score", "x"], []):
            with self.subTest(argv):
                with redirect_stderr(_GoneReader()):
                    with self.assertRaises(SystemExit) as cm:
                        cli_mod.build_parser().parse_args(argv)
                self.assertEqual(cm.exception.code, 2)

    def test_main_returns_the_status_instead_of_a_traceback(self):
        for argv, code in ((["--help"], 0), (["--version"], 0),
                           (["--bogus"], 2)):
            with self.subTest(argv):
                with redirect_stdout(_GoneReader()), \
                        redirect_stderr(_GoneReader()):
                    try:
                        got = cli_mod.main(argv)
                    except SystemExit as e:
                        got = e.code
                self.assertEqual(got, code)

    def test_ci_runs_the_oldest_supported_python_too(self):
        ci = _read(".github/workflows/ci.yml")
        self.assertIn('"3.10"', ci)
        self.assertIn("unittest discover -s tests", ci)
        self.assertIn(">=3.10", _read("pyproject.toml"))


# ---------------------------------------------------------------------
# V6 - what `init` writes, and case in sensitive paths

class TestInitWritesTheRealDefaults(unittest.TestCase):
    """`init` said "shown with defaults" and wrote 4 of the 32 sensitive
    globs and 6 of the 11 markers: committing it switched most of the
    protection off (login.py: sensitive 20 -> 0)."""

    def test_the_template_parses_back_to_exactly_the_defaults(self):
        text = config_mod.example_config()
        parsed = miniyaml.safe_load(text)
        for key, default in config_mod.DEFAULTS.items():
            self.assertEqual(parsed[key], default, key)
        self.assertEqual(set(parsed), set(config_mod.DEFAULTS))

    def test_the_template_goes_through_the_loader_unchanged(self):
        tmp, old_base = make_pr_repo()
        base = commit_at_new_base(
            tmp, old_base, {".pr-verify.yaml": config_mod.example_config()})
        cfg = config_mod.load(tmp, base)
        for key, default in config_mod.DEFAULTS.items():
            self.assertEqual(cfg[key], default, key)

    def test_a_committed_init_config_scores_like_no_config(self):
        tmp, old_base = make_pr_repo()
        base = commit_at_new_base(
            tmp, old_base, {".pr-verify.yaml": config_mod.example_config()})
        _, with_config, _ = check_json(tmp, "--base", base)
        _, without, _ = check_json(tmp, "--base", old_base)
        for key in ("files", "risk", "blast_radius", "min_score", "gates"):
            self.assertEqual(with_config[key], without[key], key)

    def test_login_py_is_still_sensitive_after_init(self):
        tmp = tempfile.mkdtemp()
        git(tmp, "init", "-qb", "main")
        commit_as(tmp, *HUMAN, "base",
                  {"app/login.py": "x = 1\n",
                   ".pr-verify.yaml": config_mod.example_config()})
        base = rev(tmp)
        commit_as(tmp, *AGENT, "Edit login\n\nCo-authored-by: Claude",
                  {"app/login.py": "x = 1\ny = 2\n"})
        _, data, _ = check_json(tmp, "--base", base)
        self.assertEqual(data["risk"]["factors"]["sensitive"]["points"], 20)

    def test_init_writes_that_template_and_says_it_is_the_defaults(self):
        tmp = tempfile.mkdtemp()
        git(tmp, "init", "-qb", "main")
        code, out, err = main("--root", tmp, "init")
        self.assertEqual(code, 0)
        with open(os.path.join(tmp, ".pr-verify.yaml"), encoding="utf-8") as f:
            written = f.read()
        self.assertEqual(written, config_mod.example_config())
        self.assertIn("defaults", written.lower())
        # no gate is switched on by the template: `gates` has no default
        self.assertEqual(miniyaml.safe_load(written)["gates"], [])


class TestSensitivePathsIgnoreCase(unittest.TestCase):
    """The globs were matched case-sensitively: Login.tsx, PASSWORD.txt and
    src/Auth/Index.ts were not sensitive."""

    GLOBS = config_mod.DEFAULTS["sensitive_paths"]

    def test_capitalised_names_are_sensitive(self):
        for rel in ("src/Login.tsx", "PASSWORD.txt", "src/Auth/Index.ts",
                    "app/AUTH.py", "config/.ENV", "db/Migrations/0001.sql",
                    "lib/Crypto.rb", "web/OAuth2Client.js", "Secrets.yaml"):
            with self.subTest(rel):
                self.assertEqual(risk_mod._sensitive_hits([rel], self.GLOBS),
                                 [rel])

    def test_the_word_boundaries_still_hold(self):
        for rel in ("src/Author.py", "app/Monkey.py", "lib/Tokenizer.py",
                    "docs/Authority.md", "src/Latest.py"):
            with self.subTest(rel):
                self.assertEqual(risk_mod._sensitive_hits([rel], self.GLOBS),
                                 [])

    def test_a_users_own_glob_ignores_case_too(self):
        self.assertEqual(
            risk_mod._sensitive_hits(["Docs/RELEASE.md"], ["**/release.*"]),
            ["Docs/RELEASE.md"])

    def test_end_to_end(self):
        tmp = tempfile.mkdtemp()
        git(tmp, "init", "-qb", "main")
        commit_as(tmp, *HUMAN, "base", {"src/Login.tsx": "a\n"})
        base = rev(tmp)
        commit_as(tmp, *AGENT, "Edit\n\nCo-authored-by: Claude",
                  {"src/Login.tsx": "a\nb\n"})
        _, data, _ = check_json(tmp, "--base", base)
        self.assertEqual(data["risk"]["factors"]["sensitive"]["points"], 20)

    def test_readme_says_so(self):
        self.assertTrue("without regard to case" in _read("README.md"))


# ---------------------------------------------------------------------
# V7 - odd repository content and odd arguments

def make_submodule_repo(*bumps):
    """main: a human commit with app/a.py and a submodule at vendor/lib (not
    populated: an empty directory, the pointer set by hand). Then one commit
    per (author, digit) in `bumps`, each moving the pointer to <digit> * 40.
    Returns (tmp, base)."""
    tmp = tempfile.mkdtemp()
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


class TestSubmoduleBump(unittest.TestCase):
    """A submodule is a commit id in the tree, not a file: `git blame` has
    nothing to blame there. A pull request that moved one ended the run with
    `error: git blame ... failed` (exit 2)."""

    def test_a_bump_by_an_agent_is_the_agents(self):
        tmp, base = make_submodule_repo((AGENT, "2"))
        code, data, err = check_json(tmp, "--base", base)
        self.assertEqual(err, "")
        self.assertIn(code, (0, 1))
        entry = data["files"]["vendor/lib"]
        self.assertEqual((entry["added"], entry["agent_added"]), (1, 1))
        self.assertEqual(entry["label"], "agent")

    def test_a_bump_by_a_human_is_the_humans(self):
        tmp, base = make_submodule_repo((HUMAN, "2"))
        code, data, err = check_json(tmp, "--base", base)
        self.assertEqual(err, "")
        entry = data["files"]["vendor/lib"]
        self.assertEqual((entry["added"], entry["agent_added"]), (1, 0))
        self.assertEqual(entry["label"], "human")

    def test_the_last_commit_to_move_the_pointer_owns_the_new_one(self):
        for bumps, agent_added in (
                (((AGENT, "2"), (HUMAN, "3")), 0),
                (((HUMAN, "2"), (AGENT, "3")), 1)):
            with self.subTest(last="agent" if agent_added else "human"):
                tmp, base = make_submodule_repo(*bumps)
                code, data, err = check_json(tmp, "--base", base)
                self.assertEqual(err, "")
                entry = data["files"]["vendor/lib"]
                self.assertEqual(entry["added"], 1)
                self.assertEqual(entry["agent_added"], agent_added)

    def test_a_submodule_that_comes_and_goes(self):
        tmp = tempfile.mkdtemp()
        git(tmp, "init", "-qb", "main")
        commit_as(tmp, *HUMAN, "base", {"app/a.py": "x = 1\n"})
        base = rev(tmp)
        os.makedirs(os.path.join(tmp, "vendor", "lib"))
        git(tmp, "update-index", "--add", "--cacheinfo",
            f"160000,{'2' * 40},vendor/lib")
        commit_as(tmp, *AGENT, "Add lib\n\nCo-authored-by: Claude", {})
        added_at = rev(tmp)
        git(tmp, "rm", "-q", "--cached", "vendor/lib")
        commit_as(tmp, *AGENT, "Drop lib\n\nCo-authored-by: Claude", {})
        code, data, err = check_json(tmp, "--base", base, "--head", added_at)
        self.assertEqual(err, "")
        entry = data["files"]["vendor/lib"]
        self.assertEqual((entry["added"], entry["agent_added"]), (1, 1))
        code, data, err = check_json(tmp, "--base", added_at)
        self.assertEqual(err, "")
        entry = data["files"]["vendor/lib"]
        self.assertTrue(entry["deleted"])
        self.assertEqual(entry["deleted_by"], [AGENT[0]])


def _limit_memory(nbytes):
    """preexec_fn for a child process: at most nbytes of memory, where the
    system can enforce it."""
    def apply():
        for name in ("RLIMIT_AS", "RLIMIT_DATA"):
            try:
                resource.setrlimit(getattr(resource, name), (nbytes, nbytes))
            except (AttributeError, ValueError, OSError):
                pass
    return apply


def run_python(code, *args, memory=1 << 30, timeout=60):
    """A child interpreter (isolated: only this repository can be imported)
    running `code` with `args` in sys.argv[1:]. Where the system can enforce
    it the child gets `memory` bytes at most, so that reading an endless file
    ends in a MemoryError there and not in a swap storm here."""
    env = {k: v for k, v in os.environ.items() if k != "PYTHONUNBUFFERED"}
    kwargs = {}
    if resource is not None and os.name == "posix":
        kwargs["preexec_fn"] = _limit_memory(memory)
    prelude = f"import sys; sys.path.insert(0, {REPO!r}); "
    return subprocess.run([PY, "-I", "-c", prelude + code, *args],
                          capture_output=True, text=True, encoding="utf-8",
                          errors="replace", env=env, timeout=timeout,
                          **kwargs)


GRAPH = ("import json; from pr_verify import blastradius as br; "
         "print(json.dumps({k: sorted(v) for k, v in "
         "sorted(br.build_graph(sys.argv[1]).items())}))")
SMALL_GRAPH = {"app/a.py": ["app/b.py"], "app/b.py": []}


def make_small_tree():
    """A directory (no repository) with app/a.py importing app/b.py."""
    tmp = tempfile.mkdtemp()
    os.makedirs(os.path.join(tmp, "app"))
    for rel, text in (("app/a.py", "import app.b\n"), ("app/b.py", "B = 1\n")):
        with open(os.path.join(tmp, rel), "w", encoding="utf-8",
                  newline="\n") as f:
            f.write(text)
    return tmp


@unittest.skipUnless(os.name == "posix" and os.path.exists("/dev/zero"),
                     "needs /dev/zero and a POSIX child process")
class TestFilesThatAreNotSource(unittest.TestCase):
    """The import scan opened every *.py it found, links and named pipes
    included: a pull request with `evil.py -> /dev/zero` ended the run in a
    MemoryError (exit 1 and a traceback), and a named pipe would block it for
    ever. Only regular files are read."""

    def test_a_link_to_an_endless_file_is_not_read(self):
        tmp = make_small_tree()
        os.symlink("/dev/zero", os.path.join(tmp, "evil.py"))
        r = run_python(GRAPH, tmp)
        self.assertEqual(r.returncode, 0, r.stderr[-600:])
        self.assertEqual(json.loads(r.stdout), SMALL_GRAPH)

    @unittest.skipUnless(hasattr(os, "mkfifo"), "needs named pipes")
    def test_a_named_pipe_is_not_opened(self):
        tmp = make_small_tree()
        os.mkfifo(os.path.join(tmp, "pipe.py"))
        r = run_python(GRAPH, tmp, timeout=30)
        self.assertEqual(r.returncode, 0, r.stderr[-600:])
        self.assertEqual(json.loads(r.stdout), SMALL_GRAPH)

    def test_a_pull_request_with_the_link_is_checked_to_the_end(self):
        tmp = tempfile.mkdtemp()
        git(tmp, "init", "-qb", "main")
        commit_as(tmp, *HUMAN, "base", {"app/a.py": "x = 1\n"})
        base = rev(tmp)
        os.symlink("/dev/zero", os.path.join(tmp, "evil.py"))
        commit_as(tmp, *AGENT, "Add link\n\nCo-authored-by: Claude", {})
        r = run_python("from pr_verify.cli import main; "
                       "sys.exit(main(sys.argv[1:]))",
                       "--root", tmp, "check", "--base", base,
                       "--skip-gates", "--format", "json")
        self.assertIn(r.returncode, (0, 1), r.stderr[-600:])
        self.assertNotIn("Traceback", r.stderr)
        self.assertIn("evil.py", json.loads(r.stdout)["files"])


@unittest.skipUnless(hasattr(os, "symlink"), "needs symbolic links")
class TestLinksAreNotFollowed(unittest.TestCase):
    def test_no_kind_of_link_enters_the_graph(self):
        tmp = make_small_tree()
        try:
            os.symlink("a.py", os.path.join(tmp, "app", "alias.py"))
            os.symlink("loop.py", os.path.join(tmp, "app", "loop.py"))
            os.symlink("nowhere.py", os.path.join(tmp, "app", "dangling.py"))
            os.symlink(".", os.path.join(tmp, "app", "dir.py"))
        except OSError as e:          # Windows without the privilege
            self.skipTest(f"cannot make symbolic links: {e}")
        graph = br.build_graph(tmp)
        self.assertEqual({k: sorted(v) for k, v in graph.items()},
                         SMALL_GRAPH)


class TestSourceThatCannotBeRead(unittest.TestCase):
    def test_a_file_over_the_limit_is_not_read(self):
        tmp = make_small_tree()
        big = os.path.join(tmp, "app", "big.py")
        with open(big, "w", encoding="utf-8", newline="\n") as f:
            f.write("import app.b\n" + "pad = 1\n" * 1000)
        graph = br.build_graph(tmp)
        self.assertEqual(graph["app/big.py"], {"app/b.py"})
        with mock.patch.object(br, "MAX_SOURCE_BYTES", 1000):
            graph = br.build_graph(tmp)
        self.assertEqual(graph["app/big.py"], set())     # in the graph, unread
        self.assertEqual(graph["app/a.py"], {"app/b.py"})

    def test_a_byte_order_mark_does_not_hide_the_imports(self):
        # Windows editors write one; the parser rejects it as part of the text
        tmp = make_small_tree()
        with open(os.path.join(tmp, "app", "a.py"), "wb") as f:
            f.write(b"\xef\xbb\xbfimport app.b\n")
        self.assertEqual(br.build_graph(tmp)["app/a.py"], {"app/b.py"})

    def test_source_too_deep_to_parse_is_skipped_like_a_syntax_error(self):
        # ast.parse raises RecursionError or MemoryError (not a SyntaxError)
        # for a very long chain of operators; Python 3.10 dies on the longest
        # ones before it can raise, so the error is injected here
        for error in (RecursionError, MemoryError):
            with self.subTest(error.__name__):
                with mock.patch.object(br.ast, "parse", side_effect=error()):
                    self.assertEqual(br._python_imports("a.py", "x = 1\n"),
                                     [])


@contextlib.contextmanager
def git_gives_up(matches):
    """Every `git` call that `matches(argv)` outlives its timeout:
    subprocess.run raises TimeoutExpired for it, as it does for a git working
    on a repository of a million files."""
    real = subprocess.run

    def run(cmd, *args, **kwargs):
        if (isinstance(cmd, (list, tuple)) and cmd and cmd[0] == "git"
                and matches(cmd)):
            raise subprocess.TimeoutExpired(cmd, kwargs.get("timeout") or 60)
        return real(cmd, *args, **kwargs)

    with mock.patch.object(subprocess, "run", run):
        yield


class TestGitThatDoesNotAnswer(unittest.TestCase):
    """A git call that outlived its timeout (60 seconds; 15 for the small
    lookups) ended the run with a traceback and exit 1, the code for "the
    verification failed". It is a run that could not verify: `error:` and
    exit 2, like every other git failure."""

    CASES = (
        ("resolving a ref", True,
         lambda c: "rev-parse" in c and "--quiet" in c),
        ("finding the base branch", False, lambda c: "symbolic-ref" in c),
        ("reading the config at the base", True,
         lambda c: "show" in c and any(
             str(a).endswith(":.pr-verify.yaml") for a in c)),
        ("snapshotting the worktree", True, lambda c: "read-tree" in c),
        ("finding the merge-base", True, lambda c: "merge-base" in c),
        ("reading the patch", True,
         lambda c: "diff-tree" in c and "-p" in c),
        ("blame settings", True,
         lambda c: "config" in c and "--get-all" in c),
        ("blame", True, lambda c: "blame" in c),
        ("who removed the lines", True,
         lambda c: "rev-list" in c and "--no-merges" in c),
        ("reading the commits", True,
         lambda c: "show" in c and "-s" in c),
    )

    def make_repo(self):
        tmp, base = make_lines_repo()
        agent_commit(tmp, {"app/auth.py": lines(0, 1, 6, 7, 8, 9, 10)})
        return tmp, base

    def test_every_stage_ends_in_an_error_not_a_traceback(self):
        for label, with_base, matches in self.CASES:
            with self.subTest(label):
                tmp, base = self.make_repo()
                argv = ["--root", tmp, "check", "--skip-gates"]
                if with_base:
                    argv += ["--base", base]
                with git_gives_up(matches):
                    code, out, err = main(*argv)
                self.assertEqual(code, 2, (out, err))
                self.assertTrue(err.startswith("error: "), err)
                self.assertIn("did not finish", err)
                self.assertNotIn("Traceback", err)

    def test_the_message_names_the_git_command(self):
        tmp, base = self.make_repo()
        with git_gives_up(lambda c: "blame" in c):
            code, out, err = main("--root", tmp, "check", "--base", base,
                                  "--skip-gates")
        self.assertEqual(code, 2)
        self.assertIn("git blame did not finish within 60 seconds", err)

    def test_the_action_reports_it_the_same_way(self):
        tmp, base = self.make_repo()
        outputs = os.path.join(tempfile.mkdtemp(), "github-output")
        err = io.StringIO()
        with git_gives_up(lambda c: "blame" in c), redirect_stderr(err):
            code = action_mod.main(
                ["--root", tmp, "check", "--base", base, "--skip-gates"],
                {"GITHUB_OUTPUT": outputs})
        self.assertEqual(code, 2)
        self.assertIn("did not finish", err.getvalue())
        with open(outputs, encoding="utf-8") as f:
            self.assertIn("exit-code=2", f.read())


class TestRefsThatLookLikeOptions(unittest.TestCase):
    """`--head=--output=FILE` went to `git diff-tree` as an option: git wrote
    its patch into FILE, whatever was there."""

    def test_no_ref_can_make_git_write_a_file(self):
        tmp, base = make_pr_repo()
        where = tempfile.mkdtemp()
        precious = os.path.join(where, "precious.txt")
        with open(precious, "w", encoding="utf-8") as f:
            f.write("precious\n")
        fresh = os.path.join(where, "fresh.txt")
        for option in ("--head", "--base"):
            for target in (precious, fresh):
                with self.subTest(option=option,
                                  target=os.path.basename(target)):
                    argv = ["--root", tmp, "check", "--skip-gates",
                            f"{option}=--output={target}"]
                    if option == "--head":
                        argv += ["--base", base]
                    code, out, err = main(*argv)
                    self.assertEqual(code, 2, out)
                    self.assertIn("error:", err)
        with open(precious, encoding="utf-8") as f:
            self.assertEqual(f.read(), "precious\n")
        self.assertFalse(os.path.exists(fresh))


# ---------------------------------------------------------------------
# V8 - every deleted file re-parsed the whole worktree

class TestDeletedFilesParseTheWorktreeOnce(unittest.TestCase):
    def test_a_file_is_parsed_once_however_many_files_are_deleted(self):
        tmp = tempfile.mkdtemp()
        git(tmp, "init", "-qb", "main")
        files = {}
        for i in range(30):
            files[f"app/mod_{i}.py"] = f"VALUE = {i}\n"
            files[f"app/use_{i}.py"] = f"from app.mod_{i} import VALUE\n"
        commit_as(tmp, *HUMAN, "base", files)
        base = rev(tmp)
        gone = range(0, 30, 2)                          # 15 modules go
        for i in gone:
            os.remove(os.path.join(tmp, "app", f"mod_{i}.py"))
        commit_as(tmp, *AGENT, "Drop modules\n\nCo-authored-by: Claude", {})
        real, parsed = ast.parse, []

        def counting(*args, **kwargs):
            parsed.append(1)
            return real(*args, **kwargs)

        with mock.patch.object(br.ast, "parse", counting):
            code, data, err = check_json(tmp, "--base", base)
        self.assertEqual(err, "")
        # what is left of the tree is read once; it was once per deleted file
        self.assertLessEqual(len(parsed), 30 + 15)
        # and each module that went still names the file that imported it
        for i in gone:
            entry = data["blast_radius"][f"app/mod_{i}.py"]
            self.assertEqual(entry["direct"], [f"app/use_{i}.py"])


# ---------------------------------------------------------------------
# Release

class TestVersionsAgree(unittest.TestCase):
    def test_the_package_and_the_cli_name_the_same_version(self):
        found = re.search(r'^version\s*=\s*"([^"]+)"', _read("pyproject.toml"),
                          re.M)
        self.assertIsNotNone(found)
        self.assertEqual(found.group(1), cli_mod.VERSION)

    def test_the_json_document_carries_it(self):
        tmp, base = make_pr_repo()
        code, data, err = check_json(tmp, "--base", base)
        self.assertEqual(data["version"], cli_mod.VERSION)


if __name__ == "__main__":
    unittest.main()
