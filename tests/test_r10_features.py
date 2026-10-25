"""0.2.0: SARIF and the PR comment, review depth, agent signals beyond
commit trailers, test integrity, policy gates as code, description-vs-diff,
and the Action's comment / summary / SARIF wiring."""

import copy
import io
import json
import os
import re
import tempfile
import threading
import unittest
from contextlib import redirect_stderr, redirect_stdout
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest import mock

from pr_verify import action as action_mod
from pr_verify import cli as cli_mod
from pr_verify import config as config_mod
from pr_verify import descdiff as dd
from pr_verify import markers as markers_mod
from pr_verify import policy as policy_mod
from pr_verify import prinfo as prinfo_mod
from pr_verify import provenance as prov_mod
from pr_verify import render as render_mod
from pr_verify import testintegrity as ti

from fixture import commit_as, commit_at_new_base, git, make_pr_repo

import subprocess


def head_of(tmp):
    return subprocess.run(["git", "-C", tmp, "rev-parse", "HEAD"],
                          capture_output=True, text=True, check=True
                          ).stdout.strip()


def run(*argv, cwd=None):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = cli_mod.main(list(argv))
    return code, out.getvalue(), err.getvalue()


def check_json(tmp, base, *extra):
    code, out, err = run("--root", tmp, "check", "--base", base,
                         "--format", "json", "--skip-gates", *extra)
    return code, json.loads(out), err


def repo(files, agent_files=None, agent_msg="agent work\n\nCo-authored-by: Claude",
         human_files=None, config=None):
    """(tmp, base): a human base commit of `files` (plus a trusted config at
    the base when given), then optionally a human and an agent commit."""
    import tempfile as tf
    tmp = tf.mkdtemp()
    git(tmp, "init", "-qb", "main")
    commit_as(tmp, "Dan Calas", "dan@example.com", "base", dict(files))
    base = head_of(tmp)
    if config is not None:
        base = commit_at_new_base(tmp, base, {".pr-verify.yaml": config})
        git(tmp, "checkout", "-q", "-B", "main", base)
    if human_files:
        commit_as(tmp, "Dan Calas", "dan@example.com", "human", human_files)
    if agent_files is not None:
        commit_as(tmp, "claude-bot", "claude-bot@example.com", agent_msg,
                  agent_files)
    return tmp, base


# ---------------------------------------------------------------------------
# agent signals
# ---------------------------------------------------------------------------

CFG = config_mod.DEFAULTS


class TestSignals(unittest.TestCase):
    def sig(self, **kw):
        return prinfo_mod.detect_signals(prinfo_mod.PRInfo(**kw), CFG)

    def test_a_label_matches_whatever_its_case(self):
        s = self.sig(labels=["bug", "AI-Generated"])
        self.assertEqual(s, [{"kind": "label", "value": "AI-Generated",
                              "rule": "ai-generated"}])

    def test_an_unrelated_label_is_nothing(self):
        self.assertEqual(self.sig(labels=["bug", "documentation"]), [])

    def test_a_label_must_match_whole(self):
        self.assertEqual(self.sig(labels=["agentic-research", "cursory"]), [])

    def test_bot_author(self):
        s = self.sig(author="copilot-swe-agent[bot]")
        self.assertEqual([x["kind"] for x in s], ["author"])

    def test_human_author_is_not_an_agent(self):
        self.assertEqual(self.sig(author="dan-calas"), [])

    def test_branch_prefixes(self):
        for b in ("claude/fix-login", "copilot/add-x", "cursor/abc",
                  "codex/y", "Claude/Mixed-Case", "refs/heads/claude/z"):
            self.assertEqual([x["kind"] for x in self.sig(branch=b)],
                             ["branch"], b)

    def test_branch_that_merely_contains_the_name_is_not_one(self):
        for b in ("feature/claude-docs", "claude", "mycursor/x"):
            self.assertEqual(self.sig(branch=b), [], b)

    def test_order_is_labels_author_branch(self):
        s = self.sig(labels=["agent"], author="claude[bot]",
                     branch="claude/x")
        self.assertEqual([x["kind"] for x in s],
                         ["label", "author", "branch"])

    def test_patterns_come_from_the_config(self):
        cfg = dict(CFG, agent_branches=["bot-*"], agent_labels=[],
                   agent_authors=[])
        s = prinfo_mod.detect_signals(
            prinfo_mod.PRInfo(branch="bot-fix", labels=["agent"],
                              author="claude[bot]"), cfg)
        self.assertEqual([x["kind"] for x in s], ["branch"])

    def test_marker_text(self):
        self.assertEqual(prinfo_mod.signal_marker(
            {"kind": "branch", "value": "claude/x", "rule": "claude/*"}),
            "branch:claude/x")


class TestEventFile(unittest.TestCase):
    def write(self, data, raw=None):
        d = tempfile.mkdtemp()
        p = os.path.join(d, "event.json")
        with open(p, "wb") as f:
            f.write(raw if raw is not None else json.dumps(data).encode())
        return p

    def test_reads_the_pull_request(self):
        p = self.write({"pull_request": {
            "number": 7, "title": "T", "body": "B",
            "labels": [{"name": "agent"}, {"name": ""}, "junk"],
            "user": {"login": "claude[bot]"}, "head": {"ref": "claude/x"}}})
        info = prinfo_mod.from_event(p)
        self.assertEqual((info.number, info.title, info.body, info.labels,
                          info.author, info.branch),
                         (7, "T", "B", ["agent"], "claude[bot]", "claude/x"))

    def test_not_a_pull_request_event_is_empty(self):
        self.assertEqual(prinfo_mod.from_event(self.write({"push": {}})),
                         prinfo_mod.PRInfo())

    def test_garbage_is_empty_not_a_crash(self):
        for raw in (b"not json", b"[1,2]", b"\xff\xfe", b"{\"pull_request\": 5}"):
            self.assertEqual(prinfo_mod.from_event(self.write(None, raw)),
                             prinfo_mod.PRInfo())

    def test_wrong_types_inside_are_ignored(self):
        p = self.write({"pull_request": {"number": True, "title": 5,
                                         "labels": "x", "user": 3,
                                         "head": []}})
        info = prinfo_mod.from_event(p)
        self.assertEqual((info.number, info.title, info.labels), (None, "", []))

    def test_merge_keeps_both_label_lists(self):
        a = prinfo_mod.PRInfo(labels=["x"], author="a", branch="b1")
        b = prinfo_mod.PRInfo(labels=["x", "y"], branch="b2")
        m = prinfo_mod.merge(a, b)
        self.assertEqual((m.labels, m.author, m.branch),
                         (["x", "y"], "a", "b2"))


class TestTrailerKeys(unittest.TestCase):
    BODY = "fix\n\nClaude-Session: https://claude.ai/code/session_1\n"

    def test_default_key_is_claude_session(self):
        self.assertEqual(markers_mod.match("Dan", "d@x", "s", self.BODY,
                                           ["claude"]), "claude")

    def test_configured_keys_replace_it(self):
        keys = markers_mod.parse_trailer_keys(["codex-session: Codex"])
        self.assertIsNone(markers_mod.match("Dan", "d@x", "s", self.BODY,
                                            ["claude", "codex"], keys))
        body = "fix\n\nCodex-Session: abc\n"
        self.assertEqual(markers_mod.match("Dan", "d@x", "s", body,
                                           ["claude", "codex"], keys), "codex")

    def test_parse(self):
        self.assertEqual(markers_mod.parse_trailer_keys(
            ["A-Key: Name", "bare", ": x", "  "]),
            {"a-key": "Name", "bare": "bare"})


class TestSignalsEndToEnd(unittest.TestCase):
    """A human-only branch becomes agent-written when the PR says so."""

    def setUp(self):
        self.tmp, self.base = repo(
            {"app/core.py": "def f():\n    return 1\n"},
            human_files={"app/core.py": "def f():\n    return 1\n\n\n"
                                        "def g():\n    return 2\n"})

    def agent_share(self, *extra):
        code, data, _ = check_json(self.tmp, self.base, *extra)
        return data, data["files"]["app/core.py"]

    def test_without_a_signal_it_is_human(self):
        data, f = self.agent_share()
        self.assertEqual((f["agent_added"], f["label"]), (0, "human"))
        self.assertEqual(data["agent_signals"], [])

    def test_branch_flag(self):
        data, f = self.agent_share("--pr-branch", "claude/fix")
        self.assertEqual((f["agent_added"], f["label"]), (f["added"], "agent"))
        self.assertEqual(data["agent_signals"][0]["kind"], "branch")
        self.assertIn("Dan Calas (branch:claude/fix)", f["agents"])

    def test_label_flag_repeats(self):
        data, f = self.agent_share("--pr-label", "bug", "--pr-label",
                                   "ai-generated")
        self.assertEqual(f["label"], "agent")
        self.assertEqual(data["agent_signals"][0]["value"], "ai-generated")

    def test_author_flag(self):
        _, f = self.agent_share("--pr-author", "copilot-swe-agent[bot]")
        self.assertEqual(f["label"], "agent")

    def test_event_file(self):
        d = tempfile.mkdtemp()
        p = os.path.join(d, "e.json")
        with open(p, "w") as fh:
            json.dump({"pull_request": {"head": {"ref": "cursor/x"},
                                        "labels": [], "user": {"login": "d"}}},
                      fh)
        data, f = self.agent_share("--event-file", p)
        self.assertEqual(f["label"], "agent")
        self.assertEqual(data["agent_signals"][0]["value"], "cursor/x")

    def test_the_checked_out_branch_counts_locally(self):
        git(self.tmp, "checkout", "-qb", "claude/local")
        _, f = self.agent_share()
        self.assertEqual(f["label"], "agent")

    def test_an_explicit_head_does_not_borrow_the_checked_out_branch(self):
        git(self.tmp, "checkout", "-qb", "claude/local")
        sha = head_of(self.tmp)
        _, f = self.agent_share("--head", sha)
        self.assertEqual(f["label"], "human")

    def test_a_signal_raises_the_score(self):
        plain, _ = self.agent_share()
        flagged, _ = self.agent_share("--pr-branch", "codex/z")
        self.assertGreater(flagged["risk"]["score"], plain["risk"]["score"])

    def test_config_patterns_come_from_the_base(self):
        tmp, base = repo({"a.py": "x = 1\n"}, human_files={"a.py": "x = 2\n"},
                         config='agent_branches:\n  - "wip-*"\n')
        _, data, _ = check_json(tmp, base, "--pr-branch", "claude/x")
        self.assertEqual(data["agent_signals"], [])
        _, data, _ = check_json(tmp, base, "--pr-branch", "wip-1")
        self.assertEqual(data["agent_signals"][0]["rule"], "wip-*")

    def test_an_unreadable_event_file_is_exit_2(self):
        code, _, err = run("--root", self.tmp, "check", "--base", self.base,
                           "--event-file", os.path.join(self.tmp, "nope.json"))
        self.assertEqual(code, 2)
        self.assertIn("error:", err)

    def test_a_trailer_key_from_the_config(self):
        tmp, base = repo({"a.py": "x = 1\n"},
                         config='agent_trailer_keys:\n  - "codex-session: Codex"\n'
                                'agent_markers:\n  - codex\n')
        commit_as(tmp, "Dan Calas", "dan@example.com",
                  "work\n\nCodex-Session: s1", {"a.py": "x = 3\n"})
        _, data, _ = check_json(tmp, base)
        self.assertEqual(data["files"]["a.py"]["label"], "agent")


# ---------------------------------------------------------------------------
# test integrity
# ---------------------------------------------------------------------------

PY_BASE = ("import pytest\n\n\n"
           "def test_a():\n    assert add(1, 2) == 3\n\n\n"
           "def test_b():\n    assert add(2, 2) == 4\n")
JS_BASE = ("describe('math', () => {\n"
           "  it('adds', () => {\n    expect(add(1, 2)).toBe(3);\n  });\n"
           "  it('subtracts', () => {\n    expect(sub(3, 1)).toEqual(2);\n  });\n"
           "});\n")

#: (name, path, before, after, rules that must be found, rules that must not)
INTEGRITY_CASES = [
    ("py skip", "tests/test_x.py", PY_BASE,
     PY_BASE.replace("def test_a", "@pytest.mark.skip\ndef test_a"),
     {"disabled-test"}, set()),
    ("py skipif", "tests/test_x.py", PY_BASE,
     PY_BASE.replace("def test_a", "@pytest.mark.skipif(True, reason='x')\ndef test_a"),
     {"disabled-test"}, set()),
    ("py xfail", "tests/test_x.py", PY_BASE,
     PY_BASE.replace("def test_a", "@pytest.mark.xfail\ndef test_a"),
     {"disabled-test"}, set()),
    ("py unittest skip", "tests/test_x.py", PY_BASE,
     PY_BASE.replace("def test_a", "@unittest.skip('later')\ndef test_a"),
     {"disabled-test"}, set()),
    ("py skipTest call", "tests/test_x.py", PY_BASE,
     PY_BASE.replace("assert add(1, 2) == 3", "self.skipTest('x')"),
     {"disabled-test"}, set()),
    ("py pytest.skip call", "tests/test_x.py", PY_BASE,
     PY_BASE.replace("    assert add(2, 2) == 4", "    pytest.skip('x')\n    assert add(2, 2) == 4"),
     {"disabled-test"}, set()),
    ("py module skip", "tests/test_x.py", PY_BASE,
     PY_BASE.replace("import pytest\n", "import pytest\npytestmark = pytest.mark.skip\n"),
     {"disabled-test"}, set()),
    ("py tautology", "tests/test_x.py", PY_BASE,
     PY_BASE.replace("    assert add(1, 2) == 3", "    assert True"),
     {"tautology-assertion", "loosened-assertion"}, set()),
    ("py equality to truthiness", "tests/test_x.py", PY_BASE,
     PY_BASE.replace("assert add(1, 2) == 3", "assert add(1, 2)"),
     {"loosened-assertion"}, {"disabled-test"}),
    ("py assertEqual to assertTrue", "tests/test_x.py",
     "class T(unittest.TestCase):\n    def test_a(self):\n        self.assertEqual(add(1, 2), 3)\n",
     "class T(unittest.TestCase):\n    def test_a(self):\n        self.assertTrue(add(1, 2))\n",
     {"loosened-assertion"}, set()),
    ("py delete a test", "tests/test_x.py", PY_BASE,
     PY_BASE.split("\n\ndef test_b")[0] + "\n",
     {"deleted-test"}, set()),
    ("py remove an assertion", "tests/test_x.py",
     "def test_a():\n    assert f(1) == 1\n    assert f(2) == 2\n",
     "def test_a():\n    assert f(1) == 1\n",
     {"removed-assertions"}, {"deleted-test"}),
    ("py rename is not a deletion", "tests/test_x.py", PY_BASE,
     PY_BASE.replace("def test_a", "def test_adds"),
     set(), {"deleted-test", "removed-assertions"}),
    ("py strengthening is fine", "tests/test_x.py",
     "def test_a():\n    assert f(1)\n",
     "def test_a():\n    assert f(1) == 1\n",
     set(), {"loosened-assertion", "removed-assertions"}),
    ("py adding tests is fine", "tests/test_x.py", PY_BASE,
     PY_BASE + "\n\ndef test_c():\n    assert add(0, 0) == 0\n",
     set(), {"deleted-test", "disabled-test", "removed-assertions"}),
    ("py skip in a comment is fine", "tests/test_x.py", PY_BASE,
     PY_BASE + "# @pytest.mark.skip was removed\n",
     set(), {"disabled-test"}),
    ("py skip outside a test file is fine", "app/skipper.py",
     "def f():\n    return 1\n",
     "import pytest\n\n@pytest.mark.skip\ndef f():\n    return 1\n",
     set(), {"disabled-test"}),
    ("js it.skip", "tests/math.test.js", JS_BASE,
     JS_BASE.replace("it('adds'", "it.skip('adds'"),
     {"disabled-test"}, set()),
    ("js test.todo", "tests/math.test.js", JS_BASE,
     JS_BASE.replace("it('adds'", "it.todo('adds'"),
     {"disabled-test"}, set()),
    ("js xit", "tests/math.test.js", JS_BASE,
     JS_BASE.replace("it('adds'", "xit('adds'"),
     {"disabled-test"}, set()),
    ("js xdescribe", "tests/math.test.js", JS_BASE,
     JS_BASE.replace("describe('math'", "xdescribe('math'"),
     {"disabled-test"}, set()),
    ("js it.only", "tests/math.test.js", JS_BASE,
     JS_BASE.replace("it('adds'", "it.only('adds'"),
     {"focused-test"}, set()),
    ("js fit", "tests/math.test.js", JS_BASE,
     JS_BASE.replace("it('adds'", "fit('adds'"),
     {"focused-test"}, set()),
    ("js describe.only", "tests/math.test.js", JS_BASE,
     JS_BASE.replace("describe('math'", "describe.only('math'"),
     {"focused-test"}, set()),
    ("js toBe to toBeTruthy", "tests/math.test.js", JS_BASE,
     JS_BASE.replace("expect(add(1, 2)).toBe(3)", "expect(add(1, 2)).toBeTruthy()"),
     {"loosened-assertion"}, set()),
    ("js toEqual to toBeDefined", "tests/math.test.js", JS_BASE,
     JS_BASE.replace("expect(sub(3, 1)).toEqual(2)", "expect(sub(3, 1)).toBeDefined()"),
     {"loosened-assertion"}, set()),
    ("js tautology", "tests/math.test.js", JS_BASE,
     JS_BASE.replace("expect(add(1, 2)).toBe(3)", "expect(true).toBe(true)"),
     {"tautology-assertion"}, set()),
    ("js delete a test", "tests/math.test.js", JS_BASE,
     JS_BASE.replace("  it('subtracts', () => {\n    expect(sub(3, 1)).toEqual(2);\n  });\n", ""),
     {"deleted-test"}, set()),
    ("ts spec skip", "src/math.spec.ts", JS_BASE,
     JS_BASE.replace("it('adds'", "it.skip('adds'"),
     {"disabled-test"}, set()),
    ("js strengthening is fine", "tests/math.test.js",
     "it('a', () => {\n  expect(f()).toBeTruthy();\n});\n",
     "it('a', () => {\n  expect(f()).toBe(1);\n});\n",
     set(), {"loosened-assertion"}),
    ("go t.Skip", "pkg/math_test.go",
     "func TestAdd(t *testing.T) {\n\tif Add(1, 2) != 3 {\n\t\tt.Fatal(\"x\")\n\t}\n}\n",
     "func TestAdd(t *testing.T) {\n\tt.Skip(\"later\")\n\tif Add(1, 2) != 3 {\n\t\tt.Fatal(\"x\")\n\t}\n}\n",
     {"disabled-test"}, set()),
    ("go delete a test", "pkg/math_test.go",
     "func TestAdd(t *testing.T) {\n}\n\nfunc TestSub(t *testing.T) {\n}\n",
     "func TestAdd(t *testing.T) {\n}\n",
     {"deleted-test"}, set()),
    ("java @Disabled", "src/test/MathTest.java",
     "class MathTest {\n    @Test\n    void adds() {}\n}\n",
     "class MathTest {\n    @Disabled\n    @Test\n    void adds() {}\n}\n",
     {"disabled-test"}, set()),
    ("ruby xit", "spec/math_spec.rb",
     "describe 'x' do\n  it 'adds' do\n  end\nend\n",
     "describe 'x' do\n  xit 'adds' do\n  end\nend\n",
     {"disabled-test"}, set()),
    ("rust ignore", "tests/math.rs",
     "#[test]\nfn adds() {}\n",
     "#[test]\n#[ignore]\nfn adds() {}\n",
     {"disabled-test"}, set()),
]


class TestIntegrityTable(unittest.TestCase):
    def test_every_row(self):
        for name, path, before, after, must, never in INTEGRITY_CASES:
            with self.subTest(name):
                tmp, base = repo({path: before, "app/src.py": "x = 1\n"},
                                 agent_files={path: after})
                _, data, _ = check_json(tmp, base)
                found = {f["rule"] for f in data["test_integrity"]["findings"]}
                self.assertTrue(must <= found, f"{name}: wanted {must}, got {found}")
                self.assertFalse(never & found, f"{name}: did not want {never & found}")
                if not must:
                    self.assertEqual(found, set(), name)
                for f in data["test_integrity"]["findings"]:
                    self.assertEqual(f["file"], path)

    def test_the_rule_tables_are_covered_by_a_row(self):
        covered = " ".join(c[3] + c[2] for c in INTEGRITY_CASES)
        # every added-line rule family has at least one row above
        for rule in {r[0] for r in ti.ADDED_RULES}:
            ids = {f for c in INTEGRITY_CASES for f in c[4]}
            self.assertIn(rule, ids)
        self.assertTrue(covered)

    def test_the_line_number_points_at_the_new_line(self):
        tmp, base = repo({"tests/test_x.py": PY_BASE},
                         agent_files={"tests/test_x.py": PY_BASE.replace(
                             "def test_a", "@pytest.mark.skip\ndef test_a")})
        _, data, _ = check_json(tmp, base)
        f = data["test_integrity"]["findings"][0]
        self.assertEqual((f["rule"], f["line"]), ("disabled-test", 4))
        self.assertEqual(f["snippet"], "@pytest.mark.skip")

    def test_deleting_a_test_file(self):
        tmp, base = repo({"tests/test_x.py": PY_BASE, "app/a.py": "x = 1\n"})
        os.remove(os.path.join(tmp, "tests/test_x.py"))
        git(tmp, "add", "-A")
        git(tmp, "-c", "user.name=claude-bot", "-c",
            "user.email=claude-bot@example.com", "commit", "-qm",
            "cleanup\n\nCo-authored-by: Claude")
        _, data, _ = check_json(tmp, base)
        self.assertEqual([f["rule"] for f in data["test_integrity"]["findings"]],
                         ["deleted-test-file"])

    def test_a_human_doing_the_same_is_not_reported(self):
        tmp, base = repo({"tests/test_x.py": PY_BASE},
                         human_files={"tests/test_x.py": PY_BASE.replace(
                             "def test_a", "@pytest.mark.skip\ndef test_a")})
        _, data, _ = check_json(tmp, base)
        self.assertEqual(data["test_integrity"]["findings"], [])

    def test_a_human_deleting_a_test_file_is_not_reported(self):
        tmp, base = repo({"tests/test_x.py": PY_BASE, "a.py": "x = 1\n"})
        os.remove(os.path.join(tmp, "tests/test_x.py"))
        git(tmp, "add", "-A")
        git(tmp, "-c", "user.name=Dan Calas", "-c",
            "user.email=dan@example.com", "commit", "-qm", "drop")
        _, data, _ = check_json(tmp, base)
        self.assertEqual(data["test_integrity"]["findings"], [])

    def test_a_moved_test_is_not_deleted(self):
        tmp, base = repo({"tests/test_a.py": "def test_one():\n    assert 1 == 1\n"
                                             "\n\ndef test_two():\n    assert 2 == 2\n",
                          "tests/test_b.py": "def test_three():\n    assert 3 == 3\n"},
                         agent_files={
                             "tests/test_a.py": "def test_one():\n    assert 1 == 1\n",
                             "tests/test_b.py": "def test_three():\n    assert 3 == 3\n"
                                                "\n\ndef test_two():\n    assert 2 == 2\n"})
        _, data, _ = check_json(tmp, base)
        # moving a test to another file is not a deletion; only the milder
        # "fewer assertions in this file" warning remains
        self.assertEqual([f["rule"] for f in data["test_integrity"]["findings"]],
                         ["removed-assertions"])
        self.assertEqual(data["test_integrity"]["findings"][0]["severity"], "warning")

    def test_a_finding_scores_and_makes_the_review_deep(self):
        tmp, base = repo({"tests/test_x.py": PY_BASE, "app/a.py": "x = 1\n"},
                         agent_files={"tests/test_x.py": PY_BASE.replace(
                             "def test_a", "@pytest.mark.skip\ndef test_a")})
        _, data, _ = check_json(tmp, base)
        self.assertEqual(data["risk"]["factors"]["test_integrity"]["points"], 15)
        self.assertEqual(data["review_depth"]["depth"], "deep")

    def test_a_pr_level_signal_makes_every_line_the_agents(self):
        tmp, base = repo({"tests/test_x.py": PY_BASE},
                         human_files={"tests/test_x.py": PY_BASE.replace(
                             "def test_a", "@pytest.mark.skip\ndef test_a")})
        _, data, _ = check_json(tmp, base, "--pr-branch", "claude/x")
        self.assertEqual([f["rule"] for f in data["test_integrity"]["findings"]],
                         ["disabled-test"])


class TestWalkHunks(unittest.TestCase):
    def test_file_content_that_looks_like_a_header_stays_content(self):
        patch = ("diff --git a/t.py b/t.py\n--- a/t.py\n+++ b/t.py\n"
                 "@@ -1,2 +1,2 @@\n--- not a header\n-x\n+++ b/evil.py\n+y\n")
        files = ti.walk_hunks(patch)
        self.assertEqual(list(files), ["t.py"])
        h = files["t.py"][0]
        self.assertEqual([t for _, t in h.removed], ["-- not a header", "x"])
        self.assertEqual([t for _, t in h.added], ["++ b/evil.py", "y"])

    def test_line_numbers(self):
        patch = ("diff --git a/t.py b/t.py\n--- a/t.py\n+++ b/t.py\n"
                 "@@ -3,1 +5,2 @@\n-old\n+new1\n+new2\n")
        h = ti.walk_hunks(patch)["t.py"][0]
        self.assertEqual(h.removed, [(3, "old")])
        self.assertEqual(h.added, [(5, "new1"), (6, "new2")])

    def test_a_deleted_file_has_no_entry(self):
        patch = ("diff --git a/t.py b/t.py\n--- a/t.py\n+++ /dev/null\n"
                 "@@ -1 +0,0 @@\n-x\n")
        self.assertEqual(ti.walk_hunks(patch), {})

    def test_assertion_strength_ladder(self):
        s = ti.assertion_strength
        self.assertGreater(s("assert a == b", "python"), s("assert a", "python"))
        self.assertGreater(s("self.assertEqual(a, b)", "python"),
                           s("self.assertTrue(a)", "python"))
        self.assertGreater(s("expect(a).toBe(1)", "js"),
                           s("expect(a).toBeTruthy()", "js"))
        self.assertEqual(s("x = 1", "python"), 0)
        self.assertEqual(s("# assert a == b", "python"), 0)
        self.assertEqual(s("assert a == b", "cobol"), 0)


# ---------------------------------------------------------------------------
# policy gates
# ---------------------------------------------------------------------------

class TestGlobs(unittest.TestCase):
    CASES = [
        ("infra/main.tf", "infra/**", True),
        ("infra", "infra/**", False),
        ("a/infra/x", "infra/**", False),
        ("a/infra/x", "**/infra/**", True),
        ("x.lock", "*.lock", True),
        ("deep/dir/x.lock", "*.lock", True),
        ("x.lockfile", "*.lock", False),
        ("src/a.py", "src/*.py", True),
        ("src/sub/a.py", "src/*.py", False),
        ("src/sub/a.py", "src/**/*.py", True),
        ("src/a.py", "src/**/*.py", True),
        (".github/workflows/ci.yml", ".github/workflows/**", True),
        (".GITHUB/Workflows/ci.yml", ".github/workflows/**", True),
        ("docs/a.md", "docs/", True),
        ("docs", "docs/", False),
        ("Jenkinsfile", "Jenkinsfile", True),
        ("sub/Jenkinsfile", "Jenkinsfile", True),
        ("a1.py", "a?.py", True),
        ("a/b.py", "a?b.py", False),
        ("a+b.py", "a+b.py", True),
        ("win\\path\\x.py", "win/path/*.py", True),
    ]

    def test_table(self):
        for path, pat, want in self.CASES:
            self.assertEqual(policy_mod.glob_match(path, pat), want,
                             f"{path} ~ {pat}")

    def test_presets_expand(self):
        ci = policy_mod.expand(["@ci", "x/**"])
        self.assertIn(".github/workflows/**", ci)
        self.assertIn("x/**", ci)
        self.assertNotIn("@ci", ci)
        self.assertIn("package-lock.json", policy_mod.expand(["@lockfiles"]))
        self.assertEqual(policy_mod.expand(["@unknown"]), ["@unknown"])

    def test_the_presets_match_what_they_name(self):
        ci = policy_mod.expand(["@ci"])
        for f in (".github/workflows/release.yml", ".gitlab-ci.yml",
                  ".circleci/config.yml", "Jenkinsfile", "azure-pipelines.yml"):
            self.assertIsNotNone(policy_mod.matches_any(f, ci), f)
        lock = policy_mod.expand(["@lockfiles"])
        for f in ("package-lock.json", "web/yarn.lock", "poetry.lock",
                  "Cargo.lock", "go.sum", "uv.lock"):
            self.assertIsNotNone(policy_mod.matches_any(f, lock), f)
        self.assertIsNone(policy_mod.matches_any("src/app.py", ci + lock))


def policy_repo(config, files=None, agent_files=None, human_files=None):
    base_files = {"app/core.py": "def f():\n    return 1\n",
                  "tests/test_core.py": "def test_f():\n    assert f() == 1\n",
                  "package-lock.json": "{}\n",
                  ".github/workflows/ci.yml": "name: ci\n",
                  "infra/main.tf": "# tf\n"}
    base_files.update(files or {})
    return repo(base_files, agent_files=agent_files, human_files=human_files,
                config=config)


def violations(data):
    return {v["rule"]: v for v in data["policy"]["violations"]}


class TestPolicy(unittest.TestCase):
    def test_nothing_is_on_by_default(self):
        tmp, base = policy_repo(None, agent_files={
            ".github/workflows/ci.yml": "name: changed\n",
            "app/core.py": "def f():\n    return 2\n"})
        code, data, _ = check_json(tmp, base)
        self.assertEqual(data["policy"], {"violations": []})
        self.assertEqual(code, 0)

    def test_protected_path_fails_for_anyone(self):
        cfg = 'protected_paths:\n  - "infra/**"\n'
        tmp, base = policy_repo(cfg, human_files={"infra/main.tf": "# changed\n"})
        code, data, _ = check_json(tmp, base)
        self.assertEqual(code, 1)
        v = violations(data)["protected-path"]
        self.assertEqual(v["files"], ["infra/main.tf"])
        self.assertIn("protected path changed: infra/main.tf", v["message"])
        self.assertEqual(data["risk"]["factors"]["policy"]["points"], 10)

    def test_an_untouched_protected_path_passes(self):
        cfg = 'protected_paths:\n  - "infra/**"\n'
        tmp, base = policy_repo(cfg, human_files={"app/core.py": "def f():\n    return 5\n"})
        code, data, _ = check_json(tmp, base)
        self.assertEqual((code, data["policy"]["violations"]), (0, []))

    def test_agent_forbidden_stops_the_agent(self):
        cfg = 'agent_forbidden_paths:\n  - "@ci"\n  - "@lockfiles"\n'
        tmp, base = policy_repo(cfg, agent_files={
            ".github/workflows/ci.yml": "name: changed\n",
            "package-lock.json": '{"a": 1}\n'})
        code, data, _ = check_json(tmp, base)
        self.assertEqual(code, 1)
        self.assertEqual(violations(data)["agent-forbidden-path"]["files"],
                         [".github/workflows/ci.yml", "package-lock.json"])

    def test_agent_forbidden_lets_a_human_through(self):
        cfg = 'agent_forbidden_paths:\n  - "@ci"\n  - "@lockfiles"\n'
        tmp, base = policy_repo(cfg, human_files={
            ".github/workflows/ci.yml": "name: changed\n",
            "package-lock.json": '{"a": 1}\n'})
        code, data, _ = check_json(tmp, base)
        self.assertEqual((code, data["policy"]["violations"]), (0, []))

    def test_agent_deleting_a_forbidden_file_counts(self):
        cfg = 'agent_forbidden_paths:\n  - "@lockfiles"\n'
        tmp, base = policy_repo(cfg)
        os.remove(os.path.join(tmp, "package-lock.json"))
        git(tmp, "add", "-A")
        git(tmp, "-c", "user.name=claude-bot", "-c",
            "user.email=claude-bot@example.com", "commit", "-qm",
            "rm lock\n\nCo-authored-by: Claude")
        _, data, _ = check_json(tmp, base)
        self.assertIn("agent-forbidden-path", violations(data))

    def test_file_budget(self):
        cfg = "max_changed_files: 2\n"
        tmp, base = policy_repo(cfg, human_files={
            "a.py": "1\n", "b.py": "2\n", "c.py": "3\n"})
        code, data, _ = check_json(tmp, base)
        self.assertEqual(code, 1)
        self.assertIn("3 files changed, the budget is 2",
                      violations(data)["change-budget-files"]["message"])

    def test_file_budget_at_the_limit_passes(self):
        cfg = "max_changed_files: 3\n"
        tmp, base = policy_repo(cfg, human_files={
            "a.py": "1\n", "b.py": "2\n", "c.py": "3\n"})
        self.assertEqual(check_json(tmp, base)[0], 0)

    def test_line_budget(self):
        cfg = "max_changed_lines: 5\n"
        tmp, base = policy_repo(cfg, human_files={"a.py": "x\n" * 6})
        code, data, _ = check_json(tmp, base)
        self.assertEqual(code, 1)
        self.assertIn("6 lines changed, the budget is 5",
                      violations(data)["change-budget-lines"]["message"])

    def test_tests_must_change_fails_without_a_test(self):
        cfg = "tests_must_change: true\n"
        tmp, base = policy_repo(cfg, human_files={"app/core.py": "def f():\n    return 9\n"})
        code, data, _ = check_json(tmp, base)
        self.assertEqual(code, 1)
        self.assertEqual(violations(data)["tests-must-change"]["files"],
                         ["app/core.py"])

    def test_tests_must_change_passes_with_a_test(self):
        cfg = "tests_must_change: true\n"
        tmp, base = policy_repo(cfg, human_files={
            "app/core.py": "def f():\n    return 9\n",
            "tests/test_core.py": "def test_f():\n    assert f() == 9\n"})
        self.assertEqual(check_json(tmp, base)[0], 0)

    def test_tests_must_change_ignores_docs_and_config(self):
        cfg = "tests_must_change: true\n"
        tmp, base = policy_repo(cfg, human_files={"README.md": "hi\n",
                                                  "setup.cfg": "[x]\n"})
        self.assertEqual(check_json(tmp, base)[0], 0)

    def test_the_pr_cannot_loosen_the_rules(self):
        cfg = 'protected_paths:\n  - "infra/**"\n'
        tmp, base = policy_repo(cfg, human_files={
            "infra/main.tf": "# changed\n",
            ".pr-verify.yaml": "protected_paths: []\n"})
        code, data, _ = check_json(tmp, base)
        self.assertEqual(code, 1)

    def test_a_violation_fails_even_with_fail_on_never(self):
        cfg = 'protected_paths:\n  - "infra/**"\n'
        tmp, base = policy_repo(cfg, human_files={"infra/main.tf": "# c\n"})
        code, _, _ = check_json(tmp, base, "--fail-on", "never")
        self.assertEqual(code, 1)

    def test_human_report_lists_the_violation(self):
        cfg = 'protected_paths:\n  - "infra/**"\n'
        tmp, base = policy_repo(cfg, human_files={"infra/main.tf": "# c\n"})
        code, out, _ = run("--root", tmp, "check", "--base", base, "--skip-gates")
        self.assertIn("policy violations:", out)
        self.assertIn("[protected-path]", out)

    def test_bad_config_values_are_one_line_errors(self):
        for cfg in ("tests_must_change: maybe\n", "max_changed_files: -1\n",
                    "max_changed_lines: lots\n",
                    "protected_paths: {a: 1}\n"):
            tmp, base = policy_repo(cfg)
            code, _, err = run("--root", tmp, "check", "--base", base)
            self.assertEqual(code, 2, cfg)
            self.assertIn("error:", err)

    def test_string_value_for_a_list_setting_is_one_entry(self):
        cfg = 'protected_paths: "infra/**"\n'
        tmp, base = policy_repo(cfg, human_files={"infra/main.tf": "# c\n"})
        self.assertEqual(check_json(tmp, base)[0], 1)

    def test_init_writes_every_new_default_and_it_round_trips(self):
        tmp, base = repo({"a.py": "x = 1\n"})
        self.assertEqual(run("--root", tmp, "init")[0], 0)
        with open(os.path.join(tmp, ".pr-verify.yaml"), encoding="utf-8") as f:
            text = f.read()
        from pr_verify import miniyaml
        data = miniyaml.safe_load(text)
        for key in ("agent_labels", "agent_authors", "agent_branches",
                    "agent_trailer_keys", "protected_paths",
                    "agent_forbidden_paths", "max_changed_files",
                    "max_changed_lines", "tests_must_change"):
            self.assertEqual(data[key], config_mod.DEFAULTS[key], key)


# ---------------------------------------------------------------------------
# description vs diff
# ---------------------------------------------------------------------------

class TestDescriptionVsDiff(unittest.TestCase):
    def adv(self, text, files=("src/auth.py",), changed=("def validate(): pass",),
            content=""):
        return dd.advisories(text, list(files), list(changed), lambda f: content)

    def test_a_mentioned_file_that_changed_is_fine(self):
        self.assertEqual(self.adv("Updated src/auth.py"), [])

    def test_a_mentioned_file_that_did_not_change(self):
        a = self.adv("Updated src/login.py")
        self.assertEqual([(x["kind"], x["text"]) for x in a],
                         [("file", "src/login.py")])

    def test_a_path_matches_by_its_tail_either_way(self):
        self.assertEqual(self.adv("see `auth.py`", files=["src/app/auth.py"]), [])
        self.assertEqual(self.adv("see app/src/auth.py", files=["src/auth.py"]), [])

    def test_a_directory_mention_is_touched_when_something_under_it_changed(self):
        self.assertEqual(self.adv("changes in src/", files=["src/auth.py"]), [])
        self.assertEqual(len(self.adv("changes in docs/", files=["src/auth.py"])), 1)

    def test_bare_names_count_only_in_backticks(self):
        self.assertEqual(self.adv("We love Node.js and next.js"), [])
        self.assertEqual(len(self.adv("edited `setup.cfg`")), 1)

    def test_prose_with_slashes_is_not_a_path(self):
        self.assertEqual(self.adv("and/or input/output he/she"), [])

    def test_urls_fences_and_comments_are_skipped(self):
        text = ("see https://example.com/a/b.py\n```\nother/file.py\n```\n"
                "<!-- docs/hidden.md -->")
        self.assertEqual(self.adv(text), [])

    def test_a_symbol_in_the_diff_is_fine(self):
        self.assertEqual(self.adv("renamed `validate_token()`",
                                  changed=["def validate_token(): pass"]), [])

    def test_a_symbol_in_a_changed_file_is_fine(self):
        self.assertEqual(self.adv("fixed `parse_config`", content="def parse_config(): ..."), [])

    def test_a_symbol_nowhere_is_reported(self):
        a = self.adv("fixed `parse_config`")
        self.assertEqual([(x["kind"], x["text"]) for x in a],
                         [("symbol", "parse_config")])

    def test_dotted_symbols_use_their_last_part(self):
        self.assertEqual(self.adv("fixed `Foo.bar`", changed=["def bar(): pass"]), [])

    def test_symbol_shapes(self):
        shaped = dd.mentioned_symbols(
            "`snake_case` `camelCase` `PascalCase` `a.b` `f()` `main` `x` "
            "`True` `None` `import` `foo bar` `1.5` `README.md`")
        self.assertEqual(shaped, ["snake_case", "camelCase", "PascalCase", "a.b"])

    def test_words_are_whole(self):
        # `validate` must not be found inside `invalidated_thing`
        a = self.adv("fixed `do_validate`", changed=["def invalidated_thing(): pass"])
        self.assertEqual(len(a), 1)

    def test_the_cap(self):
        text = " ".join(f"`sym_{i}`" for i in range(60))
        self.assertEqual(len(self.adv(text)), dd.MAX_ADVISORIES)

    def test_empty_text_is_nothing(self):
        self.assertEqual(self.adv(""), [])

    def test_end_to_end_and_it_never_changes_the_verdict(self):
        tmp, base = repo({"app/core.py": "def f():\n    return 1\n"},
                         human_files={"app/core.py": "def f():\n    return 2\n"})
        d = tempfile.mkdtemp()
        body = os.path.join(d, "body.txt")
        with open(body, "w") as fh:
            fh.write("Rewrote `lib/other.py` and `compute_totals()`.")
        c0, plain, _ = check_json(tmp, base)
        c1, data, _ = check_json(tmp, base, "--pr-title", "Fix", "--pr-body-file", body)
        kinds = {a["kind"] for a in data["description_check"]["advisories"]}
        self.assertEqual(kinds, {"file", "symbol"})
        self.assertEqual((c1, data["risk"]), (c0, plain["risk"]))
        self.assertEqual(data["review_depth"], plain["review_depth"])
        self.assertEqual(plain["description_check"], {"advisories": []})

    def test_the_human_report_labels_it_advisory(self):
        tmp, base = repo({"app/core.py": "def f():\n    return 1\n"},
                         human_files={"app/core.py": "def f():\n    return 2\n"})
        code, out, _ = run("--root", tmp, "check", "--base", base,
                           "--pr-title", "Edit `lib/other.py`")
        self.assertIn("description vs diff (advisory, not scored):", out)
        self.assertEqual(code, 0)


# ---------------------------------------------------------------------------
# review depth, SARIF, comment
# ---------------------------------------------------------------------------

def facts(**kw):
    """A minimal payload."""
    p = {"version": "0.2.0", "min_score": 70,
         "risk": {"score": 10, "band": "low", "requires_review": False,
                  "factors": {}},
         "files": {"app/a.py": {"added": 4, "agent_added": 0, "removed": 0,
                                "agent_removed": 0, "label": "human",
                                "agents": [], "deleted": False,
                                "deleted_by": []}},
         "gates": [], "agent_signals": [], "policy": {"violations": []},
         "test_integrity": {"findings": []},
         "description_check": {"advisories": []}, "sensitive_files": []}
    for k, v in kw.items():
        p[k] = v
    return p


class TestReviewDepth(unittest.TestCase):
    def depth(self, **kw):
        return render_mod.review_depth(facts(**kw))["depth"]

    def test_low_and_clean_is_skim(self):
        self.assertEqual(self.depth(), "skim")

    def test_medium_is_normal(self):
        self.assertEqual(self.depth(risk={"score": 45, "band": "medium",
                                          "requires_review": False}), "normal")

    def test_29_is_skim_and_30_is_normal(self):
        self.assertEqual(self.depth(risk={"score": 29, "band": "low",
                                          "requires_review": False}), "skim")
        self.assertEqual(self.depth(risk={"score": 30, "band": "medium",
                                          "requires_review": False}), "normal")

    def test_requires_review_is_deep(self):
        self.assertEqual(self.depth(risk={"score": 80, "band": "high",
                                          "requires_review": True}), "deep")

    def test_a_high_band_is_deep_even_with_the_gate_off(self):
        self.assertEqual(self.depth(min_score=None,
                                    risk={"score": 80, "band": "high",
                                          "requires_review": False}), "deep")

    def test_failed_gate_is_deep(self):
        self.assertEqual(self.depth(gates=[{"command": "x", "passed": False}]),
                         "deep")
        self.assertEqual(self.depth(gates=[{"command": "x", "passed": True}]),
                         "skim")

    def test_policy_violation_is_deep(self):
        self.assertEqual(self.depth(policy={"violations": [
            {"rule": "r", "message": "m", "files": []}]}), "deep")

    def test_test_integrity_finding_is_deep(self):
        self.assertEqual(self.depth(test_integrity={"findings": [
            {"rule": "disabled-test", "file": "t.py", "message": "m"}]}), "deep")

    def test_agent_deleting_a_file_is_deep(self):
        f = facts()["files"]
        f["app/gone.py"] = dict(f["app/a.py"], deleted=True, agents=["x (y)"])
        self.assertEqual(self.depth(files=f), "deep")

    def test_agent_touching_a_sensitive_file_is_deep_but_a_human_is_not(self):
        f = facts()["files"]
        f["app/auth.py"] = dict(f["app/a.py"], agents=["x (y)"])
        self.assertEqual(self.depth(files=f, sensitive_files=["app/auth.py"]), "deep")
        f["app/auth.py"]["agents"] = []
        self.assertEqual(self.depth(files=f, sensitive_files=["app/auth.py"]), "skim")

    def test_advisories_never_change_it(self):
        self.assertEqual(self.depth(description_check={"advisories": [
            {"kind": "file", "text": "x", "message": "m"}] * 5}), "skim")

    def test_nothing_to_verify_is_skim_and_says_so(self):
        d = render_mod.review_depth(facts(files={}))
        self.assertEqual((d["depth"], d["reasons"]), ("skim", ["nothing to verify"]))

    def test_it_is_a_pure_function(self):
        p = facts(risk={"score": 80, "band": "high", "requires_review": True})
        before = copy.deepcopy(p)
        a = render_mod.review_depth(p)
        b = render_mod.review_depth(copy.deepcopy(p))
        self.assertEqual(a, b)
        self.assertEqual(p, before)

    def test_reasons_come_with_every_word(self):
        for kw in ({}, {"risk": {"score": 45, "band": "medium", "requires_review": False}},
                   {"policy": {"violations": [{"rule": "r", "message": "m"}]}}):
            self.assertTrue(render_mod.review_depth(facts(**kw))["reasons"])


def validate_sarif(doc):
    """A structural check of what the SARIF 2.1.0 spec requires of a log like
    this one (no jsonschema in the standard library)."""
    assert doc["version"] == "2.1.0"
    assert doc["$schema"].endswith("sarif-schema-2.1.0.json")
    assert isinstance(doc["runs"], list) and len(doc["runs"]) == 1
    run_ = doc["runs"][0]
    driver = run_["tool"]["driver"]
    assert driver["name"] and driver["version"]
    ids = [r["id"] for r in driver["rules"]]
    assert len(ids) == len(set(ids))
    for r in driver["rules"]:
        assert r["shortDescription"]["text"]
    for res in run_["results"]:
        assert res["ruleId"] in ids
        assert driver["rules"][res["ruleIndex"]]["id"] == res["ruleId"]
        assert res["level"] in ("none", "note", "warning", "error")
        assert res["message"]["text"]
        loc = res["locations"][0]["physicalLocation"]
        assert loc["artifactLocation"]["uri"]
        assert isinstance(loc["region"]["startLine"], int)
        assert loc["region"]["startLine"] >= 1
        assert res["partialFingerprints"]["prVerify/v1"]


class TestSarif(unittest.TestCase):
    def rich(self):
        return facts(
            risk={"score": 90, "band": "high", "requires_review": True},
            files={"app/a.py": facts()["files"]["app/a.py"],
                   "tests/t.py": facts()["files"]["app/a.py"]},
            gates=[{"command": "pytest", "passed": False, "timed_out": True}],
            policy={"violations": [
                {"rule": "protected-path", "message": "protected path changed: app/a.py",
                 "files": ["app/a.py"]},
                {"rule": "change-budget-lines", "message": "too many lines", "files": []}]},
            test_integrity={"findings": [
                {"rule": "disabled-test", "severity": "error", "file": "tests/t.py",
                 "line": 12, "message": "an agent added a skip"},
                {"rule": "removed-assertions", "severity": "warning",
                 "file": "tests/t.py", "line": 0, "message": "fewer assertions"}]},
            sensitive_files=["app/a.py"],
            description_check={"advisories": [
                {"kind": "file", "text": "x.py", "message": "mentions x.py"}]})

    def test_it_is_valid(self):
        validate_sarif(render_mod.to_sarif(self.rich()))

    def test_every_kind_of_result_is_there(self):
        rules = {r["ruleId"] for r in render_mod.to_sarif(self.rich())["runs"][0]["results"]}
        self.assertEqual(rules, {"PRV001", "PRV002", "PRV003", "PRV004",
                                 "PRV005", "PRV006"})

    def test_levels(self):
        res = render_mod.to_sarif(self.rich())["runs"][0]["results"]
        by = {}
        for r in res:
            by.setdefault(r["ruleId"], set()).add(r["level"])
        self.assertEqual(by["PRV003"], {"error", "warning"})
        self.assertEqual(by["PRV006"], {"note"})
        self.assertEqual(by["PRV001"], {"error"})

    def test_locations_use_the_file_and_line(self):
        res = [r for r in render_mod.to_sarif(self.rich())["runs"][0]["results"]
               if r["ruleId"] == "PRV003"][0]
        loc = res["locations"][0]["physicalLocation"]
        self.assertEqual(loc["artifactLocation"]["uri"], "tests/t.py")
        self.assertEqual(loc["region"]["startLine"], 12)

    def test_findings_without_a_file_use_the_first_changed_file(self):
        res = [r for r in render_mod.to_sarif(self.rich())["runs"][0]["results"]
               if r["ruleId"] == "PRV004"][0]
        self.assertEqual(res["locations"][0]["physicalLocation"]
                         ["artifactLocation"]["uri"], "app/a.py")

    def test_no_files_no_results_but_still_valid(self):
        doc = render_mod.to_sarif(facts(files={}))
        validate_sarif(doc)
        self.assertEqual(doc["runs"][0]["results"], [])

    def test_uris_are_encoded_and_control_characters_shown(self):
        p = facts(files={"my dir/ü file.py": facts()["files"]["app/a.py"]},
                  sensitive_files=["my dir/ü file.py"])
        res = render_mod.to_sarif(p)["runs"][0]["results"][0]
        self.assertEqual(res["locations"][0]["physicalLocation"]
                         ["artifactLocation"]["uri"], "my%20dir/%C3%BC%20file.py")
        p = facts(gates=[{"command": "x\x1b[31m", "passed": False}])
        text = render_mod.to_sarif(p)["runs"][0]["results"][0]["message"]["text"]
        self.assertNotIn("\x1b", text)

    def test_it_is_deterministic_and_carries_the_depth(self):
        a, b = render_mod.sarif_text(self.rich()), render_mod.sarif_text(self.rich())
        self.assertEqual(a, b)
        self.assertEqual(json.loads(a)["runs"][0]["properties"]["reviewDepth"], "deep")

    def test_fingerprints_differ_between_results(self):
        res = render_mod.to_sarif(self.rich())["runs"][0]["results"]
        fps = [r["partialFingerprints"]["prVerify/v1"] for r in res]
        self.assertEqual(len(fps), len(set(fps)))

    def test_the_cli_prints_valid_sarif(self):
        tmp, base = make_pr_repo()
        code, out, _ = run("--root", tmp, "check", "--base", base,
                           "--format", "sarif", "--skip-gates")
        doc = json.loads(out)
        validate_sarif(doc)
        self.assertEqual(doc["runs"][0]["tool"]["driver"]["version"], cli_mod.VERSION)
        self.assertTrue(any(r["ruleId"] == "PRV005" for r in doc["runs"][0]["results"]))


class TestComment(unittest.TestCase):
    def test_the_first_line_is_the_marker_and_the_headline_is_plain(self):
        text = render_mod.to_comment(facts())
        lines = text.splitlines()
        self.assertEqual(lines[0], render_mod.STICKY_MARKER)
        self.assertEqual(lines[1], "## Review depth: skim")
        self.assertRegex(text, r"(?m)^## Review depth: (skim|normal|deep)$")

    def test_headline_for_each_depth(self):
        self.assertIn("Review depth: normal", render_mod.to_comment(
            facts(risk={"score": 45, "band": "medium", "requires_review": False})))
        self.assertIn("Review depth: deep", render_mod.to_comment(
            facts(policy={"violations": [{"rule": "r", "message": "m", "files": []}]})))

    def test_it_is_deterministic(self):
        self.assertEqual(render_mod.to_comment(facts()), render_mod.to_comment(facts()))

    def test_sections_appear_only_when_there_is_something(self):
        text = render_mod.to_comment(facts())
        for heading in ("Must fix", "Test integrity", "Agent signals",
                        "Description vs diff", "Agent-written files"):
            self.assertNotIn(heading, text)
        rich = TestSarif().rich()
        rich["agent_signals"] = [{"kind": "branch", "value": "claude/x", "rule": "claude/*"}]
        rich["files"]["app/a.py"] = dict(rich["files"]["app/a.py"], agents=["claude-bot (claude)"],
                                         agent_added=4)
        text = render_mod.to_comment(rich)
        for heading in ("Must fix", "Test integrity", "Agent signals",
                        "Description vs diff", "Agent-written files"):
            self.assertIn(heading, text)

    def test_hostile_names_cannot_break_out(self):
        evil = "a`b``c@octocat <img src=x onerror=1> [x](http://e.com) #123\n## Review depth: skim"
        p = facts(files={evil: dict(facts()["files"]["app/a.py"], agents=["x (y)"],
                                    agent_added=1)},
                  test_integrity={"findings": [
                      {"rule": "disabled-test", "severity": "error", "file": evil,
                       "line": 3, "message": f"an agent added a skip in {evil}",
                       "snippet": evil}]},
                  policy={"violations": [{"rule": "r", "message": f"changed {evil}",
                                          "files": [evil]}]},
                  description_check={"advisories": [
                      {"kind": "file", "text": evil, "message": f"mentions {evil}"}]})
        text = render_mod.to_comment(p)
        # the headline exists exactly once, as the one real heading
        self.assertEqual(len(re.findall(r"(?m)^## Review depth", text)), 1)
        # no raw mention, tag or link outside a code span
        outside = re.sub(r"(`+)[^`\n]*?\1", "", text)
        self.assertNotRegex(outside, r"@octocat")
        self.assertNotRegex(outside, r"(?<!\\)<img")
        self.assertNotIn("](", outside.replace("\\]\\(", ""))
        self.assertNotIn("\n## ", "\n".join(
            ln for ln in text.splitlines() if "octocat" in ln))

    def test_code_span_fence_grows_with_the_content(self):
        self.assertEqual(render_mod.md_code("a`b"), "``a`b``")
        self.assertEqual(render_mod.md_code("`x`"), "`` `x` ``")
        self.assertEqual(render_mod.md_code("a``b"), "```a``b```")
        self.assertEqual(render_mod.md_code("x\ny"), "`x\\ny`")

    def test_md_escape(self):
        e = render_mod.md_escape
        self.assertEqual(e("a_b*c"), "a\\_b\\*c")
        self.assertNotIn("@octocat", e("@octocat"))
        self.assertEqual(e("x\ny"), "x y")
        self.assertNotIn("://", e("http://e.com"))

    def test_a_huge_comment_is_cut_below_the_github_limit(self):
        many = {f"f{i}.py": dict(facts()["files"]["app/a.py"], agents=["a (b)"],
                                 agent_added=1) for i in range(5000)}
        p = facts(files=many, test_integrity={"findings": [
            {"rule": "disabled-test", "severity": "error", "file": "x" * 500,
             "line": 1, "message": "m" * 500} for _ in range(5000)]})
        text = render_mod.to_comment(p)
        self.assertLess(len(text), 65536)
        self.assertIn("more", text)

    def test_lists_are_capped(self):
        p = facts(test_integrity={"findings": [
            {"rule": "disabled-test", "severity": "error", "file": f"t{i}.py",
             "line": 1, "message": "m"} for i in range(40)]})
        text = render_mod.to_comment(p)
        self.assertIn("... and 15 more", text)

    def test_cli_comment_format_and_files(self):
        tmp, base = make_pr_repo()
        d = tempfile.mkdtemp()
        sarif, comment = os.path.join(d, "o.sarif"), os.path.join(d, "c.md")
        code, out, _ = run("--root", tmp, "check", "--base", base, "--format",
                           "comment", "--skip-gates", "--sarif-file", sarif,
                           "--comment-file", comment)
        self.assertEqual(out.splitlines()[0], render_mod.STICKY_MARKER)
        with open(comment, encoding="utf-8") as f:
            self.assertEqual(f.read().rstrip("\n"), out.rstrip("\n"))
        with open(sarif, encoding="utf-8") as f:
            validate_sarif(json.load(f))
        self.assertEqual(code, 0)

    def test_an_unwritable_extra_file_is_exit_2(self):
        tmp, base = make_pr_repo()
        code, _, err = run("--root", tmp, "check", "--base", base, "--skip-gates",
                           "--comment-file", os.path.join(tmp, "no", "such", "c.md"))
        self.assertEqual(code, 2)
        self.assertIn("could not write", err)

    def test_the_payload_has_the_new_keys_even_for_nothing_to_verify(self):
        tmp, base = make_pr_repo()
        _, full, _ = check_json(tmp, base)
        _, nothing, _ = check_json(tmp, "HEAD")
        self.assertEqual(list(nothing), list(full))
        for key in ("agent_signals", "policy", "test_integrity",
                    "description_check", "sensitive_files", "review_depth"):
            self.assertIn(key, full)
        self.assertEqual(nothing["review_depth"]["depth"], "skim")

    def test_the_human_report_opens_with_the_depth(self):
        tmp, base = make_pr_repo()
        _, out, _ = run("--root", tmp, "check", "--base", base, "--skip-gates")
        self.assertRegex(out, r"(?m)^  Review depth: (skim|normal|deep)$")


# ---------------------------------------------------------------------------
# the Action: comment, summary, SARIF file
# ---------------------------------------------------------------------------

class FakeGitHub:
    """A GitHub issue-comments API on 127.0.0.1 for the tests."""

    def __init__(self, comments=None, fail=None):
        self.comments = list(comments or [])
        self.fail = dict(fail or {})        # (method) -> status
        self.requests = []
        self.next_id = 100
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _send(self, status, body):
                data = json.dumps(body).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def _body(self):
                n = int(self.headers.get("Content-Length") or 0)
                return json.loads(self.rfile.read(n) or b"{}")

            def handle_any(self, method):
                body = self._body() if method in ("POST", "PATCH") else None
                outer.requests.append((method, self.path, dict(self.headers), body))
                if method in outer.fail:
                    return self._send(outer.fail[method], {"message": "nope"})
                if method == "GET":
                    from urllib.parse import parse_qs, urlsplit
                    q = parse_qs(urlsplit(self.path).query)
                    page = int(q.get("page", ["1"])[0])
                    per = int(q.get("per_page", ["30"])[0])
                    return self._send(200, outer.comments[(page - 1) * per:page * per])
                if method == "POST":
                    outer.next_id += 1
                    c = {"id": outer.next_id, "body": body["body"]}
                    outer.comments.append(c)
                    return self._send(201, c)
                if method == "PATCH":
                    cid = int(self.path.rsplit("/", 1)[1])
                    for c in outer.comments:
                        if c["id"] == cid:
                            c["body"] = body["body"]
                            return self._send(200, c)
                    return self._send(404, {"message": "gone"})

            def do_GET(self):
                self.handle_any("GET")

            def do_POST(self):
                self.handle_any("POST")

            def do_PATCH(self):
                self.handle_any("PATCH")

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


def action_env(gh, **extra):
    d = tempfile.mkdtemp()
    event = os.path.join(d, "event.json")
    with open(event, "w") as f:
        json.dump({"pull_request": {"number": 5, "title": "T", "body": "",
                                    "labels": [], "user": {"login": "dan"},
                                    "head": {"ref": "topic"}}}, f)
    env = {"GITHUB_API_URL": gh.url, "GITHUB_REPOSITORY": "o/r",
           "GITHUB_EVENT_PATH": event, "PR_VERIFY_GITHUB_TOKEN": "tok",
           "PR_VERIFY_COMMENT": "true", "RUNNER_TEMP": d}
    env.update(extra)
    return env


class TestActionComment(unittest.TestCase):
    def setUp(self):
        self.gh = FakeGitHub()
        self.addCleanup(self.gh.close)

    def test_creates_a_comment_the_first_time(self):
        out = action_mod.post_comment("hello " + render_mod.STICKY_MARKER,
                                      action_env(self.gh))
        self.assertTrue(out.startswith("created comment"))
        methods = [r[0] for r in self.gh.requests]
        self.assertEqual(methods, ["GET", "POST"])
        self.assertIn("/repos/o/r/issues/5/comments", self.gh.requests[1][1])

    def test_updates_its_own_comment_instead_of_adding_another(self):
        env = action_env(self.gh)
        action_mod.post_comment("v1 " + render_mod.STICKY_MARKER, env)
        out = action_mod.post_comment("v2 " + render_mod.STICKY_MARKER, env)
        self.assertTrue(out.startswith("updated comment"))
        self.assertEqual(len(self.gh.comments), 1)
        self.assertTrue(self.gh.comments[0]["body"].startswith("v2"))

    def test_finds_the_comment_on_a_later_page(self):
        self.gh.comments = [{"id": i, "body": "x"} for i in range(1, 150)]
        self.gh.comments.append({"id": 900, "body": render_mod.STICKY_MARKER})
        self.gh.next_id = 1000
        out = action_mod.post_comment("new " + render_mod.STICKY_MARKER,
                                      action_env(self.gh))
        self.assertEqual(out, "updated comment 900")

    def test_other_peoples_comments_are_left_alone(self):
        self.gh.comments = [{"id": 1, "body": "looks good to me"}]
        action_mod.post_comment(render_mod.STICKY_MARKER, action_env(self.gh))
        self.assertEqual(self.gh.comments[0]["body"], "looks good to me")
        self.assertEqual(len(self.gh.comments), 2)

    def test_a_comment_it_may_not_edit_is_replaced_by_a_new_one(self):
        self.gh.comments = [{"id": 7, "body": render_mod.STICKY_MARKER}]
        self.gh.fail = {"PATCH": 403}
        out = action_mod.post_comment(render_mod.STICKY_MARKER + "x",
                                      action_env(self.gh))
        self.assertTrue(out.startswith("created comment"))

    def test_the_token_is_sent_as_a_bearer_and_never_returned(self):
        out = action_mod.post_comment("x", action_env(self.gh))
        headers = {k.lower(): v for k, v in self.gh.requests[0][2].items()}
        self.assertEqual(headers["authorization"], "Bearer tok")
        self.assertNotIn("tok", out)

    def test_a_read_only_token_is_a_skip_with_the_reason(self):
        self.gh.fail = {"GET": 403}
        out = action_mod.post_comment("x", action_env(self.gh))
        self.assertTrue(out.startswith("skipped: HTTP 403"))
        self.assertIn("pull-requests: write", out)
        self.assertIn("fork", out)

    def test_a_server_error_is_a_skip_not_a_crash(self):
        self.gh.fail = {"GET": 500}
        out = action_mod.post_comment("x", action_env(self.gh))
        self.assertTrue(out.startswith("skipped: HTTP 500"))

    def test_no_server_is_a_skip(self):
        env = action_env(self.gh, GITHUB_API_URL="http://127.0.0.1:1")
        self.assertTrue(action_mod.post_comment("x", env).startswith("skipped"))

    def test_no_token(self):
        env = action_env(self.gh, PR_VERIFY_GITHUB_TOKEN="")
        self.assertEqual(action_mod.post_comment("x", env), "skipped: no github-token")
        self.assertEqual(self.gh.requests, [])

    def test_not_a_pull_request(self):
        env = action_env(self.gh, GITHUB_EVENT_PATH="", GITHUB_REF="refs/heads/main")
        self.assertIn("not for a pull request", action_mod.post_comment("x", env))

    def test_the_number_can_come_from_the_ref(self):
        env = action_env(self.gh, GITHUB_EVENT_PATH="", GITHUB_REF="refs/pull/42/merge")
        action_mod.post_comment("x", env)
        self.assertIn("/issues/42/comments", self.gh.requests[0][1])

    def test_a_plain_http_api_url_to_another_host_is_refused(self):
        for url in ("http://example.com", "ftp://x", "file:///etc/passwd", ""):
            env = action_env(self.gh, GITHUB_API_URL=url)
            if url == "":
                continue
            self.assertIn("not https", action_mod.post_comment("x", env), url)
        self.assertEqual(self.gh.requests, [])

    def test_a_bad_repository_name(self):
        env = action_env(self.gh, GITHUB_REPOSITORY="../../etc")
        self.assertIn("GITHUB_REPOSITORY", action_mod.post_comment("x", env))
        self.assertEqual(self.gh.requests, [])


class TestActionPublishing(unittest.TestCase):
    def setUp(self):
        self.gh = FakeGitHub()
        self.addCleanup(self.gh.close)
        self.tmp, self.base = make_pr_repo()

    def run_action(self, **extra):
        env = action_env(self.gh, PR_VERIFY_ROOT=self.tmp,
                         PR_VERIFY_BASE=self.base, PR_VERIFY_SKIP_GATES="true",
                         **extra)
        d = tempfile.mkdtemp()
        env["GITHUB_OUTPUT"] = os.path.join(d, "out")
        env["GITHUB_STEP_SUMMARY"] = os.path.join(d, "summary.md")
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = action_mod.main(environ=env)
        return code, out.getvalue(), err.getvalue(), env

    def test_posts_one_comment_and_writes_the_summary(self):
        code, out, err, env = self.run_action()
        self.assertEqual(code, 0)
        self.assertEqual(len(self.gh.comments), 1)
        body = self.gh.comments[0]["body"]
        self.assertEqual(body.splitlines()[0], render_mod.STICKY_MARKER)
        self.assertRegex(body, r"(?m)^## Review depth: (skim|normal|deep)$")
        self.assertIn("pull request comment: created comment", err)
        with open(env["GITHUB_STEP_SUMMARY"], encoding="utf-8") as f:
            self.assertIn("## Review depth", f.read())

    def test_a_second_run_updates_it(self):
        self.run_action()
        self.run_action()
        self.assertEqual(len(self.gh.comments), 1)

    def test_no_comment_unless_asked(self):
        code, _, err, _ = self.run_action(PR_VERIFY_COMMENT="false")
        self.assertEqual((code, self.gh.requests), (0, []))

    def test_the_summary_can_be_switched_off(self):
        _, _, _, env = self.run_action(PR_VERIFY_COMMENT="false",
                                       PR_VERIFY_STEP_SUMMARY="false")
        self.assertFalse(os.path.exists(env["GITHUB_STEP_SUMMARY"]))

    def test_a_failed_post_never_changes_the_verdict(self):
        self.gh.fail = {"GET": 403}
        code, _, err, _ = self.run_action()
        self.assertEqual(code, 0)
        self.assertIn("warning: pull request comment skipped", err)

    def test_the_agent_signals_are_read_from_the_event(self):
        d = tempfile.mkdtemp()
        event = os.path.join(d, "e.json")
        with open(event, "w") as f:
            json.dump({"pull_request": {"number": 5, "labels": [{"name": "ai-generated"}],
                                        "user": {"login": "dan"},
                                        "head": {"ref": "topic"}}}, f)
        _, out, _, _ = self.run_action(PR_VERIFY_FORMAT="json", GITHUB_EVENT_PATH=event)
        self.assertEqual(json.loads(out)["agent_signals"][0]["value"], "ai-generated")

    def test_the_sarif_file_input(self):
        path = os.path.join(tempfile.mkdtemp(), "out.sarif")
        self.run_action(PR_VERIFY_SARIF_FILE=path)
        with open(path, encoding="utf-8") as f:
            validate_sarif(json.load(f))

    def test_build_argv_adds_the_event_and_the_comment_file(self):
        env = action_env(self.gh)
        argv = action_mod.build_argv(env)
        self.assertEqual(argv[argv.index("--event-file") + 1], env["GITHUB_EVENT_PATH"])
        self.assertEqual(argv[argv.index("--comment-file") + 1],
                         os.path.join(env["RUNNER_TEMP"], "pr-verify-comment.md"))
        cli_mod.build_parser().parse_args(argv)

    def test_build_argv_stays_minimal_without_the_new_inputs(self):
        env = {"PR_VERIFY_STEP_SUMMARY": "false"}
        self.assertEqual(action_mod.build_argv(env), ["check"])

    def test_action_yml_declares_the_permissions_story(self):
        with open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(
                __file__))), "README.md"), encoding="utf-8") as f:
            readme = f.read()
        for needle in ("pull-requests: write", "security-events: write",
                       "read-only token", "Review depth"):
            self.assertIn(needle, readme)


if __name__ == "__main__":
    unittest.main()
