"""Round 10c: blame budget, pull_request_target warning, gate output omission,
agent-share badge and `pr-verify trend`."""

import io
import json
import os
import subprocess
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

from pr_verify import cli as cli_mod
from pr_verify import provenance as prov_mod
from pr_verify import render as render_mod
from pr_verify import trend as trend_mod

from fixture import PY, commit_as, git, gate, yaml_str


def run(*argv):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = cli_mod.main(list(argv))
    return code, out.getvalue(), err.getvalue()


def repo(n_files=3):
    tmp = tempfile.mkdtemp()
    git(tmp, "init", "-qb", "main")
    commit_as(tmp, "Dan Calas", "dan@example.com", "base", {"a.txt": "x\n"})
    base = subprocess.run(["git", "-C", tmp, "rev-parse", "HEAD"],
                          capture_output=True, text=True, check=True
                          ).stdout.strip()
    commit_as(tmp, "claude-bot", "claude-bot@example.com",
              "add\n\nCo-authored-by: Claude",
              {f"f{i}.py": "print(1)\n" for i in range(n_files)})
    return tmp, base


def check_json(tmp, base, *extra, env=None):
    with mock.patch.dict(os.environ, env or {}):
        code, out, err = run("--root", tmp, "check", "--base", base,
                             "--format", "json", "--skip-gates", *extra)
    return code, json.loads(out), err


class TestBlameBudget(unittest.TestCase):
    def test_a_file_cap_leaves_the_rest_unverified(self):
        tmp, base = repo(4)
        code, doc, err = check_json(tmp, base, "--max-blame-files", "2")
        self.assertEqual(len(doc["unverified_files"]), 2)
        self.assertEqual(code, 1)           # fail closed
        self.assertTrue(any("UNVERIFIED" in n for n in doc["notes"]))
        agent = [f for f, v in doc["files"].items() if v["agent_added"]]
        self.assertEqual(len(agent), 2)

    def test_no_cap_means_everything_is_blamed(self):
        tmp, base = repo(4)
        _, doc, _ = check_json(tmp, base, "--max-blame-files", "0")
        self.assertEqual(doc["unverified_files"], [])

    def test_the_time_budget_uses_a_fake_clock(self):
        tmp, base = repo(3)
        ticks = iter(range(0, 1000, 100))
        with mock.patch.object(prov_mod, "_monotonic", lambda: next(ticks)):
            _, doc, _ = check_json(tmp, base, "--blame-budget", "150")
        self.assertGreaterEqual(len(doc["unverified_files"]), 1)

    def test_score_gate_off_does_not_fail_on_unverified(self):
        tmp, base = repo(3)
        code, doc, _ = check_json(tmp, base, "--max-blame-files", "1",
                                  "--fail-on", "never")
        self.assertEqual(code, 0)
        self.assertEqual(len(doc["unverified_files"]), 2)

    def test_the_comment_names_unverified_files(self):
        tmp, base = repo(3)
        _, doc, _ = check_json(tmp, base, "--max-blame-files", "1")
        self.assertIn("2 file(s) unverified", render_mod.to_comment(doc))

    def test_bad_values_are_usage_errors(self):
        with self.assertRaises(SystemExit):
            run("check", "--max-blame-files", "-1")


class TestPullRequestTarget(unittest.TestCase):
    def test_warns_under_pull_request_target(self):
        tmp, base = repo(1)
        _, doc, err = check_json(tmp, base,
                                 env={"GITHUB_EVENT_NAME": "pull_request_target"})
        self.assertIn("pull_request_target", err)
        self.assertTrue(any("pull_request_target" in n for n in doc["notes"]))

    def test_silent_otherwise(self):
        tmp, base = repo(1)
        _, doc, err = check_json(tmp, base, env={"GITHUB_EVENT_NAME": "pull_request"})
        self.assertNotIn("pull_request_target", err)


class TestGateOutput(unittest.TestCase):
    def _gated(self):
        tmp, base = repo(1)
        cfg = ("gates:\n  - " + yaml_str(gate(
            PY, "-c", "print('sekrit-output'); raise SystemExit(1)")) + "\n")
        commit_as(tmp, "Dan Calas", "dan@example.com", "cfg",
                  {".pr-verify.yaml": cfg})
        base = subprocess.run(["git", "-C", tmp, "rev-parse", "HEAD"],
                              capture_output=True, text=True, check=True
                              ).stdout.strip()
        commit_as(tmp, "Dan Calas", "dan@example.com", "more", {"z.py": "1\n"})
        return tmp, base

    def _json(self, tmp, base, *extra):
        code, out, err = run("--root", tmp, "check", "--base", base,
                             "--format", "json", *extra)
        return json.loads(out)

    def test_tails_are_kept_by_default_and_omitted_on_request(self):
        tmp, base = self._gated()
        self.assertIn("sekrit-output",
                      self._json(tmp, base)["gates"][0]["output_tail"])
        doc = self._json(tmp, base, "--omit-gate-output")
        self.assertEqual(doc["gates"][0]["output_tail"], "")
        self.assertFalse(doc["gates"][0]["passed"])


class TestBadgeAndTrend(unittest.TestCase):
    def test_badge_is_text(self):
        files = {"a": {"added": 10, "agent_added": 4, "removed": 0,
                       "agent_removed": 0}}
        self.assertEqual(render_mod.share_badge(files),
                         "Agent share: 40% [####------]")
        self.assertEqual(render_mod.share_badge({}),
                         "Agent share: 0% [----------]")

    def test_badge_is_in_the_comment(self):
        tmp, base = repo(1)
        _, doc, _ = check_json(tmp, base)
        self.assertIn("Agent share: 100% [##########]",
                      render_mod.to_comment(doc))

    def test_trend_reads_reports(self):
        tmp, base = repo(2)
        d = tempfile.mkdtemp()
        _, doc, _ = check_json(tmp, base)
        a, b = os.path.join(d, "01.json"), os.path.join(d, "02.json")
        for p, score in ((a, 10), (b, 30)):
            doc2 = dict(doc, risk=dict(doc["risk"], score=score))
            with open(p, "w", encoding="utf-8") as f:
                json.dump(doc2, f)
        code, out, err = run("trend", a, b)
        self.assertEqual(code, 0, err)
        self.assertIn("score +20", out)
        code, out, _ = run("trend", "--format", "json", a, b)
        self.assertEqual(json.loads(out)["score_change"], 20)

    def test_trend_rejects_other_json_and_missing_files(self):
        d = tempfile.mkdtemp()
        p = os.path.join(d, "x.json")
        with open(p, "w", encoding="utf-8") as f:
            f.write("{}")
        self.assertEqual(run("trend", p)[0], 2)
        self.assertEqual(run("trend", os.path.join(d, "nope.json"))[0], 2)
        with open(p, "w", encoding="utf-8") as f:
            f.write("[" * 100000)
        self.assertEqual(run("trend", p)[0], 2)


if __name__ == "__main__":
    unittest.main()
