"""The score gate is ONE rule (panel round 3): the verification fails when
score >= min-score, where min-score is --min-score, else the config's
risk_threshold, else 70. requires_review (JSON), the ✗/✓ line and the exit
code must all agree, at the boundary too; band names never decide."""

import io
import json
import unittest
from contextlib import redirect_stderr, redirect_stdout

from pr_verify import cli as cli_mod
from pr_verify import config as config_mod
from pr_verify import provenance as pv
from pr_verify import risk as rk

from fixture import commit_at_new_base, make_pr_repo

# make_pr_repo() scores exactly 57 (see README example output).
FIXTURE_SCORE = 57


def _check(tmp, base, *extra):
    buf = io.StringIO()
    with redirect_stdout(buf):
        code = cli_mod.main(["--root", tmp, "check", "--base", base,
                             "--skip-gates", "--format", "json", *extra])
    return code, json.loads(buf.getvalue())


class TestGateRule(unittest.TestCase):
    def test_gate_boundary(self):
        # score() computes requires_review as score >= threshold (equal
        # fails); drive it with an all-agent file worth exactly 40 + 5 pts.
        def score_at(threshold):
            f = pv.FileProvenance(file="a.py")
            f.added = f.agent_added = 10
            return rk.score({"a.py": f}, {}, [], [], threshold)

        self.assertEqual(score_at(45).score, 45)
        self.assertFalse(score_at(46).requires_review)
        self.assertTrue(score_at(45).requires_review)   # equal fails
        self.assertTrue(score_at(44).requires_review)
        self.assertTrue(rk.score({}, {}, [], [], 0).requires_review)   # 0 >= 0
        self.assertFalse(rk.score({}, {}, [], [], 101).requires_review)

    def test_resolve_min_score(self):
        self.assertEqual(cli_mod.resolve_min_score("high", None, 70), 70)
        self.assertEqual(cli_mod.resolve_min_score("high", 55, 70), 55)
        self.assertEqual(cli_mod.resolve_min_score("any-risk", None, 70), 1)
        self.assertEqual(cli_mod.resolve_min_score("any-risk", 55, 70), 1)
        self.assertIsNone(cli_mod.resolve_min_score("never", None, 70))
        self.assertIsNone(cli_mod.resolve_min_score("never", 55, 70))

    def test_score_requires_review_uses_gate(self):
        f = rk.score({}, {}, [], [], 0)
        self.assertEqual(f.score, 0)
        self.assertTrue(f.requires_review)   # 0 >= 0
        f = rk.score({}, {}, [], [], 1)
        self.assertFalse(f.requires_review)


class TestMinScoreCLI(unittest.TestCase):
    def test_min_score_boundary_values(self):
        tmp, base = make_pr_repo()
        code, data = _check(tmp, base)
        self.assertEqual(data["risk"]["score"], FIXTURE_SCORE)
        for min_score, expect_fail in ((FIXTURE_SCORE - 1, True),
                                       (FIXTURE_SCORE, True),
                                       (FIXTURE_SCORE + 1, False)):
            code, data = _check(tmp, base, "--min-score", str(min_score))
            self.assertEqual(data["min_score"], min_score)
            self.assertEqual(code, 1 if expect_fail else 0,
                             f"--min-score {min_score}")
            self.assertEqual(data["risk"]["requires_review"], expect_fail,
                             f"--min-score {min_score}: JSON disagrees with exit")

    def test_min_score_overrides_config_threshold(self):
        tmp, old = make_pr_repo()
        # config says fail at 50 (fixture would fail) — CLI raises the bar
        base = commit_at_new_base(tmp, old,
                                  {".pr-verify.yaml": "risk_threshold: 50\n"})
        code, data = _check(tmp, base)
        self.assertEqual(code, 1)
        code, data = _check(tmp, base, "--min-score", "90")
        self.assertEqual(code, 0)
        self.assertFalse(data["risk"]["requires_review"])

    def test_human_report_line_matches_exit(self):
        tmp, base = make_pr_repo()
        for min_score, mark in ((FIXTURE_SCORE, "✗"), (FIXTURE_SCORE + 1, "✓")):
            buf = io.StringIO()
            with redirect_stdout(buf):
                code = cli_mod.main(["--root", tmp, "check", "--base", base,
                                     "--skip-gates", "--min-score",
                                     str(min_score)])
            out = buf.getvalue()
            self.assertIn(f"{mark} score {FIXTURE_SCORE}", out)
            self.assertIn(f"min-score {min_score}", out)
            self.assertEqual(code, 1 if mark == "✗" else 0)

    def test_fail_on_presets_are_the_same_rule(self):
        tmp, base = make_pr_repo()
        code, data = _check(tmp, base, "--fail-on", "any-risk")
        self.assertEqual((code, data["min_score"]), (1, 1))
        code, data = _check(tmp, base, "--fail-on", "never")
        self.assertEqual((code, data["min_score"]), (0, None))
        self.assertFalse(data["risk"]["requires_review"])
        # never + an explicit --min-score: the gate stays off
        code, data = _check(tmp, base, "--fail-on", "never", "--min-score", "1")
        self.assertEqual(code, 0)

    def test_min_score_validation(self):
        tmp, base = make_pr_repo()
        for bad in ("-1", "101", "abc"):
            err = io.StringIO()
            with redirect_stderr(err), self.assertRaises(SystemExit) as cm:
                cli_mod.main(["--root", tmp, "check", "--base", base,
                              "--min-score", bad])
            self.assertEqual(cm.exception.code, 2, bad)


class TestConfigThreshold(unittest.TestCase):
    def test_quoted_threshold_is_coerced(self):
        # risk_threshold: "57" used to raise TypeError ('>=' int vs str)
        tmp, old = make_pr_repo()
        base = commit_at_new_base(tmp, old,
                                  {".pr-verify.yaml": 'risk_threshold: "57"\n'})
        self.assertEqual(config_mod.load(tmp, base)["risk_threshold"], 57)
        code, data = _check(tmp, base)
        self.assertEqual(code, 1)
        self.assertEqual(data["min_score"], 57)

    def test_garbage_threshold_is_a_clean_error(self):
        tmp, old = make_pr_repo()
        for bad in ("risk_threshold: high\n", "risk_threshold: 140\n",
                    "timeout: soon\n", "gates: 5\n"):
            base = commit_at_new_base(tmp, old, {".pr-verify.yaml": bad},
                                      message=f"cfg {bad.strip()}")
            with self.assertRaises(ValueError):
                config_mod.load(tmp, base)
            err = io.StringIO()
            with redirect_stdout(io.StringIO()), redirect_stderr(err):
                code = cli_mod.main(["--root", tmp, "check", "--base", base,
                                     "--skip-gates"])
            self.assertEqual(code, 2, bad)
            self.assertIn(".pr-verify.yaml", err.getvalue())
            self.assertNotIn("Traceback", err.getvalue())


if __name__ == "__main__":
    unittest.main()
