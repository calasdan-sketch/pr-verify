"""CLI end-to-end tests on the fixture PR repo."""

import io
import json
import os
import unittest
from contextlib import redirect_stdout

from pr_verify import cli as cli_mod

from fixture import (FAIL_GATE, PASS_GATE, PY, commit_at_new_base, gate,
                     make_deletion_repo, make_pr_repo,
                     make_sensitive_deletion_repo, yaml_str)


def run(*argv) -> int:
    return cli_mod.main(list(argv))


class TestCLI(unittest.TestCase):
    def test_init(self):
        import tempfile
        tmp = tempfile.mkdtemp()
        with redirect_stdout(io.StringIO()):
            self.assertEqual(run("--root", tmp, "init"), 0)
            self.assertTrue(os.path.isfile(os.path.join(tmp, ".pr-verify.yaml")))
            self.assertEqual(run("--root", tmp, "init"), 2)

    def test_check_human(self):
        tmp, BASE = make_pr_repo()
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = run("--root", tmp, "check", "--base", BASE,
                       "--skip-gates")
        out = buf.getvalue()
        self.assertIn("PR VERIFY", out)
        self.assertIn("agent-authored", out)
        self.assertIn("claude-bot", out)
        # fixture scores 57/medium < default 70 threshold -> exit 0
        self.assertEqual(code, 0)
        self.assertIn("medium", out.lower())

    def test_check_json(self):
        tmp, BASE = make_pr_repo()
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = run("--root", tmp, "check", "--base", BASE,
                       "--skip-gates", "--format", "json")
        data = json.loads(buf.getvalue())
        self.assertEqual(data["tool"], "pr-verify")
        self.assertIn("risk", data)
        self.assertIn("app/auth.py", data["files"])
        self.assertEqual(data["files"]["app/auth.py"]["label"], "agent")
        self.assertEqual(data["files"]["app/core.py"]["label"], "mixed")
        self.assertIn("claude-bot", data["files"]["app/auth.py"]["agents"])
        self.assertIn("gates", data)
        self.assertEqual(data["risk"]["band"], "medium")
        self.assertEqual(code, 0)

    def test_threshold_triggers_exit_1(self):
        tmp, old_base = make_pr_repo()
        base = commit_at_new_base(tmp, old_base,
                                  {".pr-verify.yaml": "risk_threshold: 50\n"})
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = run("--root", tmp, "check", "--base", base,
                       "--skip-gates")
        # fixture scores 57 >= 50 -> exit 1
        self.assertEqual(code, 1)

    def test_check_fail_on_never(self):
        tmp, BASE = make_pr_repo()
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = run("--root", tmp, "check", "--base", BASE,
                       "--skip-gates", "--fail-on", "never")
        self.assertEqual(code, 0)

    def test_check_no_changes(self):
        tmp, BASE = make_pr_repo()
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = run("--root", tmp, "check", "--base", "HEAD",
                       "--skip-gates")
        self.assertEqual(code, 0)
        self.assertIn("nothing to verify", buf.getvalue())

    def test_gates_run(self):
        tmp, old_base = make_pr_repo()
        base = commit_at_new_base(
            tmp, old_base,
            {".pr-verify.yaml": f"gates:\n  - {yaml_str(PASS_GATE)}\n"
                                f"  - {yaml_str(FAIL_GATE)}\n"})
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = run("--root", tmp, "check", "--base", base, "--format", "json")
        data = json.loads(buf.getvalue())
        self.assertEqual(len(data["gates"]), 2)
        self.assertTrue(data["gates"][0]["passed"])
        self.assertFalse(data["gates"][1]["passed"])
        # a failing gate is a failed verification -> nonzero exit
        self.assertNotEqual(code, 0)

    def test_gates_come_from_base_not_worktree(self):
        # A hostile PR must not be able to ship its own gate config in the
        # worktree and have it executed: gates load from the base ref only.
        tmp, old_base = make_pr_repo()
        base = commit_at_new_base(
            tmp, old_base,
            {".pr-verify.yaml": f"gates:\n  - {yaml_str(PASS_GATE)}\n"})
        sentinel = os.path.join(tmp, "pwned-by-gate")
        hostile = gate(PY, "-c", f"open({sentinel!r}, 'w').close()")
        with open(os.path.join(tmp, ".pr-verify.yaml"), "w",
                  encoding="utf-8") as f:
            f.write(f"gates:\n  - {yaml_str(hostile)}\n")
        buf = io.StringIO()
        with redirect_stdout(buf):
            run("--root", tmp, "check", "--base", base, "--format", "json")
        data = json.loads(buf.getvalue())
        self.assertFalse(os.path.exists(sentinel),
                         "worktree gate config was executed!")
        self.assertEqual(len(data["gates"]), 1)
        self.assertEqual(data["gates"][0]["command"], PASS_GATE)
        self.assertTrue(data["gates"][0]["passed"])

    def test_gate_shell_metachars_not_interpreted(self):
        # Gates run WITHOUT a shell: ; $() `` | && are literal arguments.
        tmp, old_base = make_pr_repo()
        s1 = os.path.join(tmp, "metachar-1")
        s2 = os.path.join(tmp, "metachar-2")
        mk1 = gate(PY, "-c", f"open({s1!r}, 'w').close()")
        mk2 = gate(PY, "-c", f"open({s2!r}, 'w').close()")
        # with a shell, `;` and `$()` would run mk1/mk2; without one they
        # are literal extra arguments to a harmless `python -c pass`
        base = commit_at_new_base(tmp, old_base, {".pr-verify.yaml": (
            "gates:\n"
            f"  - {yaml_str(PASS_GATE + '; ' + mk1)}\n"
            f"  - {yaml_str(PASS_GATE + ' $(' + mk2 + ')')}\n")})
        buf = io.StringIO()
        with redirect_stdout(buf):
            run("--root", tmp, "check", "--base", base, "--format", "json")
        data = json.loads(buf.getvalue())
        self.assertFalse(os.path.exists(s1))
        self.assertFalse(os.path.exists(s2))
        # python -c pass with literal extra args still exits 0 -> gates pass
        self.assertEqual(len(data["gates"]), 2)
        self.assertTrue(all(g["passed"] for g in data["gates"]))

    def test_failing_gate_exits_nonzero(self):
        tmp, old_base = make_pr_repo()
        base = commit_at_new_base(
            tmp, old_base,
            {".pr-verify.yaml": f"gates:\n  - {yaml_str(FAIL_GATE)}\n"})
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = run("--root", tmp, "check", "--base", base,
                       "--format", "human")
        out = buf.getvalue()
        # fixture scores 57/medium < 70, so only the gate drives the exit
        self.assertNotEqual(code, 0)
        self.assertIn("FAIL", out)

    def test_dirty_worktree_included(self):
        # Uncommitted working-tree changes (the Claude Code workflow) must
        # be verified too, not just committed diffs.
        tmp, BASE = make_pr_repo()
        with open(os.path.join(tmp, "app/core.py"), "a", encoding="utf-8",
                  newline="\n") as f:
            f.write("\n\ndef dirty_wip(x):\n    return x\n")
        with open(os.path.join(tmp, "app/scratch.py"), "w", encoding="utf-8",
                  newline="\n") as f:
            f.write("def s():\n    return 1\n")
        buf = io.StringIO()
        with redirect_stdout(buf):
            run("--root", tmp, "check", "--base", BASE,
                "--skip-gates", "--format", "json")
        data = json.loads(buf.getvalue())
        # brand-new uncommitted file is seen...
        self.assertIn("app/scratch.py", data["files"])
        self.assertEqual(data["files"]["app/scratch.py"]["added"], 2)
        # ...and uncommitted lines have no commit authorship -> human, not agent
        self.assertEqual(data["files"]["app/scratch.py"]["label"], "human")
        # committed 8 + 4 uncommitted added lines in core.py
        self.assertEqual(data["files"]["app/core.py"]["added"], 12)

    def test_deleted_file_reported(self):
        tmp, BASE = make_deletion_repo()
        buf = io.StringIO()
        with redirect_stdout(buf):
            run("--root", tmp, "check", "--base", BASE,
                "--skip-gates", "--format", "json")
        data = json.loads(buf.getvalue())
        self.assertIn("app/util.py", data["files"])
        f = data["files"]["app/util.py"]
        self.assertEqual(f["label"], "deleted")
        self.assertTrue(f["deleted"])
        self.assertEqual(f["added"], 0)
        self.assertIn("claude-bot", f["deleted_by"])
        # blast radius: app/main.py still imports the deleted module
        blast = data["blast_radius"]["app/util.py"]
        self.assertIn("app/main.py", blast["direct"])
        self.assertIn("app/main.py", blast["transitive"])

    def test_deletion_only_never_nothing_to_verify(self):
        tmp, BASE = make_deletion_repo()
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = run("--root", tmp, "check", "--base", BASE,
                       "--skip-gates")
        out = buf.getvalue()
        self.assertNotIn("nothing to verify", out)
        self.assertIn("deleted", out)
        self.assertIn("claude-bot", out)

    def test_uncommitted_deletion_caught(self):
        tmp, BASE = make_pr_repo()
        os.remove(os.path.join(tmp, "app/auth.py"))  # not committed
        buf = io.StringIO()
        with redirect_stdout(buf):
            run("--root", tmp, "check", "--base", BASE,
                "--skip-gates", "--format", "json")
        data = json.loads(buf.getvalue())
        self.assertIn("app/auth.py", data["files"])
        self.assertEqual(data["files"]["app/auth.py"]["label"], "deleted")
        self.assertNotIn("nothing to verify", buf.getvalue())

    def test_sensitive_deletion_trips_high(self):
        # Agent deletes sensitive app/auth.py: deletion 45 + sensitive 20
        # + no_tests 5 = 70 >= default threshold 70 -> HIGH, exit 1.
        tmp, BASE = make_sensitive_deletion_repo()
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = run("--root", tmp, "check", "--base", BASE,
                       "--skip-gates")
        out = buf.getvalue()
        self.assertIn("deleted", out)
        self.assertIn("high", out.lower())
        self.assertEqual(code, 1)

    def test_report_survives_cp1252_console(self):
        # Windows consoles often run cp1252 with errors="strict"; the box
        # drawing and ✓/✗ marks used to raise UnicodeEncodeError. main()
        # hardens the streams so they are replaced instead.
        tmp, BASE = make_pr_repo()
        raw = io.BytesIO()
        strict = io.TextIOWrapper(raw, encoding="cp1252", errors="strict")
        with redirect_stdout(strict):
            code = run("--root", tmp, "check", "--base", BASE, "--skip-gates")
            strict.flush()
        self.assertEqual(code, 0)
        text = raw.getvalue().decode("cp1252")
        self.assertIn("PR VERIFY", text)
        self.assertIn("score 57 < min-score 70", text)

    def test_version(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            with self.assertRaises(SystemExit) as cm:
                run("--version")
        self.assertEqual(cm.exception.code, 0)
        self.assertIn("pr-verify", buf.getvalue())
        self.assertIn(cli_mod.VERSION, buf.getvalue())


if __name__ == "__main__":
    unittest.main()
