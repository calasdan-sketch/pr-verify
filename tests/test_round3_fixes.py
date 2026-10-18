"""Panel round 3 (second pass): regression tests, one class per finding.

V-1  Non-ASCII paths: git quotes them in diff headers (`+++ "b/app/\\316..."`)
     so the header was not recognised and the file's hunks were appended
     to the PREVIOUS file. core.quotePath=false + defensive unquoting.
V-2  Markers were case-insensitive substrings of name/email/subject/body:
     "Tim Abbott" was an agent ("bot"), "Fix cursor jump" was Cursor's.
     Whole-word matching on the places agents sign, never on prose.
V-3  A failed policy gate exited 1 while the report ended with a green
     `✓ score 48 < min-score 70`.
V-4  `--base main` default died on master repos; the base is detected.
V-5  `init` wrote a config the base ref never sees; the uncommitted file
     was scored as human source with no_tests. init says so; the config
     file is excluded from scoring; a note flags a worktree copy that is
     not in effect.
V-6  Every `check` snapshotted UNTRACKED files (a `.env.local` with a
     secret) into .git/objects. Tracked-only by default,
     --include-untracked opt-in, a note lists what was skipped.
V-7  Windows gates: argv[0] not resolved through PATHEXT (.cmd shims),
     POSIX shlex ate backslashes in unquoted paths; list-form gates.
V-8  `_is_test_file` substring "test" matched latest.py/attestation.py;
     sensitive globs `*key*`/`*token*` hit monkey.py/tokenizer.py.
V-9  `agents` showed the author only; now `author (marker)`.
V-10 README `@main` on a master repo, `git clone <repo>`; missing git
     was a traceback.
Simplify: one `git show` for all shas; risk.gate() inlined;
BlastRadius.external_only reported.
"""

import io
import json
import os
import subprocess
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

from pr_verify import blastradius as br
from pr_verify import cli as cli_mod
from pr_verify import config as config_mod
from pr_verify import gates as gates_mod
from pr_verify import markers
from pr_verify import miniyaml
from pr_verify import provenance as pv
from pr_verify import risk as rk

from fixture import (FAIL_GATE, PASS_GATE, PY, commit_as, commit_at_new_base,
                     git, make_pr_repo, yaml_str)

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_MARKERS = config_mod.DEFAULTS["agent_markers"]
GREEK = "app/Καλάς.py"


def _sha(tmp: str, rev: str = "HEAD") -> str:
    return subprocess.run(["git", "-C", tmp, "rev-parse", rev],
                          capture_output=True, text=True, encoding="utf-8",
                          check=True).stdout.strip()


def _check_json(tmp, *extra) -> tuple[int, dict]:
    buf = io.StringIO()
    with redirect_stdout(buf):
        code = cli_mod.main(["--root", tmp, "check", "--skip-gates",
                             "--format", "json", *extra])
    return code, json.loads(buf.getvalue())


def _check_human(tmp, *extra) -> tuple[int, str]:
    buf = io.StringIO()
    with redirect_stdout(buf):
        code = cli_mod.main(["--root", tmp, "check", *extra])
    return code, buf.getvalue()


def make_greek_repo() -> tuple[str, str]:
    """base: app/core.py. Then a human commit adding more lines to core.py
    plus a new Greek-named file, then another human commit adding
    app/editor.py (one line). The Greek file sorts LAST in the diff, so
    with the bug its hunks landed on editor.py."""
    tmp = tempfile.mkdtemp()
    git(tmp, "init", "-qb", "main")
    commit_as(tmp, "Dan Calas", "dan@example.com", "base",
              {"app/core.py": "def calc(x):\n    return x\n"})
    base = _sha(tmp)
    commit_as(tmp, "Tim Abbott", "tim.abbott@example.com", "Add Greek module",
              {"app/core.py": "def calc(x):\n    return x\n\n\n"
                              "def more():\n    return 1\n",
               GREEK: "A = 1\nB = 2\nC = 3\n"})
    commit_as(tmp, "Dan Calas", "dan@example.com", "Fix cursor jump in editor",
              {"app/editor.py": "x = 1\n"})
    return tmp, base


# ---------------------------------------------------------------------
# V-1

class TestNonAsciiPaths(unittest.TestCase):
    def test_git_quotes_the_path_without_our_flag(self):
        # The precondition for the bug: plain git quotes the Greek path.
        tmp, base = make_greek_repo()
        raw = subprocess.run(["git", "-C", tmp, "diff", "-U0", f"{base}..HEAD"],
                             capture_output=True, text=True, encoding="utf-8").stdout
        self.assertIn('+++ "b/app/\\316\\232', raw)

    def test_added_lines_per_file(self):
        tmp, base = make_greek_repo()
        added = pv.added_lines(tmp, base, "HEAD")
        self.assertEqual({k: len(v) for k, v in added.items()},
                         {"app/core.py": 4, "app/editor.py": 1, GREEK: 3})

    def test_unquote_git_path(self):
        self.assertEqual(pv.unquote_git_path('"b/app/\\316\\232\\316\\261.py"'),
                         "b/app/Κα.py")
        self.assertEqual(pv.unquote_git_path('"a\\tb\\"c\\\\d"'), 'a\tb"c\\d')
        self.assertEqual(pv.unquote_git_path("b/plain.py"), "b/plain.py")

    def test_cli_reports_the_greek_file_and_blames_it_right(self):
        tmp, base = make_greek_repo()
        code, data = _check_json(tmp, "--base", base)
        self.assertEqual(code, 0)
        self.assertIn(GREEK, data["files"])
        self.assertEqual(data["files"][GREEK]["added"], 3)
        self.assertEqual(data["files"]["app/editor.py"]["added"], 1)

    def test_deleted_greek_file_reported(self):
        tmp, base = make_greek_repo()
        base = _sha(tmp)
        os.remove(os.path.join(tmp, GREEK))
        git(tmp, "add", "-A")
        git(tmp, "-c", "user.name=claude-bot", "-c", "user.email=cb@example.com",
            "commit", "-qm", "drop it")
        code, data = _check_json(tmp, "--base", base)
        self.assertIn(GREEK, data["files"])
        self.assertTrue(data["files"][GREEK]["deleted"])


# ---------------------------------------------------------------------
# V-2 / V-9

class TestMarkerMatching(unittest.TestCase):
    def m(self, name="", email="", subject="", body="", mk=DEFAULT_MARKERS):
        return markers.match(name, email, subject, body, mk)

    def test_human_false_positives(self):
        self.assertIsNone(self.m("Tim Abbott", "tim.abbott@example.com", "x"))
        self.assertIsNone(self.m("Claude Dupont", "claude.dupont@acme.fr", "x"))
        self.assertIsNone(self.m("Cody Smith", "cody.smith@example.com", "x"))
        self.assertIsNone(self.m("Dan Calas", "dan@example.com",
                                 "Fix cursor jump in editor",
                                 "The copilot docs mention claude and codex."))
        self.assertIsNone(self.m("Robot Ross", "ross@example.com", "x"))
        self.assertIsNone(self.m("Abbot Kinney", "abbot@example.com", "x"))

    def test_agent_true_positives(self):
        self.assertEqual(self.m("claude-bot", "claude-bot@example.com"), "claude")
        self.assertEqual(self.m("Claude", "noreply@anthropic.com"), "claude")
        self.assertEqual(self.m("dependabot[bot]", "x@github.com"), "bot")
        self.assertEqual(self.m("copilot-swe-agent[bot]", "x@github.com"), "copilot")
        self.assertEqual(self.m("Dan Calas (aider)", "dan@example.com"), "aider")
        self.assertEqual(self.m("Dan Calas", "dan@example.com", "aider: fix tests"),
                         "aider")
        self.assertEqual(self.m("Dan Calas", "cursoragent@cursor.com"), "cursor")
        self.assertEqual(self.m("Dan", "dan@example.com", "Add feature",
                                "Co-Authored-By: Claude <noreply@anthropic.com>"),
                         "claude")
        self.assertEqual(self.m("Dan", "dan@example.com", "x",
                                "Signed-off-by: Dan\nCo-authored-by: Copilot "
                                "<223556219+Copilot@users.noreply.github.com>"),
                         "copilot")
        self.assertEqual(self.m("Claude Code", "x@example.com"), "claude code")

    def test_email_rules(self):
        self.assertTrue(markers.email_matches("claude-bot@example.com", "bot"))
        self.assertTrue(markers.email_matches("cody@example.com", "cody"))
        self.assertTrue(markers.email_matches("x@aider.chat", "aider"))
        self.assertFalse(markers.email_matches("tim.abbott@example.com", "bot"))
        self.assertFalse(markers.email_matches("claude.dupont@acme.fr", "claude"))
        self.assertFalse(markers.email_matches("not-an-email", "bot"))

    def test_legacy_trailer_marker_only_matches_trailers(self):
        mk = ["co-authored-by: claude"]
        self.assertIsNone(self.m("Claude", "c@example.com", "x", "", mk))
        self.assertEqual(self.m("Dan", "d@example.com", "x",
                                "Co-Authored-By: Claude <n@a.com>", mk),
                         "co-authored-by: claude")

    def test_provenance_shows_author_and_marker(self):
        tmp, base = make_pr_repo()
        prov = pv.analyze(tmp, base, "HEAD", DEFAULT_MARKERS)
        self.assertEqual(prov["app/auth.py"].agents, {"claude-bot (claude)"})
        code, out = _check_human(tmp, "--base", base, "--skip-gates")
        self.assertIn("[claude-bot (claude)]", out)

    def test_human_named_tim_abbott_is_human_end_to_end(self):
        tmp, base = make_greek_repo()
        prov = pv.analyze(tmp, base, "HEAD", DEFAULT_MARKERS)
        self.assertEqual(prov["app/core.py"].label(), "human")
        self.assertEqual(prov["app/editor.py"].label(), "human")
        self.assertEqual(prov[GREEK].label(), "human")

    def test_default_markers_cover_the_known_agents(self):
        for name in ("claude", "codex", "cursor", "copilot", "bot", "aider",
                     "cody", "devin"):
            self.assertIn(name, DEFAULT_MARKERS)


# ---------------------------------------------------------------------
# V-3

class TestGateVerdictLine(unittest.TestCase):
    def test_failed_gate_prints_cross_not_tick(self):
        tmp, old_base = make_pr_repo()
        base = commit_at_new_base(
            tmp, old_base,
            {".pr-verify.yaml": f"gates:\n  - {yaml_str(FAIL_GATE)}\n"})
        code, out = _check_human(tmp, "--base", base)
        self.assertEqual(code, 1)
        self.assertIn("✗ policy gate failed: " + FAIL_GATE, out)
        self.assertNotIn("✓", out)
        # the score line is still informative, but neutral
        self.assertIn("- score 67 < min-score 70", out)

    def test_passing_gates_keep_the_tick(self):
        tmp, old_base = make_pr_repo()
        base = commit_at_new_base(
            tmp, old_base,
            {".pr-verify.yaml": f"gates:\n  - {yaml_str(PASS_GATE)}\n"})
        code, out = _check_human(tmp, "--base", base)
        self.assertEqual(code, 0)
        self.assertIn("✓ score 57 < min-score 70", out)
        self.assertNotIn("policy gate failed", out)


# ---------------------------------------------------------------------
# V-4

def make_master_repo() -> str:
    tmp = tempfile.mkdtemp()
    git(tmp, "init", "-qb", "master")
    commit_as(tmp, "Dan Calas", "dan@example.com", "base",
              {"app/core.py": "def calc(x):\n    return x\n"})
    git(tmp, "checkout", "-qb", "feature")
    commit_as(tmp, "claude-bot", "claude-bot@example.com", "feat",
              {"app/core.py": "def calc(x):\n    return x\n\n\n"
                              "def more():\n    return 1\n"})
    return tmp


class TestBaseDetection(unittest.TestCase):
    def test_master_repo_without_base_flag(self):
        tmp = make_master_repo()
        self.assertEqual(cli_mod.detect_base(tmp), "master")
        code, data = _check_json(tmp)
        self.assertEqual(data["base"], "master")
        self.assertTrue(data["base_detected"])
        self.assertEqual(data["files"]["app/core.py"]["added"], 4)
        code, out = _check_human(tmp, "--skip-gates")
        self.assertIn("base: master  (auto-detected)", out)

    def test_main_repo_without_base_flag(self):
        tmp, base = make_pr_repo()
        git(tmp, "checkout", "-qb", "feature")
        commit_as(tmp, "claude-bot", "cb@example.com", "feat",
                  {"app/new.py": "x = 1\n"})
        self.assertEqual(cli_mod.detect_base(tmp), "main")
        code, data = _check_json(tmp)
        self.assertEqual(data["base"], "main")
        self.assertEqual(sorted(data["files"]), ["app/new.py"])

    def test_origin_head_wins(self):
        tmp = make_master_repo()
        git(tmp, "update-ref", "refs/remotes/origin/trunk", "master")
        git(tmp, "symbolic-ref", "refs/remotes/origin/HEAD",
            "refs/remotes/origin/trunk")
        self.assertEqual(cli_mod.detect_base(tmp), "origin/trunk")

    def test_explicit_missing_base_is_a_clean_error(self):
        tmp = make_master_repo()
        err = io.StringIO()
        with redirect_stdout(io.StringIO()), redirect_stderr(err):
            code = cli_mod.main(["--root", tmp, "check", "--base", "main"])
        self.assertEqual(code, 2)
        self.assertIn("base ref 'main' does not exist", err.getvalue())
        self.assertIn("master", err.getvalue())
        self.assertNotIn("Traceback", err.getvalue())

    def test_nothing_detectable_is_a_clean_error(self):
        tmp = tempfile.mkdtemp()
        git(tmp, "init", "-qb", "trunk")
        commit_as(tmp, "Dan", "d@example.com", "base", {"a.py": "x = 1\n"})
        err = io.StringIO()
        with redirect_stdout(io.StringIO()), redirect_stderr(err):
            code = cli_mod.main(["--root", tmp, "check"])
        self.assertEqual(code, 2)
        self.assertIn("could not detect the base branch", err.getvalue())

    def test_action_yml_base_default_is_auto_detect(self):
        with open(os.path.join(REPO, "action.yml"), encoding="utf-8") as f:
            action = miniyaml.safe_load(f.read())
        self.assertEqual(action["inputs"]["base"]["default"], "")


# ---------------------------------------------------------------------
# V-5

class TestInitAndConfigFile(unittest.TestCase):
    def test_init_says_commit_to_base(self):
        tmp = make_master_repo()
        buf = io.StringIO()
        with redirect_stdout(buf):
            self.assertEqual(cli_mod.main(["--root", tmp, "init"]), 0)
        self.assertIn("commit this file to master", buf.getvalue())

    def test_uncommitted_config_is_not_scored_and_is_flagged(self):
        tmp = make_master_repo()
        with redirect_stdout(io.StringIO()):
            cli_mod.main(["--root", tmp, "init"])
        git(tmp, "add", ".pr-verify.yaml")  # tracked but not at base
        code, data = _check_json(tmp)
        self.assertNotIn(".pr-verify.yaml", data["files"])
        self.assertTrue(any(".pr-verify.yaml" in n and "defaults are in effect" in n
                            for n in data["notes"]), data["notes"])
        code, out = _check_human(tmp, "--skip-gates")
        self.assertIn("note: .pr-verify.yaml", out)

    def test_worktree_config_differing_from_base_is_flagged(self):
        tmp, old_base = make_pr_repo()
        base = commit_at_new_base(tmp, old_base,
                                  {".pr-verify.yaml": "risk_threshold: 80\n"})
        with open(os.path.join(tmp, ".pr-verify.yaml"), "w", encoding="utf-8") as f:
            f.write("risk_threshold: 10\n")
        code, data = _check_json(tmp, "--base", base)
        self.assertEqual(data["min_score"], 80)   # the base copy rules
        self.assertEqual(code, 0)
        self.assertTrue(any("differs from" in n for n in data["notes"]), data["notes"])

    def test_config_only_diff_is_nothing_to_verify(self):
        tmp, old_base = make_pr_repo()
        head = _sha(tmp)
        commit_as(tmp, "claude-bot", "cb@example.com", "cfg",
                  {".pr-verify.yaml": "risk_threshold: 1\n"})
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = cli_mod.main(["--root", tmp, "check", "--base", head,
                                 "--skip-gates"])
        self.assertEqual(code, 0)
        self.assertIn("nothing to verify", buf.getvalue())


# ---------------------------------------------------------------------
# V-6

def _blobs_containing(tmp: str, needle: str) -> int:
    out = subprocess.run(["git", "-C", tmp, "cat-file", "--batch-all-objects",
                          "--batch-check"], capture_output=True, text=True,
                         encoding="utf-8").stdout
    n = 0
    for line in out.splitlines():
        sha, kind = line.split()[:2]
        if kind != "blob":
            continue
        blob = subprocess.run(["git", "-C", tmp, "cat-file", "-p", sha],
                              capture_output=True, text=True, encoding="utf-8",
                              errors="replace").stdout
        if needle in blob:
            n += 1
    return n


class TestUntrackedSnapshot(unittest.TestCase):
    def _dirty(self) -> str:
        tmp = make_master_repo()
        with open(os.path.join(tmp, ".env.local"), "w", encoding="utf-8") as f:
            f.write("API_SECRET=hunter2-super-secret\n")
        with open(os.path.join(tmp, "app/core.py"), "a", encoding="utf-8",
                  newline="\n") as f:
            f.write("\n\ndef wip():\n    return 2\n")
        return tmp

    def test_untracked_excluded_by_default_and_not_in_object_store(self):
        tmp = self._dirty()
        code, data = _check_json(tmp)
        self.assertNotIn(".env.local", data["files"])
        self.assertEqual(data["files"]["app/core.py"]["added"], 8)  # 4 committed + 4 dirty
        self.assertEqual(data["untracked_skipped"], [".env.local"])
        self.assertTrue(any("1 untracked file(s) not verified (.env.local)" in n
                            for n in data["notes"]), data["notes"])
        self.assertEqual(_blobs_containing(tmp, "hunter2-super-secret"), 0,
                         "untracked secret was written into .git/objects")

    def test_include_untracked_opt_in(self):
        tmp = self._dirty()
        code, data = _check_json(tmp, "--include-untracked")
        self.assertIn(".env.local", data["files"])
        self.assertEqual(data["untracked_skipped"], [])
        self.assertEqual(_blobs_containing(tmp, "hunter2-super-secret"), 1)

    def test_snapshot_api_default_is_tracked_only(self):
        tmp = self._dirty()
        snap = pv.snapshot_worktree(tmp)
        files = subprocess.run(["git", "-C", tmp, "ls-tree", "-r", "--name-only", snap],
                               capture_output=True, text=True, encoding="utf-8").stdout
        self.assertNotIn(".env.local", files)
        snap2 = pv.snapshot_worktree(tmp, include_untracked=True)
        files2 = subprocess.run(["git", "-C", tmp, "ls-tree", "-r", "--name-only", snap2],
                                capture_output=True, text=True, encoding="utf-8").stdout
        self.assertIn(".env.local", files2)
        # the user's index is untouched either way
        status = subprocess.run(["git", "-C", tmp, "status", "--porcelain"],
                                capture_output=True, text=True, encoding="utf-8").stdout
        self.assertIn("?? .env.local", status)

    def test_readme_documents_the_side_effect(self):
        with open(os.path.join(REPO, "README.md"), encoding="utf-8") as f:
            readme = f.read()
        self.assertIn("--include-untracked", readme)
        self.assertIn(".git/objects", readme)


# ---------------------------------------------------------------------
# V-7

class TestWindowsGates(unittest.TestCase):
    def test_split_follows_the_platform(self):
        win = r'"C:\Program Files\Python311\python.exe" -m pytest -q'
        with mock.patch.object(os, "name", "nt"):
            self.assertEqual(gates_mod.split_command(win),
                             [r"C:\Program Files\Python311\python.exe",
                              "-m", "pytest", "-q"])
            self.assertEqual(gates_mod.split_command(r"C:\py\python.exe -q"),
                             [r"C:\py\python.exe", "-q"])
        with mock.patch.object(os, "name", "posix"):
            self.assertEqual(gates_mod.split_command("python -m pytest 'a b'"),
                             ["python", "-m", "pytest", "a b"])
            # the old behaviour that broke Windows paths
            self.assertEqual(gates_mod.split_command(r"C:\py\python.exe -q"),
                             ["C:pypython.exe", "-q"])

    def test_list_form_gate_is_argv_as_is(self):
        self.assertEqual(gates_mod.split_command([PY, "-c", "pass; echo x"]),
                         [PY, "-c", "pass; echo x"])

    def test_argv0_resolved_with_which(self):
        seen = []

        def fake_which(name):
            seen.append(name)
            return r"C:\Users\dan\AppData\Roaming\npm\npx.cmd" if name == "npx" else None

        with mock.patch.object(gates_mod.shutil, "which", fake_which):
            argv = gates_mod.resolve_executable(["npx", "tsc", "--noEmit"])
        self.assertEqual(argv, [r"C:\Users\dan\AppData\Roaming\npm\npx.cmd",
                                "tsc", "--noEmit"])
        self.assertEqual(seen, ["npx"])
        with mock.patch.object(gates_mod.shutil, "which", lambda n: None):
            self.assertEqual(gates_mod.resolve_executable(["nope", "x"]),
                             ["nope", "x"])

    def test_run_gates_uses_which_and_list_gates(self):
        tmp = tempfile.mkdtemp()
        calls = []
        real_which = gates_mod.shutil.which

        def spy(name):
            calls.append(name)
            return real_which(name)

        with mock.patch.object(gates_mod.shutil, "which", spy):
            res = gates_mod.run_gates(tmp, [PASS_GATE, [PY, "-c", "raise SystemExit(3)"]])
        self.assertEqual([r.passed for r in res], [True, False])
        self.assertEqual(res[1].returncode, 3)
        self.assertEqual(res[1].command, f"{PY} -c raise SystemExit(3)")
        self.assertEqual(calls, [PY, PY])

    def test_list_gate_from_yaml_config(self):
        tmp, old_base = make_pr_repo()
        # list items are literal argv entries: "; echo INJECTED" is just an
        # extra argument to `python -c pass`, never a shell command
        base = commit_at_new_base(tmp, old_base, {".pr-verify.yaml": (
            "gates:\n"
            f"  - [{yaml_str(PY)}, \"-c\", \"pass\", \"; echo INJECTED\"]\n")})
        cfg = config_mod.load(tmp, base)
        self.assertEqual(cfg["gates"], [[PY, "-c", "pass", "; echo INJECTED"]])
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = cli_mod.main(["--root", tmp, "check", "--base", base,
                                 "--format", "json"])
        data = json.loads(buf.getvalue())
        self.assertTrue(data["gates"][0]["passed"])

    def test_bad_list_gate_is_a_config_error(self):
        tmp, old_base = make_pr_repo()
        base = commit_at_new_base(tmp, old_base,
                                  {".pr-verify.yaml": "gates:\n  - []\n"})
        with self.assertRaises(ValueError):
            config_mod.load(tmp, base)


# ---------------------------------------------------------------------
# V-8

class TestTestFileAndSensitiveGlobs(unittest.TestCase):
    def test_is_test_file(self):
        for yes in ("tests/x.py", "test/x.py", "src/__tests__/a.js", "spec/a_spec.rb",
                    "test_x.py", "pkg/x_test.go", "web/app.test.ts", "web/app.spec.ts",
                    "FooTest.java", "conftest.py", "testing/helpers.py"):
            self.assertTrue(rk._is_test_file(yes), yes)
        for no in ("latest.py", "attestation.py", "app/contest.py", "app/testimony.py",
                   "app/tests_util.py", "protest/x.py"):
            self.assertFalse(rk._is_test_file(no), no)

    def test_no_tests_factor_with_lookalikes(self):
        prov = {"app/latest.py": pv.FileProvenance(file="app/latest.py")}
        prov["app/latest.py"].added = 5
        b = rk.score(prov, {}, [], [], 70)
        self.assertEqual(b.factors["no_tests"]["points"], 5, "latest.py is source")
        prov["tests/test_latest.py"] = pv.FileProvenance(file="tests/test_latest.py")
        prov["tests/test_latest.py"].added = 1
        self.assertEqual(rk.score(prov, {}, [], [], 70).factors["no_tests"]["points"], 0)

    def _sens(self, *rels) -> list[str]:
        return rk._sensitive_hits(list(rels), config_mod.DEFAULTS["sensitive_paths"])

    def test_default_sensitive_globs(self):
        self.assertEqual(self._sens("app/monkey.py", "nlp/tokenizer.py",
                                    "app/author.py", "docs/authors.md",
                                    "app/keyboard.py", "app/tokens_test.py"), [])
        self.assertEqual(self._sens("app/auth.py", "app/auth/views.py",
                                    "app/auth_token.py", "settings/api_key.py",
                                    "config/secrets.py", ".env", ".env.local",
                                    "db/migrations/0001_init.py", "lib/crypto.py",
                                    "pay/payment_service.py", "app/oauth_client.py"),
                         [".env", ".env.local", "app/auth.py", "app/auth/views.py",
                          "app/auth_token.py", "app/oauth_client.py",
                          "config/secrets.py", "db/migrations/0001_init.py",
                          "lib/crypto.py", "pay/payment_service.py",
                          "settings/api_key.py"])

    def test_readme_documents_the_patterns(self):
        with open(os.path.join(REPO, "README.md"), encoding="utf-8") as f:
            readme = f.read()
        self.assertIn("tokenizer.py", readme)
        self.assertIn("latest.py", readme)


# ---------------------------------------------------------------------
# V-10

class TestReadmeAndGit(unittest.TestCase):
    def test_readme_install_and_action_ref(self):
        with open(os.path.join(REPO, "README.md"), encoding="utf-8") as f:
            readme = f.read()
        self.assertNotIn("<repo>", readme)
        self.assertIn("pip install git+https://github.com/calasdan-sketch/pr-verify",
                      readme)
        # The Action reference resolves against the GitHub repository, whose
        # default branch is `main`; the working branch of a local clone
        # (`master` here) is not what `uses:` sees.
        self.assertNotIn("pr-verify@master", readme)
        self.assertIn("pr-verify@main", readme)

    def test_missing_git_is_a_clean_error(self):
        err = io.StringIO()
        with mock.patch.object(cli_mod.subprocess, "run",
                               side_effect=FileNotFoundError(2, "git")):
            with redirect_stderr(err), self.assertRaises(SystemExit) as cm:
                cli_mod._ensure_repo(tempfile.mkdtemp())
        self.assertEqual(cm.exception.code, 2)
        self.assertIn("git not found", err.getvalue())
        self.assertNotIn("Traceback", err.getvalue())


# ---------------------------------------------------------------------
# Simplifications

class TestSimplifications(unittest.TestCase):
    def test_commit_text_is_one_git_show_per_chunk(self):
        tmp, base = make_pr_repo()
        shas = set(subprocess.run(["git", "-C", tmp, "rev-list", "HEAD"],
                                  capture_output=True, text=True,
                                  encoding="utf-8").stdout.split())
        self.assertEqual(len(shas), 3)
        calls = []
        real = pv._git

        def spy(root, *args, **kw):
            calls.append(args)
            return real(root, *args, **kw)

        with mock.patch.object(pv, "_git", spy):
            texts = pv._commit_text(tmp, shas)
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][:2], ("show", "-s"))
        self.assertEqual(set(texts), shas)
        names = {t[0] for t in texts.values()}
        self.assertEqual(names, {"Dan Calas", "claude-bot"})
        bodies = [t[3] for t in texts.values() if "Co-authored-by" in t[3]]
        self.assertEqual(len(bodies), 1)

    def test_commit_text_chunks_large_sets(self):
        tmp, base = make_pr_repo()
        shas = set(subprocess.run(["git", "-C", tmp, "rev-list", "HEAD"],
                                  capture_output=True, text=True,
                                  encoding="utf-8").stdout.split())
        calls = []
        real = pv._git

        def spy(root, *args, **kw):
            calls.append(args)
            return real(root, *args, **kw)

        with mock.patch.object(pv, "_SHOW_CHUNK", 2), \
                mock.patch.object(pv, "_git", spy):
            texts = pv._commit_text(tmp, shas)
        self.assertEqual(len(calls), 2)
        self.assertEqual(set(texts), shas)

    def test_risk_gate_wrapper_gone(self):
        self.assertFalse(hasattr(rk, "gate"))

    def test_external_only_reported(self):
        tmp, base = make_pr_repo()
        radii = br.analyze(tmp, ["nope/missing.py"])
        self.assertTrue(radii["nope/missing.py"].external_only)
        # delete a base file nothing imports: reported as deleted, with no
        # in-repo importers left to break
        os.remove(os.path.join(tmp, "tests/test_core.py"))
        code, data = _check_json(tmp, "--base", base)
        self.assertTrue(data["files"]["tests/test_core.py"]["deleted"])
        self.assertTrue(data["blast_radius"]["tests/test_core.py"]["external_only"])
        self.assertFalse(data["blast_radius"]["app/core.py"]["external_only"])
        code, out = _check_human(tmp, "--base", base, "--skip-gates")
        self.assertIn("not in the worktree; nothing in-repo imports it", out)


if __name__ == "__main__":
    unittest.main()
