"""Round 5 tests: author pin, gate hardening, GitHub bot addresses,
property-style tests (seeded, no extra packages), a differential test against
PyYAML (when installed) and golden files for every output format."""

import io
import json
import os
import random
import re
import subprocess
import tempfile
import unittest
from contextlib import redirect_stdout

from pr_verify import __author__, __version__
from pr_verify import cli as cli_mod
from pr_verify import config as config_mod
from pr_verify import gates, markers, miniyaml, pathglob, textsafe

from fixture import PY, make_pr_repo

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GOLDEN = os.path.join(ROOT, "tests", "golden")
AUTHOR = "Calas Automations Inc."


class TestAuthor(unittest.TestCase):
    def test_author_string_is_pinned_everywhere(self):
        self.assertEqual(__author__, AUTHOR)
        with open(os.path.join(ROOT, "pyproject.toml"), encoding="utf-8") as f:
            toml = f.read()
        self.assertIn('authors = [{ name = "%s" }]' % AUTHOR, toml)
        self.assertIn('maintainers = [{ name = "%s" }]' % AUTHOR, toml)
        # no e-mail address is claimed for the project
        self.assertNotRegex(toml, r"(?m)^(authors|maintainers)\s*=.*email")
        with open(os.path.join(ROOT, "LICENSE"), encoding="utf-8") as f:
            self.assertIn("Copyright (c) 2026 " + AUTHOR, f.read())
        with open(os.path.join(ROOT, "README.md"), encoding="utf-8") as f:
            self.assertIn(AUTHOR, f.read())

    def test_no_personal_name_left_as_author_label(self):
        bad = re.compile(r"Dan Calas|\bDC Enterprises\b")
        for base in ("pr_verify", "tests", "benchmarks", "docs", ".github"):
            for dp, _dn, fns in os.walk(os.path.join(ROOT, base)):
                if "__pycache__" in dp or os.sep + "golden" in dp:
                    continue
                for fn in fns:
                    if fn == "test_r5_experts.py" or fn.endswith(".pyc"):
                        continue
                    with open(os.path.join(dp, fn), encoding="utf-8",
                              errors="replace") as f:
                        self.assertIsNone(bad.search(f.read()), (dp, fn))

    def test_help_and_sarif_name_the_maintainer(self):
        buf = io.StringIO()
        with self.assertRaises(SystemExit), redirect_stdout(buf):
            cli_mod.main(["--help"])
        self.assertIn(AUTHOR, buf.getvalue())
        from pr_verify import sarif
        doc = sarif.build(__version__, [], [])
        self.assertEqual(doc["runs"][0]["tool"]["driver"]["organization"], AUTHOR)


class TestGateHardening(unittest.TestCase):
    def test_secret_named_variables_are_not_inherited(self):
        env = {"PATH": "/bin", "GITHUB_TOKEN": "t", "NPM_TOKEN": "n",
               "AWS_SECRET_ACCESS_KEY": "s", "MY_PASSWORD": "p",
               "SSH_AUTH_SOCK": "/s", "DEPLOY_KEY": "k",
               "GIT_AUTHOR_NAME": "a", "TOKENIZERS_PARALLELISM": "false",
               "HOME": "/h", "ACTIONS_ID_TOKEN_REQUEST_URL": "u"}
        got = gates.gate_env((), env)
        self.assertEqual(sorted(got), ["GIT_AUTHOR_NAME", "HOME", "PATH",
                                       "TOKENIZERS_PARALLELISM"])
        got = gates.gate_env(["npm_token"], env)
        self.assertIn("NPM_TOKEN", got)
        self.assertNotIn("GITHUB_TOKEN", got)

    def test_gate_runs_without_the_secret_and_with_a_passed_one(self):
        os.environ["R5_TEST_TOKEN"] = "sekret"
        os.environ["R5_OTHER_TOKEN"] = "sekret2"
        self.addCleanup(os.environ.pop, "R5_TEST_TOKEN", None)
        self.addCleanup(os.environ.pop, "R5_OTHER_TOKEN", None)
        code = ("import os,sys;"
                "sys.exit(0 if os.environ.get('R5_TEST_TOKEN')=='sekret' "
                "and 'R5_OTHER_TOKEN' not in os.environ else 1)")
        tmp = tempfile.mkdtemp()
        r = gates.run_gates(tmp, [[PY, "-c", code]], 30, ["R5_TEST_TOKEN"])
        self.assertTrue(r[0].passed, r[0].output_tail)
        r = gates.run_gates(tmp, [[PY, "-c", code]], 30)
        self.assertFalse(r[0].passed)

    def test_gate_output_flood_keeps_only_the_tail(self):
        code = ("import sys\n"
                "for i in range(60):\n"
                " sys.stdout.write('x'*1000000+'\\n')\n"
                "sys.stdout.write('END-MARK\\n')\n")
        r = gates.run_gates(tempfile.mkdtemp(), [[PY, "-c", code]], 60)
        self.assertTrue(r[0].passed)
        self.assertLessEqual(len(r[0].output_tail), 2000)
        self.assertTrue(r[0].output_tail.rstrip().endswith("END-MARK"))

    def test_stdout_and_stderr_keep_their_order(self):
        code = ("import sys\nprint('one');sys.stdout.flush()\n"
                "print('two',file=sys.stderr);sys.stderr.flush()\n"
                "print('three')\nsys.exit(4)")
        r = gates.run_gates(tempfile.mkdtemp(), [[PY, "-c", code]], 30)
        self.assertEqual(r[0].returncode, 4)
        self.assertEqual(r[0].output_tail.split(), ["one", "two", "three"])

    def test_gate_does_not_read_the_callers_stdin(self):
        r = gates.run_gates(tempfile.mkdtemp(), [[PY, "-c",
            "import sys;sys.exit(0 if sys.stdin.read()=='' else 1)"]], 30)
        self.assertTrue(r[0].passed)

    @unittest.skipIf(os.name == "nt", "process groups are POSIX")
    def test_timeout_kills_what_the_gate_started(self):
        marker = os.path.join(tempfile.mkdtemp(), "alive")
        code = ("import subprocess,sys,time\n"
                "subprocess.Popen([sys.executable,'-c',"
                "'import time,sys;time.sleep(3);open(sys.argv[1],\"w\").close()',"
                "%r])\ntime.sleep(60)" % marker)
        r = gates.run_gates(tempfile.mkdtemp(), [[PY, "-c", code]], 1)
        self.assertTrue(r[0].timed_out)
        self.assertFalse(r[0].passed)
        import time
        time.sleep(4)
        self.assertFalse(os.path.exists(marker), "grandchild survived")

    def test_config_gate_env_pass(self):
        self.assertEqual(config_mod.DEFAULTS["gate_env_pass"], [])
        self.assertIn("gate_env_pass:", config_mod.example_config())
        text = config_mod.example_config()
        self.assertEqual(miniyaml.safe_load(text)["gate_env_pass"], [])


class TestGithubBotAddress(unittest.TestCase):
    M = config_mod.DEFAULTS["agent_markers"]

    def test_noreply_bot_address_beats_a_person_shaped_name(self):
        self.assertIsNotNone(markers.match(
            "Devin AI", "158243242+devin-ai-integration[bot]@users.noreply.github.com",
            "x", "", self.M))
        self.assertEqual(markers.match(
            "Pat Lee", "1+some-app[bot]@users.noreply.github.com",
            "x", "", self.M), "bot")
        self.assertIsNotNone(markers.match(
            "Pat Lee", "x@y.z", "x",
            "Co-authored-by: Pat Lee <9+app[bot]@users.noreply.github.com>",
            self.M))

    def test_person_noreply_and_look_alikes_stay_human(self):
        for email in ("1+patlee@users.noreply.github.com",
                      "1+app[bot]@example.com",
                      "app[bot]@users.noreply.github.com.evil.example"):
            self.assertIsNone(markers.match("Pat Lee", email, "x", "", self.M),
                              email)


class TestProperties(unittest.TestCase):
    """Seeded generators: the same inputs on every run, no extra packages."""

    NASTY = ("a", "Z", "0", " ", "\t", "\n", "\x00", "\x1b", "\x7f", "\x9b",
             "\u202e", "\u2066", "\u2028", "\\", "é", "\udc80", "\udcff",
             "[", "]", "*", "?", "/", ":", "\U0001f600")

    def test_neutralize_is_total_idempotent_and_leaves_no_control_char(self):
        rng = random.Random(5)
        for _ in range(2000):
            s = "".join(rng.choice(self.NASTY) for _ in range(rng.randint(0, 40)))
            out = textsafe.neutralize(s)
            self.assertFalse(any(ord(c) in textsafe.ESCAPES for c in out), repr(s))
            self.assertFalse(re.search("[\udc80-\udcff]", out), repr(s))
            self.assertEqual(textsafe.neutralize(out), out)
            out.encode("utf-8")           # never raises: no lone surrogate
            json.dumps(textsafe.scrub({s: [s]}), ensure_ascii=False).encode("utf-8")

    @staticmethod
    def _ref_match(path_parts, pat_parts):
        """A slow, obviously-correct reference for `**`/`*`/`?` globbing."""
        import fnmatch

        def go(i, j):
            if j == len(pat_parts):
                return True          # a matched name also matches below it
            if pat_parts[j] == "**":
                return any(go(k, j + 1) for k in range(i, len(path_parts) + 1))
            if i == len(path_parts):
                return False
            return (fnmatch.fnmatchcase(path_parts[i], pat_parts[j])
                    and go(i + 1, j + 1))
        return go(0, 0)

    def test_pathglob_agrees_with_a_reference_matcher(self):
        rng = random.Random(7)
        names = ["a", "b", "ab", "auth", "x.py", "a.b", "src", "tests"]
        pats = ["a", "b", "*", "a*", "*b", "?", "*.py", "x.*", "au?h", "src",
                "**", "t*"]
        checked = 0
        for _ in range(3000):
            path = [rng.choice(names) for _ in range(rng.randint(1, 4))]
            pat = [rng.choice(pats) for _ in range(rng.randint(1, 3))]
            if all(p == "**" for p in pat):
                continue
            pattern = "/" + "/".join(pat)      # anchored: no any-depth rule
            want = self._ref_match(path, pat)
            self.assertEqual(pathglob.match("/".join(path), pattern), want,
                             (path, pattern))
            checked += 1
        self.assertGreater(checked, 2500)

    @unittest.skipUnless(
        __import__("importlib").util.find_spec("yaml"), "PyYAML not installed")
    def test_miniyaml_agrees_with_pyyaml_on_generated_configs(self):
        import yaml
        rng = random.Random(11)
        words = ["claude", "a b", "x/y/**", "*.py", "true", "70", "co-authored-by: x"]
        for _ in range(300):
            doc = {}
            for key in rng.sample(["agent_markers", "gates", "sensitive_paths",
                                   "extra_agent_markers"], rng.randint(1, 3)):
                doc[key] = [rng.choice(words) for _ in range(rng.randint(0, 4))]
            doc["risk_threshold"] = rng.randint(0, 100)
            doc["timeout"] = rng.randint(1, 999)
            text = "\n".join(
                [f"{k}: []" if v == [] else
                 f"{k}:\n" + "\n".join("  - " + json.dumps(x) for x in v)
                 if isinstance(v, list) else f"{k}: {v}"
                 for k, v in doc.items()]) + "\n"
            self.assertEqual(miniyaml.safe_load(text), yaml.safe_load(text), text)


def _normalise(text: str, tmp: str) -> str:
    text = text.replace(tmp, "<repo>").replace(tmp.replace("\\", "/"), "<repo>")
    text = re.sub(r"\b[0-9a-f]{40}\b", "<sha40>", text)
    text = re.sub(r"\b[0-9a-f]{7,12}\b", "<sha>", text)
    text = re.sub(r"[A-Za-z]:\\\\?[^\s\"]*prv-test-[^\s\"]*", "<repo>", text)
    return text


class TestGoldenOutputs(unittest.TestCase):
    """The four report formats for one fixed fixture PR. To refresh after an
    intended change: PR_VERIFY_UPDATE_GOLDEN=1 python -m unittest tests.test_r5_experts"""

    FORMATS = {"human": "txt", "json": "json", "markdown": "md", "sarif": "sarif"}

    def _render(self, fmt):
        tmp, base = make_pr_repo()
        env = dict(os.environ, NO_COLOR="1")
        p = subprocess.run(
            [PY, "-m", "pr_verify", "--root", tmp, "check", "--base", base,
             "--skip-gates", "--format", fmt],
            capture_output=True, cwd=ROOT, env=dict(env, PYTHONPATH=ROOT))
        self.assertIn(p.returncode, (0, 1), p.stderr)
        return _normalise(p.stdout.decode("utf-8"), tmp)

    def test_each_format_matches_its_golden_file(self):
        update = os.environ.get("PR_VERIFY_UPDATE_GOLDEN") == "1"
        os.makedirs(GOLDEN, exist_ok=True)
        for fmt, ext in self.FORMATS.items():
            got = self._render(fmt)
            if fmt in ("json", "sarif"):
                json.loads(got)            # parses
            path = os.path.join(GOLDEN, f"pr_repo.{fmt}.{ext}")
            if update:
                with open(path, "w", encoding="utf-8", newline="\n") as f:
                    f.write(got)
            with open(path, encoding="utf-8", newline="") as f:
                want = f.read()
            self.assertEqual(got, want, f"{fmt} output changed (golden {path})")


if __name__ == "__main__":
    unittest.main()
