"""Regression tests for 0.1.4: a quadratic Ruby pattern, the Windows program
lookup, --root after the subcommand, packaging.

Fixtures are throwaway directories and git repos (see fixture.py); nothing
touches the network, HOME or the real git configuration.
"""

import io
import os
import re
import subprocess
import sys
import tempfile
import time
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

try:
    import tomllib
except ImportError:  # Python 3.10
    tomllib = None

from pr_verify import blastradius as br
from pr_verify import cli as cli_mod
from pr_verify import gates as gates_mod

from fixture import commit_as, make_pr_repo

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _read(*parts):
    with open(os.path.join(REPO, *parts), encoding="utf-8") as f:
        return f.read()


def main(*argv):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = cli_mod.main(list(argv))
    return code, out.getvalue(), err.getvalue()


class TestRubyRequireRelativeIsLinear(unittest.TestCase):
    def test_what_the_pattern_reads_is_unchanged(self):
        text = ("require_relative 'a'\n"
                'require_relative "b/c"\n'
                "  require_relative('d')\n"
                "require_relative (  'e' )\n"
                "require_relative\t\"f\"\n"
                "require_relative(\"g\")  # comment\n"
                "# require_relative 'no'\n"
                "require_relativex 'no'\n"
                "require_relative foo\n")
        self.assertEqual(br._imports_of("x.rb", text),
                         ["a", "b/c", "d", "e", "f", "g"])

    def test_the_pattern_has_no_two_whitespace_runs_side_by_side(self):
        self.assertNotIn(r"\s*\(?\s*", br._RUBY_IMPORT_RE.pattern)

    def test_a_500_kb_line_is_read_at_once(self):
        # the reported repro: it ran for more than two minutes before.
        # Run in a child process with a deadline, so a regression fails here
        # instead of hanging the whole suite.
        code = (
            "import time\n"
            "from pr_verify import blastradius as br\n"
            "shapes = ['require_relative' + ' ' * 500000,\n"
            "          'require_relative' + '\\t' * 500000,\n"
            "          'require_relative (' + ' ' * 500000,\n"
            "          'require_relative' + ' (' * 250000,\n"
            "          ('require_relative ' * 30000)]\n"
            "t = time.monotonic()\n"
            "for s in shapes:\n"
            "    br._imports_of('evil.rb', s)\n"
            "print(round(time.monotonic() - t, 2))\n")
        env = dict(os.environ, PYTHONPATH=REPO)
        p = subprocess.run([sys.executable, "-c", code], capture_output=True,
                           text=True, timeout=60, env=env, cwd=REPO)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertLess(float(p.stdout.strip()), 10)

    def test_check_finishes_on_a_pull_request_with_such_a_file(self):
        tmp, base = make_pr_repo()
        commit_as(tmp, "Dan Calas", "dan@example.com", "ruby",
                  {"lib/evil.rb": "require_relative" + " " * 500000 + "\n"})
        env = dict(os.environ, PYTHONPATH=REPO)
        p = subprocess.run(
            [sys.executable, "-m", "pr_verify", "--root", tmp, "check",
             "--base", base], capture_output=True, text=True, timeout=90,
            env=env, cwd=tempfile.gettempdir())
        self.assertIn(p.returncode, (0, 1), p.stderr)
        self.assertNotIn("Traceback", p.stderr)


class TestWindowsProgramLookup(unittest.TestCase):
    """A file the pull request adds at its root must not be the gate's
    program on Windows (shutil.which searches the working directory first).
    The Windows branch is exercised here on any platform."""

    def setUp(self):
        self.checkout = tempfile.mkdtemp()
        self.tools = tempfile.mkdtemp()
        for d, name in ((self.checkout, "mytool.bat"),
                        (self.tools, "mytool.cmd")):
            path = os.path.join(d, name)
            with open(path, "w") as f:
                f.write("@echo off\n")
            os.chmod(path, 0o755)
        self.env = mock.patch.dict(os.environ, {
            "PATH": os.pathsep.join(["", os.curdir, self.checkout,
                                     self.tools]),
            "PATHEXT": ".com;.exe;.bat;.cmd"})
        self.env.start()
        self.addCleanup(self.env.stop)
        self.win = mock.patch.object(gates_mod, "_on_windows", lambda: True)
        self.win.start()
        self.addCleanup(self.win.stop)

    def test_the_checkout_is_not_searched_even_when_it_is_on_path(self):
        argv = gates_mod.resolve_executable(["mytool", "x"], self.checkout)
        self.assertEqual(argv, [os.path.join(self.tools, "mytool.cmd"), "x"])

    def test_the_working_directory_is_not_searched(self):
        cwd = os.getcwd()
        try:
            os.chdir(self.checkout)
            argv = gates_mod.resolve_executable(["mytool"], None)
        finally:
            os.chdir(cwd)
        self.assertEqual(argv, [os.path.join(self.tools, "mytool.cmd")])

    def test_a_name_that_is_nowhere_but_in_the_checkout_is_not_found(self):
        # was: returned the bare name, which CreateProcess searches for in
        # the parent's working directory (the checkout).
        with mock.patch.dict(os.environ, {"PATH": os.pathsep.join(
                ["", os.curdir, self.checkout])}):
            with self.assertRaises(gates_mod.ProgramNotFound):
                gates_mod.resolve_executable(["mytool"], self.checkout)

    def test_a_path_is_taken_as_written(self):
        explicit = os.path.join(self.checkout, "mytool.bat")
        self.assertEqual(
            gates_mod.resolve_executable([explicit], self.checkout),
            [explicit])

    def test_run_gates_hands_the_checkout_to_the_lookup(self):
        seen = []

        def spy(argv, root=None):
            seen.append(root)
            return [sys.executable, "-c", "pass"]
        with mock.patch.object(gates_mod, "resolve_executable", spy):
            res = gates_mod.run_gates(self.checkout, ["whatever"])
        self.assertEqual(seen, [self.checkout])
        self.assertTrue(res[0].passed)

    def test_other_platforms_still_use_shutil_which(self):
        self.win.stop()
        try:
            with mock.patch.object(gates_mod.shutil, "which",
                                   lambda n: "/usr/bin/" + n):
                self.assertEqual(gates_mod.resolve_executable(["git", "x"]),
                                 ["/usr/bin/git", "x"])
        finally:
            self.win.start()

    def test_the_readme_says_so(self):
        readme = " ".join(_read("README.md").split())
        self.assertIn("neither the working directory, the pull request's "
                      "checkout (or anything below it) nor a relative", readme)
        self.assertIn("fails the gate with exit 127", readme)


class TestRootAfterTheSubcommand(unittest.TestCase):
    def test_both_spellings_mean_the_same(self):
        tmp, base = make_pr_repo()
        before = main("--root", tmp, "check", "--base", base, "--format",
                      "json")
        after = main("check", "--root", tmp, "--base", base, "--format",
                     "json")
        self.assertEqual(before[0], after[0])
        self.assertEqual(before[1], after[1])
        self.assertEqual(after[2], "")

    def test_init_takes_it_too(self):
        tmp, _ = make_pr_repo()
        code, out, err = main("init", "--root", tmp)
        self.assertEqual(code, 0, err)
        self.assertTrue(os.path.isfile(os.path.join(tmp, ".pr-verify.yaml")))

    def test_leaving_it_out_keeps_the_one_before(self):
        tmp, base = make_pr_repo()
        code, out, err = main("--root", tmp, "check", "--base", base)
        self.assertIn(code, (0, 1), err)
        self.assertNotIn("unrecognized", err)


class TestPackaging(unittest.TestCase):
    def test_versions_agree_and_the_changelog_names_it(self):
        m = re.search(r'(?m)^version\s*=\s*"([^"]+)"', _read("pyproject.toml"))
        self.assertEqual(m.group(1), cli_mod.VERSION)
        self.assertIn("## " + cli_mod.VERSION, _read("CHANGELOG.md"))

    @unittest.skipIf(tomllib is None, "tomllib needs Python 3.11+")
    def test_metadata_matches_what_pypi_shows(self):
        with open(os.path.join(REPO, "pyproject.toml"), "rb") as f:
            project = tomllib.load(f)["project"]
        self.assertEqual(project["authors"],
                         [{"name": "Calas Automations Inc."}])
        url = "https://github.com/calasdan-sketch/pr-verify"
        self.assertEqual(project["urls"]["Homepage"], url)
        self.assertEqual(project["urls"]["Repository"], url)
        self.assertEqual(project["urls"]["Issues"], url + "/issues")
        self.assertIn("Programming Language :: Python :: 3.14",
                      project["classifiers"])

    def test_workflows(self):
        ci = _read(".github", "workflows", "ci.yml")
        for word in ("ubuntu-latest", "windows-latest", "macos-latest",
                     '"3.10"', '"3.12"', '"3.14"', "twine check --strict",
                     "unittest discover -s tests"):
            self.assertIn(word, ci)
        release = _read(".github", "workflows", "release.yml")
        self.assertIn('tags: ["v*"]', release)
        self.assertIn("pypa/gh-action-pypi-publish@release/v1", release)
        self.assertIn("environment: pypi", release)
        self.assertEqual(release.count("id-token: write"), 1)
        self.assertGreater(release.index("id-token: write"),
                           release.index("publish:"))
        self.assertIn("does not match pyproject version", release)

    def test_the_manifest_ships_the_new_files(self):
        manifest = _read("MANIFEST.in")
        for line in ("include .github/workflows/release.yml",
                     "include CHANGELOG.md"):
            self.assertIn(line, manifest)

    def test_the_readme_installs_from_pypi(self):
        readme = _read("README.md")
        self.assertIn("pip install pr-verify\n", readme)
        self.assertIn("From source", readme)


if __name__ == "__main__":
    unittest.main()
