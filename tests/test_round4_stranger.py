"""Round 4 (the stranger's first hour): a file name that is not UTF-8, the
version in one place, --root after the subcommand, packaging metadata."""
import io
import json
import os
import re
import subprocess
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

from fixture import PY, commit_as, git

import pr_verify
from pr_verify import cli, textsafe

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)


def run(argv):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        rc = cli.main(argv)
    return rc, out.getvalue(), err.getvalue()


@unittest.skipIf(os.name == "nt", "a non-UTF-8 byte in a name needs POSIX")
class TestNonUtf8FileName(unittest.TestCase):
    """A PR that adds `caf<0xE9>.py` (Latin-1) used to stop the whole run
    with `git blame ... fatal: no such path caf?.py` (exit 2)."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        git(self.tmp, "init", "-qb", "main")
        commit_as(self.tmp, "Alex", "d@example.com", "base", {"a.py": "x = 1\n"})
        with open(os.path.join(self.tmp, os.fsdecode(b"caf\xe9.py")), "w") as f:
            f.write("import os\nos.system(input())\n")
        git(self.tmp, "add", "-A")
        git(self.tmp, "-c", "user.name=Claude", "-c",
            "user.email=noreply@anthropic.com", "commit", "-qm",
            "add\n\nCo-Authored-By: Claude <noreply@anthropic.com>")

    def test_every_format_works_and_shows_the_byte_as_an_escape(self):
        for fmt in ("human", "json", "markdown", "sarif"):
            rc, out, err = run(["--root", self.tmp, "check", "--base",
                                "HEAD~1", "--format", fmt])
            self.assertEqual((rc, err), (0, ""), fmt)
            self.assertNotIn("\udce9", out, fmt)
            self.assertNotIn("�", out, fmt)
        rc, out, _ = run(["--root", self.tmp, "check", "--base", "HEAD~1",
                          "--format", "json"])
        data = json.loads(out)
        self.assertIn("caf\\xe9.py", data["files"])
        self.assertEqual(data["files"]["caf\\xe9.py"]["agent_added"], 2)

    def test_sarif_uri_is_the_percent_encoded_byte(self):
        rc, out, _ = run(["--root", self.tmp, "check", "--base", "HEAD~1",
                          "--format", "sarif"])
        self.assertEqual(rc, 0)
        self.assertIn("caf%E9.py", out)
        json.loads(out)


class TestScrub(unittest.TestCase):
    def test_scrub_and_neutralize(self):
        self.assertEqual(textsafe.scrub({"a\udce9": ["x\udcffy", 3]}),
                         {"a\\xe9": ["x\\xffy", 3]})
        self.assertEqual(textsafe.neutralize("a\udce9\x1b"), "a\\xe9\\x1b")
        self.assertEqual(textsafe.neutralize("plain é"), "plain é")


class TestVersionAndMetadata(unittest.TestCase):
    def read(self, name):
        with open(os.path.join(ROOT, name), encoding="utf-8") as f:
            return f.read()

    def test_one_version_everywhere(self):
        v = pr_verify.__version__
        self.assertEqual(cli.VERSION, v)
        self.assertIn(f'version = "{v}"', self.read("pyproject.toml"))
        self.assertTrue(self.read("CHANGELOG.md").startswith(
            f"# Changelog\n\n## {v}"))

    def test_metadata_a_stranger_sees_on_the_package_page(self):
        text = self.read("pyproject.toml")
        for needle in ("authors =", "Changelog =", "Source =", "Issues =",
                       "Homepage =", "license = \"MIT\"", "requires-python"):
            self.assertIn(needle, text)
        low = re.search(r"requires-python = \">=3\.(\d+)\"", text).group(1)
        self.assertIn(f"Programming Language :: Python :: 3.{low}", text)
        # no runtime dependencies: stdlib only, as the README says
        self.assertNotRegex(text, r"(?m)^dependencies\s*=")

    def test_install_line_in_readme_is_not_stale(self):
        readme = self.read("README.md")
        self.assertIn("pip install", readme)


class TestRootAfterSubcommand(unittest.TestCase):
    def test_root_works_after_the_subcommand(self):
        tmp = tempfile.mkdtemp()
        git(tmp, "init", "-qb", "main")
        commit_as(tmp, "Alex", "d@example.com", "base", {"a.py": "x = 1\n"})
        commit_as(tmp, "Alex", "d@example.com", "two", {"a.py": "x = 2\n"})
        a = run(["--root", tmp, "check", "--base", "HEAD~1", "--format", "json"])
        b = run(["check", "--root", tmp, "--base", "HEAD~1", "--format", "json"])
        self.assertEqual(a[0], 0)
        self.assertEqual(a, b)
        rc, out, err = run(["rules", "--root", tmp])
        self.assertEqual(rc, 0)

    def test_version_flag_from_a_separate_process(self):
        p = subprocess.run([PY, "-m", "pr_verify", "--version"], cwd=ROOT,
                           capture_output=True, text=True)
        self.assertEqual(p.stdout.strip(), "pr-verify " + pr_verify.__version__)
        self.assertEqual(p.returncode, 0)


if __name__ == "__main__":
    unittest.main()
