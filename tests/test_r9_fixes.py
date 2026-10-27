"""Regression tests for 0.1.5: on Windows a gate whose program is found
nowhere on a trusted PATH entry fails with exit 127 instead of being handed
to CreateProcess (which searches the parent's working directory, the pull
request's checkout); subdirectories of the checkout and relative PATH
entries are never searched either. The Windows branch runs on any platform."""

import os
import sys
import tempfile
import unittest
from unittest import mock

from pr_verify import gates as gates_mod


def _tool(d, name):
    os.makedirs(d, exist_ok=True)
    path = os.path.join(d, name)
    with open(path, "w") as f:
        f.write("@echo off\n")
    os.chmod(path, 0o755)
    return path


class TestWindowsLookupHole(unittest.TestCase):
    def setUp(self):
        self.base = os.path.realpath(tempfile.mkdtemp())
        self.checkout = os.path.join(self.base, "checkout")
        self.outside = os.path.join(self.base, "tools")
        os.makedirs(self.checkout)
        os.makedirs(self.outside)
        for p in (mock.patch.object(gates_mod, "_on_windows", lambda: True),
                  mock.patch.dict(os.environ, {
                      "PATHEXT": ".com;.exe;.bat;.cmd"})):
            p.start()
            self.addCleanup(p.stop)

    def _path(self, *entries):
        return mock.patch.dict(os.environ,
                               {"PATH": os.pathsep.join(entries)})

    def test_a_program_found_nowhere_is_a_127_gate_not_a_bare_name(self):
        _tool(self.checkout, "mytool.bat")
        with self._path(self.checkout, os.curdir):
            res = gates_mod.run_gates(self.checkout, ["mytool --x"])
        self.assertEqual(len(res), 1)
        self.assertFalse(res[0].passed)
        self.assertEqual(res[0].returncode, 127)
        self.assertIn("mytool", res[0].output_tail)
        self.assertIn("PATH", res[0].output_tail)

    def test_resolve_raises_instead_of_returning_the_bare_name(self):
        with self._path(self.outside):
            with self.assertRaises(gates_mod.ProgramNotFound):
                gates_mod.resolve_executable(["nosuchtool"], self.checkout)

    def test_the_file_in_the_checkout_never_runs(self):
        marker = os.path.join(self.base, "ran")
        with open(os.path.join(self.checkout, "mytool.bat"), "w") as f:
            f.write("")
        launched = []
        with self._path(self.outside), mock.patch.object(
                gates_mod.subprocess, "run",
                lambda *a, **k: launched.append(a)):
            res = gates_mod.run_gates(self.checkout, ["mytool"])
        self.assertEqual(launched, [])
        self.assertEqual(res[0].returncode, 127)
        self.assertFalse(os.path.exists(marker))

    def test_a_subdirectory_of_the_checkout_on_path_is_not_searched(self):
        sub = os.path.join(self.checkout, "node_modules", ".bin")
        _tool(sub, "tsc.cmd")
        good = _tool(self.outside, "tsc.cmd")
        with self._path(sub, self.outside):
            self.assertEqual(
                gates_mod.resolve_executable(["tsc", "x"], self.checkout),
                [good, "x"])

    def test_a_subdirectory_alone_is_not_enough(self):
        sub = os.path.join(self.checkout, "bin")
        _tool(sub, "tsc.cmd")
        with self._path(sub):
            with self.assertRaises(gates_mod.ProgramNotFound):
                gates_mod.resolve_executable(["tsc"], self.checkout)

    def test_a_subdirectory_of_the_working_directory_is_not_searched(self):
        sub = os.path.join(self.checkout, "bin")
        _tool(sub, "tsc.cmd")
        cwd = os.getcwd()
        try:
            os.chdir(self.checkout)
            with self._path(sub):
                with self.assertRaises(gates_mod.ProgramNotFound):
                    gates_mod.resolve_executable(["tsc"], None)
        finally:
            os.chdir(cwd)

    def test_relative_path_entries_are_skipped(self):
        _tool(self.checkout, "rel.cmd")
        cwd = os.getcwd()
        try:
            os.chdir(self.base)
            with self._path("checkout", "tools"):
                with self.assertRaises(gates_mod.ProgramNotFound):
                    gates_mod.resolve_executable(["rel"], None)
        finally:
            os.chdir(cwd)

    def test_a_sibling_with_the_same_prefix_is_not_a_subdirectory(self):
        sibling = os.path.join(self.base, "checkout-tools")
        good = _tool(sibling, "x.cmd")
        with self._path(sibling):
            self.assertEqual(
                gates_mod.resolve_executable(["x"], self.checkout), [good])

    def test_a_filesystem_root_working_directory_does_not_bar_everything(self):
        good = _tool(self.outside, "ok.cmd")
        root = os.path.abspath(os.sep)
        with self._path(self.outside), mock.patch.object(
                gates_mod.os, "getcwd", lambda: root):
            self.assertEqual(
                gates_mod.resolve_executable(["ok"], self.checkout), [good])

    def test_a_path_with_a_directory_is_still_taken_as_written(self):
        explicit = os.path.join(self.checkout, "tool.exe")
        with self._path(self.outside):
            self.assertEqual(
                gates_mod.resolve_executable([explicit], self.checkout),
                [explicit])
            self.assertEqual(
                gates_mod.resolve_executable(["./tool.exe"], self.checkout),
                ["./tool.exe"])

    def test_other_platforms_leave_a_missing_name_alone(self):
        with mock.patch.object(gates_mod, "_on_windows", lambda: False), \
                mock.patch.object(gates_mod.shutil, "which", lambda n: None):
            self.assertEqual(gates_mod.resolve_executable(["nope", "x"]),
                             ["nope", "x"])
            res = gates_mod.run_gates(self.checkout, ["nope-no-such-prog"])
        self.assertEqual(res[0].returncode, 127)

    def test_the_changelog_and_readme_describe_it(self):
        here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with open(os.path.join(here, "CHANGELOG.md"), encoding="utf-8") as f:
            top = f.read().split("## 0.1.4")[0]
        self.assertIn("## 0.1.5", top)
        self.assertIn("127", top)


if __name__ == "__main__":
    unittest.main()
