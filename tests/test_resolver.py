"""Import resolver regression (panel round 3): relative imports and src/
layouts used to resolve to nothing, so a changed module looked like it had
no dependents (and no tests reaching it)."""

import io
import json
import unittest
from contextlib import redirect_stdout

from pr_verify import blastradius as br
from pr_verify import cli as cli_mod

from fixture import make_src_layout_repo


class TestPythonImportResolution(unittest.TestCase):
    def test_module_candidates_include_every_dotted_suffix(self):
        self.assertEqual(br._module_candidates("src/pkg/core.py"),
                         ["src.pkg.core", "pkg.core", "core"])
        self.assertEqual(br._module_candidates("src/pkg/__init__.py"),
                         ["src.pkg", "pkg"])
        self.assertEqual(br._module_candidates("x.py"), ["x"])
        self.assertEqual(br._module_candidates("web/app.ts"), ["web.app", "app"])

    def test_relative_imports_resolve_against_own_package(self):
        self.assertEqual(
            br._python_imports("src/pkg/sub/helpers.py",
                               "from ..core import calc\nfrom . import util\n"),
            ["src.pkg.core", "src.pkg.core.calc", "src.pkg.sub",
             "src.pkg.sub.util"])
        self.assertEqual(
            br._python_imports("src/pkg/sub/util.py", "from .. import core\n"),
            ["src.pkg", "src.pkg.core"])
        # a package's __init__ resolves single-dot imports to itself
        self.assertEqual(
            br._python_imports("src/pkg/__init__.py", "from .core import calc\n"),
            ["src.pkg.core", "src.pkg.core.calc"])
        # climbing past the repo root is ignored, never a crash
        self.assertEqual(br._python_imports("top.py", "from ... import x\n"), [])

    def test_from_import_names_may_be_submodules(self):
        self.assertEqual(br._python_imports("t.py", "from pkg import core, api\n"),
                         ["pkg", "pkg.core", "pkg.api"])
        self.assertEqual(br._python_imports("t.py", "from pkg import *\n"),
                         ["pkg"])

    def test_src_layout_graph(self):
        tmp, _ = make_src_layout_repo()
        graph = br.build_graph(tmp)
        self.assertIn("src/pkg/core.py", graph["src/pkg/api.py"])
        self.assertIn("src/pkg/core.py", graph["src/pkg/sub/helpers.py"])
        self.assertIn("src/pkg/sub/util.py", graph["src/pkg/sub/helpers.py"])
        self.assertIn("src/pkg/core.py", graph["src/pkg/sub/util.py"])
        self.assertIn("src/pkg/core.py", graph["tests/test_core.py"])
        self.assertIn("src/pkg/sub/helpers.py", graph["tests/test_helpers.py"])

    def test_blast_radius_reaches_relative_and_src_importers(self):
        tmp, _ = make_src_layout_repo()
        r = br.analyze(tmp, ["src/pkg/core.py"])["src/pkg/core.py"]
        self.assertEqual(r.direct, ["src/pkg/api.py", "src/pkg/sub/helpers.py",
                                    "src/pkg/sub/util.py", "tests/test_core.py"])
        self.assertIn("tests/test_helpers.py", r.transitive)  # via helpers
        self.assertFalse(r.external_only)
        self.assertEqual(r.size, 5)

    def test_cli_reports_dependents_for_src_layout_change(self):
        tmp, base = make_src_layout_repo()
        buf = io.StringIO()
        with redirect_stdout(buf):
            cli_mod.main(["--root", tmp, "check", "--base", base,
                          "--skip-gates", "--format", "json"])
        data = json.loads(buf.getvalue())
        blast = data["blast_radius"]["src/pkg/core.py"]
        self.assertIn("tests/test_core.py", blast["direct"])
        self.assertIn("src/pkg/sub/helpers.py", blast["direct"])
        self.assertIn("tests/test_helpers.py", blast["transitive"])
        self.assertGreater(data["risk"]["factors"]["blast"]["points"], 0)


if __name__ == "__main__":
    unittest.main()
