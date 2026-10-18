"""Round-7 panel regressions (third verification panel, 2026-10-18).

V1  The blast radius found no dependents for JavaScript and TypeScript, nor
    for the other languages the README listed: an import like './b' was
    looked up among dotted module names. The same edit to auth.ts scored 65
    (pass) and to auth.py 75 (fail). Now './' and '../' are resolved against
    the importing file's directory, and a language without a resolver says so
    in the report instead of printing a bare "0 downstream dependent(s)".

V2  A file or process error outside the checks' own error handling ended in a
    traceback and exit 1, the code for a failed verification: `init` with no
    git on PATH, and a report that cannot be written (`check > /dev/full`).
    Both are a run that could not do its job: one `error:` line, exit 2.

V2b The same for stderr: a message it will not take (`2> log` on a full disk)
    ended in a traceback and exit 1, where the error it was about to say is
    exit 2. The text is lost, the exit status is not.

V3  A setting the tool does not know was ignored without a word: `gate:` for
    `gates:` or `risk_treshold:` meant "no gates configured", exit 0. Now one
    `warning:` line on stderr per unknown key, naming the nearest known one;
    the run goes on as before (a config that works keeps working).

V4  Who removed a line costs one `git blame` for each agent commit and each
    file it took lines out of: 200 such commits over eight files took some
    fourteen seconds. The calls cannot share their answer (every commit reads
    a different parent), so this is a limit the README states, and a test
    pins what it says.

V5  The sdist held tests/test*.py but not tests/fixture.py, action.yml,
    run_action.py or the CI workflow the tests read: nine of its eleven test
    modules failed to import once unpacked. MANIFEST.in ships them.

V6  Two mutants of provenance.py survived the whole suite: the cap that keeps
    an agent's removal credit at or under the lines removed (agent removes
    lines 1-3, a human puts line 1 back: 2, not 3) and the `:(literal)` that
    keeps a file called `:x` from being read as pathspec syntax.

V7  The CI workflow had no `permissions:` block, so its token had whatever the
    repository's default is. It asks for `contents: read`.

V8  README: `init --force` was not mentioned (nor explained by `--help`), and
    the example output came from a repository nobody has. It is what the
    fixture in tests/fixture.py prints, and a test now checks that it stays
    so.

Fixtures are throwaway directories and git repos (see fixture.py); nothing
touches the network, HOME or the real git configuration.
"""

import errno
import io
import json
import os
import stat
import subprocess
import tempfile
import time
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

from pr_verify import action as action_mod
from pr_verify import blastradius as br
from pr_verify import cli as cli_mod
from pr_verify import config as config_mod
from pr_verify import provenance as prov_mod

from fixture import (FAIL_GATE, PY, commit_as, commit_at_new_base, git,
                     make_pr_repo, yaml_str)

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
AGENT = ("claude-bot", "claude-bot@example.com")
HUMAN = ("Dan Calas", "dan@example.com")


def _read(name: str) -> str:
    with open(os.path.join(REPO, name), encoding="utf-8") as f:
        return f.read()


def tree(files: dict) -> str:
    """A throwaway directory (no repository) holding `files`."""
    tmp = tempfile.mkdtemp(prefix="prv-r7-")
    for rel, text in files.items():
        path = os.path.join(tmp, *rel.split("/"))
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8", newline="\n") as f:
            f.write(text)
    return tmp


def deps(files: dict) -> dict:
    """file -> the files it imports, for the files that import anything."""
    graph = br.build_graph(tree(files))
    return {rel: sorted(d) for rel, d in sorted(graph.items()) if d}


def check_json(tmp, base):
    out = io.StringIO()
    with redirect_stdout(out):
        code = cli_mod.main(["--root", tmp, "check", "--base", base,
                             "--skip-gates", "--format", "json"])
    return code, json.loads(out.getvalue())


def head(tmp) -> str:
    return subprocess.run(["git", "-C", tmp, "rev-parse", "HEAD"], check=True,
                          capture_output=True, text=True,
                          encoding="utf-8").stdout.strip()


# ---------------------------------------------------------------------
# V1 - JavaScript and TypeScript

class TestTheSameEditInTypeScriptAndPython(unittest.TestCase):
    """The reviewer's repro: five files import auth.ts, five import auth.py,
    an agent edits each. Both must be found with the same dependents."""

    def repo(self, ext):
        tmp = tempfile.mkdtemp(prefix="prv-r7-")
        git(tmp, "init", "-qb", "main")
        if ext == "ts":
            files = {"src/auth.ts": "export const x = 1\n"}
            files.update({f"src/user{i}.ts": "import { x } from './auth'\n"
                          for i in range(1, 6)})
            edited = {"src/auth.ts": "export const x = 2\n"}
        else:
            files = {"src/auth.py": "x = 1\n"}
            files.update({f"src/user{i}.py": "from auth import x\n"
                          for i in range(1, 6)})
            edited = {"src/auth.py": "x = 2\n"}
        commit_as(tmp, *HUMAN, "base", files)
        base = head(tmp)
        commit_as(tmp, *AGENT, "Edit auth\n\nCo-authored-by: Claude", edited)
        return tmp, base

    def test_typescript_has_the_dependents_python_has(self):
        results = {}
        for ext in ("ts", "py"):
            tmp, base = self.repo(ext)
            code, data = check_json(tmp, base)
            results[ext] = (code, data)
        ts, py = results["ts"][1], results["py"][1]
        radius = ts["blast_radius"]["src/auth.ts"]
        self.assertEqual(radius["direct"],
                         [f"src/user{i}.ts" for i in range(1, 6)])
        self.assertEqual(radius["scan"], "graph")
        self.assertEqual(len(py["blast_radius"]["src/auth.py"]["direct"]), 5)
        # the same shape, the same score and the same verdict
        self.assertEqual(ts["risk"]["score"], py["risk"]["score"])
        self.assertEqual({k: v["points"] for k, v in ts["risk"]["factors"].items()},
                         {k: v["points"] for k, v in py["risk"]["factors"].items()})
        self.assertEqual(results["ts"][0], results["py"][0])
        self.assertEqual(ts["risk"]["factors"]["blast"]["points"], 10)


class TestRelativeSpecifiers(unittest.TestCase):
    """'./x' and '../x' name a file next to, or above, the importing one."""

    def test_every_extension_the_import_may_leave_out(self):
        for ext in (".ts", ".tsx", ".d.ts", ".js", ".jsx", ".mjs", ".cjs",
                    ".mts", ".cts"):
            with self.subTest(ext=ext):
                self.assertEqual(
                    deps({"src/a.js": "import x from './b'\n",
                          "src/b" + ext: "export const x = 1\n"}),
                    {"src/a.js": ["src/b" + ext]})

    def test_a_directory_is_its_index_file(self):
        for ext in (".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".mts",
                    ".cts"):
            with self.subTest(ext=ext):
                self.assertEqual(
                    deps({"src/a.ts": "import x from './lib'\n",
                          "src/lib/index" + ext: "export const x = 1\n"}),
                    {"src/a.ts": ["src/lib/index" + ext]})

    def test_a_file_wins_over_a_directory_of_the_same_name(self):
        self.assertEqual(
            deps({"src/a.ts": "import x from './lib'\n",
                  "src/lib.ts": "export const x = 1\n",
                  "src/lib/index.ts": "export const x = 2\n"}),
            {"src/a.ts": ["src/lib.ts"]})

    def test_every_extension_that_exists_counts(self):
        # b.ts next to a compiled b.js, or typings next to a script
        self.assertEqual(
            deps({"src/a.ts": "import x from './b'\n",
                  "src/b.ts": "", "src/b.js": "", "src/b.d.ts": ""}),
            {"src/a.ts": ["src/b.d.ts", "src/b.js", "src/b.ts"]})

    def test_the_parent_directory_and_deeper_ones(self):
        self.assertEqual(
            deps({"src/app/deep/a.ts": "import x from '../../util'\n"
                                       "import y from '../sibling'\n"
                                       "import z from './inner/z'\n",
                  "src/util.ts": "", "src/app/sibling.ts": "",
                  "src/app/deep/inner/z.ts": ""}),
            {"src/app/deep/a.ts": ["src/app/deep/inner/z.ts",
                                   "src/app/sibling.ts", "src/util.ts"]})

    def test_a_file_at_the_top_level(self):
        self.assertEqual(
            deps({"a.ts": "import x from './src/b'\n", "src/b.ts": ""}),
            {"a.ts": ["src/b.ts"]})

    def test_dots_inside_the_specifier_are_folded(self):
        self.assertEqual(
            deps({"src/a.ts": "import x from './sub/../b'\n"
                              "import y from './sub/./c'\n"
                              "import z from './lib/'\n",
                  "src/b.ts": "", "src/sub/c.ts": "",
                  "src/lib/index.ts": ""}),
            {"src/a.ts": ["src/b.ts", "src/lib/index.ts", "src/sub/c.ts"]})

    def test_a_trailing_slash_means_the_directory(self):
        self.assertEqual(
            deps({"src/a.ts": "import x from './lib/'\n",
                  "src/lib.ts": "", "src/lib/index.ts": ""}),
            {"src/a.ts": ["src/lib/index.ts"]})
        self.assertEqual(
            deps({"src/a.ts": "import x from './lib/'\n", "src/lib.ts": ""}),
            {})

    def test_dot_and_dot_dot_are_the_index_of_a_directory(self):
        self.assertEqual(
            deps({"src/a.ts": "import x from '.'\n", "src/index.ts": ""}),
            {"src/a.ts": ["src/index.ts"]})
        self.assertEqual(
            deps({"src/app/a.ts": "import x from '..'\n",
                  "src/index.ts": ""}),
            {"src/app/a.ts": ["src/index.ts"]})
        self.assertEqual(
            deps({"a.ts": "import x from '.'\n", "index.ts": ""}),
            {"a.ts": ["index.ts"]})

    def test_a_specifier_that_leaves_the_repository_finds_nothing(self):
        self.assertEqual(
            deps({"a.ts": "import x from '../x'\n", "x.ts": ""}), {})
        self.assertEqual(
            deps({"src/a.ts": "import x from '../../x'\n", "x.ts": ""}), {})

    def test_a_specifier_with_an_extension_is_that_file(self):
        self.assertEqual(
            deps({"src/a.ts": "import x from './b.js'\n", "src/b.js": ""}),
            {"src/a.ts": ["src/b.js"]})
        self.assertEqual(
            deps({"src/a.ts": "import x from './b.ts'\n", "src/b.ts": "",
                  "src/b.js": ""}),
            {"src/a.ts": ["src/b.ts"]})

    def test_typescript_writes_the_name_of_the_file_it_will_compile(self):
        # moduleResolution node16: import './b.js' where only b.ts exists
        for written, source in ((".js", ".ts"), (".js", ".tsx"),
                                (".jsx", ".tsx"), (".mjs", ".mts"),
                                (".cjs", ".cts")):
            with self.subTest(written=written, source=source):
                self.assertEqual(
                    deps({"src/a.ts": f"import x from './b{written}'\n",
                          "src/b" + source: ""}),
                    {"src/a.ts": ["src/b" + source]})

    def test_the_twin_is_only_for_the_matching_extension(self):
        self.assertEqual(
            deps({"src/a.ts": "import x from './b.mjs'\n", "src/b.ts": ""}),
            {})
        self.assertEqual(
            deps({"src/a.ts": "import x from './b.js'\n", "src/b.mts": ""}),
            {})

    def test_a_dot_in_the_name_is_not_an_extension(self):
        self.assertEqual(
            deps({"src/a.ts": "import x from './b.config'\n",
                  "src/b.config.ts": ""}),
            {"src/a.ts": ["src/b.config.ts"]})

    def test_files_that_are_not_scripts_are_not_edges(self):
        self.assertEqual(
            deps({"src/a.ts": "import d from './data.json'\n"
                              "import './style.css'\n",
                  "src/data.json": "{}", "src/style.css": ""}), {})

    def test_the_case_must_match(self):
        self.assertEqual(
            deps({"src/a.ts": "import x from './B'\n", "src/b.ts": ""}), {})


class TestBareSpecifiers(unittest.TestCase):
    """Without a leading './' or '../' the name is a package, a baseUrl
    path or an alias: no path is followed (tsconfig is not read), only a
    name without a slash finds a file of that name, as it always did."""

    def test_a_name_without_a_slash_finds_a_script_of_that_name(self):
        self.assertEqual(
            deps({"src/a.ts": "import x from 'config'\n",
                  "src/config.ts": ""}),
            {"src/a.ts": ["src/config.ts"]})

    def test_only_a_script_is_found_that_way(self):
        self.assertEqual(
            deps({"src/a.ts": "import x from 'config'\n",
                  "src/config.py": ""}), {})

    def test_paths_and_aliases_are_not_followed(self):
        for spec in ("lib/util", "@/lib/util", "src/lib/util", "@acme/util",
                     "node:fs", "/abs/util", "file:///tmp/util",
                     "lib.util"):       # a dot is not a path separator here
            with self.subTest(spec=spec):
                self.assertEqual(
                    deps({"src/a.ts": f"import x from '{spec}'\n",
                          "src/lib/util.ts": ""}), {})


class TestTheFormsOfAnImport(unittest.TestCase):
    FORMS = [
        "import x from './b'",
        'import x from "./b";',
        "import { a, b } from './b'",
        "import * as ns from './b'",
        "import type { T } from './b'",
        "import x, { y } from './b'",
        "import x from './b' // trailing comment",
        "import x from './b' with { type: 'json' }",
        "import './b'",
        "export * from './b'",
        "export * as ns from './b'",
        "export { a, b as c } from './b'",
        "export type { T } from './b'",
        "const m = require('./b')",
        "const m = require( \"./b\" );",
        "import m = require('./b')",
        "const m = await import('./b')",
        "import {\n  a,\n  b,\n} from './b'",
        "export {\n  a,\n} from './b';",
        "import Long, {\n  a,\n} from \"./b\"",
    ]
    NOT_IMPORTS = [
        "// import x from './b'",
        " * import x from './b'",
        "export const x = 1",
        "export default function () { return from('./b') }",
        "const o = {\n  a: 1,\n}",
        "const s = 'from b'",
        "import { a, b }",
    ]

    def test_each_form_is_read(self):
        for text in self.FORMS:
            with self.subTest(text=text):
                self.assertEqual(br._imports_of("src/a.ts", text + "\n"),
                                 ["./b"])

    def test_text_that_is_not_an_import_is_not_read(self):
        for text in self.NOT_IMPORTS:
            with self.subTest(text=text):
                self.assertEqual(br._imports_of("src/a.ts", text + "\n"), [])

    def test_several_imports_on_one_line(self):
        self.assertEqual(
            br._imports_of("a.js", "const a = require('./a'), b = require('./b')\n"),
            ["./a", "./b"])
        self.assertEqual(
            br._imports_of("a.js", "import a from './a'; const b = await import('./b')\n"),
            ["./a", "./b"])

    def test_several_imports_in_one_file(self):
        text = ("import a from './a'\r\n"
                "import {\r\n  b,\r\n} from \"../b\"\r\n"
                "export * from './c'\r\n"
                "const d = require('./d')\r\n"
                "const e = () => import('./e')\r\n")
        self.assertEqual(br._imports_of("src/x.ts", text),
                         ["./a", "../b", "./c", "./d", "./e"])

    def test_the_same_forms_are_read_in_every_script_extension(self):
        for ext in (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".mts",
                    ".cts"):
            with self.subTest(ext=ext):
                self.assertEqual(
                    br._imports_of("src/a" + ext, "import x from './b'\n"),
                    ["./b"])

    def test_a_byte_order_mark_and_windows_line_ends(self):
        tmp = tree({"src/b.ts": ""})
        with open(os.path.join(tmp, "src", "a.ts"), "wb") as f:
            f.write(b"\xef\xbb\xbfimport {\r\n  x,\r\n} from './b'\r\n")
        self.assertEqual(br.build_graph(tmp)["src/a.ts"], {"src/b.ts"})

    def test_a_chain_of_imports_is_followed_to_the_end(self):
        tmp = tree({"src/c.ts": "export const c = 1\n",
                    "src/b.ts": "export * from './c'\n",
                    "src/index.ts": "export { x } from './b'\n",
                    "src/app.ts": "import { x } from './index'\n"})
        r = br.analyze(tmp, ["src/c.ts"])["src/c.ts"]
        self.assertEqual(r.direct, ["src/b.ts"])
        self.assertEqual(r.transitive, ["src/app.ts", "src/b.ts",
                                        "src/index.ts"])


class TestAFileThatIsGone(unittest.TestCase):
    """Deleted, a file has no place in the graph: the files that still
    import it are found by what their imports say."""

    def test_a_deleted_script_keeps_the_files_that_import_it(self):
        tmp = tree({"src/a.ts": "import x from './b'\n",
                    "src/sub/c.ts": "import x from '../b.js'\n",
                    "src/d.ts": "import x from './other'\n"})
        r = br.analyze(tmp, ["src/b.ts"])["src/b.ts"]
        self.assertEqual((r.scan, r.direct, r.external_only),
                         ("not_in_worktree", ["src/a.ts", "src/sub/c.ts"],
                          False))

    def test_a_deleted_index_file(self):
        tmp = tree({"src/a.ts": "import x from './lib'\n",
                    "src/b.ts": "import x from './lib/'\n"})
        r = br.analyze(tmp, ["src/lib/index.ts"])["src/lib/index.ts"]
        self.assertEqual(r.direct, ["src/a.ts", "src/b.ts"])

    def test_a_deleted_script_nobody_imports(self):
        tmp = tree({"src/a.ts": "import x from './other'\n"})
        r = br.analyze(tmp, ["src/b.ts"])["src/b.ts"]
        self.assertEqual((r.direct, r.external_only), ([], True))

    def test_the_dependents_of_a_dependent_count_too(self):
        tmp = tree({"src/a.ts": "import x from './b'\n",
                    "src/z.ts": "import a from './a'\n"})
        r = br.analyze(tmp, ["src/b.ts"])["src/b.ts"]
        self.assertEqual((r.direct, r.transitive),
                         (["src/a.ts"], ["src/a.ts", "src/z.ts"]))

    def test_the_command_line_reports_them(self):
        tmp = tempfile.mkdtemp(prefix="prv-r7-")
        git(tmp, "init", "-qb", "main")
        commit_as(tmp, *HUMAN, "base",
                  {"src/util.ts": "export const u = 1\n",
                   "src/main.ts": "import { u } from './util'\n"})
        base = head(tmp)
        os.remove(os.path.join(tmp, "src", "util.ts"))
        git(tmp, "add", "-A")
        git(tmp, "-c", "user.name=claude-bot",
            "-c", "user.email=claude-bot@example.com",
            "commit", "-qm", "Drop util\n\nCo-authored-by: Claude")
        code, data = check_json(tmp, base)
        radius = data["blast_radius"]["src/util.ts"]
        self.assertEqual((radius["direct"], radius["scan"]),
                         (["src/main.ts"], "not_in_worktree"))
        self.assertGreater(data["risk"]["factors"]["deletion"]["points"], 10)


class TestRuby(unittest.TestCase):
    def test_require_relative_is_a_path_from_the_requiring_file(self):
        self.assertEqual(
            deps({"lib/app.rb": "require_relative 'util'\n"
                                "require_relative \"sub/deep\"\n"
                                "require_relative('../top')\n"
                                "  require_relative 'helper.rb'\n",
                  "lib/util.rb": "", "lib/sub/deep.rb": "", "top.rb": "",
                  "lib/helper.rb": ""}),
            {"lib/app.rb": ["lib/helper.rb", "lib/sub/deep.rb",
                            "lib/util.rb", "top.rb"]})

    def test_require_follows_the_load_path_which_is_not_read(self):
        self.assertEqual(
            deps({"lib/a.rb": "require 'util'\nrequire 'lib/util'\n"
                              "load 'util.rb'\n",
                  "lib/util.rb": ""}), {})

    def test_only_a_ruby_file_is_found(self):
        self.assertEqual(
            deps({"lib/a.rb": "require_relative 'util'\n",
                  "lib/util.py": "", "lib/util.js": ""}), {})

    def test_a_ruby_file_that_is_gone_keeps_its_requirers(self):
        tmp = tree({"lib/a.rb": "require_relative 'util'\n",
                    "lib/b/c.rb": "require_relative '../util'\n"})
        r = br.analyze(tmp, ["lib/util.rb"])["lib/util.rb"]
        self.assertEqual((r.scan, r.direct),
                         ("not_in_worktree", ["lib/a.rb", "lib/b/c.rb"]))

    def test_the_line_is_read_where_it_begins(self):
        self.assertEqual(br._imports_of("a.rb", "puts 'require_relative x'\n"),
                         [])
        self.assertEqual(br._imports_of("a.rb", "# require_relative 'x'\n"),
                         [])


JAVA = {
    "src/main/java/com/acme/App.java": (
        "package com.acme;\n"
        "import com.acme.util.Strings;\n"
        "import static com.acme.util.Numbers.parse;\n"
        "import com.acme.model.*;\n"
        "import com.acme.util.Strings.Inner;\n"
        "import java.util.List;\n"
        "import com.acme.util.Missing;\n"),
    "src/main/java/com/acme/util/Strings.java": "package com.acme.util;\n",
    "src/main/java/com/acme/util/Numbers.java": "package com.acme.util;\n",
    "src/main/java/com/acme/model/User.java": "package com.acme.model;\n",
    "src/main/java/com/acme/model/Order.java": "package com.acme.model;\n",
    "src/main/java/com/acme/model/deep/Deep.java": "package x;\n",
    "src/main/java/com/acme/Sibling.java": "package com.acme;\n",
}


class TestJava(unittest.TestCase):
    def test_an_import_is_the_file_whose_path_ends_like_it(self):
        pkg = "src/main/java/com/acme/"
        self.assertEqual(
            deps(JAVA),
            {pkg + "App.java": sorted([
                pkg + "util/Strings.java",      # import com.acme.util.Strings
                pkg + "util/Numbers.java",      # import static ...Numbers.parse
                pkg + "model/User.java",        # import com.acme.model.*
                pkg + "model/Order.java"])})

    def test_a_class_of_the_same_package_needs_no_import_and_is_not_seen(self):
        self.assertEqual(
            deps({"p/A.java": "package p;\nclass A { B b; }\n",
                  "p/B.java": "package p;\nclass B { }\n"}), {})

    def test_a_wildcard_import_of_a_class_is_its_static_members(self):
        self.assertEqual(
            deps({"a/Main.java": "import static com.Util.*;\n",
                  "x/com/Util.java": ""}),
            {"a/Main.java": ["x/com/Util.java"]})

    def test_a_name_alone_is_not_enough(self):
        # an import that is not in the repository (org.junit.Assert) must not
        # fall back to its first word: any file org.java, in any directory
        self.assertEqual(
            deps({"a/Main.java": "import org.junit.Assert;\n",
                  "x/org.java": "", "y/junit.java": "", "z/Assert.java": ""}),
            {})

    def test_only_a_java_file_is_found(self):
        self.assertEqual(
            deps({"a/Main.java": "import com.acme.Thing;\n",
                  "com/acme/Thing.py": "", "com/acme/Thing.kt": ""}), {})

    def test_the_forms_that_are_read(self):
        for text, spec in (("import a.b.C;", "a.b.C"),
                           ("import static a.b.C.m;", "a.b.C.m"),
                           ("import a.b.*;", "a.b.*"),
                           ("   import   a.b.C ;  // note", "a.b.C"),
                           ("import a.b.C$D;", "a.b.C$D")):
            with self.subTest(text=text):
                self.assertEqual(br._imports_of("A.java", text + "\n"),
                                 [spec])
        for text in ("// import a.b.C;", "import a.b.C", "String s = \"import "
                     "a.b.C;\";", "importa.b.C;"):
            with self.subTest(text=text):
                self.assertEqual(br._imports_of("A.java", text + "\n"), [])

    def test_a_java_file_that_is_gone_keeps_its_importers(self):
        files = {k: v for k, v in JAVA.items() if "Strings" not in k
                 and "model" not in k}
        files["src/main/java/com/acme/Other.java"] = (
            "import com.acme.model.*;\n")
        tmp = tree(files)
        pkg = "src/main/java/com/acme/"
        r = br.analyze(tmp, [pkg + "util/Strings.java"])[pkg + "util/Strings.java"]
        self.assertEqual((r.scan, r.direct), ("not_in_worktree",
                                              [pkg + "App.java"]))
        # a wildcard import wants every file of the package, one that is gone too
        r = br.analyze(tmp, [pkg + "model/User.java"])[pkg + "model/User.java"]
        self.assertEqual(r.direct, [pkg + "App.java", pkg + "Other.java"])


class TestLanguagesWithoutAResolver(unittest.TestCase):
    """Go, Rust and PHP imports name a module, crate or namespace whose files
    only go.mod, Cargo.toml or composer.json say. Those files are not
    scanned, and the report says that, not "0 downstream dependent(s)"."""

    FILES = {"main.go": 'package main\nimport "app/util"\n',
             "util/util.go": "package util\n",
             "src/lib.rs": "mod util;\nuse crate::util::f;\n",
             "src/util.rs": "pub fn f() {}\n",
             "app/Http.php": "<?php\nuse App\\Util;\n",
             "app/Util.php": "<?php\n",
             "Program.cs": "using App.Util;\n"}

    def test_they_are_not_scanned(self):
        tmp = tree(self.FILES)
        self.assertEqual(br.build_graph(tmp), {})
        radii = br.analyze(tmp, sorted(self.FILES))
        for rel, radius in radii.items():
            with self.subTest(file=rel):
                self.assertEqual((radius.scan, radius.direct,
                                  radius.external_only),
                                 ("not_source", [], True))

    def test_the_report_says_so(self):
        tmp = tree(self.FILES)
        b = br.analyze(tmp, ["util/util.go"])["util/util.go"]
        self.assertEqual(cli_mod._blast_tail(b),
                         "  (.go files are not scanned for imports)")

    def test_they_are_not_imported_from_python_either(self):
        # they used to be in the dotted-name index: `import util` found util.go
        self.assertEqual(
            deps({"a.py": "import util\n", "util.go": "package util\n",
                  "util.rs": "", "util.php": ""}), {})


class TestTheReadmeIsTrueAboutTheScan(unittest.TestCase):
    def setUp(self):
        self.readme = " ".join(_read("README.md").split())

    def test_every_file_type_that_is_scanned_is_named(self):
        for ext in sorted(br.SCANNED_EXTS):
            with self.subTest(ext=ext):
                self.assertIn("`" + ext + "`", self.readme)

    def test_the_languages_without_a_resolver_are_said_not_to_be_scanned(self):
        # the README listed Go, Rust, Java, Ruby and PHP as read "via
        # heuristic fallback", and nothing was found for any of them
        self.assertNotIn("heuristic fallback", self.readme)
        self.assertNotIn("extraction is heuristic", self.readme)
        self.assertIn("Every other language (Go, Rust, PHP, C#, Kotlin and the "
                      "rest) is not scanned", self.readme)
        for ext in (".go", ".rs", ".php", ".cs", ".kt"):
            self.assertNotIn(ext, br.SCANNED_EXTS)

    def test_what_the_readme_calls_an_over_approximation_is_one(self):
        # "a require('./x') in a comment still counts"
        self.assertEqual(
            br._imports_of("a.ts", "// was: const m = require('./x')\n"),
            ["./x"])
        # "a name without a slash matches a script of that name anywhere"
        self.assertEqual(
            deps({"a/x.ts": "import m from 'util'\n", "b/c/util.ts": ""}),
            {"a/x.ts": ["b/c/util.ts"]})
        # "each of b.ts, b.js and b.d.ts counts as what ./b means"
        self.assertEqual(
            deps({"x.ts": "import m from './b'\n", "b.ts": "", "b.js": "",
                  "b.d.ts": ""}),
            {"x.ts": ["b.d.ts", "b.js", "b.ts"]})


class TestTheCostStaysLinear(unittest.TestCase):
    """A file of a few megabytes is read for its imports (up to the 4 MiB
    limit), and a pull request writes the file: nothing in it may make the
    reading quadratic. Quadratic here is hours; the bound is generous."""

    def test_text_that_starts_like_an_import_and_never_finishes(self):
        size = 1_000_000
        shapes = {
            "one long line": "import " * (size // 7) + "\n",
            "many lines": "export {\n" * (size // 9),
            "no quote ever": "export " + "x" * size + "\n",
            "open require": "require(" + " " * size + "\n",
            "many requires": "require(a" * (size // 9) + "\n",
            "an endless string": "import x from '" + "y" * size + "\n",
            "a thousand from": "import x " + "from " * (size // 5) + "\n",
            "dynamic imports": "import(" * (size // 7) + "\n",
        }
        for name, text in shapes.items():
            with self.subTest(shape=name):
                started = time.monotonic()
                br._imports_of("src/a.ts", text)
                self.assertLess(time.monotonic() - started, 15, name)


# ---------------------------------------------------------------------
# V2 - an error of the operating system is exit 2 with one line

def main(*argv):
    """cli.main(argv) in this process: (exit code, stdout, stderr)."""
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = cli_mod.main(list(argv))
    return code, out.getvalue(), err.getvalue()


def one_error_line(test, err, *mentions):
    got = err.strip().splitlines()
    test.assertEqual(len(got), 1, err)
    test.assertTrue(got[0].startswith("error: "), err)
    test.assertNotIn("Traceback", err)
    for text in mentions:
        test.assertIn(text, got[0])


class FullDisk(io.StringIO):
    """A stdout that takes the text and then refuses it, as a file on a full
    disk does: at the write (unbuffered) or at the flush (buffered)."""

    def __init__(self, fail_at="flush"):
        super().__init__()
        self.fail_at = fail_at
        self.pending = False        # text taken in, not yet flushed

    def _full(self):
        raise OSError(errno.ENOSPC, "No space left on device")

    def write(self, text):
        if self.fail_at == "write":
            self._full()
        self.pending = True
        return super().write(text)

    def flush(self):
        # a flush with nothing buffered writes nothing, so it cannot fail
        if self.fail_at == "flush" and self.pending:
            self._full()


def default_signals():
    """preexec_fn: a child starts with default signal dispositions, whatever
    the job that started this runner handed down."""
    import signal
    for name in ("SIGINT", "SIGQUIT", "SIGHUP", "SIGTERM"):
        if hasattr(signal, name):
            signal.signal(getattr(signal, name), signal.SIG_DFL)


def run_cli(args, stdout=subprocess.PIPE, env_extra=None,
            stderr=subprocess.PIPE):
    """pr-verify's main() in a child interpreter: the completed process."""
    env = {k: v for k, v in os.environ.items() if k != "PYTHONUNBUFFERED"}
    env.update(env_extra or {})
    code = (f"import sys; sys.path.insert(0, {REPO!r}); "
            "from pr_verify.cli import main; sys.exit(main(sys.argv[1:]))")
    return subprocess.run([PY, "-I", "-c", code, *args], stdout=stdout,
                          stderr=stderr, env=env, timeout=120,
                          preexec_fn=default_signals if os.name == "posix"
                          else None)


def new_repo():
    tmp = tempfile.mkdtemp(prefix="prv-r7-")
    git(tmp, "init", "-qb", "main")
    return tmp


class TestInitWithoutGit(unittest.TestCase):
    def test_a_git_that_is_not_there_is_one_line_exit_2(self):
        tmp = new_repo()
        err = io.StringIO()
        missing = FileNotFoundError(errno.ENOENT, "No such file or directory",
                                    "git")
        with mock.patch.object(subprocess, "run", side_effect=missing), \
                redirect_stderr(err), redirect_stdout(io.StringIO()):
            with self.assertRaises(SystemExit) as cm:
                cli_mod.main(["--root", tmp, "init"])
        self.assertEqual(cm.exception.code, 2)
        one_error_line(self, err.getvalue(), "git not found on PATH")
        self.assertFalse(os.path.exists(os.path.join(tmp, ".pr-verify.yaml")))

    @unittest.skipUnless(os.name == "posix",
                         "an empty PATH stops the interpreter on Windows")
    def test_the_same_in_a_real_process_with_an_empty_path(self):
        tmp = new_repo()
        empty = tempfile.mkdtemp(prefix="prv-r7-")
        r = run_cli(["--root", tmp, "init"], env_extra={"PATH": empty})
        err = r.stderr.decode("utf-8", "replace")
        self.assertEqual(r.returncode, 2, err)
        one_error_line(self, err, "git not found on PATH")
        self.assertEqual(r.stdout, b"")
        self.assertFalse(os.path.exists(os.path.join(tmp, ".pr-verify.yaml")))

    def test_a_git_that_cannot_be_started_otherwise_says_so_too(self):
        tmp = new_repo()
        err = io.StringIO()
        refused = PermissionError(errno.EACCES, "Permission denied", "git")
        with mock.patch.object(subprocess, "run", side_effect=refused), \
                redirect_stderr(err), redirect_stdout(io.StringIO()):
            with self.assertRaises(SystemExit) as cm:
                cli_mod.main(["--root", tmp, "init"])
        self.assertEqual(cm.exception.code, 2)
        one_error_line(self, err.getvalue(), "could not run git",
                       "Permission denied")

    def test_a_base_lookup_that_fails_does_not_undo_the_file(self):
        # git runs; only the name of the base branch (for the note) is lost
        for failure in (subprocess.TimeoutExpired(["git", "symbolic-ref"], 15),
                        OSError(errno.EMFILE, "Too many open files")):
            with self.subTest(failure=type(failure).__name__):
                tmp = new_repo()
                with mock.patch.object(cli_mod, "detect_base",
                                       side_effect=failure):
                    code, out, err = main("--root", tmp, "init")
                self.assertEqual((code, err), (0, ""))
                self.assertIn("commit this file to your base branch", out)
                self.assertTrue(os.path.isfile(
                    os.path.join(tmp, ".pr-verify.yaml")))

    def test_init_with_git_is_unchanged(self):
        tmp = new_repo()
        commit_as(tmp, *HUMAN, "base", {"a.py": "x = 1\n"})
        code, out, err = main("--root", tmp, "init")
        self.assertEqual((code, err), (0, ""))
        self.assertIn("commit this file to main", out)


class TestAReportThatCannotBeWritten(unittest.TestCase):
    def check(self, fail_at, *extra):
        tmp, base = make_pr_repo()
        err = io.StringIO()
        with redirect_stdout(FullDisk(fail_at)), redirect_stderr(err):
            code = cli_mod.main(["--root", tmp, "check", "--base", base,
                                 "--skip-gates", *extra])
        return code, err.getvalue()

    def test_it_is_exit_2_whichever_the_verdict_was(self):
        for verdict, extra in (("pass", ()), ("fail", ("--min-score", "1"))):
            for fail_at in ("flush", "write"):
                for fmt in ("human", "json"):
                    with self.subTest(verdict=verdict, at=fail_at, fmt=fmt):
                        code, err = self.check(fail_at, "--format", fmt,
                                               *extra)
                        self.assertEqual(code, 2, err)
                        one_error_line(self, err, "could not write the report",
                                       "No space left on device")

    def test_nothing_to_verify_is_a_report_too(self):
        tmp, base = make_pr_repo()
        err = io.StringIO()
        with redirect_stdout(FullDisk()), redirect_stderr(err):
            code = cli_mod.main(["--root", tmp, "check", "--base", "HEAD",
                                 "--skip-gates"])
        self.assertEqual(code, 2)
        one_error_line(self, err.getvalue(), "could not write the report")

    @unittest.skipUnless(os.name == "posix" and os.path.exists("/dev/full")
                         and stat.S_ISCHR(os.stat("/dev/full").st_mode),
                         "needs the /dev/full device")
    def test_the_device_that_is_always_full(self):
        tmp, base = make_pr_repo()
        for fmt in ("human", "json"):
            with self.subTest(fmt=fmt), open("/dev/full", "wb") as full:
                r = run_cli(["--root", tmp, "check", "--base", base,
                             "--skip-gates", "--format", fmt], stdout=full)
                err = r.stderr.decode("utf-8", "replace")
                # 2, not the traceback's 1 and not the 120 of a flush that
                # fails a second time when the interpreter exits
                self.assertEqual(r.returncode, 2, err)
                one_error_line(self, err, "could not write the report",
                               "No space left on device")

    def test_a_closed_pipe_is_still_not_an_error(self):
        # the reader that went away (| head -1) never changes the verdict
        tmp, base = make_pr_repo()

        class Gone(FullDisk):
            def _full(self):
                raise BrokenPipeError(errno.EPIPE, "Broken pipe")
        err = io.StringIO()
        with redirect_stdout(Gone()), redirect_stderr(err):
            code = cli_mod.main(["--root", tmp, "check", "--base", base,
                                 "--skip-gates", "--min-score", "1"])
        self.assertEqual((code, err.getvalue()), (1, ""))

    def test_the_action_sets_its_exit_code_and_stops_with_2(self):
        tmp, base = make_pr_repo()
        out_file = os.path.join(tempfile.mkdtemp(prefix="prv-r7-"), "output")
        env = {"PR_VERIFY_ROOT": tmp, "PR_VERIFY_BASE": base,
               "PR_VERIFY_SKIP_GATES": "true", "GITHUB_OUTPUT": out_file}
        err = io.StringIO()
        with redirect_stdout(FullDisk()), redirect_stderr(err):
            code = action_mod.main(environ=env)
        self.assertEqual(code, 2)
        one_error_line(self, err.getvalue(), "could not write the report")
        with open(out_file, encoding="utf-8") as f:
            written = dict(line.split("=", 1) for line in f.read().split())
        self.assertEqual(written["exit-code"], "2")


class TestTheReadmeIsTrueAboutExit2(unittest.TestCase):
    def test_it_names_the_report_that_cannot_be_written(self):
        readme = " ".join(_read("README.md").split())
        self.assertIn("a report that cannot be written (`pr-verify check > "
                      "/dev/full`: `error: could not write the report: No "
                      "space left on device`)", readme)

    def test_it_says_what_happens_when_stderr_is_the_full_one(self):
        readme = " ".join(_read("README.md").split())
        self.assertIn("If it is stderr that cannot take the line (`2> "
                      "/dev/full`), the line is lost and the exit status is "
                      "still 2.", readme)

    def test_the_message_is_the_one_the_readme_shows(self):
        tmp, base = make_pr_repo()
        err = io.StringIO()
        with redirect_stdout(FullDisk()), redirect_stderr(err):
            cli_mod.main(["--root", tmp, "check", "--base", base,
                          "--skip-gates"])
        self.assertEqual(err.getvalue().strip(),
                         "error: could not write the report: No space left "
                         "on device")


class TestAStderrThatCannotTakeTheMessage(unittest.TestCase):
    """The messages go to stderr, which can be a file on a full disk too.
    There is nowhere else to say so: the text is lost, the exit status that
    goes with it is not."""

    def test_an_error_is_still_exit_2(self):
        for fail_at in ("flush", "write"):
            with self.subTest(at=fail_at):
                tmp, base = make_pr_repo()
                with redirect_stdout(io.StringIO()), \
                        redirect_stderr(FullDisk(fail_at)):
                    code = cli_mod.main(["--root", tmp, "check",
                                         "--base", "no-such-ref"])
                self.assertEqual(code, 2)

    def test_outside_a_repository(self):
        tmp = tempfile.mkdtemp(prefix="prv-r7-")
        with redirect_stdout(io.StringIO()), redirect_stderr(FullDisk()):
            with self.assertRaises(SystemExit) as cm:
                cli_mod.main(["--root", tmp, "check"])
        self.assertEqual(cm.exception.code, 2)

    def test_git_that_is_not_there(self):
        tmp = new_repo()
        missing = FileNotFoundError(errno.ENOENT, "No such file or directory",
                                    "git")
        with mock.patch.object(subprocess, "run", side_effect=missing), \
                redirect_stdout(io.StringIO()), redirect_stderr(FullDisk()):
            with self.assertRaises(SystemExit) as cm:
                cli_mod.main(["--root", tmp, "init"])
        self.assertEqual(cm.exception.code, 2)

    def test_a_usage_error_is_still_exit_2(self):
        with redirect_stdout(io.StringIO()), redirect_stderr(FullDisk()):
            try:
                code = cli_mod.main(["check", "--min-score", "500"])
            except SystemExit as e:
                code = e.code
        self.assertEqual(code, 2)

    def test_a_warning_that_cannot_be_said_does_not_stop_the_run(self):
        tmp, base = repo_with_config("gate: x\n")
        out = io.StringIO()
        with redirect_stdout(out), redirect_stderr(FullDisk()):
            code = cli_mod.main(["--root", tmp, "check", "--base", base,
                                 "--skip-gates", "--format", "json"])
        self.assertEqual(code, 0)
        self.assertIn("risk", json.loads(out.getvalue()))

    @unittest.skipUnless(os.name == "posix" and os.path.exists("/dev/full")
                         and stat.S_ISCHR(os.stat("/dev/full").st_mode),
                         "needs the /dev/full device")
    def test_the_device_that_is_always_full(self):
        tmp, base = make_pr_repo()
        with open("/dev/full", "wb") as full:
            r = run_cli(["--root", tmp, "check", "--base", "no-such-ref"],
                        stderr=full)
        # 2, not the traceback's 1 and not the 120 of a flush that fails a
        # second time when the interpreter exits
        self.assertEqual(r.returncode, 2)
        self.assertEqual(r.stdout, b"")


class TestAnyOtherOutputThatFails(unittest.TestCase):
    def test_init_cannot_say_what_it_did(self):
        tmp = new_repo()
        err = io.StringIO()
        with redirect_stdout(FullDisk()), redirect_stderr(err):
            code = cli_mod.main(["--root", tmp, "init"])
        self.assertEqual(code, 2)
        one_error_line(self, err.getvalue(), "No space left on device")

    def test_version_into_a_full_disk(self):
        err = io.StringIO()
        with redirect_stdout(FullDisk()), redirect_stderr(err):
            code = cli_mod.main(["--version"])
        self.assertEqual(code, 2)
        one_error_line(self, err.getvalue(), "No space left on device")

    def test_help_and_usage_errors_keep_their_exit_codes(self):
        for argv, status in ((["--help"], 0), (["--version"], 0),
                             (["check", "--format", "xml"], 2), ([], 2)):
            with self.subTest(argv=argv):
                with redirect_stdout(io.StringIO()), \
                        redirect_stderr(io.StringIO()):
                    with self.assertRaises(SystemExit) as cm:
                        cli_mod.main(argv)
                self.assertEqual(cm.exception.code, status)


# ---------------------------------------------------------------------
# V3 - a setting nobody reads

def repo_with_config(text):
    """(repo, base): make_pr_repo, with .pr-verify.yaml = text at the base."""
    tmp, old_base = make_pr_repo()
    return tmp, commit_at_new_base(tmp, old_base,
                                   {".pr-verify.yaml": text})


def run_check(tmp, base, *extra):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = cli_mod.main(["--root", tmp, "check", "--base", base,
                             "--skip-gates", *extra])
    return code, out.getvalue(), err.getvalue()


def warnings_of(err):
    return [line for line in err.splitlines() if line.strip()]


class TestUnknownSettings(unittest.TestCase):
    def test_a_misspelt_key_is_named_with_the_one_it_looks_like(self):
        for wrong, right in (("gate", "gates"),
                             ("risk_treshold", "risk_threshold"),
                             ("agent_marker", "agent_markers"),
                             ("sensitive_path", "sensitive_paths"),
                             ("timeouts", "timeout"),
                             ("markers", "agent_markers"),
                             ("threshold", "risk_threshold"),
                             ("Gates", "gates"),
                             ("RISK_THRESHOLD", "risk_threshold")):
            with self.subTest(key=wrong):
                tmp, base = repo_with_config(f"{wrong}:\n  - x\n")
                code, out, err = run_check(tmp, base, "--format", "json")
                self.assertEqual(code, 0)
                json.loads(out)                    # stdout is still JSON
                self.assertEqual(
                    warnings_of(err),
                    [f"warning: .pr-verify.yaml at {base}: unknown setting "
                     f"{wrong!r} is ignored (did you mean {right!r}?)"])

    def test_a_key_that_looks_like_nothing_is_named_without_a_guess(self):
        tmp, base = repo_with_config("banana: 1\n")
        code, out, err = run_check(tmp, base)
        self.assertEqual(
            warnings_of(err),
            [f"warning: .pr-verify.yaml at {base}: unknown setting "
             f"'banana' is ignored"])

    def test_one_line_for_each_unknown_key_in_the_order_of_the_file(self):
        tmp, base = repo_with_config(
            "gate: x\nrisk_threshold: 70\nbanana: 1\ntimeout: 5\n"
            "risk_treshold: 3\n")
        code, out, err = run_check(tmp, base)
        self.assertEqual(len(warnings_of(err)), 3, err)
        self.assertIn("'gate'", warnings_of(err)[0])
        self.assertIn("'banana'", warnings_of(err)[1])
        self.assertIn("'risk_treshold'", warnings_of(err)[2])

    def test_the_run_goes_on_exactly_as_before(self):
        # the gate that would fail, spelt wrongly, still does not run ...
        wrong = f"gate:\n  - {yaml_str(FAIL_GATE)}\n"
        tmp, base = repo_with_config(wrong)
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = cli_mod.main(["--root", tmp, "check", "--base", base])
        self.assertEqual(code, 0)
        self.assertIn("none configured", out.getvalue())
        self.assertEqual(len(warnings_of(err.getvalue())), 1)
        # ... and spelt right, it does, with nothing said
        tmp, base = repo_with_config(f"gates:\n  - {yaml_str(FAIL_GATE)}\n")
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = cli_mod.main(["--root", tmp, "check", "--base", base])
        self.assertEqual((code, err.getvalue()), (1, ""))

    def test_the_other_settings_of_the_file_are_still_used(self):
        tmp, base = repo_with_config("risk_treshold: 1\nrisk_threshold: 10\n")
        code, out, err = run_check(tmp, base, "--format", "json")
        self.assertEqual(json.loads(out)["min_score"], 10)
        self.assertEqual(code, 1)           # the fixture scores 57

    def test_a_file_with_only_known_settings_says_nothing(self):
        for text in (config_mod.example_config(),
                     "agent_markers: [claude]\nsensitive_paths: []\n"
                     "gates: []\nrisk_threshold: 60\ntimeout: 30\n",
                     ""):
            with self.subTest(text=text[:30]):
                tmp, base = repo_with_config(text)
                code, out, err = run_check(tmp, base)
                self.assertEqual(err, "")

    def test_no_config_at_the_base_says_nothing(self):
        tmp, base = make_pr_repo()
        code, out, err = run_check(tmp, base)
        self.assertEqual(err, "")

    def test_the_worktree_copy_is_not_read_so_not_warned_about(self):
        tmp, base = make_pr_repo()
        with open(os.path.join(tmp, ".pr-verify.yaml"), "w",
                  encoding="utf-8") as f:
            f.write("gate: x\n")
        code, out, err = run_check(tmp, base)
        self.assertEqual(err, "")

    def test_the_action_warns_too(self):
        tmp, base = repo_with_config("gate: x\n")
        env = {"PR_VERIFY_ROOT": tmp, "PR_VERIFY_BASE": base,
               "PR_VERIFY_SKIP_GATES": "true"}
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = action_mod.main(environ=env)
        self.assertEqual(code, 0)
        self.assertEqual(len(warnings_of(err.getvalue())), 1, err.getvalue())

    def test_load_reports_through_the_function_it_is_given(self):
        tmp, base = repo_with_config("gate: x\nbanana: 1\n")
        said = []
        cfg = config_mod.load(tmp, base, warn=said.append)
        self.assertEqual(len(said), 2)
        self.assertEqual(cfg["gates"], [])
        self.assertNotIn("gate", cfg)
        # without one it is silent, and unchanged
        self.assertEqual(config_mod.load(tmp, base), cfg)

    def test_a_key_that_is_not_text_is_named_too(self):
        tmp, base = repo_with_config("1: x\ntrue: y\n")
        said = []
        config_mod.load(tmp, base, warn=said.append)
        self.assertEqual(len(said), 2, said)

    def test_the_readme_names_the_settings_and_the_warning(self):
        readme = " ".join(_read("README.md").split())
        for key in config_mod.DEFAULTS:
            self.assertIn("`" + key + "`", readme)
        self.assertIn("warning: .pr-verify.yaml at <base>: unknown setting "
                      "'gate' is ignored (did you mean 'gates'?)", readme)


# ---------------------------------------------------------------------
# V4 - what "who removed this line" costs

def agent_commits_over_files(commits, files):
    """(repo, base): a base of `files` files of 8 lines, then `commits`
    agent commits, each rewriting its own line of every file."""
    tmp = tempfile.mkdtemp(prefix="prv-r7-")
    git(tmp, "init", "-qb", "main")
    names = [f"mod{i}.py" for i in range(files)]

    def body(version):
        return "".join(f"line_{k} = {version.get(k, k)}\n" for k in range(8))

    commit_as(tmp, *HUMAN, "base", {name: body({}) for name in names})
    base = subprocess.run(["git", "-C", tmp, "rev-parse", "HEAD"],
                          capture_output=True, text=True, encoding="utf-8",
                          check=True).stdout.strip()
    version = {}
    for c in range(commits):
        version[c] = 100 + c
        commit_as(tmp, *AGENT, f"change {c}\n\nCo-authored-by: Claude",
                  {name: body(version) for name in names})
    return tmp, base


class TestWhatTheRemovalBlameCosts(unittest.TestCase):
    def blame_calls(self, tmp, base):
        """The `git blame ^base <parent>` calls analyze makes."""
        calls = []
        real = prov_mod._git

        def spy(root, *args, **kw):
            if args[:1] == ("blame",) and f"^{base}" in args:
                calls.append(args)
            return real(root, *args, **kw)

        with mock.patch.object(prov_mod, "_git", spy):
            result = prov_mod.analyze(tmp, base, "HEAD", ["claude"])
        return calls, result

    def test_one_blame_for_each_agent_commit_and_file_and_none_is_shared(self):
        tmp, base = agent_commits_over_files(commits=4, files=2)
        calls, result = self.blame_calls(tmp, base)
        # the first commit starts at the base and needs no question; each
        # of the other three asks about both files, at its own parent
        self.assertEqual(len(calls), 3 * 2, calls)
        parents = {args[args.index(f"^{base}") + 1] for args in calls}
        self.assertEqual(len(parents), 3)
        # ... and the answers are the right ones: every rewritten line was
        # the base's, and each is credited to the agent
        for name in ("mod0.py", "mod1.py"):
            self.assertEqual(result[name].agent_removed, 4)

    def test_a_commit_that_starts_at_the_base_asks_nothing(self):
        tmp, base = agent_commits_over_files(commits=1, files=3)
        calls, result = self.blame_calls(tmp, base)
        self.assertEqual(calls, [])
        self.assertEqual(result["mod2.py"].agent_removed, 1)

    def test_the_readme_states_it(self):
        text = _read("README.md")
        limits = " ".join(text.split("## Honest limits")[1].split("## Windows")[0]
                          .split())
        for said in ("one `git blame` for each agent commit and each file it "
                     "took lines out of",
                     "the calls share nothing",
                     "per call, not for the whole run"):
            self.assertIn(said, limits)


# ---------------------------------------------------------------------
# V5 - the tests run from the source distribution

class TestSourceDistribution(unittest.TestCase):
    """The tests are part of the sdist, so they must find what they read
    there: setuptools ships the package, the README, the licence and
    tests/test*.py by itself, but not the helper module the tests import,
    the action's files, nor the CI workflow. MANIFEST.in names them."""

    #: files the test suite opens or runs that are not in an sdist by default
    READ_BY_THE_TESTS = (".github/workflows/ci.yml", "action.yml",
                         "run_action.py")

    def manifest(self):
        lines = (ln.strip() for ln in _read("MANIFEST.in").splitlines())
        return [ln.split() for ln in lines if ln and not ln.startswith("#")]

    def test_manifest_ships_what_the_tests_read(self):
        included = {args[1] for args in self.manifest()
                    if args[0] == "include" and len(args) == 2}
        for path in self.READ_BY_THE_TESTS:
            with self.subTest(path=path):
                self.assertIn(path, included)
                self.assertTrue(os.path.isfile(os.path.join(REPO, path)))

    def test_every_module_under_tests_goes_in(self):
        # tests/fixture.py (imported by nine modules) and tests/__init__.py
        # are not called test*.py
        self.assertIn(["recursive-include", "tests", "*.py"], self.manifest())
        for name in ("fixture.py", "__init__.py"):
            self.assertTrue(os.path.isfile(os.path.join(REPO, "tests", name)))

    def test_every_line_of_the_manifest_names_something_that_exists(self):
        # a misspelt path is skipped by setuptools with a warning nobody reads
        for args in self.manifest():
            with self.subTest(line=" ".join(args)):
                self.assertIn(args[0], ("include", "recursive-include"))
                if args[0] == "include":
                    self.assertTrue(os.path.isfile(
                        os.path.join(REPO, *args[1].split("/"))))
                else:
                    self.assertTrue(os.path.isdir(
                        os.path.join(REPO, *args[1].split("/"))))


# ---------------------------------------------------------------------
# V6 - two mutants that survived

def numbered(*ks):
    return "".join(f"line_{k} = {k}\n" for k in ks)


def rev_parse(tmp):
    return subprocess.run(["git", "-C", tmp, "rev-parse", "HEAD"],
                          capture_output=True, text=True, encoding="utf-8",
                          check=True).stdout.strip()


class TestTheRemovalCreditIsBoundedByTheRemovals(unittest.TestCase):
    def test_a_line_a_human_puts_back_is_not_counted_for_the_agent(self):
        # the agent takes out lines 1-3 of the base; a human puts line 1
        # back. The diff of the PR removes two lines, so the agent can have
        # removed two of them, not three.
        tmp = tempfile.mkdtemp(prefix="prv-r7-")
        git(tmp, "init", "-qb", "main")
        commit_as(tmp, *HUMAN, "base", {"mod.py": numbered(*range(6))})
        base = rev_parse(tmp)
        commit_as(tmp, *AGENT, "tidy up\n\nCo-authored-by: Claude",
                  {"mod.py": numbered(*range(3, 6))})
        commit_as(tmp, *HUMAN, "that one was needed",
                  {"mod.py": numbered(0, *range(3, 6))})
        code, out, err = run_check(tmp, base, "--format", "json")
        data = json.loads(out)
        f = data["files"]["mod.py"]
        self.assertEqual((f["added"], f["removed"]), (0, 2))
        self.assertEqual(f["agent_removed"], 2)
        self.assertTrue(data["risk"]["factors"]["agent_share"]["detail"]
                        .startswith("2/2 changed lines agent-authored (100%)"),
                        data["risk"]["factors"]["agent_share"])

    def test_the_same_when_the_agent_does_not_start_at_the_base(self):
        # a human commit comes first, so the agent's removals are looked up
        # with a blame, not taken from the base as they are
        tmp = tempfile.mkdtemp(prefix="prv-r7-")
        git(tmp, "init", "-qb", "main")
        commit_as(tmp, *HUMAN, "base", {"mod.py": numbered(*range(6))})
        base = rev_parse(tmp)
        commit_as(tmp, *HUMAN, "one more",
                  {"mod.py": numbered(*range(6), 6)})
        commit_as(tmp, *AGENT, "tidy up\n\nCo-authored-by: Claude",
                  {"mod.py": numbered(*range(3, 7))})
        commit_as(tmp, *HUMAN, "that one was needed",
                  {"mod.py": numbered(0, *range(3, 7))})
        code, out, err = run_check(tmp, base, "--format", "json")
        f = json.loads(out)["files"]["mod.py"]
        self.assertEqual((f["added"], f["removed"], f["agent_removed"]),
                         (1, 2, 2))


@unittest.skipIf(os.name == "nt", "a file name cannot hold ':' on Windows")
class TestAFileNamedLikePathspecSyntax(unittest.TestCase):
    """`:x` as a pathspec means the file x. The commits that took lines out
    of a file are looked up by its name, so the name goes in as a literal."""

    def test_the_agent_that_edited_colon_x_is_found_through_its_name(self):
        tmp = tempfile.mkdtemp(prefix="prv-r7-")
        git(tmp, "init", "-qb", "main")
        commit_as(tmp, *HUMAN, "base", {":x": numbered(*range(6)),
                                        "x": numbered(*range(6))})
        base = rev_parse(tmp)
        commit_as(tmp, *HUMAN, "one more", {":x": numbered(*range(7)),
                                            "x": numbered(*range(7))})
        # the agent edits the file with the odd name, and not the other
        commit_as(tmp, *AGENT, "tidy up\n\nCo-authored-by: Claude",
                  {":x": numbered(*range(3, 7))})
        code, out, err = run_check(tmp, base, "--format", "json")
        files = json.loads(out)["files"]
        self.assertEqual(sorted(files), [":x", "x"])
        self.assertEqual((files[":x"]["removed"], files[":x"]["agent_removed"]),
                         (3, 3))
        self.assertEqual((files["x"]["removed"], files["x"]["agent_removed"],
                          files["x"]["label"]), (0, 0, "human"))


# ---------------------------------------------------------------------
# V8 - the README says what `init` does, and shows real output

class TestInitAndForce(unittest.TestCase):
    def test_init_will_not_overwrite_and_force_does(self):
        tmp = new_repo()
        path = os.path.join(tmp, ".pr-verify.yaml")
        with open(path, "w", encoding="utf-8", newline="\n") as f:
            f.write("risk_threshold: 12\n")
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = cli_mod.main(["--root", tmp, "init"])
        self.assertEqual(code, 2)
        self.assertIn("exists (use --force)", out.getvalue())
        with open(path, encoding="utf-8") as f:
            self.assertEqual(f.read(), "risk_threshold: 12\n")
        out = io.StringIO()
        with redirect_stdout(out), redirect_stderr(io.StringIO()):
            code = cli_mod.main(["--root", tmp, "init", "--force"])
        self.assertEqual(code, 0)
        with open(path, encoding="utf-8") as f:
            self.assertEqual(f.read().replace("\r\n", "\n"),
                             config_mod.example_config())

    def test_outside_a_repository_check_exits_2_and_init_writes_its_file(self):
        tmp = tempfile.mkdtemp(prefix="prv-r7-")
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            with self.assertRaises(SystemExit) as cm:
                cli_mod.main(["--root", tmp, "check"])
        self.assertEqual(cm.exception.code, 2)
        self.assertTrue(err.getvalue().startswith("error: "), err.getvalue())
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = cli_mod.main(["--root", tmp, "init"])
        self.assertEqual((code, err.getvalue()), (0, ""))
        self.assertTrue(os.path.isfile(os.path.join(tmp, ".pr-verify.yaml")))

    def test_help_says_what_force_is_for(self):
        out = io.StringIO()
        with redirect_stdout(out), redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as cm:
                cli_mod.main(["init", "--help"])
        self.assertEqual(cm.exception.code, 0)
        text = " ".join(out.getvalue().split())
        self.assertIn("--force Overwrite a .pr-verify.yaml that is already "
                      "there", text)

    def test_the_readme_names_force_and_what_happens_without_it(self):
        readme = " ".join(_read("README.md").split())
        self.assertIn("`pr-verify init --force`", readme)
        self.assertIn("will not overwrite a `.pr-verify.yaml` that is already "
                      "there (it says so and exits 2)", readme)


class TestTheExampleOutputIsReal(unittest.TestCase):
    def test_it_is_what_the_fixture_prints(self):
        tmp, base = make_pr_repo()
        git(tmp, "checkout", "-qb", "pr")
        git(tmp, "branch", "-f", "main", base)
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = cli_mod.main(["--root", tmp, "check"])
        self.assertEqual((code, err.getvalue()), (0, ""))
        section = _read("README.md").split("## Example output\n", 1)[1]
        example = section.split("```\n")[1]
        self.assertEqual(example, out.getvalue().replace("\r\n", "\n"))

    def test_the_readme_says_where_it_comes_from(self):
        readme = " ".join(_read("README.md").split())
        self.assertIn("`make_pr_repo()` in `tests/fixture.py`", readme)
        self.assertIn("A test runs it again and compares", readme)


# ---------------------------------------------------------------------
# V7 - the CI token can only read

class TestTheWorkflowTokenCanOnlyRead(unittest.TestCase):
    def test_ci_asks_for_contents_read_and_nothing_else(self):
        lines = [ln.rstrip() for ln in
                 _read(".github/workflows/ci.yml").splitlines()]
        # at the top level (no indent), as a block of its own
        self.assertIn("permissions:", lines)
        at = lines.index("permissions:")
        self.assertEqual(lines[at + 1], "  contents: read")
        rest = lines[at + 2:]
        self.assertTrue(not rest or not rest[0].startswith(" "), rest[:1])

    def test_no_job_widens_it(self):
        text = _read(".github/workflows/ci.yml")
        self.assertEqual(text.count("permissions:"), 1)


if __name__ == "__main__":
    unittest.main()
