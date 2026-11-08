"""Synapse round 1 (0.2.0):

S1  --format markdown, and the Action's job summary ($GITHUB_STEP_SUMMARY):
    every name the PR controls is shown literally (code spans, fenced
    blocks), never as a link, an image, HTML or a table cell of its own;
    the report stays under its size limit for a huge PR.
S2  a failed gate says why: the end of its output under it in the human
    report, in a collapsed block in the Markdown one.
S3  extra_agent_markers / extra_sensitive_paths extend the defaults.
S4  an empty agent_markers fails closed (exit 2), it does not score every
    line as human.
S5  Copilot's coding agent is recognised by its Agent-Logs-Url trailer.
"""

import io
import json
import os
import re
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

from pr_verify import action as action_mod
from pr_verify import cli as cli_mod
from pr_verify import config as config_mod
from pr_verify import markers as markers_mod
from pr_verify import mdreport

from fixture import (PY, commit_as, commit_at_new_base, gate, git,
                     make_pr_repo, yaml_str)

try:                                    # optional: a real GFM renderer
    import cmarkgfm
    from cmarkgfm.cmark import Options as _CmarkOptions
except ImportError:                     # the suite stays stdlib-only
    cmarkgfm = None
#: Set in this repo's CI on the job that installs cmarkgfm: there the GFM
#: tests must run, a missing renderer is a failure and not a skip.
REQUIRE_GFM = os.environ.get("PR_VERIFY_REQUIRE_GFM") == "1"


def render_gfm(test, md):
    if cmarkgfm is None:
        if REQUIRE_GFM:
            test.fail("PR_VERIFY_REQUIRE_GFM=1 but cmarkgfm is not installed")
        test.skipTest("cmarkgfm not installed (optional)")
    return cmarkgfm.github_flavored_markdown_to_html(
        md, options=_CmarkOptions.CMARK_OPT_UNSAFE)

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def main(*argv):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = cli_mod.main(list(argv))
    return code, out.getvalue(), err.getvalue()


def with_config(text):
    tmp, old_base = make_pr_repo()
    return tmp, commit_at_new_base(tmp, old_base, {".pr-verify.yaml": text})


#: A code span with any fence: what mdreport.code() writes.
_SPAN = re.compile(r"(`+) .*? \1")


def outside_code(md: str) -> str:
    """The Markdown with every code span and fenced block taken out: what is
    left is what GitHub would read as Markdown."""
    kept, fence = [], None
    for line in md.split("\n"):
        if fence:
            if line == fence:
                fence = None
            continue
        m = re.match(r"^(`{3,})text$", line)
        if m:
            fence = m.group(1)
            continue
        kept.append(_SPAN.sub("", line))
    return "\n".join(kept)


HOSTILE_NAMES = [
    "app/![x](https://tracker.example/p.png).py",
    "app/[click](https://evil.example).py",
    "app/<img src=x onerror=alert(1)>.py",
    "app/a|b|c.py",
    "app/x\\|![i](https://e.example/i.png)|.py",
    "app/``` fence.py",
    "app/` tick.py",
    "app/**bold** _em_ ~~del~~.py",
    "app/www.evil.example.py",
    # the extension itself is the payload (review finding 1): a dotless
    # decimal IP needs no . or / -- and the not-scanned note names it
    "app/p.![i](https:1572395042)",
    "app/q.[Signed off by security](https:1572395042)",
    "app/r.<img src=https:1572395042>",
]


def hostile_repo():
    """A PR whose agent commit adds a file under each HOSTILE_NAMES name,
    authored by a bot whose name is Markdown too."""
    tmp = tempfile.mkdtemp(prefix="prv-s1-")
    git(tmp, "init", "-qb", "main")
    commit_as(tmp, "Alex Dev", "alex@example.com", "base",
              {"app/core.py": "x = 1\n"})
    git(tmp, "branch", "base")
    files = {}
    for name in HOSTILE_NAMES:
        if os.name == "nt" and any(c in name for c in '<>|*'):
            continue          # not a legal file name on Windows
        files[name] = "y = 2\n"
    commit_as(tmp, "evil-bot [x](https://e.example)", "bot@example.com",
              "add", files)
    return tmp, sorted(files)


class TestMarkdownCodeSpan(unittest.TestCase):
    def test_a_span_cannot_be_closed_from_inside(self):
        for text in ("plain", "`", "``", "a ` b `` c", "```", " lead",
                     "trail ", "", "`start", "end`"):
            with self.subTest(text):
                span = mdreport.code(text)
                fence = re.match(r"`+", span).group(0)
                inner = span[len(fence) + 1:-len(fence) - 1]
                self.assertTrue(span.endswith(" " + fence))
                self.assertNotIn(fence, inner)
                self.assertEqual(inner, text)

    def test_controls_and_newlines_are_escaped(self):
        span = mdreport.code("a\nb\rc\x1b[31md\u202ee")
        self.assertNotIn("\n", span)
        self.assertNotIn("\r", span)
        self.assertNotIn("\x1b", span)
        self.assertNotIn("\u202e", span)
        self.assertIn("\\x0a", span)
        self.assertIn("\\x1b", span)

    def test_a_table_cell_cannot_be_split(self):
        for text in ("a|b", "a\\|b", "a\\\\|b", "|", "\\"):
            with self.subTest(text):
                span = mdreport.code(text, table=True)
                # every | is escaped, and no backslash is left that could
                # pair with one
                self.assertNotRegex(span, r"(?<!\\)\|")
                self.assertNotIn("\\\\", span)

    def test_a_long_name_is_shortened(self):
        span = mdreport.code("a" * 10_000)
        self.assertLess(len(span), mdreport.MAX_NAME + 10)
        self.assertIn("…", span)

    def test_a_fenced_block_cannot_be_closed_from_inside(self):
        text = "ok\n```\n````\n~~~\n</details>\n![x](https://e.example/p)\n"
        lines = mdreport.fenced(text)
        fence = lines[-1]
        self.assertEqual(lines[0], fence + "text")
        self.assertNotIn(fence, lines[1:-1])
        self.assertGreater(len(fence), 4)

    def test_windows_line_ends_are_line_ends(self):
        lines = mdreport.fenced("one\r\ntwo\r\n")
        self.assertEqual(lines[1:3], ["one", "two"])

    def test_a_long_output_keeps_its_end(self):
        lines = mdreport.fenced("\n".join(f"line {i}" for i in range(500)))
        self.assertIn("line 499", lines)
        self.assertNotIn("line 0", lines)
        self.assertLessEqual(len(lines), mdreport.MAX_GATE_LINES + 3)


class TestMarkdownReport(unittest.TestCase):
    def test_same_verdict_and_numbers_as_json(self):
        tmp, base = make_pr_repo()
        for min_score in ("57", "70"):
            with self.subTest(min_score):
                code_md, md, _ = main("--root", tmp, "check", "--base", base,
                                      "--format", "markdown", "--min-score",
                                      min_score)
                code_js, js, _ = main("--root", tmp, "check", "--base", base,
                                      "--format", "json", "--min-score",
                                      min_score)
                self.assertEqual(code_md, code_js)
                data = json.loads(js)
                self.assertIn(f"risk {data['risk']['score']}/100", md)
                self.assertIn("❌ fail" if code_md else "✅ pass", md)
                for name, fac in data["risk"]["factors"].items():
                    self.assertIn(f"| {name} | {fac['points']} |", md)
                self.assertIn("` app/auth.py `", md)
                self.assertIn("pr-verify " + cli_mod.VERSION, md)

    def test_hostile_names_are_never_markdown(self):
        tmp, names = hostile_repo()
        code, md, err = main("--root", tmp, "check", "--base", "base",
                             "--format", "markdown", "--fail-on", "never")
        self.assertEqual(code, 0, err)
        rest = outside_code(md)
        for bad in ("](", "<img", "<a ", "**bold**", "~~del~~", "www.evil",
                    "https:1572395042"):
            self.assertNotIn(bad, rest)
        # the not-scanned note is there, with the extension quoted
        self.assertIn("` .![i](https:1572395042) ` files are not scanned", md)
        # every table row keeps its four cells
        for line in md.splitlines():
            if line.startswith("| agent |"):
                cells = re.split(r"(?<!\\)\|", line)
                self.assertEqual(len(cells), 6, line)
        self.assertNotIn("\n::", md)

    def test_hostile_names_render_as_code_in_gfm(self):
        tmp, names = hostile_repo()
        _, md, _ = main("--root", tmp, "check", "--base", "base",
                        "--format", "markdown", "--fail-on", "never")
        html = render_gfm(self, md)
        self.assertNotIn("1572395042\"", html)      # in no href or src
        self.assertNotIn("<img", html)
        self.assertNotIn("<a ", html)
        self.assertNotIn("<strong>bold", html)
        self.assertNotIn("<del>", html)
        rows = [r for r in re.findall(r"<tr>(.*?)</tr>", html, re.S)
                if "<td>agent</td>" in r]
        self.assertEqual(len(rows), len(names))
        for row in rows:
            self.assertEqual(row.count("<td"), 4, row)

    def test_a_huge_pr_stays_under_the_limit(self):
        tmp = tempfile.mkdtemp(prefix="prv-s1-")
        git(tmp, "init", "-qb", "main")
        commit_as(tmp, "Alex Dev", "alex@example.com", "base",
                  {"seed.txt": "x\n"})
        git(tmp, "branch", "base")
        files = {f"pkg/{'d' * 40}/{i:04d}_{'n' * 60}.txt": "y\n"
                 for i in range(1500)}
        commit_as(tmp, "claude-bot", "claude-bot@example.com", "many", files)
        code, md, err = main("--root", tmp, "check", "--base", "base",
                             "--format", "markdown", "--skip-gates")
        self.assertLess(len(md), mdreport.MAX_CHARS, err)
        self.assertIn("1400 more file(s)", md)

    def test_nothing_to_verify(self):
        tmp, base = make_pr_repo()
        git(tmp, "checkout", "-q", base)
        code, md, _ = main("--root", tmp, "check", "--base", base,
                           "--format", "markdown")
        self.assertEqual(code, 0)
        self.assertIn("nothing to verify", md)


class TestNoSectionCanBeBlanked(unittest.TestCase):
    """Review finding 2: a PR must not be able to make the report drop the
    gate list, the files or the blast radius by making one entry huge."""

    def test_gate_output_that_grows_when_escaped(self):
        flood = gate(PY, "-c", "import sys; sys.stdout.write(chr(0x2028) * "
                               "1990); sys.exit(1)")
        tmp, base = with_config(
            "gates:\n" + "".join(f"  - {yaml_str(flood + ' #' + str(i))}\n"
                                 for i in range(5)))
        code, md, err = main("--root", tmp, "check", "--base", base,
                             "--format", "markdown")
        self.assertEqual(code, 1, err)
        self.assertLess(len(md), mdreport.MAX_CHARS)
        self.assertEqual(md.count("- **FAIL**"), 5)
        for heading in ("### Policy gates", "### Provenance",
                        "### Blast radius"):
            self.assertIn(heading, md)
        self.assertIn("` app/auth.py `", md)
        self.assertNotIn("The rest of this report was cut", md)
        for block in re.findall(r"<details>.*?</details>", md, re.S):
            self.assertLess(len(block), mdreport.MAX_BLOCK_CHARS + 200)

    def test_file_names_that_grow_when_escaped(self):
        tmp = tempfile.mkdtemp(prefix="prv-s1-")
        git(tmp, "init", "-qb", "main")
        commit_as(tmp, "Alex Dev", "alex@example.com", "base",
                  {"seed.txt": "x\n"})
        git(tmp, "branch", "base")
        files = {f"f{i:03d}" + "`" * 150 + ".md": "y\n" for i in range(150)}
        commit_as(tmp, "claude-bot", "claude-bot@example.com", "many", files)
        code, md, err = main("--root", tmp, "check", "--base", "base",
                             "--format", "markdown", "--skip-gates")
        self.assertLess(len(md), mdreport.MAX_CHARS, err)
        self.assertIn("### Blast radius", md)
        self.assertRegex(md, r"… \d+ more file\(s\) not shown here")
        # rows that are shown are whole rows
        rows = [line for line in md.splitlines() if line.startswith("| agent")]
        self.assertTrue(rows)
        for row in rows:
            self.assertTrue(row.endswith("|"), row[-40:])

    def test_fenced_block_is_capped_after_escaping(self):
        lines = mdreport.fenced("\u2028" * 1990 + "\n" + "`" * 1500)
        self.assertLess(sum(len(x) + 1 for x in lines),
                        mdreport.MAX_BLOCK_CHARS + 2 * mdreport.MAX_LINE)


class TestHideGateOutput(unittest.TestCase):
    """Review finding 3: gate output can be left out of what is posted."""

    def repo(self):
        return with_config("gates:\n  - " + yaml_str(gate(
            PY, "-c", "print('SECRET' + '_VALUE'); raise SystemExit(5)")) + "\n")

    def test_left_out_of_human_and_markdown_kept_in_json(self):
        tmp, base = self.repo()
        for fmt in ("human", "markdown"):
            with self.subTest(fmt):
                code, out, _ = main("--root", tmp, "check", "--base", base,
                                    "--format", fmt, "--hide-gate-output")
                self.assertEqual(code, 1)
                self.assertNotIn("SECRET_VALUE", out)
                self.assertIn("FAIL", out)
        _, md, _ = main("--root", tmp, "check", "--base", base,
                        "--format", "markdown", "--hide-gate-output")
        self.assertIn("(exit 5)", md)
        self.assertIn("`--hide-gate-output`", md)
        _, js, _ = main("--root", tmp, "check", "--base", base,
                        "--format", "json", "--hide-gate-output")
        self.assertIn("SECRET_VALUE", json.loads(js)["gates"][0]["output_tail"])

    def test_the_action_input_hides_it_from_the_summary(self):
        tmp, base = self.repo()
        summary = os.path.join(tempfile.mkdtemp(), "summary.md")
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = action_mod.main(environ={
                "PR_VERIFY_ROOT": tmp, "PR_VERIFY_BASE": base,
                "PR_VERIFY_HIDE_GATE_OUTPUT": "true",
                "GITHUB_STEP_SUMMARY": summary})
        self.assertEqual(code, 1)
        with open(summary, encoding="utf-8") as f:
            text = f.read()
        self.assertIn("**FAIL**", text)
        self.assertNotIn("SECRET_VALUE", text)
        self.assertNotIn("SECRET_VALUE", out.getvalue())


class TestFailedGateSaysWhy(unittest.TestCase):
    def failing_gate_repo(self):
        script = ("import sys; print('step one'); "
                  "print('AssertionError: expected 2 \\x1b[2J got 3'); "
                  "print('```'); sys.exit(4)")
        return with_config("gates:\n  - " + yaml_str(gate(PY, "-c", script))
                           + "\n")

    def test_the_human_report_shows_the_end_of_the_output(self):
        tmp, base = self.failing_gate_repo()
        code, out, _ = main("--root", tmp, "check", "--base", base)
        self.assertEqual(code, 1)
        self.assertIn("      | AssertionError: expected 2 \\x1b[2J got 3", out)
        self.assertNotIn("\x1b", out)

    def test_the_markdown_report_has_it_in_a_block(self):
        tmp, base = self.failing_gate_repo()
        code, md, _ = main("--root", tmp, "check", "--base", base,
                           "--format", "markdown")
        self.assertEqual(code, 1)
        self.assertIn("**❌ fail** - policy gate failed", md)
        self.assertIn("<summary>Output of gate 1 (exit 4)</summary>", md)
        self.assertIn("AssertionError: expected 2 \\x1b[2J got 3", md)
        self.assertIn("````text", md)       # longer than the ``` it printed

    def test_a_passing_gate_shows_no_output(self):
        tmp, base = with_config(
            "gates:\n  - " + yaml_str(gate(PY, "-c", "print('NO' + 'ISE')"))
            + "\n")
        code, out, _ = main("--root", tmp, "check", "--base", base)
        self.assertIn("[PASS]", out)
        self.assertNotIn("NOISE", out)


class TestActionJobSummary(unittest.TestCase):
    def env(self, tmp, base, summary, **extra):
        env = {"PR_VERIFY_ROOT": tmp, "PR_VERIFY_BASE": base,
               "PR_VERIFY_SKIP_GATES": "true", "GITHUB_STEP_SUMMARY": summary}
        env.update(extra)
        return env

    def run_action(self, env):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = action_mod.main(environ=env)
        return code, out.getvalue(), err.getvalue()

    def test_the_summary_is_the_markdown_report(self):
        tmp, base = make_pr_repo()
        summary = os.path.join(tempfile.mkdtemp(), "summary.md")
        code, out, _ = self.run_action(self.env(tmp, base, summary))
        self.assertEqual(code, 0)
        with open(summary, encoding="utf-8") as f:
            text = f.read()
        self.assertTrue(text.startswith("## PR Verify: risk 57/100"))
        self.assertIn("PR VERIFY", out)     # the log keeps the human report

    def test_a_check_that_cannot_run_says_so_in_the_summary(self):
        tmp, base = make_pr_repo()
        summary = os.path.join(tempfile.mkdtemp(), "summary.md")
        code, _, err = self.run_action(
            self.env(tmp, "no-such-ref-[x](https://e.example)", summary))
        self.assertEqual(code, 2)
        with open(summary, encoding="utf-8") as f:
            text = f.read()
        self.assertIn("could not run", text)
        self.assertNotIn("](", outside_code(text))

    def test_a_root_that_is_not_a_repository_says_so_in_the_summary(self):
        summary = os.path.join(tempfile.mkdtemp(), "summary.md")
        not_a_repo = tempfile.mkdtemp()
        with self.assertRaises(SystemExit) as cm:
            self.run_action(self.env(not_a_repo, "", summary))
        self.assertEqual(cm.exception.code, 2)
        with open(summary, encoding="utf-8") as f:
            self.assertIn("could not run", f.read())

    def test_a_report_that_cannot_be_written_is_not_a_pass_in_the_summary(self):
        # review finding 4: exit 2, so the summary must not say pass
        tmp, base = make_pr_repo()
        summary = os.path.join(tempfile.mkdtemp(), "summary.md")
        real = cli_mod.write_report
        cli_mod.write_report = lambda result, fmt: False
        try:
            code, _, _ = self.run_action(self.env(tmp, base, summary))
        finally:
            cli_mod.write_report = real
        self.assertEqual(code, 2)
        with open(summary, encoding="utf-8") as f:
            text = f.read()
        self.assertIn("could not run", text)
        self.assertIn("exit 2", text)
        self.assertNotIn("✅", text)

    def test_an_unwritable_summary_is_a_warning(self):
        tmp, base = make_pr_repo()
        missing = os.path.join(tempfile.mkdtemp(), "no", "such", "dir", "s.md")
        code, _, err = self.run_action(
            self.env(tmp, base, missing, PR_VERIFY_MIN_SCORE="57"))
        self.assertEqual(code, 1)           # the verdict stands
        self.assertIn("warning: could not write the job summary", err)
        self.assertNotIn("Traceback", err)


class TestExtraSettings(unittest.TestCase):
    def test_extra_markers_keep_the_defaults(self):
        tmp, old = make_pr_repo()
        base = commit_at_new_base(
            tmp, old, {".pr-verify.yaml": "extra_agent_markers:\n  - mybot\n"})
        commit_as(tmp, "mybot", "ci@example.com", "more",
                  {"app/extra.py": "z = 3\n"})
        code, out, err = main("--root", tmp, "check", "--base", base,
                              "--format", "json", "--skip-gates")
        data = json.loads(out)
        self.assertEqual(err, "")
        self.assertEqual(data["files"]["app/extra.py"]["agents"],
                         ["mybot (mybot)"])
        # the default `claude` marker still catches claude-bot
        self.assertEqual(data["files"]["app/auth.py"]["label"], "agent")
        cfg = config_mod.load(tmp, base)
        self.assertEqual(cfg["agent_markers"],
                         config_mod.DEFAULTS["agent_markers"] + ["mybot"])

    def test_extra_sensitive_paths_keep_the_defaults(self):
        tmp, old = make_pr_repo()
        base = commit_at_new_base(
            tmp, old, {".pr-verify.yaml":
                       'extra_sensitive_paths: ["app/views.py"]\n'})
        cfg = config_mod.load(tmp, base)
        self.assertIn("**/auth.*", cfg["sensitive_paths"])
        self.assertEqual(cfg["sensitive_paths"][-1], "app/views.py")
        code, out, _ = main("--root", tmp, "check", "--base", base,
                            "--format", "json", "--skip-gates")
        detail = json.loads(out)["risk"]["factors"]["sensitive"]["detail"]
        self.assertIn("app/auth.py", detail)
        self.assertIn("app/views.py", detail)

    def test_an_entry_already_there_is_not_repeated(self):
        tmp, base = with_config("extra_agent_markers: [claude, Claude]\n")
        cfg = config_mod.load(tmp, base)
        self.assertEqual(cfg["agent_markers"].count("claude"), 1)

    def test_extra_must_be_a_list(self):
        tmp, base = with_config("extra_agent_markers:\n  key: value\n")
        code, _, err = main("--root", tmp, "check", "--base", base)
        self.assertEqual(code, 2)
        self.assertIn("extra_agent_markers must be a list", err)


class TestNoMarkersFailsClosed(unittest.TestCase):
    def test_an_empty_marker_list_is_an_error(self):
        for text in ("agent_markers: []\n", 'agent_markers: [""]\n',
                     "agent_markers:\n", 'agent_markers: ["co-authored-by:"]\n',
                     'agent_markers: ["  ", "--"]\n'):
            with self.subTest(text):
                tmp, base = with_config(text)
                code, out, err = main("--root", tmp, "check", "--base", base,
                                      "--format", "json")
                self.assertEqual(code, 2)
                self.assertEqual(out, "")
                self.assertIn("agent_markers is empty", err)
                self.assertEqual(len(err.strip().splitlines()), 1, err)

    def test_extra_markers_alone_are_enough(self):
        tmp, base = with_config("agent_markers: []\n"
                                "extra_agent_markers: [claude]\n")
        code, out, err = main("--root", tmp, "check", "--base", base,
                              "--format", "json", "--skip-gates")
        self.assertIn(code, (0, 1), err)
        self.assertEqual(json.loads(out)["files"]["app/auth.py"]["label"],
                         "agent")


class TestNoSensitivePathsFailsClosed(unittest.TestCase):
    """Review finding 5: like the markers."""

    def test_an_empty_glob_list_is_an_error(self):
        for text in ("sensitive_paths: []\n", 'sensitive_paths: [" "]\n',
                     "sensitive_paths:\n"):
            with self.subTest(text):
                tmp, base = with_config(text)
                code, out, err = main("--root", tmp, "check", "--base", base,
                                      "--format", "json")
                self.assertEqual(code, 2)
                self.assertEqual(out, "")
                self.assertIn("sensitive_paths is empty", err)
                self.assertEqual(len(err.strip().splitlines()), 1, err)

    def test_extra_globs_alone_are_enough(self):
        tmp, base = with_config('sensitive_paths: []\n'
                                'extra_sensitive_paths: ["**/auth.*"]\n')
        code, out, err = main("--root", tmp, "check", "--base", base,
                              "--format", "json", "--skip-gates")
        self.assertIn(code, (0, 1), err)
        self.assertEqual(
            json.loads(out)["risk"]["factors"]["sensitive"]["points"], 20)


class TestCopilotAgentTrailer(unittest.TestCase):
    MARKERS = config_mod.DEFAULTS["agent_markers"]

    def test_agent_logs_url_names_copilot(self):
        body = ("Fix the parser\n\nAgent-Logs-Url: "
                "https://github.com/o/r/sessions/0000\n"
                "Co-authored-by: Alex Dev <alex@example.com>\n")
        self.assertEqual(markers_mod.match("Alex Dev", "alex@example.com",
                                           "Fix the parser", body,
                                           self.MARKERS), "copilot")

    def test_only_as_a_trailer_line(self):
        body = "See the Agent-Logs-Url: field of the other tool\n"
        self.assertIsNone(markers_mod.match("Alex Dev", "alex@example.com",
                                            "notes", body, self.MARKERS))

    def test_end_to_end(self):
        tmp, base = make_pr_repo()
        commit_as(tmp, "Alex Dev", "alex@example.com",
                  "Add helper\n\nAgent-Logs-Url: https://github.com/o/r/x\n",
                  {"app/helper.py": "def h():\n    return 1\n"})
        _, out, _ = main("--root", tmp, "check", "--base", base,
                         "--format", "json", "--skip-gates")
        self.assertEqual(json.loads(out)["files"]["app/helper.py"]["agents"],
                         ["Alex Dev (copilot)"])


class TestDocs(unittest.TestCase):
    def read(self, name):
        with open(os.path.join(REPO, name), encoding="utf-8") as f:
            return f.read()

    def test_readme_and_changelog(self):
        readme = self.read("README.md")
        for text in ("--format markdown", "GITHUB_STEP_SUMMARY",
                     "extra_agent_markers", "extra_sensitive_paths",
                     "Agent-Logs-Url"):
            self.assertIn(text, readme)
        self.assertIn(f"## {cli_mod.VERSION}", self.read("CHANGELOG.md"))

    def test_ci_runs_the_gfm_tests_somewhere(self):
        ci = self.read(".github/workflows/ci.yml")
        self.assertIn('pip install "cmarkgfm==', ci)
        self.assertIn("PR_VERIFY_REQUIRE_GFM:", ci)

    def test_versions_agree(self):
        pyproject = self.read("pyproject.toml")
        self.assertIn(f'version = "{cli_mod.VERSION}"', pyproject)


if __name__ == "__main__":
    unittest.main()
