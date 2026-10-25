"""action.yml must match the CLI (panel round 3): every input maps to a
real `pr-verify check` flag with the same default, the step's env wiring
matches the entry module, the outputs exist, and the entry command runs.
Parsed with the repo's own stdlib YAML subset parser."""

import importlib.util
import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout

from pr_verify import action as action_mod
from pr_verify import cli as cli_mod
from pr_verify import miniyaml

from fixture import make_pr_repo

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ACTION_YML = os.path.join(REPO, "action.yml")


def _load_action() -> dict:
    with open(ACTION_YML, encoding="utf-8") as f:
        return miniyaml.safe_load(f.read())


def _check_parser_defaults() -> dict:
    """flag -> default of the `check` subparser (plus the global --root)."""
    parser = cli_mod.build_parser()
    out = {}
    for act in parser._actions:
        for opt in act.option_strings:
            out[opt] = act.default
    sub = next(a for a in parser._actions
               if isinstance(a, type(parser._subparsers._group_actions[0])))
    check = sub.choices["check"]
    for act in check._actions:
        for opt in act.option_strings:
            out[opt] = act.default
    return out


class TestActionYml(unittest.TestCase):
    def setUp(self):
        self.action = _load_action()

    def test_runs_composite_with_entry_module(self):
        runs = self.action["runs"]
        self.assertEqual(runs["using"], "composite")
        step = runs["steps"][0]
        self.assertEqual(step["id"], "verify")
        self.assertEqual(step["shell"], "bash")
        # isolated python, started from the action's own directory (why:
        # test_round5_fixes.TestActionNeverRunsCheckoutCode)
        self.assertEqual(step["run"].strip(),
                         'python -I "$GITHUB_ACTION_PATH/run_action.py"')
        self.assertTrue(os.path.isfile(os.path.join(REPO, "run_action.py")))
        # the entry module exists and is importable
        self.assertIsNotNone(importlib.util.find_spec("pr_verify.action"))

    def test_every_input_maps_to_a_real_cli_flag(self):
        flags = _check_parser_defaults()
        inputs = self.action["inputs"]
        self.assertEqual(set(inputs),
                         set(action_mod.INPUTS) | set(action_mod.ACTION_ONLY),
                         "action.yml inputs and action.INPUTS disagree")
        for name, (env_var, flag, kind) in action_mod.INPUTS.items():
            self.assertIn(flag, flags, f"input {name!r} -> unknown flag {flag}")
            self.assertEqual(flag, f"--{name}",
                             "input name must be the flag without dashes")
            self.assertIn(f"--{name}", inputs[name]["description"],
                          f"input {name!r} description should name its flag")

    def test_input_defaults_match_cli_defaults(self):
        flags = _check_parser_defaults()
        inputs = self.action["inputs"]
        for name, (env_var, flag, kind) in action_mod.INPUTS.items():
            yml_default = inputs[name].get("default")
            cli_default = flags[flag]
            if kind == "flag":
                self.assertEqual(str(yml_default).lower(), str(bool(cli_default)).lower(),
                                 name)
            elif name == "root":
                self.assertEqual(yml_default, "", name)  # cwd at run time
            elif cli_default is None:
                self.assertEqual(yml_default, "", name)  # empty = unset
            else:
                self.assertEqual(yml_default, cli_default, name)
            self.assertFalse(inputs[name].get("required"), name)

    def test_step_env_wires_every_input(self):
        env = self.action["runs"]["steps"][0]["env"]
        for name, (env_var, flag, kind) in action_mod.INPUTS.items():
            self.assertEqual(env.get(env_var), "${{ inputs." + name + " }}",
                             env_var)
        for name, var in action_mod.ACTION_ONLY.items():
            self.assertEqual(env.get(var), "${{ inputs." + name + " }}", var)
        self.assertEqual(set(env), {v[0] for v in action_mod.INPUTS.values()}
                         | set(action_mod.ACTION_ONLY.values()))

    def test_outputs_declared(self):
        outputs = self.action["outputs"]
        self.assertEqual(set(outputs), set(action_mod.OUTPUTS))
        for name, spec in outputs.items():
            self.assertEqual(spec["value"],
                             "${{ steps.verify.outputs." + name + " }}")
            self.assertTrue(spec["description"])

    def test_readme_mentions_action(self):
        with open(os.path.join(REPO, "README.md"), encoding="utf-8") as f:
            readme = f.read()
        self.assertIn("action.yml", readme)
        self.assertNotIn(".github/workflows/pr-verify.yml", readme,
                         "README must not point at a file that does not exist")
        for name in (*action_mod.INPUTS, *action_mod.ACTION_ONLY):
            self.assertIn(name, readme)


class TestBuildArgv(unittest.TestCase):
    def test_empty_env_gives_cli_defaults(self):
        # the step summary is on by default, so the comment file is written
        self.assertEqual(action_mod.build_argv({"RUNNER_TEMP": "/rt"}),
                         ["check", "--comment-file", "/rt/pr-verify-comment.md"])
        self.assertEqual(action_mod.build_argv(
            {"RUNNER_TEMP": "/rt", "PR_VERIFY_STEP_SUMMARY": "false"}),
            ["check"])

    def test_values_and_flags(self):
        env = {"PR_VERIFY_BASE": "origin/main", "PR_VERIFY_HEAD": " HEAD ",
               "PR_VERIFY_FORMAT": "json", "PR_VERIFY_FAIL_ON": "never",
               "PR_VERIFY_MIN_SCORE": "55", "PR_VERIFY_SKIP_GATES": "true",
               "PR_VERIFY_ROOT": "/repo", "PR_VERIFY_STEP_SUMMARY": "false"}
        self.assertEqual(action_mod.build_argv(env), [
            "--root", "/repo", "check", "--base", "origin/main", "--head", "HEAD",
            "--format", "json", "--fail-on", "never", "--min-score", "55",
            "--skip-gates"])
        self.assertNotIn("--skip-gates",
                         action_mod.build_argv({"PR_VERIFY_SKIP_GATES": "false"}))
        # whatever build_argv emits must parse
        cli_mod.build_parser().parse_args(action_mod.build_argv(env))

    def test_end_to_end_writes_github_output(self):
        tmp, base = make_pr_repo()
        out_file = os.path.join(tempfile.mkdtemp(), "gh_output")
        env = {"PR_VERIFY_ROOT": tmp, "PR_VERIFY_BASE": base,
               "PR_VERIFY_FORMAT": "json", "PR_VERIFY_SKIP_GATES": "true",
               "PR_VERIFY_MIN_SCORE": "57", "GITHUB_OUTPUT": out_file}
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = action_mod.main(environ=env)
        self.assertEqual(code, 1)  # fixture scores 57 >= 57
        data = json.loads(buf.getvalue())
        self.assertEqual(data["risk"]["score"], 57)
        with open(out_file, encoding="utf-8") as f:
            outputs = dict(line.rstrip("\n").split("=", 1) for line in f if line.strip())
        self.assertEqual(outputs, {"score": "57", "band": "medium",
                                   "requires-review": "true", "exit-code": "1"})
        self.assertEqual(set(outputs), set(action_mod.OUTPUTS))


if __name__ == "__main__":
    unittest.main()
