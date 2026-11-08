# Round 5: gates, GitHub bots, the author line

Branch `expert-2`. Run on a Linux sandbox; nothing was run on Windows or macOS.

## How the review was done (honest)

No tool for starting independent sub-agents was used; one reviewer played the
four roles in turn and ran real commands for each. The findings are not an
independent second opinion.

## Specialists and what each found

| Role | Finding (command that proved it) |
|---|---|
| AppSec engineer | A gate (it runs the PR's code) inherited the whole environment, `GITHUB_TOKEN` included: `GITHUB_TOKEN=x pr-verify check` with a gate printing the variable showed it. Now stripped by name pattern, `gate_env_pass` lets one through (tests `test_gate_runs_without_the_secret_and_with_a_passed_one`; end-to-end from the built wheel: gate passes only because the variable is absent). A gate printing 400 MB made pr-verify use 1.16 GB (`resource.getrusage`); now 17 MB. A gate read the caller's stdin; now closed. |
| GitHub Actions integrator | Clone with `--depth 1`: tool says so in plain words and exits 0 with the base used (already fine). Merge commit of a PR (`git merge --no-ff`, `--base HEAD^1`): attribution intact (already fine). README example now sets `persist-credentials: false` so a gate cannot find the checkout token in `.git/config` (claim about actions/checkout's default not re-verified here). Workflow-command injection (`::add-mask::` at line start) already neutralised (cli.py). |
| AI-coding-agent PR reviewer | `Devin AI <158243242+devin-ai-integration[bot]@users.noreply.github.com>` counted as human (two-word name hides the address). GitHub's `[bot]` noreply address now always marks an agent. Other agents (Gemini, Windsurf, Junie, Amp, Roo) are not in the default list: how they sign commits was not verified, so none was invented; `extra_agent_markers` adds them. |
| Code-review lead | `.pr-verify.yaml` changed in a PR: already reported ("read that change as a request to loosen them"). Upgrade from 0.1.0: the file `pr-verify init` wrote with 0.1.0 and a 0.1.0 `check --format json` result run unchanged on this tree: same score (75), every old JSON key still present (only additions). No migration needed. |

Quality methods added: golden files for human, JSON, Markdown and SARIF; seeded
property tests (escaping is total and idempotent; glob matcher against a slow
reference on 3,000 random cases); PyYAML differential on 300 generated
configs; `benchmarks/mutation_sanity.py` (15 hand-picked flips of verdict,
secret and escaping conditions: 15 killed, 0 survived).

## Numbers

- Tests before: 603 passed, 2 skipped. After: 619 passed, 2 skipped (pytest, 3.13; the new file also passes on 3.10 with unittest). New file `tests/test_r5_experts.py` has 16 tests.
- `riskclass_bench.py`: 151/151, precision/recall 1.00 before and after. `attribution_bench.py`: unchanged (29 scenarios; its two known-limit lines are the documented limits).
- Gate memory for 400 MB of output: 1,162 MB before, 17 MB after.
- Competitors re-read 2026-11-08: Git AI home page still says "Git AI is now part of OpenAI" and "attribution survives rebases, merges, stash/pops, squashes"; CodeRabbit docs still say Triage prioritises "by value and risk". Not tested: how either behaves.

## Scored ideas (value / difference / effort / risk, 1 low to 5 high)

| # | Idea | V | D | E | R | Status |
|---|---|---|---|---|---|---|
| 1 | Strip secret-named env from gates, `gate_env_pass` | 5 | 3 | 2 | 3 | DONE |
| 2 | Bound gate output memory | 4 | 1 | 2 | 1 | DONE |
| 3 | Kill gate process group on timeout | 3 | 2 | 2 | 2 | DONE (POSIX; Windows untested) |
| 4 | Gate stdin closed | 2 | 1 | 1 | 1 | DONE |
| 5 | GitHub `[bot]` noreply address = agent | 4 | 2 | 1 | 1 | DONE |
| 6 | Author line everywhere, pinned by test | 3 | 1 | 1 | 1 | DONE |
| 7 | SARIF `organization` | 1 | 1 | 1 | 1 | DONE |
| 8 | Golden files, four formats | 4 | 1 | 2 | 1 | DONE |
| 9 | Property tests (escaping, glob) | 3 | 1 | 2 | 1 | DONE |
| 10 | PyYAML differential | 3 | 1 | 1 | 1 | DONE |
| 11 | Mutation sanity script | 3 | 2 | 2 | 1 | DONE |
| 12 | README: `persist-credentials: false` | 3 | 1 | 1 | 1 | DONE |
| 13 | Upgrade test from 0.1.0 | 4 | 1 | 1 | 1 | DONE (no change needed) |
| 14 | Default markers for Gemini/Windsurf/Junie/Amp | 3 | 2 | 1 | 3 | NOT-DONE (signing conventions unverified) |
| 15 | Warn in the report when env vars were stripped and a gate failed | 3 | 2 | 2 | 1 | NOT-DONE |
| 16 | Real sandbox for gates (container, no network) | 5 | 4 | 5 | 4 | NOT-DONE |
| 17 | Check a merged PR's `[skip ci]`-style bypass of the Action | 2 | 2 | 2 | 2 | NOT-DONE |
| 18 | PR comment poster (sticky comment) in the Action | 4 | 2 | 3 | 3 | NOT-DONE (needs a write token; changes the trust model) |
| 19 | Trusted Publishing workflow | 4 | 3 | 2 | 3 | NOT-DONE (owner's PyPI setup) |
| 20 | Windows kill-tree test | 3 | 1 | 3 | 2 | NOT-DONE (no machine) |
| 21 | Go / Rust / PHP import graph | 4 | 4 | 5 | 3 | NOT-DONE |
| 22 | ASCII-only report for cp1252 consoles | 3 | 2 | 3 | 2 | NOT-DONE |
| 23 | Faster test suite (shared fixture repo) | 3 | 1 | 4 | 2 | NOT-DONE |
| 24 | Ruff in CI (299 style hits today, 0 real F-class in the package) | 2 | 1 | 3 | 1 | NOT-DONE |

## What could not be tested

Windows and macOS (the `taskkill` path is unrun); Python 3.14; the Action on
GitHub itself; a real PyPI install; competitors' behaviour beyond their
pages; whether `actions/checkout` still stores the token in `.git/config`
by default (README states it as the reason for the setting).
