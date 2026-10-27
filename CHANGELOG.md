# Changelog

## 0.2.0

- Large PRs degrade instead of hanging: `--max-blame-files` (default 1000) and `--blame-budget` (default 300 s) cap blame; files left over are listed as `unverified_files`, count as neither human nor agent, and the run requires review (exit 1 unless the score gate is off).
- Under `GITHUB_EVENT_NAME=pull_request_target` a warning is printed and added to the report notes (gates run the PR's code); documented in the README.
- `--omit-gate-output` blanks the gate output tails in the JSON report.
- `pr-verify trend REPORT.json ...` shows score and agent share across earlier JSON reports; the PR comment gets a text "Agent share" badge.
- `--format sarif` prints a SARIF 2.1.0 log and `--format comment` the markdown
  of a sticky pull request comment whose headline is `Review depth:
  skim|normal|deep`, a pure function of the facts in the JSON. `--sarif-file`
  and `--comment-file` write them beside any format.
- The GitHub Action can post that comment (one comment, updated on every
  push; `comment: "true"`, needs `pull-requests: write`), add it to the job
  summary, and write the SARIF file (`sarif-file`). No new dependency: the
  standard library does the HTTP, the token is never sent anywhere a redirect
  points, and a comment that merely contains the marker (anyone can paste it)
  cannot block the real one. New inputs: `comment`, `github-token`,
  `step-summary`, `sarif-file`.
- Agent detection beyond commit trailers: PR labels (`agent_labels`), bot
  accounts (`agent_authors`), branch patterns `claude/*`, `copilot/*`,
  `cursor/*`, `codex/*` (`agent_branches`) and configurable trailer keys
  (`agent_trailer_keys`, `Claude-Session` by default). All case-insensitive
  globs from the base ref's config; the Action reads the facts from the event
  payload, a local run from `--pr-label`, `--pr-author`, `--pr-branch`,
  `--event-file`.
- Test-integrity check: deleted test files and tests, removed assertions,
  added skip / xfail / `.only` markers, loosened and always-true assertions in
  lines an agent wrote. Python and JS/TS in depth; table-driven. New `test_integrity`
  score factor.
- Policy gates as code in `.pr-verify.yaml`: `protected_paths`,
  `agent_forbidden_paths` (with `@ci` and `@lockfiles` presets),
  `max_changed_files`, `max_changed_lines`, `tests_must_change`. A violation
  fails the check. New `policy` score factor.
- description-vs-diff advisory: files and symbols the PR text mentions that
  the diff does not touch (`--pr-title`, `--pr-body-file`). Advisory only.
- Tests only: the comment-file path test builds the expected path with os.path.join (RUNNER_TEMP is a Windows path on a Windows runner).
- Tests only: the Windows gate-lookup tests no longer depend on the runner's real `npx`, compare paths case- and short-name-insensitively, and the bash-run release-workflow steps are skipped on Windows.

## 0.1.5

- Windows: a gate whose program is found on no trusted `PATH` entry now fails
  with exit 127 and a one-line reason. Before, the bare name went to
  CreateProcess, which searches the parent's working directory first, so a
  `python.bat` added by the pull request could still run.
- Windows: the gate-program search also skips every subdirectory of the
  checkout and of the working directory (for example `node_modules\.bin`) and
  every relative `PATH` entry, not only the exact checkout directory.

## 0.1.4

- A pull request can no longer make `pr-verify check` hang: a Ruby file with a
  line of `require_relative` followed by hundreds of thousands of spaces took
  minutes (quadratic matching); it is now read in linear time.
- On Windows a gate's program is looked up in `PATH` only, not in the working
  directory or the pull request's checkout, whatever the Python version: a
  `python.bat` or `npx.cmd` in the PR cannot replace the program a gate runs
  (0.1.5 closes the case where the name was found nowhere).
- Package page on PyPI: author, repository link and the Python 3.14 classifier.
- CI on Linux, Windows and macOS with Python 3.10, 3.12 and 3.14, a package
  job (build, `twine check --strict`, install the wheel) and a release
  workflow that publishes to PyPI from a `v*` tag.
- `pip install pr-verify`.

## 0.1.3

- JS/TS, Ruby and Java dependents are found (Go, Rust and PHP report "not
  scanned"), file and stderr errors exit 2 with one line, unknown settings
  warn, the README Action reference is `@main`.

## 0.1.2

- Agents are credited only for the base's own lines, UTF-8 BOM configs are
  read, a missing blame ignore file is tolerated, the Action always writes
  `exit-code`.

## 0.1.0 and 0.1.1

- First releases: provenance, blast radius, risk score and policy gates.
