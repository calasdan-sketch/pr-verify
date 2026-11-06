# Changelog

## 0.2.0 (unreleased)

Added

- `check --format markdown`: the report as GitHub-flavoured Markdown, for a
  pull request comment (`gh pr comment --body-file`). Every file name, author
  name, note and line of gate output is inside a code span or a fenced block
  that the text cannot close, so a name like `![x](https://...)` or
  `<img ...>` is shown, never rendered; `|` cannot split a table cell. The
  report stays under 60,000 characters on any pull request.
- The GitHub Action appends that report to `$GITHUB_STEP_SUMMARY`: the
  verdict, the factors and why a gate failed are on the run's summary page.
  A check that could not run says so there too; a summary that cannot be
  written is a warning.
- A failed gate says why: the last 8 lines of its output under it in the
  human report (escaped like every other text from the PR), the last 30 in a
  collapsed block in the Markdown one.
- `extra_agent_markers` and `extra_sensitive_paths` in `.pr-verify.yaml` add
  to the defaults instead of replacing them (`pr-verify init` writes both,
  empty).
- Copilot's coding agent is recognised by the `Agent-Logs-Url:` trailer it
  writes into its commits, also when a human is the commit's author.

Changed

- A config whose `agent_markers` (with `extra_agent_markers`) leaves no
  marker is refused, exit 2 (`agent_markers is empty`). It used to run and
  score every line as human. To keep only your own markers, list them.
- The `format` input of the Action takes `markdown` too.

## 0.1.3

JavaScript/TypeScript, Ruby and Java dependents are found (Go, Rust and PHP
report not scanned); file and stderr errors exit 2 with one line; unknown
settings warn.
