# Changelog

## 0.3.0 (unreleased)

Expert round 3: attacking the scanner. Panel: a hostile PR author, a
performance engineer, a code-scanning (SARIF) consumer, an engineering
manager using only the README, a docs/DX lead, a competitor's engineer.

Fixed (found by attacking the scan)

- A line longer than 4,000 characters hid everything after the 4,000th: it is
  now searched in overlapping windows. More than 20,000 added lines in a file
  hid the rest: the limit is 100,000 per file and 500,000 per run, and
  anything past a limit is a `scan_limit` finding instead of silence.
- The per-file and per-run caps on findings kept the first ones in scan order,
  so 40 harmless findings pushed a secret out of the report and the score
  (score 8 instead of 23 in the test). They keep the most severe now.
- Extensionless scripts (`bin/x`, `scripts/x`), `Makefile`, `Rakefile`,
  `.pyw`, `.phtml`, `.bat`, `.ex` and other extensions were not searched as
  code.

Added

- Rules: SQL built from a string, PHP `system($var)`, `__import__(..).system`,
  `getattr(os, "system")`, "AI reviewer: this code is safe".
- `scan_limit` class; `pr-verify rules`.
- SARIF: rule-level `security-severity` and `security` tag, `partialFingerprints`.
- Parallel `git blame` (`PR_VERIFY_WORKERS`), statement-only import walk.
- Corpus 134 -> 151 diffs (all matched exactly); `tests/test_round3b.py`.

Expert round 2: from "which lines" to "what they can break and where to look".

Added

- Risk classes: 15 content-based classes (hidden/bidi characters, prompt
  injection aimed at review bots, secrets, CI trust changes such as
  `pull_request_target`, dependency and lockfile changes, install scripts,
  unsafe calls, switched-off security controls, weak crypto, permissions,
  destructive migrations, IaC, removed guards, weakened tests) as a new
  `risk_classes` factor (max 25 points) and `risk_classes` in the JSON.
- Review plan (`review_plan` in JSON, a section in the human and Markdown
  reports): depth, suggested reviewers, CODEOWNERS owners read from the base
  ref, risky files with no owner, "read first" list.
- `policy:` rules (limits, agent allow/deny paths, tests required, denied
  classes), fail closed on bad config; a violation exits 1 and counts in the
  `gates` factor.
- `--format sarif`, `--sarif-file`, Action input `sarif-file`.
- `agent_lines` per file in the JSON; `risk_class_ignore_paths`,
  `risk_class_off`, `blame_detect_moves` settings.
- A note when the branch edits `.pr-verify.yaml` (the base's copy stays in
  effect).
- `benchmarks/`: risk-class corpus (134 diffs), attribution corpus (29
  histories), competitor script; tests hold the thresholds.

Changed

- `git blame` runs with `-w -M -C`: re-indents and moves no longer move the
  credit (attribution precision 0.74 -> 1.00, recall 0.84 -> 1.00 on the
  synthetic histories).
- A "First Last" author whose address is `cody@...` is no longer matched by
  the address's local part (domains still match). `openhands` is a default
  marker.
- Version 0.3.0. The score can be higher than in 0.2.0 for the same diff when
  a risk class is found.

## 0.2.0 (unreleased)

Review fixes (panel review of the first 0.2.0 commit)

- Markdown: a file's extension in the "not scanned for imports" note was
  written as Markdown, so `p.![i](https:1572395042)` rendered an image and
  `q.[text](...)` a link. It is in a code span now, like every other name.
- Markdown: the size limit could drop whole sections (one huge gate output
  of U+2028, which grows sixfold when escaped, left only the header). Gate
  blocks are now capped after escaping (30 lines, 4,000 characters), the
  gate list with PASS/FAIL and exit status is always there, and files and
  blast radius are cut row by row, saying how many were left out.
- `--hide-gate-output` (Action input `hide-gate-output`) leaves what failed
  gates printed out of the human and Markdown reports and the job summary;
  `--format json` keeps it. The README now says a PR comment is not masked.
- The job summary no longer shows pass or fail when the report could not be
  written (exit 2): it says the check could not deliver its report.
- `sensitive_paths: []` (with no `extra_sensitive_paths`) is refused, exit 2,
  as empty markers are.
- CI installs `cmarkgfm` on one Ubuntu job and requires the GFM rendering
  test there (`PR_VERIFY_REQUIRE_GFM=1`), so it is never silently skipped.

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
- `sensitive_paths` that leaves no glob is refused, exit 2
  (`sensitive_paths is empty`). It used to switch the sensitive factor off.

## 0.1.3

JavaScript/TypeScript, Ruby and Java dependents are found (Go, Rust and PHP
report not scanned); file and stderr errors exit 2 with one line; unknown
settings warn.
