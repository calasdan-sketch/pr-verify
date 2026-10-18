# PR Verify

Deterministic trust for agent-authored PRs. Not another AI reviewer —
**verification, not opinion.** Agents now write more code than seniors can
review; this tells a senior exactly how deep to review, from observable
facts: which lines an agent wrote, what could break, and whether policy
gates pass.

## Install

Stdlib only, Python 3.10+, needs the `git` command line tool on PATH.

```bash
pip install git+https://github.com/calasdan-sketch/pr-verify
pr-verify check
```

Or run from a checkout without installing: `python3 -m pr_verify` from the
repo root.

## Quick start

```bash
cd your-repo
pr-verify init            # write .pr-verify.yaml with every default spelled out (commit it to your base branch)
pr-verify check           # base auto-detected: origin/HEAD, then main, master, origin/main, origin/master
pr-verify check --base origin/main --format json --min-score 60
```

The report says which base was used (`base: master  (auto-detected)`); pass
`--base <ref>` to choose. Without `git` on PATH or outside a repo the tool
prints a one-line error and exits 2. So does a git call that fails or does
not finish in time (60 seconds for the heavy ones, 15 for the small
lookups): `error: git blame did not finish within 60 seconds`. That is a run
that could not verify, not the exit 1 of a failed verification.

The diff starts at the **merge-base** of the base and `HEAD`
(`git merge-base`), not at the base's tip. When `main` moved on after your
branch left it, what `main` gained is not your PR's change, and counting it
(as reverted lines in the PR) would dilute the agent's share and hide a
failing score. The JSON carries that commit as `merge_base`, and the report
adds a note when the base is ahead of it. If the two share no history
(unrelated histories, or a shallow clone that does not reach back to the
fork point) the base itself is used, a note says so and `merge_base` is
`null`: fetch the full history (`git fetch --unshallow`, or `fetch-depth: 0`
in the Action) for the exact range.

Start it anywhere inside the repository. The top level is found with `git
rev-parse --show-toplevel` and everything — paths, blame, the snapshot of
uncommitted changes, the blast-radius scan, the gates (which run from the
top level) — is computed from there, so `pr-verify check` run from `src/`
gives the same report as from the root. `--root <path>` takes any path
inside the repository, a subdirectory included, and still verifies the
whole repository; the report adds a note when the top level is not the
directory you gave. `pr-verify init` writes `.pr-verify.yaml` at the top
level, where the base ref's copy is read from.

## What it reports

**Provenance** — every added line labeled agent/human via `git blame` +
commit-author analysis. Per file: `agent` / `mixed` / `human`, with the
detected identities shown as `author (marker)` — e.g. `[claude-bot
(claude)]` or `[Dan Calas (aider)]` — so you can see *why* a line counts
as agent-written.

**Removed lines count as changed lines.** A line the PR takes out of a file
is credited to the commit that removed it, as an added line is to the
commit that wrote it: for each file that lost lines, the commits of the
range that touched it are looked at, and the lines an agent commit removed
are the agent's (`files.<name>.removed` / `agent_removed` in the JSON,
`4/4 removed agent` in the report). An agent that only deletes four lines
of `auth.py` is no longer "nothing to verify". The agent's removals in a
file never exceed what the range removes from it in total, so lines an
agent added and took out again do not count, and the figure is an upper
bound when agent commits remove each other's lines. A whole deleted file
keeps its own `deletion` factor and is not counted in lines.

A submodule is a commit id, not a file, so there is nothing to blame in it:
moving one is a single added line (and a single removed one), credited to
the last commit of the range that moved the pointer.

Markers match on **whole words** where agents actually sign, never on
prose:

- the author name — a bot-shaped name (one word, or a hyphen/underscore
  handle: `claude-bot`, `Claude`, `copilot-swe-agent`) matches on any
  word; a human-shaped "First Last" name only matches a marker covering
  the whole name (`Claude Code`) or a bracketed/parenthesised tag
  (`dependabot[bot]`, `Dan Calas (aider)`). So **Tim Abbott, Claude Dupont
  and Cody Smith are humans**; "bot" matches the word `bot`, not `Abbott`;
- the author email — whole local part (`cody@…`), a hyphen/underscore word
  of it (`claude-bot@…`; dots join `first.last` names and are not split),
  or a domain label (`…@aider.chat`, `…@cursor.com`);
- `Co-Authored-By:` / `Generated-by:` / `Signed-off-by:` trailers in the
  body, matched by the same rules (`Co-Authored-By: Claude
  <noreply@anthropic.com>`). Two lines Claude Code leaves count as well:
  its footer `Generated with [Claude Code](...)` (the bracketed text is the
  name) and the `Claude-Session:` trailer;
- a marker containing an `@` is one exact address, compared whole and
  without case, never read as a name. The default
  `co-authored-by: noreply@anthropic.com` is how Claude Code's own trailer
  (`Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>` - the model
  name changes with every release) is caught, in trailers only, while
  other people at anthropic.com stay human;
- a `marker:` subject prefix (`aider: fix the tests`).

The rest of the subject and the body are not scanned: "Fix cursor jump in
editor" is a commit about a cursor, not Cursor's commit, and "paired with
Claude <noreply@anthropic.com>" in a sentence is not a trailer. Default
markers: claude, claude code, codex, cursor, cursor agent, copilot, github
copilot, bot, aider, cody, devin, and the Claude Code address above. If a
human on your team commits as a single word that is also a marker (`Cody`),
drop that marker and rely on trailers. A list of `agent_markers` in
`.pr-verify.yaml` replaces the defaults, it does not extend them: keep
`"co-authored-by: noreply@anthropic.com"` in it (quoted - it contains a
colon) to keep catching Claude Code.

Non-ASCII file names (`app/Καλάς.py`) are files of their own: git is run
with `core.quotePath=false` and quoted diff headers are unescaped, so
their hunks are never credited to the previous file.

Everything git prints is read as text the PR's author wrote. A `\x1e` in
a commit body, subject or author name, a vertical tab or `U+2028` in a file
line, or a line that merely reads `++ /dev/null` cannot cut a trailer off,
drop a commit, forge a `git blame` or `git diff` record, or end a file's
hunks: output is read as bytes and split on `\n` only, path lists use
`-z`, the diff is walked by the line counts in its hunk headers, and
`git show` is NUL-framed and checked against the commits asked for. If
that check ever fails the run stops with an error (exit 2) instead of
guessing who wrote a commit.

The diff is read the way a machine reads it, not as a person likes to see
it. It comes from git's plumbing (`git diff-tree`), which ignores
`color.ui`, `diff.noprefix`, `diff.external`, `diff.interHunkContext`,
`diff.submodule` and the other settings that reshape `git diff`, and the
repository's `.gitattributes` is left out of it: a PR cannot hide a source
file from the gate by adding `*.py binary` or `*.py -diff`, and `diff`
cannot turn a real binary into a pile of added lines. `git blame` ignores
a `blame.ignoreRevsFile` for the same reason (that file is in the PR too).

`--base` and `--head` name commits, and a name that starts with `-` is
refused before git sees it (`error: head ref '--output=FILE' does not
exist`): git would read it as an option, and `--head=--output=FILE` used to
make it write its patch into FILE.

What the report prints is that text again — file names, author names, the
name of a deleted file — and a terminal acts on some of it: an escape
sequence recolors the screen or rewrites what is already there, a carriage
return overwrites the line, and a newline inside a name starts a line of
its own, which can read as a verdict (in a GitHub Actions log, as a
`::command::` that adds an annotation or switches command processing off).
So the human report and the error messages never print such a character.
C0 and C1 controls, DEL, the Unicode line and paragraph separators and the
bidirectional overrides and isolates are shown as the escapes Python
writes for them (`\x1b`, `\x9b`; `\u` and four hex digits above U+00FF), a
newline inside a name as `\x0a`, and a line that would start with `::` has
its first colon shown as `\x3a`. Tab is kept, and so is every other
character: accented letters, CJK, emoji, joiners, the box drawing of the
report. `--format json` is exact — JSON escapes those characters itself, and
a program reads the real name.

**Blast radius** — reverse dependency graph: for each changed file, the
transitive set of in-repo dependents that could break. Python via AST —
absolute imports, relative imports (`from . import x`, `from ..core import
y`, resolved against the importing file's own package), `from pkg import
submodule`, and `src/` layouts (`src/pkg/core.py` answers to `pkg.core`);
JS/TS/Go/Rust/Java/Ruby/PHP via heuristic fallback. Those file types are
read from the worktree; `node_modules`, `vendor`, `build`, `dist`, `venv`,
`.venv`, `.tox`, `__pycache__` and `.git` are skipped. Only regular files
are opened, and none over 4 MiB: a symbolic link (a PR can commit `evil.py
-> /dev/zero`), a named pipe or a device is left alone, and a larger file
stays in the graph without the imports it makes. A Python file the parser
cannot read (a syntax error, or an expression nested or chained too deep for
it) makes none either. The worktree is read once per run, however many files
the PR deleted (each deleted file used to cost another full scan: 300 of
them in a 2,000-file repository took minutes).

A changed file the graph does not contain says why, instead of a bare "0
downstream dependent(s)". The JSON carries the same as a code in
`blast_radius.<file>.scan`:

| `scan` | Report | Meaning |
|---|---|---|
| `graph` | *(nothing)* | in the import graph |
| `not_source` | `(.md files are not scanned for imports)` | a file type the scan does not read (README, YAML, logs …); no dependents are guessed for it |
| `skipped_dir` | `(in vendor/, which the import scan skips; nothing in-repo imports it)` | on disk, under a skipped directory |
| `not_in_worktree` | `(not in the worktree; nothing in-repo imports it)` | deleted, or absent from the checked-out tree |
| `not_scanned` | `(not reached by the import scan; nothing in-repo imports it)` | on disk, but the walk never reached it |

A file outside the graph that code elsewhere still imports by name (a
deleted module, a vendored one) keeps those dependents and prints no
label; `external_only` is true when none was found.

**Policy gates** — commands from `.pr-verify.yaml` (tests, typecheck,
lint), run with timeout, pass/fail captured. The config is read from the
base ref (never the worktree under review) and gates run **without** a
shell — `;`, `&&`, `$()`, pipes and the rest are literal arguments, never
interpreted. A gate is a command string (split with the platform's rules —
on Windows `C:\Python311\python.exe -m pytest` keeps its backslashes and
`npx`/`npm`/`tsc` `.cmd` shims are found through `PATHEXT`) or a YAML list
used as the argv as-is:

```yaml
gates:
  - "python -m pytest -x -q"
  - ["npx", "tsc", "--noEmit"]
```

A failing gate fails the verification (exit 1) and the report ends with
`✗ policy gate failed: <command>` — never a green tick.

**Risk score** — deterministic 0–100 from six public factors:

| Factor | Max | What it measures |
|---|---|---|
| agent_share | 40 | % of changed (added + removed) lines agent-authored |
| blast | 25 | log-scaled transitive dependents |
| sensitive | 20 | changed files under sensitive globs (auth, crypto, payments, migrations, secrets…); deleted files match like touched ones |
| gates | 10 | any policy gate failed |
| no_tests | 5 | source changed with no test changes |
| deletion | 50 | agent-attributed deletions: 45 if any deleted file is sensitive, else 10 for deleting tracked files at all, plus log-scaled points for the deleted files' dependents — pure-deletion PRs can trip the threshold too |

Test files are recognised by path component (`tests/`, `test/`,
`__tests__/`, `spec/`) or filename pattern (`test_*.py`, `*_test.*`,
`*.test.*`, `*.spec.*`, `*Test.java`, `conftest.py`) — `latest.py` and
`attestation.py` are source. The default sensitive globs are word-ish on
purpose (`**/auth.*`, `**/auth/**`, `**/*_key.*`, `**/*token.*`,
`**/*secret*`, `**/.env*`…): `author.py`, `monkey.py` and `tokenizer.py`
do not match; `api_key.py`, `auth_token.py` and `.env.local` do. Globs
match without regard to case, so `Login.tsx`, `PASSWORD.txt` and
`src/Auth/Index.ts` count. See `DEFAULTS` in `config.py` for the full list
and override `sensitive_paths` in your config; `pr-verify init` writes
every default out, so the file it creates changes nothing until you edit
it. A list in the config replaces the default list, it does not extend it.

Bands: 0–29 low · 30–69 medium · 70–100 high — labels only, they never
decide pass/fail. The formula is documented so teams can argue with it and
tune it — a black-box score is just another opinion.

### The gate — one rule

**The verification fails (exit 1) when `score >= min-score`.** A score
exactly equal to `min-score` fails. `min-score` comes from, in order:
`--min-score N` on the command line, `risk_threshold` in `.pr-verify.yaml`
at the base ref, the default 70. The JSON `risk.requires_review`, the ✗/✓
line of the human report and the exit code are all computed from that one
comparison.

- `--fail-on high` (default): the rule above.
- `--fail-on any-risk`: same rule with `min-score` = 1 (any nonzero score fails).
- `--fail-on never`: the score gate is off.
- A failing **policy gate** fails the verification regardless of `--fail-on`
  — the tool cannot vouch for a diff whose tests or lint failed.

The exit status is the verdict and nothing else changes it: piping the
report into a reader that stops early (`pr-verify check | head -1`) cuts it
short quietly — no traceback — and the exit status stays 0 for a pass and 1
for a fail. The same holds for `--help`, `--version` and error messages (2
stays 2), and on Windows, where such a pipe is not a `BrokenPipeError` but
an `OSError` with errno 22 that shows up when the output is flushed.

## Uncommitted changes and the snapshot

With the default `--head HEAD`, `check` also verifies your uncommitted
changes to **tracked** files: they are staged into a temporary index and
written as a synthetic commit so `diff`/`blame` can see them. That commit
is a dangling object under `.git/objects` — unreachable from any ref,
never pushed, removed by `git gc` — and your own index is untouched.
Untracked files are **not** snapshotted by default (an untracked
`.env.local` with a secret must not land in the object store because
someone ran a check); the report lists what was skipped, and
`--include-untracked` opts them in. An explicit `--head <ref>` verifies the
committed range only.

Uncommitted lines have no commit to blame, so they count as human-written,
never agent-written.

## The config file

`.pr-verify.yaml` is read **from the base ref**, not from the worktree —
a hostile PR must not be able to ship its own gate config and get it
executed. That means a freshly written config does nothing until it is
committed to your base branch: `init` says so, the report prints a note
when the worktree copy differs from (or does not exist at) the base, and
the file itself is excluded from provenance and scoring.

## CI

```bash
python3 -m pr_verify check --base origin/main --format json --min-score 60
```

`--format json` prints one JSON document and nothing else. With nothing to
verify (no line added or deleted between base and head) it is still that
document, with the same keys: `files` and `blast_radius` are `{}`, `gates`
is `[]`, `risk.score` is 0 (`low`, `requires_review` false) and the exit
status is 0; `notes` and `untracked_skipped` say what was left out. The
human format says `no added lines in main..HEAD — nothing to verify`.

### GitHub Action

`action.yml` at the repo root is a composite action. Its inputs are the
`check` flags, same names without the dashes, same defaults. This repo's
default branch is `master`; pin to it (or to a tag once one exists):

```yaml
- uses: actions/checkout@v4
  with: { fetch-depth: 0 }
- uses: calasdan-sketch/pr-verify@master
  with:
    base: origin/main      # --base (empty = auto-detect; be explicit in CI)
    head: HEAD             # --head
    format: human          # --format human|json
    fail-on: high          # --fail-on high|any-risk|never
    min-score: "60"        # --min-score (empty = risk_threshold from config)
    skip-gates: "false"    # --skip-gates
    root: ""               # --root (empty = the checked-out repo)
```

Outputs: `score`, `band`, `requires-review`, `exit-code`. The step runs
`python -I "$GITHUB_ACTION_PATH/run_action.py"`, which maps each input to
the matching CLI flag — the test suite parses `action.yml` and asserts that
mapping stays true.

The PR's checkout is the step's working directory, and it is only ever
data. Python's isolated mode (`-I`) keeps the working directory off the
import path and ignores `PYTHONPATH`, so a pull request that adds its own
`argparse.py`, `json.py` or `pr_verify/` package gets nothing run (a test
plants exactly those, commits them to a PR and runs the step as written).
Nothing is installed with pip either. No `${{ }}` expression is ever
written into a script: inputs reach the step as environment variables.
The gates in `.pr-verify.yaml` do run the PR's code, which is what a test
gate is for; they come from the base ref, which the PR cannot change. On
Windows the launcher also stops the working directory from being searched
for `git.exe` and other programs by bare name.

## Example output

```
════════════════════════════════════════════════════════
  PR VERIFY  risk 57/100 (MEDIUM)
════════════════════════════════════════════════════════

  base: main  (auto-detected)

  provenance: 9/13 added lines agent-authored
    agent   app/auth.py (4/4 agent) [claude-bot (claude)]
    mixed   app/core.py (4/8 agent) [claude-bot (claude)]
    agent   app/views.py (1/1 agent) [claude-bot (claude)]

  blast radius:
    app/core.py: 1 downstream dependent(s)
      direct: app/views.py
    app/auth.py: 0 downstream dependent(s)
    app/views.py: 0 downstream dependent(s)

  gates:
    none configured

  risk factors:
     28 pts  agent_share  9/13 added lines agent-authored (69%)
      4 pts  blast        largest blast radius: 1 downstream dependent(s)
     20 pts  sensitive    sensitive files touched: app/auth.py
      0 pts  gates        no gates configured
      5 pts  no_tests     source changed with no test changes
      0 pts  deletion     no agent-attributed deletions

  ✓ score 57 < min-score 70
════════════════════════════════════════════════════════
```

## Honest limits

- Provenance depends on commit authorship — squashed or rebased PRs lose
  per-commit attribution (tune `agent_markers` for your workflow). An agent
  committing under a plain human identity with no trailer is invisible.
- A file git considers binary produces no diff text, so its lines are not
  scored. That is git's own test, a NUL byte in the first 8000 bytes
  (images, archives, UTF-16 text — and a source file with a NUL put
  there). `.gitattributes` does not decide it: it is ignored, so a PR
  cannot hide a source file by marking it `binary` or `-diff`. Attributes
  you set yourself in `.git/info/attributes` or a global attributes file
  still apply.
- Which commit removed a line is worked out per commit and per file name,
  so a file that is renamed inside the PR hides its earlier removals from
  the attribution: they read as human. And when agent commits remove each
  other's lines the agent's removal count is an upper bound.
- Non-Python blast-radius extraction is heuristic.
- The blast radius does not follow symbolic links and reads no source file
  larger than 4 MiB for its imports (such a file is still in the graph and
  still has dependents).
- On Python 3.10 a Python file that is one expression with some 200,000
  terms (`a+a+a+...`) crashes the interpreter inside `ast.parse`, a CPython
  bug fixed in 3.11. The run then ends with the signal (exit 139 on Linux)
  and no verdict: that fails a CI job, it cannot pass one. Use Python 3.11
  or newer for pull requests you do not trust.
- The time limits on git calls (60 seconds, 15 for lookups) are fixed: on a
  repository where one is not enough the run stops with exit 2.
- The blast radius is read from the files in the worktree, whatever
  `--head` says: to verify a branch other than the checked-out one, check
  it out.
- The risk formula is a starting point, not a verdict — tune the threshold
  per team.

## Windows

Works on Windows 11 / Python 3.11: git output is decoded as UTF-8 (paths
included), the report survives a cp1252 console (unencodable marks are
replaced instead of crashing), gate commands are split with Windows rules
and their executables resolved through `PATHEXT`, and the test suite uses
no `true`/`false`/`touch` and never reads your global gitconfig.

## Tests

```bash
python3 -m unittest discover -s tests   # or: python3 -m pytest -q
```

Both runners, no network. Fixtures are throwaway git repos; the suite
covers provenance (including a Greek filename and the marker false
positives), src-layout/relative-import blast radius, the gate at its
boundary values, policy gates without a shell (string and list form, the
Windows split rules via a monkeypatched `os.name`), base detection on
main/master/origin-HEAD repos, the tracked-only snapshot, `action.yml`
against the CLI, running from a subdirectory, a closed output pipe (also
the way Windows reports it, faked on every platform), a PR's
`.gitattributes` and a user's git settings that would change the diff, text
that tries to forge git's own records (separators in commit messages and
file lines) or the report itself (control characters and newlines in
names), JSON for a range with nothing to verify, and a scan of the
repository's own files for invisible characters.

This repo's own CI ([`.github/workflows/ci.yml`](.github/workflows/ci.yml))
runs the suite on Ubuntu, Windows and macOS with Python 3.11, 3.12 and
3.13, and on Python 3.10 (the oldest supported) on Ubuntu. That floor
matters: argparse on 3.10 does not ignore a failed write of its help text,
so `--help | head -0` needed its own handling there.
