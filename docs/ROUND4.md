# Round 4: the stranger's first hour

Branch `expert-2`. Question for this round: what does someone get who types
`pip install` and follows only the README? Everything below was run on a Linux
sandbox; nothing was run on Windows or macOS.

## How the review was done (honest)

No tool for starting independent sub-agents was available in this session, so
one reviewer played each role in turn, one after the other. Each role ran real
commands; the findings are not an independent second opinion. Python
3.10.20, 3.11.18, 3.12.3 and 3.13.18 were installed and used; 3.14 was not.

## Specialists and what each found

| Role | Finding (command that proved it) |
|---|---|
| First-time user, README only | Built wheel installed in a fresh 3.11, 3.10 and 3.13 venv (`pip install dist/*.whl`); `pr-verify --version`, `init`, `check`, `check --format json/markdown/sarif`, `--min-score`, `--fail-on`, `rules` all worked from a folder with a space in its name. `pr-verify check --root X` failed: "unrecognized arguments" (fixed). |
| Release / packaging | `python -m build` + `twine check`: both pass. Wheel holds only `pr_verify/` + LICENSE + metadata; sdist adds tests, CI file, action files, no secrets, no personal paths (`tar tzf`, `unzip -l`). Missing: `__version__` (`python -c "import pr_verify; print(pr_verify.__version__)"` failed), author, Source and Changelog links (fixed). No `py.typed`: not added, the package documents a CLI, not an importable API. |
| Supply chain | Zero runtime dependencies (clean venv imports everything; `pip list` shows only pr-verify). Build requirement `setuptools>=77` only. Git is called as an argument list, never through a shell (`grep -n "shell=" pr_verify/*.py`: only in rule text). |
| Hostile-input fuzzer | A file named `caf<0xE9>.py` (not UTF-8) aborted the whole run: `error: git blame ... fatal: no such path` (exit 2). One hostile PR could therefore block verification. Fixed. 2 MB binary, 300,000-line CRLF file, RLO-named file: all handled, 2.9 s total. 4 parallel runs in one repo: no clash. |
| Git-config tamperer | 13 user git settings that change diff output (`diff.noprefix`, `mnemonicPrefix`, `srcPrefix`, `color.ui=always`, `core.autocrlf`, `diff.external`, `log.showSignature`, ...) gave byte-identical results. `diff.orderFile` pointing at a missing file makes `git show` fail (exit 2, plain message): not fixed. |
| CI/CD integrator | JSON, SARIF and Markdown parse in every case after the fix. JSON used to carry a lone surrogate for odd names (strict parsers reject it); SARIF crashed with a traceback (`UnicodeEncodeError` in `urllib.parse.quote`). Both fixed. Exit codes checked: 0 pass, 1 failed verification, 2 could not verify. |
| Docs / DX | README install line pointed at git; PyPI has 0.1.0 (`pip index versions pr-verify`; JSON API shows author "Calas Automations Inc."). README now says so. Windows section claimed "Works on Windows 11": changed to say it was read, not run. |
| Windows reviewer (static) | Read every `open`, `os.replace`, `tempfile`, `subprocess`, signal, newline and encoding use. No `shell=True`, no signals, no `os.replace`; temp index file is closed before git uses it; stdout switches to `errors=replace` for cp1252; gates resolve `.cmd` through PATHEXT; closed pipe EINVAL handled. Remaining Windows risks: box-drawing characters show as `?` on a cp1252 console; a timed-out gate may leave grandchild processes; non-UTF-8 names (POSIX-only fix). Not run on Windows. |
| Competitor's maintainer | Git AI page (read 2026-11-07): banner "Git AI is now part of OpenAI"; says attributions are "preserved through rebases, squashes, cherry-picks". CodeRabbit docs: Triage "by value and risk", no scoring formula stated. README comparison updated with the banner. Not tested: how either behaves. |
| Performance | Benchmarks unchanged (below). Large-file run 2.9 s. Test suite 282 s on this machine (slow: it builds many git repos). |

## Numbers

- Tests before: 595 passed, 2 skipped. After: 603 passed, 2 skipped (pytest, 3.13); 605 run, OK with 2 skipped (unittest, Python 3.10.20).
- `benchmarks/riskclass_bench.py`: 151/151 exact, precision/recall 1.00 before and after.
- `benchmarks/attribution_bench.py`: 29/29 scenarios, 75 lines, 1.000 before and after.
- Registry: PyPI `pr-verify` 0.1.0 only; repo 0.3.0.

## Scored ideas (value / difference / effort / risk: 1 low to 5 high)

| # | Idea | Value | Diff. | Effort | Risk | Status |
|---|---|---|---|---|---|---|
| 1 | Survive non-UTF-8 file names end to end | 5 | 2 | 2 | 2 | DONE |
| 2 | No lone surrogates in JSON/SARIF | 4 | 1 | 1 | 1 | DONE |
| 3 | `--root` accepted after the subcommand | 3 | 1 | 1 | 1 | DONE |
| 4 | `__version__` as the single source | 3 | 1 | 1 | 1 | DONE |
| 5 | Test: pyproject, CHANGELOG, `__version__` agree | 3 | 1 | 1 | 1 | DONE |
| 6 | Author / Source / Changelog / Git classifier | 3 | 1 | 1 | 1 | DONE |
| 7 | README: PyPI-vs-repo version honesty | 4 | 1 | 1 | 1 | DONE |
| 8 | README: Windows claim honest | 3 | 1 | 1 | 1 | DONE |
| 9 | Competitor row refreshed (Git AI banner) | 2 | 1 | 1 | 1 | DONE |
| 10 | Fresh-venv install check on 3.10, 3.11, 3.13 | 4 | 1 | 1 | 1 | DONE (manual; 3.12 install done earlier) |
| 11 | Tolerate `diff.orderFile` to a missing file | 1 | 1 | 2 | 2 | NOT-DONE (exotic) |
| 12 | ASCII-only report mode for cp1252 consoles | 3 | 2 | 3 | 2 | NOT-DONE |
| 13 | Kill whole process tree on gate timeout (Windows) | 2 | 2 | 3 | 3 | NOT-DONE (cannot test) |
| 14 | `py.typed` + typed public API | 2 | 1 | 4 | 2 | NOT-DONE (no library API promised) |
| 15 | Python 3.14 classifier + CI | 2 | 1 | 1 | 2 | NOT-DONE (3.14 not available here) |
| 16 | Trusted Publishing workflow (PyPI, no token) | 4 | 3 | 2 | 3 | NOT-DONE (needs the owner's PyPI setup; never publish from here) |
| 17 | Faster test suite (share one fixture repo) | 3 | 1 | 4 | 2 | NOT-DONE |
| 18 | Go / Rust / PHP import graph | 4 | 4 | 5 | 3 | NOT-DONE (earlier "not built") |
| 19 | Multi-line rule matching (`eval` split by backslash) | 3 | 3 | 5 | 3 | NOT-DONE (earlier "not built") |
| 20 | Bare `pr-verify` prints help instead of an error | 2 | 1 | 1 | 1 | NOT-DONE |
| 21 | Sign releases / provenance attestations | 3 | 2 | 3 | 3 | NOT-DONE |
| 22 | Windows and macOS runs of this round | 5 | 1 | 2 | 1 | NOT-DONE (no machine) |

## What could not be tested

Windows and macOS; Python 3.14; a read-only filesystem and a full disk (the
sandbox user is root, so permission bits do not bite); real PyPI upload and
install from the registry; the GitHub Action on GitHub; any competitor's
behaviour beyond what their pages say.
