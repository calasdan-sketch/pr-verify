# Changelog

## 0.1.4

- A pull request can no longer make `pr-verify check` hang: a Ruby file with a
  line of `require_relative` followed by hundreds of thousands of spaces took
  minutes (quadratic matching); it is now read in linear time.
- On Windows a gate's program is looked up in `PATH` only, not in the working
  directory or the pull request's checkout, whatever the Python version: a
  `python.bat` or `npx.cmd` in the PR cannot replace the program a gate runs.
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
