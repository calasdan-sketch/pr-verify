# Publish checklist for pr-verify (read, then run it yourself; nothing here has been run)

Version to release: **0.3.0**. PyPI has only 0.1.0 (checked 2026-11-07), so
0.3.0 is the next release; nothing was uploaded. Scores and report layout
differ a lot from 0.1.0: say so in the release notes. Old 0.1.0 config files
and JSON consumers keep working (tested, docs/ROUND5.md).

New in this round that users may notice: gates no longer receive environment
variables with secret-looking names (TOKEN, SECRET, PASSWORD, KEY, AUTH);
the setting `gate_env_pass` lets one through. Put that in the release notes.

## Check first

1. `git status` is clean and you are on the commit you mean to ship.
2. `python3 -m pytest -q` passes (about 5 minutes).
3. CHANGELOG top heading says `0.3.0`; change "(unreleased)" to today's date.
4. You own the `pr-verify` name on PyPI (the 0.1.0 upload lists the author as
   "Calas Automations Inc."; ownership was not verified).
5. Build in a throwaway folder and look at it:
   `python3 -m pip install build twine && python3 -m build --outdir /tmp/pv-dist . && twine check /tmp/pv-dist/*`
   Then `unzip -p /tmp/pv-dist/*.whl '*/METADATA' | head -8` must show
   `Author: Calas Automations Inc.` and `Version: 0.3.0`.

## Release

6. `git tag v0.3.0`, then push the tag, only after steps 1 to 5.
7. Upload: `twine upload /tmp/pv-dist/*` (needs your PyPI token; this step
   cannot be undone, a version number can never be reused).
8. In a fresh folder: `python3 -m venv t && t/bin/pip install pr-verify && t/bin/pr-verify --version` must print `pr-verify 0.3.0`.
9. Then change the README install section to plain `pip install pr-verify` and remove the "PyPI gives 0.1.0" paragraph.
