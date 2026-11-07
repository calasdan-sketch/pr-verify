# Publish checklist for pr-verify (read, then run it yourself; nothing here has been run)

Version to release: **0.3.0**. PyPI has only 0.1.0 today (checked 2026-11-07),
so this is a new minor release. It is not "breaking" in the packaging sense
(still 0.x), but scores and report layout differ a lot from 0.1.0: say so in
the release notes.

## Check first

1. `git status` is clean and you are on the commit you mean to ship.
2. `python3 -m pytest -q` passes (about 5 minutes).
3. CHANGELOG top heading says `0.3.0`; change "(unreleased)" to today's date.
4. You own the `pr-verify` name on PyPI (the 0.1.0 upload lists the author as
   "Calas Automations Inc.", but ownership was not verified).
5. Build in a throwaway folder and look at it:
   `python3 -m pip install build twine && python3 -m build --outdir /tmp/pv-dist . && twine check /tmp/pv-dist/*`

## Release

6. `git tag v0.3.0` then push the tag, only after step 1 to 5.
7. Upload: `twine upload /tmp/pv-dist/*` (needs a PyPI token; this is the step that cannot be undone, a version number can never be reused).
8. In a fresh folder: `python3 -m venv t && t/bin/pip install pr-verify && t/bin/pr-verify --version` must print `pr-verify 0.3.0`.
9. Then change the README install section to plain `pip install pr-verify` and remove the "PyPI gives 0.1.0" paragraph.
