"""Start point of the GitHub Action (action.yml): `python -I run_action.py`.

The step runs with the pull request's checkout as its working directory,
and that directory is data, never code. A plain `python -m pr_verify.action`
puts the working directory first on sys.path, so a PR that adds an
`argparse.py`, a `json.py` or a `pr_verify/` package gets its own code run
by the job before the check starts. `-I` (isolated mode) keeps the working
directory and the script's directory off sys.path and ignores the PYTHON*
variables; this file then puts back exactly one directory, the one it lives
in (the action's own checkout, which has the pr_verify package), found from
its own path and not from anything the PR controls.

Nothing is installed, so nothing is built from the checkout either.
"""

import os
import sys

# Windows searches the working directory for `git` (and every other program
# a bare name asks for) before PATH, unless this is set: a `git.exe` in the
# PR would run in place of git. It reaches pr-verify's own git calls and the
# gates' executable lookup (Python 3.12+: shutil.which honours it); run a
# program from the repository with a path (`.\tool.exe`) as a gate.
os.environ.setdefault("NoDefaultCurrentDirectoryInExePath", "1")

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from pr_verify.action import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
