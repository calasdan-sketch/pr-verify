"""Shared fixture: temp git repo with human + agent commits.

Importing this module isolates git from the developer's machine for the
whole test process: no global/system gitconfig (autocrlf, gpgsign, hooks
or color settings cannot leak in) and HOME/USERPROFILE point at a temp
dir. Every commit sets its author explicitly.
"""

import os
import shlex
import subprocess
import sys
import tempfile

_GIT_HOME = tempfile.mkdtemp(prefix="prv-home-")
with open(os.path.join(_GIT_HOME, "gitconfig"), "w", encoding="utf-8") as _f:
    _f.write("[init]\n\tdefaultBranch = main\n")
os.environ["GIT_CONFIG_GLOBAL"] = os.path.join(_GIT_HOME, "gitconfig")
os.environ["GIT_CONFIG_NOSYSTEM"] = "1"
os.environ["HOME"] = _GIT_HOME
os.environ["USERPROFILE"] = _GIT_HOME

PY = sys.executable


def gate(*argv: str) -> str:
    """A policy-gate command string (what goes in .pr-verify.yaml) that
    runs argv. shlex-quoted so a Windows interpreter path with spaces and
    backslashes survives gates.run_gates' shlex.split."""
    return " ".join(shlex.quote(a) for a in argv)


def yaml_str(s: str) -> str:
    """Double-quoted YAML scalar for miniyaml (escapes \\ and \")."""
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


#: Gate commands that exist on every platform (`true`/`false` do not on
#: Windows): a passing and a failing python one-liner.
PASS_GATE = gate(PY, "-c", "pass")
FAIL_GATE = gate(PY, "-c", "raise SystemExit(1)")


def git(tmp, *args, **kw):
    env = dict(os.environ)
    env.update(kw.get("env", {}))
    subprocess.run(["git", "-C", tmp, *args], check=True,
                   capture_output=True, env=env)


def commit_as(tmp, name, email, message, files: dict[str, str]):
    for rel, content in files.items():
        p = os.path.join(tmp, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w", encoding="utf-8", newline="\n") as f:
            f.write(content)
    git(tmp, "add", "-A")
    git(tmp, "-c", f"user.name={name}", "-c", f"user.email={email}",
        "commit", "-qm", message)


def make_deletion_repo() -> tuple[str, str]:
    """Returns (tmp, base_sha). base: app/util.py imported by app/main.py.
    Then one agent commit deletes app/util.py."""
    tmp = tempfile.mkdtemp()
    git(tmp, "init", "-qb", "main")
    commit_as(tmp, "Dan Calas", "dan@example.com", "base",
              {"app/util.py": "def helper():\n    return 42\n",
               "app/main.py": "from app.util import helper\n\n\n"
                              "def main():\n    return helper()\n"})
    base = subprocess.run(["git", "-C", tmp, "rev-parse", "HEAD"],
                          capture_output=True, text=True, encoding="utf-8",
                          check=True).stdout.strip()
    # agent commit: delete util.py (main.py still imports it -> broken)
    os.remove(os.path.join(tmp, "app/util.py"))
    git(tmp, "add", "-A")
    git(tmp, "-c", "user.name=claude-bot",
        "-c", "user.email=claude-bot@example.com",
        "commit", "-qm", "Remove unused util\n\nCo-authored-by: Claude")
    return tmp, base


def make_sensitive_deletion_repo() -> tuple[str, str]:
    """Returns (tmp, base_sha). base: app/auth.py (sensitive) + app/main.py.
    Then one agent commit deletes app/auth.py. Nothing imports auth.py, so
    the score comes from the deletion factor alone (45) + sensitive (20)
    + no_tests (5) = 70, tripping the default HIGH threshold."""
    tmp = tempfile.mkdtemp()
    git(tmp, "init", "-qb", "main")
    commit_as(tmp, "Dan Calas", "dan@example.com", "base",
              {"app/auth.py": "def login(u, p):\n    return True\n",
               "app/main.py": "def main():\n    return 0\n"})
    base = subprocess.run(["git", "-C", tmp, "rev-parse", "HEAD"],
                          capture_output=True, text=True, encoding="utf-8",
                          check=True).stdout.strip()
    os.remove(os.path.join(tmp, "app/auth.py"))
    git(tmp, "add", "-A")
    git(tmp, "-c", "user.name=claude-bot",
        "-c", "user.email=claude-bot@example.com",
        "commit", "-qm", "Drop auth module\n\nCo-authored-by: Claude")
    return tmp, base


def commit_at_new_base(tmp: str, old_base: str, files: dict[str, str],
                       message: str = "config") -> str:
    """Commit files on a detached copy of old_base; return the new base sha.

    Lets tests place trusted files (e.g. .pr-verify.yaml) AT the base ref:
    checks out old_base detached, commits, then returns to main. The new
    base is diff-equivalent to old_base for everything committed later.
    """
    git(tmp, "checkout", "-q", old_base)
    commit_as(tmp, "Dan Calas", "dan@example.com", message, files)
    new_base = subprocess.run(["git", "-C", tmp, "rev-parse", "HEAD"],
                              capture_output=True, text=True, encoding="utf-8",
                              check=True).stdout.strip()
    git(tmp, "checkout", "-q", "main")
    return new_base


def make_pr_repo() -> tuple[str, str]:
    """Returns (tmp, base_sha). base: human commit. Then one human commit
    + one agent commit on top."""
    tmp = tempfile.mkdtemp()
    git(tmp, "init", "-qb", "main")
    commit_as(tmp, "Dan Calas", "dan@example.com", "base",
              {"app/core.py": "def calc(x):\n    return x * 2\n",
               "app/auth.py": "def login(u, p):\n    return True\n",
               "tests/test_core.py": "def test_calc():\n    assert True\n"})
    base = subprocess.run(["git", "-C", tmp, "rev-parse", "HEAD"],
                          capture_output=True, text=True, encoding="utf-8",
                          check=True).stdout.strip()
    # human follow-up: touches core
    commit_as(tmp, "Dan Calas", "dan@example.com", "tweak calc",
              {"app/core.py": "def calc(x):\n    return x * 2\n\n\n"
                              "def double(x):\n    return x + x\n"})
    # agent commit: new feature in core + touches auth (sensitive)
    commit_as(tmp, "claude-bot", "claude-bot@example.com",
              "Add caching to core\n\nCo-authored-by: Claude",
              {"app/core.py": ("def calc(x):\n    return x * 2\n\n\n"
                               "def double(x):\n    return x + x\n\n\n"
                               "def cached_calc(x):\n    return calc(x)\n"),
               "app/auth.py": ("def login(u, p):\n    return True\n\n\n"
                               "def sso(t):\n    return t\n"),
               "app/views.py": "from app.core import cached_calc\n"})
    return tmp, base


def make_src_layout_repo() -> tuple[str, str]:
    """Returns (tmp, base_sha). A src/ layout package whose modules reach
    each other only through relative imports and src-style absolute
    imports, with tests importing the package the installed way:

      src/pkg/core.py              <- the file the agent changes
      src/pkg/api.py               from pkg.core import calc
      src/pkg/sub/helpers.py       from ..core import calc / from . import util
      src/pkg/sub/util.py          from .. import core
      tests/test_core.py           from pkg import core
      tests/test_helpers.py        import pkg.sub.helpers

    Then one agent commit edits src/pkg/core.py (no test change)."""
    tmp = tempfile.mkdtemp()
    git(tmp, "init", "-qb", "main")
    commit_as(tmp, "Dan Calas", "dan@example.com", "base", {
        "src/pkg/__init__.py": "",
        "src/pkg/core.py": "def calc(x):\n    return x * 2\n",
        "src/pkg/api.py": "from pkg.core import calc\n\n\n"
                          "def api(x):\n    return calc(x)\n",
        "src/pkg/sub/__init__.py": "",
        "src/pkg/sub/helpers.py": "from ..core import calc\nfrom . import util\n",
        "src/pkg/sub/util.py": "from .. import core\n",
        "tests/test_core.py": "from pkg import core\n",
        "tests/test_helpers.py": "import pkg.sub.helpers\n",
    })
    base = subprocess.run(["git", "-C", tmp, "rev-parse", "HEAD"],
                          capture_output=True, text=True, encoding="utf-8",
                          check=True).stdout.strip()
    commit_as(tmp, "claude-bot", "claude-bot@example.com",
              "Speed up calc\n\nCo-authored-by: Claude",
              {"src/pkg/core.py": "def calc(x):\n    return x + x\n"})
    return tmp, base
