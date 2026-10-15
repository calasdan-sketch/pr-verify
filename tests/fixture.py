"""Shared fixture: temp git repo with human + agent commits."""

import os
import subprocess
import tempfile


def git(tmp, *args, **kw):
    env = dict(os.environ)
    env.update(kw.get("env", {}))
    subprocess.run(["git", "-C", tmp, *args], check=True,
                   capture_output=True, env=env)


def commit_as(tmp, name, email, message, files: dict[str, str]):
    for rel, content in files.items():
        p = os.path.join(tmp, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w") as f:
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
                          capture_output=True, text=True,
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
                          capture_output=True, text=True,
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
                              capture_output=True, text=True,
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
                          capture_output=True, text=True,
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
