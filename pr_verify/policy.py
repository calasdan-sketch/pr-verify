"""Policy gates as code: rules in `.pr-verify.yaml` (read from the base ref,
so the pull request cannot loosen them) that the diff must obey.

  protected_paths        globs: nobody's change to these passes
  agent_forbidden_paths  globs: an agent-attributed change to these does not
                         pass (humans may). `@ci` and `@lockfiles` stand for
                         the usual CI configuration and lock files (below)
  max_changed_files      change budget: more files than this fails (0 = off)
  max_changed_lines      change budget: more added+removed lines than this
                         fails (0 = off). A deleted file's lines are not
                         counted (they are not in the diff as lines), its
                         existence is: it counts as one file.
  tests_must_change      true: source files changed with no test file changed
                         fails. "Source" is a file with a code extension
                         (SOURCE_EXTENSIONS) that is not a test file.

Every violation is a plain sentence naming the rule, the files and the limit.
A violation fails the verification (exit 1) the way a failed gate does, and
adds the `policy` factor to the score. All rules are off by default.

Globs are the .gitignore kind, matched on the repo-relative path with `/`
separators and without regard to case: `*` is anything but `/`, `**` any
number of directories, `?` one character; a pattern with no `/` matches
that name at any depth (`*.lock`, `Jenkinsfile`); a trailing `/` means the
directory and everything under it.
"""

from __future__ import annotations

import dataclasses
import functools
import os
import re

from . import risk as risk_mod

#: `@name` -> globs, usable in agent_forbidden_paths / protected_paths
PRESETS = {
    "@ci": [
        ".github/workflows/**", ".github/actions/**", ".gitlab-ci.yml",
        ".gitlab/**", ".circleci/**", "azure-pipelines.yml", "Jenkinsfile",
        ".buildkite/**", ".travis.yml", "appveyor.yml",
        "bitbucket-pipelines.yml", ".drone.yml", ".woodpecker/**",
        "cloudbuild.yaml", "buildspec.yml",
    ],
    "@lockfiles": [
        "package-lock.json", "npm-shrinkwrap.json", "yarn.lock",
        "pnpm-lock.yaml", "bun.lock", "bun.lockb", "poetry.lock", "uv.lock",
        "pdm.lock", "Pipfile.lock", "Cargo.lock", "Gemfile.lock",
        "composer.lock", "go.sum", "mix.lock", "pubspec.lock", "flake.lock",
        "packages.lock.json", "gradle.lockfile", "Podfile.lock",
    ],
}

SOURCE_EXTENSIONS = frozenset((
    ".py", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".go", ".rs", ".rb",
    ".java", ".kt", ".kts", ".scala", ".swift", ".c", ".h", ".cc", ".cpp",
    ".hpp", ".cs", ".php", ".m", ".mm", ".lua", ".sh", ".ex", ".exs", ".dart",
    ".vue", ".svelte",
))


@dataclasses.dataclass
class Violation:
    rule: str
    message: str
    files: list = dataclasses.field(default_factory=list)

    def as_dict(self) -> dict:
        return {"rule": self.rule, "message": self.message,
                "files": list(self.files)}


def expand(globs) -> list[str]:
    """Globs with the `@preset` names replaced by what they stand for."""
    out: list[str] = []
    for g in globs:
        g = str(g)
        out.extend(PRESETS.get(g.strip().lower(), [g]))
    return out


@functools.lru_cache(maxsize=512)
def _compile(pattern: str):
    pat = pattern.strip().replace("\\", "/")
    anywhere = "/" not in pat.rstrip("/")
    if pat.endswith("/"):
        pat += "**"
    pat = pat.lstrip("/")
    out, i = [], 0
    while i < len(pat):
        c = pat[i]
        if pat.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
        elif pat.startswith("**", i):
            out.append(".*")
            i += 2
        elif c == "*":
            out.append("[^/]*")
            i += 1
        elif c == "?":
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(c))
            i += 1
    body = "".join(out)
    prefix = "(?:.*/)?" if anywhere else ""
    return re.compile("^" + prefix + body + "$", re.IGNORECASE | re.DOTALL)


def glob_match(path: str, pattern: str) -> bool:
    """Whether the repo-relative `path` matches the .gitignore-style glob."""
    return _compile(pattern).match(path.replace("\\", "/")) is not None


def matches_any(path: str, globs) -> str | None:
    """The first glob of `globs` that `path` matches, or None."""
    for g in globs:
        if glob_match(path, g):
            return g
    return None


def is_source(path: str) -> bool:
    return (os.path.splitext(path)[1].lower() in SOURCE_EXTENSIONS
            and not risk_mod._is_test_file(path))


def _by_agent(fp) -> bool:
    return bool(fp.agents) or fp.agent_added > 0 or fp.agent_removed > 0


def _names(files, limit: int = 8) -> str:
    shown = ", ".join(files[:limit])
    return shown + (f", and {len(files) - limit} more" if len(files) > limit
                    else "")


def evaluate(prov: dict, cfg: dict) -> list[Violation]:
    """The policy violations of a change (`prov`: file -> FileProvenance),
    in a fixed order: protected paths, agent-forbidden paths, budgets, tests."""
    found: list[Violation] = []
    protected = expand(cfg.get("protected_paths") or [])
    if protected:
        hit = sorted(f for f in prov if matches_any(f, protected))
        if hit:
            found.append(Violation(
                "protected-path",
                f"protected path changed: {_names(hit)} "
                f"(protected_paths in .pr-verify.yaml)", hit))
    forbidden = expand(cfg.get("agent_forbidden_paths") or [])
    if forbidden:
        hit = sorted(f for f, fp in prov.items()
                     if _by_agent(fp) and matches_any(f, forbidden))
        if hit:
            found.append(Violation(
                "agent-forbidden-path",
                f"an agent changed files it may not touch: {_names(hit)} "
                f"(agent_forbidden_paths in .pr-verify.yaml)", hit))
    max_files = int(cfg.get("max_changed_files") or 0)
    if max_files and len(prov) > max_files:
        found.append(Violation(
            "change-budget-files",
            f"{len(prov)} files changed, the budget is {max_files} "
            f"(max_changed_files)", sorted(prov)))
    max_lines = int(cfg.get("max_changed_lines") or 0)
    lines = sum(fp.added + fp.removed for fp in prov.values())
    if max_lines and lines > max_lines:
        found.append(Violation(
            "change-budget-lines",
            f"{lines} lines changed, the budget is {max_lines} "
            f"(max_changed_lines)", []))
    if cfg.get("tests_must_change"):
        src = sorted(f for f in prov if is_source(f))
        tests = [f for f in prov if risk_mod._is_test_file(f)]
        if src and not tests:
            found.append(Violation(
                "tests-must-change",
                f"source changed but no test file did: {_names(src)} "
                f"(tests_must_change)", src))
    return found
