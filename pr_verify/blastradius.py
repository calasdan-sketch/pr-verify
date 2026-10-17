"""Blast radius: who depends on the changed files?

Builds a module import graph for the repo (Python via AST, other languages
via heuristic regex), inverts it, and for each changed file reports the
transitive set of dependents — the code that could break if the change is
wrong. Standalone: no dependency on sibling packages.

Python import resolution (deterministic, no execution):
  - absolute imports: `import a.b`, `from a.b import c` resolve to a/b.py
    (or a/b/__init__.py) and, for `from a.b import c`, also to a/b/c.py
    when c is a submodule rather than a name;
  - relative imports: `from . import x`, `from ..core import y` are
    resolved against the importing file's own package path, so a module
    that is only reached through relative imports still shows up as a
    dependent;
  - layouts: a file is indexed under every dotted suffix of its path
    (src/pkg/core.py -> src.pkg.core, pkg.core, core), so `src/` layouts,
    namespace dirs and bare-name imports resolve. Over-approximating a
    dependent is the safe direction for a trust tool.
"""

from __future__ import annotations

import ast
import dataclasses
import os
import re

PY_EXTS = {".py"}
OTHER_EXTS = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs",
              ".go", ".rs", ".java", ".rb", ".php"}
#: File types whose imports are read; nothing else is in the graph.
SCANNED_EXTS = PY_EXTS | OTHER_EXTS
#: Directories the scan never enters.
SKIP_DIRS = frozenset({".git", "node_modules", "__pycache__", ".venv", "venv",
                       "dist", "build", ".tox", "vendor"})

_GENERIC_IMPORT_RES = [
    re.compile(r'^\s*import\s+(?:type\s+)?[{*]?[^"\']*?from\s+["\']([^"\']+)["\']'),
    re.compile(r'^\s*import\s+["\']([^"\']+)["\']'),
    re.compile(r'require\(\s*["\']([^"\']+)["\']\s*\)'),
    re.compile(r'^\s*use\s+([a-zA-Z0-9_:]+)(?:::|\s*[{;])'),
]


def _module_path(rel: str) -> list[str]:
    """Dotted parts of a file's own module path: a/b/c.py -> [a, b, c];
    a/b/__init__.py -> [a, b]."""
    base = rel.replace(os.sep, "/")
    if base.endswith("/__init__.py"):
        base = base[: -len("/__init__.py")]
    elif base == "__init__.py":
        return []
    elif base.endswith(".py"):
        base = base[: -len(".py")]
    return [p for p in base.split("/") if p]


def _package_of(rel: str) -> list[str]:
    """Dotted parts of the package a Python file belongs to (what a
    single-dot relative import is resolved against)."""
    parts = _module_path(rel)
    if rel.replace(os.sep, "/").endswith("__init__.py"):
        return parts          # a package's __init__ is the package itself
    return parts[:-1]


def _python_imports(rel: str, content: str) -> list[str]:
    """Dotted names a Python file may depend on (absolute form)."""
    try:
        tree = ast.parse(content)
    except (SyntaxError, ValueError):
        return []
    pkg = _package_of(rel)
    mods: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            mods.extend(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                # relative: climb (level - 1) packages from our own package
                up = node.level - 1
                if up > len(pkg):
                    continue  # beyond the repo root: unresolvable
                base = pkg[: len(pkg) - up] if up else list(pkg)
                if node.module:
                    base = base + node.module.split(".")
                if not base:
                    continue
            else:
                if not node.module:
                    continue
                base = node.module.split(".")
            dotted = ".".join(base)
            mods.append(dotted)
            # `from pkg import mod` may name a submodule file: resolve it too
            for alias in node.names:
                if alias.name != "*":
                    mods.append(f"{dotted}.{alias.name}")
    return mods


def _imports_of(path: str, content: str, rel: str | None = None) -> list[str]:
    ext = os.path.splitext(path)[1].lower()
    if ext in PY_EXTS:
        return _python_imports(rel if rel is not None else path, content)
    if ext in OTHER_EXTS:
        mods = []
        for line in content.splitlines():
            for rx in _GENERIC_IMPORT_RES:
                m = rx.search(line)
                if m:
                    mods.append(m.group(1))
                    break
        return mods
    return []


def _module_candidates(rel: str) -> list[str]:
    """Dotted names a file might be imported as, most specific first:
    src/pkg/core.py -> src.pkg.core, pkg.core, core (every dotted suffix,
    so src/ layouts and bare-name imports resolve); a/b.py -> a.b, b."""
    base = rel.replace(os.sep, "/")
    if base.endswith(".py"):
        parts = _module_path(base)
    else:
        parts = [p for p in base.rsplit(".", 1)[0].split("/") if p]
    if not parts:
        return []
    return [".".join(parts[i:]) for i in range(len(parts))]


@dataclasses.dataclass
class BlastRadius:
    file: str
    direct: list[str]          # files directly importing it
    transitive: list[str]      # all downstream dependents
    external_only: bool = False  # changed file imported by nothing in-repo
    #: How the file was covered: "graph" (it is in the import graph) or why
    #: it is not -- "not_source" (a file type the scan does not read; no
    #: dependents are guessed for it), "not_in_worktree" (deleted, or absent
    #: from the checked-out tree), "skipped_dir" (under node_modules,
    #: vendor, build ...) or "not_scanned" (on disk, but the walk never
    #: reached it).
    scan: str = "graph"

    @property
    def size(self) -> int:
        return len(self.transitive)


def _iter_files(root: str) -> list[str]:
    out = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in filenames:
            if os.path.splitext(fn)[1].lower() in SCANNED_EXTS:
                out.append(os.path.join(dirpath, fn))
    return sorted(out)


def skipped_dir(rel: str) -> str | None:
    """The first directory in rel's path that the scan skips, or None."""
    return next((p for p in rel.split("/")[:-1] if p in SKIP_DIRS), None)


def _scan_status(root: str, rel: str) -> str:
    """Why the changed file rel is not in the import graph (BlastRadius.scan).
    A type the scan does not read comes first: whether such a file is still
    on disk is beside the point, imports of it are never looked for."""
    if os.path.splitext(rel)[1].lower() not in SCANNED_EXTS:
        return "not_source"
    if not os.path.lexists(os.path.join(root, *rel.split("/"))):
        return "not_in_worktree"
    if skipped_dir(rel):
        return "skipped_dir"
    return "not_scanned"


def build_graph(root: str) -> dict[str, set[str]]:
    """rel path -> set of rel paths it imports (in-repo only)."""
    files = _iter_files(root)
    rels = [os.path.relpath(p, root).replace(os.sep, "/") for p in files]
    # index: dotted name -> rel
    index: dict[str, str] = {}
    for rel in rels:
        for cand in _module_candidates(rel):
            index.setdefault(cand, rel)
    graph: dict[str, set[str]] = {rel: set() for rel in rels}
    for path, rel in zip(files, rels):
        try:
            with open(path, encoding="utf-8", errors="replace") as f:
                content = f.read()
        except OSError:
            continue
        for mod in _imports_of(path, content, rel):
            target = index.get(mod)
            if target and target != rel:
                graph[rel].add(target)
    return graph


def dependents_of_modules(root: str, module_names: set[str]) -> list[str]:
    """rel paths in the current worktree importing any of module_names.

    Used for changed files absent from the worktree (e.g. deleted files):
    the normal graph can't resolve them, so match the raw imported module
    strings instead. Over-approximates on bare-name matches (e.g. "core");
    for a trust tool, flagging a possibly-broken dependent beats silence.
    """
    if not module_names:
        return []
    out = []
    for path in _iter_files(root):
        rel = os.path.relpath(path, root).replace(os.sep, "/")
        try:
            with open(path, encoding="utf-8", errors="replace") as f:
                content = f.read()
        except OSError:
            continue
        if set(_imports_of(path, content, rel)) & module_names:
            out.append(rel)
    return sorted(out)


def _transitive_dependents(reverse: dict[str, set[str]],
                           direct: list[str], rel: str) -> list[str]:
    seen = set(direct)
    stack = list(direct)
    while stack:
        cur = stack.pop()
        for nxt in reverse.get(cur, ()):
            if nxt not in seen:
                seen.add(nxt)
                stack.append(nxt)
    seen.discard(rel)
    return sorted(seen)


def analyze(root: str, changed: list[str]) -> dict[str, BlastRadius]:
    graph = build_graph(root)
    # invert
    reverse: dict[str, set[str]] = {rel: set() for rel in graph}
    for src, deps in graph.items():
        for dep in deps:
            reverse[dep].add(src)
    result: dict[str, BlastRadius] = {}
    for rel in changed:
        if rel in reverse:
            direct = sorted(reverse[rel])
            transitive = _transitive_dependents(reverse, direct, rel)
            result[rel] = BlastRadius(file=rel, direct=direct,
                                      transitive=transitive)
            continue
        # Not in the worktree graph (deleted, unknown or unscanned file):
        # fall back to matching the file's module names against the raw
        # imports of every file still in the worktree, so deleted imports
        # still show their (now broken) dependents. Only a file that can be
        # imported has a module name: config.yaml is not the module
        # `config`, so it gets no guessed dependents.
        scan = _scan_status(root, rel)
        direct = ([] if scan == "not_source" else
                  dependents_of_modules(root, set(_module_candidates(rel))))
        transitive = _transitive_dependents(reverse, direct, rel)
        result[rel] = BlastRadius(file=rel, direct=direct,
                                  transitive=transitive,
                                  external_only=not direct, scan=scan)
    return result
