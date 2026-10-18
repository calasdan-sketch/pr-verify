"""Blast radius: who depends on the changed files?

Builds a module import graph for the repo (Python via AST; JavaScript,
TypeScript, Java and Ruby by reading their import lines), inverts it, and for
each changed file reports the transitive set of dependents — the code that
could break if the change is wrong. Other languages are not scanned: a
changed file of one says so (scan "not_source"), it does not claim "0
dependents". Standalone: no dependency on sibling packages.

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

JavaScript and TypeScript (.js .jsx .ts .tsx .mjs .cjs .mts .cts): the module
names are the ones written in `import ... from`, `export ... from`,
`import '...'`, `import('...')` and `require('...')`, one line at a time (a
clause that spans lines is found at its last line, `} from '...'`). A name
that starts with ./ or ../ (or is . or ..) is resolved against the directory
of the importing file: with an extension it is that file, and a .js/.jsx/
.mjs/.cjs name also finds the .ts/.tsx/.mts/.cts source TypeScript compiles
it from; without one every file of that name with one of the script
extensions (and .d.ts) counts, or, when there is none, the index file of
the directory of that name. Anything else (a package, a baseUrl path, a
tsconfig alias) is not followed to a path: only a name that is the file name
of a script, without its extension, finds that script, wherever it is.

Ruby (.rb): `require_relative 'x'` is x.rb, relative to the requiring file.
Java (.java): `import a.b.C;` (also `import static a.b.C.m;`) is the file whose
path ends in a/b/C.java, and `import a.b.*;` is every file directly in a
directory whose path ends in a/b. What needs no import (a class of the same
Java package) is not seen.

The worktree is read ONCE per run (_scan): the graph and the dependents of
every deleted file are both worked out from that one pass. And only regular
files are opened, and only up to MAX_SOURCE_BYTES: a pull request can bring a
link to /dev/zero named evil.py, and a worktree can hold a named pipe.
"""

from __future__ import annotations

import ast
import dataclasses
import os
import posixpath
import re
import stat

PY_EXTS = {".py"}
#: JavaScript and TypeScript, in every spelling of the extension.
JS_EXTS = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".mts", ".cts"}
#: The other file types whose imports are read: those of a language whose
#: import names a path by itself (Java: package = directory; Ruby:
#: require_relative). Go, Rust, PHP and the rest need the build's configuration
#: (go.mod, Cargo.toml, composer.json) to say where an import points, and are
#: not scanned.
OTHER_EXTS = JS_EXTS | {".java", ".rb"}
#: File types whose imports are read; nothing else is in the graph.
SCANNED_EXTS = PY_EXTS | OTHER_EXTS
#: Directories the scan never enters.
SKIP_DIRS = frozenset({".git", "node_modules", "__pycache__", ".venv", "venv",
                       "dist", "build", ".tox", "vendor"})
#: A source file larger than this is not read for imports (a generated
#: bundle or a data dump with a source extension): it stays in the graph,
#: with nothing that it imports. The read itself stops one byte past this.
MAX_SOURCE_BYTES = 4 * 1024 * 1024

#: The ways a line of JavaScript or TypeScript names a module. Each is tried on
#: one line at a time, and none of them can be made to rescan a line from many
#: starting points: reading a file stays linear in its size, however a pull
#: request writes it (a test feeds them the shapes that would not).
_JS_IMPORT_RES = (
    # import x from 'm' | import {a} from "m" | export * from 'm' | export {a} from 'm'
    re.compile(r'^\s*(?:import|export)\b[^\'"`]*?\bfrom\s*["\']([^"\']+)["\']'),
    # the last line of an import or export clause that began above: } from 'm'
    re.compile(r'^\s*\}\s*from\s*["\']([^"\']+)["\']'),
    # import 'm'
    re.compile(r'^\s*import\s*["\']([^"\']+)["\']'),
    # import('m')
    re.compile(r'\bimport\s*\(\s*["\']([^"\']+)["\']\s*\)'),
    # require('m')
    re.compile(r'\brequire\s*\(\s*["\']([^"\']+)["\']\s*\)'),
)
_RUBY_IMPORT_RE = re.compile(
    r'^\s*require_relative\b\s*\(?\s*["\']([^"\']+)["\']')
#: import a.b.C; | import static a.b.C.m; | import a.b.*;
_JAVA_IMPORT_RE = re.compile(
    r'^\s*import\s+(?:static\s+)?'
    r'([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*(?:\.\*)?)\s*;')


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
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        # RecursionError / MemoryError: source nested or chained too deep
        # for the parser (a SyntaxError on some versions, not on others)
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
        regexes = (_JS_IMPORT_RES if ext in JS_EXTS else
                   (_RUBY_IMPORT_RE,) if ext == ".rb" else (_JAVA_IMPORT_RE,))
        mods = []
        for line in content.splitlines():
            for rx in regexes:
                mods.extend(m.group(1) for m in rx.finditer(line))
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


#: Extensions a JavaScript/TypeScript import may leave out, and the index
#: files of a directory with them.
_JS_RESOLVE_EXTS = (".ts", ".tsx", ".d.ts", ".js", ".jsx", ".mjs", ".cjs",
                    ".mts", ".cts")
#: TypeScript's ESM way to name a file: `import './b.js'` is b.ts (or b.tsx),
#: the file the compiler turns into b.js.
_TS_SOURCES = {".js": (".ts", ".tsx"), ".jsx": (".tsx",),
               ".mjs": (".mts",), ".cjs": (".cts",)}


def _ext(rel: str) -> str:
    return posixpath.splitext(rel)[1].lower()


def _beside(importer: str, spec: str) -> str:
    """`spec`, a path relative to the directory of `importer` (a repo-relative
    path), as a path from the repository root. One that leaves the repository
    starts with ../ (or is absolute) and so is the path of no file in it."""
    return posixpath.normpath(posixpath.join(posixpath.dirname(importer), spec))


def _js_wants(importer: str, spec: str) -> list[list[str]]:
    """The files a JavaScript/TypeScript specifier may mean, as groups in
    order of preference: the first group that has a file in the repository is
    the import. Only ./ and ../ names (and . and ..) are paths."""
    if spec not in (".", "..") and not spec.startswith(("./", "../")):
        return []
    base = _beside(importer, spec)
    prefix = "" if base == "." else base + "/"
    index = [prefix + "index" + e for e in _JS_RESOLVE_EXTS]
    if spec.endswith("/"):          # './lib/' is the directory, as in Node
        return [index]
    stem, ext = posixpath.splitext(base)
    files: list[str] = []
    if ext.lower() in JS_EXTS:
        files.append(base)
        files.extend(stem + src for src in _TS_SOURCES.get(ext.lower(), ()))
    files.extend(base + e for e in _JS_RESOLVE_EXTS)
    return [files, index]


def _ruby_wants(importer: str, spec: str) -> list[list[str]]:
    base = _beside(importer, spec)
    return [[base if base.endswith(".rb") else base + ".rb"]]


def _java_wants(spec: str) -> list[list[str]]:
    """a.b.C -> the class a.b.C; a.b.C.m (a static import) or a.b.C.D (a
    nested class) -> the longest of those that is a class; a.b.* -> the
    package a.b, or else the class a.b (a static wildcard). Never the first
    word alone: of org.junit.Assert that would be any file called org.java."""
    if spec.endswith(".*"):
        package = spec[:-2]
        groups = [["javadir:" + package]]
        if "." in package:
            groups.append(["java:" + package])
        return groups
    parts = spec.split(".")
    return [["java:" + ".".join(parts[:n])] for n in range(len(parts), 1, -1)]


def _wants(importer: str, spec: str) -> list[list[str]]:
    """Lookup keys (see _keys) of the files the import `spec` of `importer`
    may mean, in groups of descending preference. Python is not here: its
    names go through the dotted index."""
    ext = _ext(importer)
    if ext in JS_EXTS:
        return _js_wants(importer, spec)
    if ext == ".rb":
        return _ruby_wants(importer, spec)
    if ext == ".java":
        return _java_wants(spec)
    return []


def _keys(rel: str) -> list[str]:
    """The lookup keys a file answers to for the imports of _wants: itself
    (JavaScript, Ruby), or every dotted suffix of its path as a class and of
    its directory as a package (Java)."""
    ext = _ext(rel)
    if ext in JS_EXTS or ext == ".rb":
        return [rel]
    if ext == ".java":
        parts = [p for p in rel.rsplit(".", 1)[0].split("/") if p]
        package = parts[:-1]
        return (["java:" + ".".join(parts[i:]) for i in range(len(parts))] +
                ["javadir:" + ".".join(package[i:])
                 for i in range(len(package))])
    return []


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


def _is_regular(path: str) -> bool:
    """A regular file: not a link (to a file, a directory, a device ...), not
    a named pipe, not a device. Opening a link to /dev/zero reads for ever,
    opening a pipe blocks for ever, and a pull request can bring the link.
    Links to directories are not followed either (os.walk)."""
    try:
        return stat.S_ISREG(os.lstat(path).st_mode)
    except OSError:
        return False


def _iter_files(root: str) -> list[str]:
    out = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in filenames:
            if os.path.splitext(fn)[1].lower() in SCANNED_EXTS:
                path = os.path.join(dirpath, fn)
                if _is_regular(path):
                    out.append(path)
    return sorted(out)


def _read_source(path: str) -> str | None:
    """The text of a source file, or None when it is not read: bigger than
    MAX_SOURCE_BYTES, or unreadable. A UTF-8 byte order mark (Windows
    editors write one) is not part of the text: the parser rejects it."""
    try:
        with open(path, "rb") as f:
            data = f.read(MAX_SOURCE_BYTES + 1)
    except (OSError, MemoryError):
        return None
    if len(data) > MAX_SOURCE_BYTES:
        return None
    return data.decode("utf-8-sig", "replace")


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


def _scan(root: str) -> tuple[list[str], dict[str, list[str]]]:
    """Read the worktree: (rel paths of its source files, rel path -> the
    module names that file imports, as written). Everything below is worked
    out from this, so a file is read and parsed once per run, not once more
    for every deleted file."""
    rels: list[str] = []
    imports: dict[str, list[str]] = {}
    for path in _iter_files(root):
        rel = os.path.relpath(path, root).replace(os.sep, "/")
        rels.append(rel)
        content = _read_source(path)
        imports[rel] = ([] if content is None
                        else _imports_of(path, content, rel))
    return rels, imports


def _graph(rels: list[str],
           imports: dict[str, list[str]]) -> dict[str, set[str]]:
    """rel path -> set of rel paths it imports (in-repo only)."""
    # index: dotted name -> rel
    index: dict[str, str] = {}
    scripts: dict[str, str] = {}     # script file name (no extension) -> rel
    by_key: dict[str, list[str]] = {}
    for rel in rels:
        for cand in _module_candidates(rel):
            index.setdefault(cand, rel)
        if _ext(rel) in JS_EXTS:
            scripts.setdefault(
                posixpath.splitext(posixpath.basename(rel))[0], rel)
        for key in _keys(rel):
            by_key.setdefault(key, []).append(rel)
    graph: dict[str, set[str]] = {rel: set() for rel in rels}
    for rel in rels:
        ext = _ext(rel)
        for mod in imports[rel]:
            if ext in PY_EXTS:
                found = [index[mod]] if mod in index else []
            else:
                found = []
                groups = _wants(rel, mod)
                for group in groups:
                    found = [t for key in group for t in by_key.get(key, ())]
                    if found:
                        break
                if not groups and ext in JS_EXTS and mod in scripts:
                    # a name without ./ : a package, an alias ... or a script
                    # of that name somewhere in the repository
                    found = [scripts[mod]]
            graph[rel].update(t for t in found if t != rel)
    return graph


def _importers(imports: dict[str, list[str]]) -> dict[str, set[str]]:
    """Module name, as written in an import -> the files that import it."""
    out: dict[str, set[str]] = {}
    for rel, mods in imports.items():
        for mod in mods:
            out.setdefault(mod, set()).add(rel)
    return out


def _importing(importers: dict[str, set[str]],
               module_names: set[str]) -> list[str]:
    """rel paths importing any of module_names (see dependents_of_modules)."""
    found: set[str] = set()
    for name in module_names:
        found.update(importers.get(name, ()))
    return sorted(found)


def _wanting(imports: dict[str, list[str]]) -> dict[str, set[str]]:
    """Lookup key (see _keys) -> the files that import something that may
    mean it, in any group. The graph has only files that exist; this is how
    a file that does not exist any more (deleted) finds the files that still
    import it."""
    out: dict[str, set[str]] = {}
    for rel, mods in imports.items():
        for mod in mods:
            for group in _wants(rel, mod):
                for key in group:
                    out.setdefault(key, set()).add(rel)
    return out


def build_graph(root: str) -> dict[str, set[str]]:
    """rel path -> set of rel paths it imports (in-repo only)."""
    return _graph(*_scan(root))


def dependents_of_modules(root: str, module_names: set[str]) -> list[str]:
    """rel paths in the current worktree importing any of module_names.

    Used for changed files absent from the worktree (e.g. deleted files):
    the normal graph can't resolve them, so match the raw imported module
    strings instead. Over-approximates on bare-name matches (e.g. "core");
    for a trust tool, flagging a possibly-broken dependent beats silence.
    """
    if not module_names:
        return []
    _, imports = _scan(root)
    return _importing(_importers(imports), module_names)


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
    rels, imports = _scan(root)         # the one read of the worktree
    graph = _graph(rels, imports)
    importers = _importers(imports)
    # invert
    reverse: dict[str, set[str]] = {rel: set() for rel in graph}
    for src, deps in graph.items():
        for dep in deps:
            reverse[dep].add(src)
    wanting: dict[str, set[str]] | None = None   # worked out when needed
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
        if scan == "not_source":
            direct = []
        else:
            found = set(_importing(importers, set(_module_candidates(rel))))
            keys = _keys(rel)
            if keys:
                if wanting is None:
                    wanting = _wanting(imports)
                for key in keys:
                    found |= wanting.get(key, set())
            direct = sorted(found)
        transitive = _transitive_dependents(reverse, direct, rel)
        result[rel] = BlastRadius(file=rel, direct=direct,
                                  transitive=transitive,
                                  external_only=not direct, scan=scan)
    return result
