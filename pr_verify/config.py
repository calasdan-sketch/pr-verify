"""Config: .pr-verify.yaml — markers, sensitive paths, gates, thresholds.

Security: the config is read from the BASE REF (the trusted side of the
diff), never from the worktree. A hostile PR must not be able to ship its
own gate config and get it executed on the reviewer's/CI machine.
"""

from __future__ import annotations

import json
import os
import subprocess

from . import miniyaml

CONFIG_FILE = ".pr-verify.yaml"

DEFAULTS = {
    # Agent markers, matched on WHOLE WORDS (see markers.py) against the
    # commit author name and email, Co-Authored-By/Generated-by trailers
    # and a `marker:` subject prefix -- never against free message text.
    # A bot-shaped author ("claude-bot", "Claude", "dan (aider)",
    # "dependabot[bot]") matches on any word; a human-shaped "First Last"
    # name only matches a marker covering the whole name ("Claude Code"),
    # so "Claude Dupont", "Cody Smith" and "Tim Abbott" stay human. If your
    # team has a human called Cody or Claude who commits as a single word,
    # drop that marker and rely on trailers. The last one is an exact
    # address (it has an @), in trailers only: Claude Code signs its commits
    # `Co-Authored-By: Claude <model name> <noreply@anthropic.com>`, and the
    # model name changes with every release.
    "agent_markers": [
        "claude", "claude code", "codex", "cursor", "cursor agent",
        "copilot", "github copilot", "bot", "aider", "cody", "devin",
        "co-authored-by: noreply@anthropic.com",
    ],
    # Globs (repo-relative) for security-sensitive areas. Matched against
    # the full path and the bare filename (fnmatch), without regard to case
    # (Login.tsx, PASSWORD.txt). Word-ish on purpose:
    # "*auth*" also caught author.py, "*token*" tokenizer.py and "*key*"
    # monkey.py -- these do not.
    "sensitive_paths": [
        "**/auth/**", "**/auth.*", "**/auth_*", "**/*_auth.*",
        "**/authn*", "**/authz*", "**/authentication*", "**/authorization*",
        "**/oauth*", "**/login*",
        "**/crypto/**", "**/crypto.*", "**/crypt_*", "**/*_crypt.*",
        "**/encrypt*", "**/decrypt*", "**/cipher*",
        "**/payment*", "**/billing*",
        "**/migrations/**", "**/migrate/**", "**/migrate.*",
        "**/*secret*", "**/*credential*", "**/*password*", "**/*passwd*",
        "**/*apikey*", "**/*api_key*", "**/*_key.*", "**/*token.*",
        "**/.env", "**/.env.*",
    ],
    # Policy gates: commands run from the repo root, WITHOUT a shell. A
    # string is split into an argv list (POSIX rules; Windows rules on
    # Windows, so C:\paths keep their backslashes) and argv[0] is looked
    # up with shutil.which (so `npx`/`npm`/`tsc` .cmd shims are found on
    # Windows); a YAML list is used as the argv as-is. Keep them to plain
    # executables with arguments — no pipes, redirects, or $VARs.
    "gates": [],
    # "gates": ["python -m pytest -x -q"],
    "risk_threshold": 70,   # score >= this fails (see risk.gate); --min-score overrides
    "timeout": 300,         # seconds per gate
}


#: The byte-order marks of UTF-16 text (little- and big-endian). No UTF-8
#: text starts with either byte.
_UTF16_MARKS = (b"\xff\xfe", b"\xfe\xff")


def _read_base_config(root: str, base: str) -> dict:
    """Return the parsed config file as committed at <base>, or {}.

    The file is UTF-8 text; a byte-order mark in front of it (Notepad's
    "UTF-8", PowerShell's `Set-Content -Encoding utf8`) is not part of the
    first key. UTF-16 text (what PowerShell's `>` writes) is refused by
    name: read as UTF-8 it is a screenful of NULs."""
    p = subprocess.run(
        ["git", "-C", root, "show", f"{base}:{CONFIG_FILE}"],
        capture_output=True, timeout=15)
    if p.returncode != 0:
        return {}
    if p.stdout[:2] in _UTF16_MARKS:
        raise RuntimeError(
            f"invalid {CONFIG_FILE} at {base}: the file is UTF-16 text "
            f"(PowerShell's > writes that) - save it as UTF-8")
    text = p.stdout.decode("utf-8-sig", errors="replace")
    try:
        data = miniyaml.safe_load(text) or {}
    except ValueError as e:
        if "list item inside mapping" in str(e):
            # `key:` and then `- x` at the same indent: valid YAML (it is
            # how PyYAML writes lists) that the shared reader does not take
            hint = ("indent the list items under their key, two spaces "
                    "more than the `key:` line")
        else:
            hint = ("supported: plain mappings/lists/scalars, no anchors or "
                    "multi-line scalars")
        raise RuntimeError(
            f"invalid {CONFIG_FILE} at {base}: {e} ({hint})") from e
    if not isinstance(data, dict):
        kind = "a list" if isinstance(data, list) else type(data).__name__
        raise RuntimeError(
            f"invalid {CONFIG_FILE} at {base}: it must be a mapping of "
            f"settings (risk_threshold: 70), not {kind}")
    return data


_INT_FIELDS = {"risk_threshold": (0, 100), "timeout": (1, None)}
_LIST_FIELDS = ("agent_markers", "sensitive_paths", "gates")


def _as_gate(g) -> str | list[str]:
    """A gate is a command string or an argv list of strings."""
    if isinstance(g, list):
        if not g or not all(isinstance(x, (str, int, float)) for x in g):
            raise ValueError(
                f"{CONFIG_FILE}: a gate given as a list must be a non-empty "
                f"list of strings, got {g!r}")
        return [str(x) for x in g]
    return str(g)


def _as_int(key: str, val, lo: int | None, hi: int | None) -> int:
    """Coerce a config number. A YAML-quoted "70" must behave like 70, and
    garbage must fail with a clear message instead of a TypeError when
    the gate compares it to the score."""
    if isinstance(val, bool) or val is None:
        raise ValueError(f"{CONFIG_FILE}: {key} must be an integer, got {val!r}")
    try:
        num = int(str(val).strip())
    except ValueError:
        raise ValueError(
            f"{CONFIG_FILE}: {key} must be an integer, got {val!r}") from None
    if (lo is not None and num < lo) or (hi is not None and num > hi):
        rng = f"{lo}..{hi}" if hi is not None else f">= {lo}"
        raise ValueError(f"{CONFIG_FILE}: {key} must be {rng}, got {num}")
    return num


def load(root: str, base: str) -> dict:
    cfg = dict(DEFAULTS)
    for key, val in _read_base_config(root, base).items():
        cfg[key] = val
    for key, (lo, hi) in _INT_FIELDS.items():
        cfg[key] = _as_int(key, cfg[key], lo, hi)
    for key in _LIST_FIELDS:
        val = cfg.get(key)
        if val is None:
            cfg[key] = []
        elif isinstance(val, str):
            cfg[key] = [val]
        elif not isinstance(val, list):
            raise ValueError(f"{CONFIG_FILE}: {key} must be a list, got {val!r}")
    # normalize marker matching inputs
    cfg["agent_markers"] = [str(m).lower() for m in cfg["agent_markers"]]
    cfg["sensitive_paths"] = [str(x) for x in cfg["sensitive_paths"]]
    cfg["gates"] = [_as_gate(g) for g in cfg["gates"]]
    return cfg


def _yaml_list(key: str, items: list) -> list[str]:
    """`key:` and one double-quoted entry per item (JSON strings are YAML
    strings, and an entry like `co-authored-by: x` needs the quotes)."""
    if not items:
        return [f"{key}: []"]
    return [f"{key}:"] + [f"  - {json.dumps(str(item))}" for item in items]


def example_config() -> str:
    """The text `pr-verify init` writes: DEFAULTS, written out in full, so
    that committing it changes nothing (it used to carry a handful of the
    markers and globs and switch the rest off)."""
    lines = [
        "# PR Verify config. All fields optional; shown with their defaults.",
        "# A list given here REPLACES the default list, it does not extend it:",
        "# delete a field to get its default back.",
        "# This file is read from the BASE ref of the diff (not the worktree), so",
        "# commit it to your base branch for it to take effect.",
        "",
        "# Names that mark a commit as written by an agent: matched on whole",
        "# words in the author, in Co-Authored-By / Generated-by trailers and in",
        "# a subject prefix. An entry with an @ is one exact e-mail address, and",
        "# an entry starting with co-authored-by: only counts in trailers.",
        *_yaml_list("agent_markers", DEFAULTS["agent_markers"]),
        "",
        "# Globs for security-sensitive files, matched against the repo-relative",
        "# path and the bare file name, without regard to case.",
        *_yaml_list("sensitive_paths", DEFAULTS["sensitive_paths"]),
        "",
        "# Policy gates: commands run from the repo root, without a shell. A",
        "# failing gate fails the check. None by default; for example:",
        "#   gates:",
        '#     - "python -m pytest -x -q"',
        *_yaml_list("gates", DEFAULTS["gates"]),
        "",
        "# The score at which the check fails (score >= this; --min-score",
        "# overrides), and the seconds each gate may take.",
        f"risk_threshold: {DEFAULTS['risk_threshold']}",
        f"timeout: {DEFAULTS['timeout']}",
        "",
    ]
    return "\n".join(lines)
