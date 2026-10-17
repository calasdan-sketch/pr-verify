"""Config: .pr-verify.yaml — markers, sensitive paths, gates, thresholds.

Security: the config is read from the BASE REF (the trusted side of the
diff), never from the worktree. A hostile PR must not be able to ship its
own gate config and get it executed on the reviewer's/CI machine.
"""

from __future__ import annotations

import os
import subprocess

from . import miniyaml

CONFIG_FILE = ".pr-verify.yaml"

DEFAULTS = {
    # Substrings matched (case-insensitive) against commit author name/email
    # and message to classify a commit as agent-authored.
    "agent_markers": [
        "claude", "codex", "cursor", "copilot", "bot",
        "co-authored-by: claude", "aider", "cody",
    ],
    # Globs (repo-relative) for security-sensitive areas.
    "sensitive_paths": [
        "**/auth*/**", "**/*auth*.py",
        "**/crypto*/**", "**/*crypt*.py",
        "**/payment*/**", "**/billing*/**",
        "**/migrations/**", "**/migrate/**",
        "**/*secret*", "**/*password*", "**/*token*", "**/*key*.py",
    ],
    # Policy gates: commands run from the repo root, WITHOUT a shell
    # (each command is split with shlex into an argv list). Keep them to
    # plain executables with arguments — no pipes, redirects, or $VARs.
    "gates": [],
    # "gates": ["python -m pytest -x -q"],
    "risk_threshold": 70,   # score >= this fails (see risk.gate); --min-score overrides
    "timeout": 300,         # seconds per gate
}


def _read_base_config(root: str, base: str) -> dict:
    """Return the parsed config file as committed at <base>, or {}."""
    p = subprocess.run(
        ["git", "-C", root, "show", f"{base}:{CONFIG_FILE}"],
        capture_output=True, text=True, encoding="utf-8",
        errors="replace", timeout=15)
    if p.returncode != 0:
        return {}
    try:
        return miniyaml.safe_load(p.stdout) or {}
    except ValueError as e:
        raise RuntimeError(
            f"invalid {CONFIG_FILE} at {base}: {e} "
            f"(supported: plain mappings/lists/scalars, no anchors or "
            f"multi-line scalars)") from e


_INT_FIELDS = {"risk_threshold": (0, 100), "timeout": (1, None)}
_LIST_FIELDS = ("agent_markers", "sensitive_paths", "gates")


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
    cfg["gates"] = [str(g) for g in cfg["gates"]]
    return cfg


def example_config() -> str:
    return """# PR Verify config. All fields optional; shown with defaults.
agent_markers:
  - claude
  - codex
  - cursor
  - copilot
  - bot
sensitive_paths:
  - "**/auth*/**"
  - "**/migrations/**"
  - "**/*secret*"
gates:
  - "python -m pytest -x -q"
risk_threshold: 70
timeout: 300
"""
