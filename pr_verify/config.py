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
    "risk_threshold": 70,   # >= this => exit 1 (needs senior review)
    "timeout": 300,         # seconds per gate
}


def _read_base_config(root: str, base: str) -> dict:
    """Return the parsed config file as committed at <base>, or {}."""
    p = subprocess.run(
        ["git", "-C", root, "show", f"{base}:{CONFIG_FILE}"],
        capture_output=True, text=True, timeout=15)
    if p.returncode != 0:
        return {}
    try:
        return miniyaml.safe_load(p.stdout) or {}
    except ValueError as e:
        raise RuntimeError(
            f"invalid {CONFIG_FILE} at {base}: {e} "
            f"(supported: plain mappings/lists/scalars, no anchors or "
            f"multi-line scalars)") from e


def load(root: str, base: str) -> dict:
    cfg = dict(DEFAULTS)
    for key, val in _read_base_config(root, base).items():
        cfg[key] = val
    # normalize marker matching inputs
    cfg["agent_markers"] = [m.lower() for m in cfg.get("agent_markers", [])]
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
