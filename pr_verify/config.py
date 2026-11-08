"""Config: .pr-verify.yaml — markers, sensitive paths, gates, thresholds.

Security: the config is read from the BASE REF (the trusted side of the
diff), never from the worktree. A hostile PR must not be able to ship its
own gate config and get it executed on the reviewer's/CI machine.
"""

from __future__ import annotations

import difflib
import json
import subprocess

from . import markers as markers_mod
from . import miniyaml
from . import policy as policy_mod
from . import riskclass

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
        "openhands",
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
    # A gate runs the pull request's code, so it does not inherit environment
    # variables whose names look like secrets (TOKEN, SECRET, PASSWORD, KEY,
    # AUTH ...). List here the names a gate really needs, e.g. [NPM_TOKEN].
    "gate_env_pass": [],
    # Added to agent_markers / sensitive_paths instead of replacing them: the
    # way to add your own bot or your own sensitive folder and keep every
    # default (a list under agent_markers drops them, Claude Code's address
    # included).
    "extra_agent_markers": [],
    "extra_sensitive_paths": [],
    # Declarative rules the tool checks itself (see policy.py); a violation
    # fails the check. Nothing is enforced until you set one.
    "policy": {},
    # git blame sees through re-indents (-w), moves inside a file (-M) and
    # copies from another file of the same commit (-C) when it names who
    # wrote a line. Turn off only if blame is too slow on a huge repository.
    "blame_detect_moves": True,
    # Files whose lines the risk-class scan skips (vendored, generated), and
    # classes it does not report. Names: see riskclass.CLASSES.
    "risk_class_ignore_paths": [],
    "risk_class_off": [],
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
_LIST_FIELDS = ("agent_markers", "sensitive_paths", "gates",
                "extra_agent_markers", "extra_sensitive_paths",
                "risk_class_ignore_paths", "risk_class_off", "gate_env_pass")


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


def _as_bool(key: str, val) -> bool:
    if isinstance(val, bool):
        return val
    text = str(val).strip().lower()
    if text in ("true", "yes", "on", "1"):
        return True
    if text in ("false", "no", "off", "0"):
        return False
    raise ValueError(f"{CONFIG_FILE}: {key} must be true or false, got {val!r}")


def _unknown_setting(key, base: str) -> str:
    """The warning for a key that is not a setting, with the setting it
    looks like when there is one (`gate` -> `gates`, `risk_treshold` ->
    `risk_threshold`; case aside, as the keys are matched exactly)."""
    near = difflib.get_close_matches(
        str(key).casefold(), list(DEFAULTS), n=1, cutoff=0.6)
    guess = f" (did you mean {near[0]!r}?)" if near else ""
    return f"{CONFIG_FILE} at {base}: unknown setting {key!r} is ignored{guess}"


def load(root: str, base: str, warn=None) -> dict:
    """The settings in force: DEFAULTS, then what the file at <base> says.

    A key that is not a setting is not an error (a config that works must
    keep working), but it does nothing, and a silent nothing is how a
    `gate:` that was meant to fail the build never ran. Each one is
    reported through `warn(message)`, if given, and left out of the result."""
    cfg = dict(DEFAULTS)
    for key, val in _read_base_config(root, base).items():
        if key in DEFAULTS:
            cfg[key] = val
        elif warn is not None:
            warn(_unknown_setting(key, base))
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
    # normalize marker matching inputs; the extra_ lists extend, in order,
    # without repeating an entry
    # (the extra_ keys stay in the result as given, for the record)
    cfg["extra_agent_markers"] = [str(m).lower()
                                  for m in cfg["extra_agent_markers"]]
    cfg["extra_sensitive_paths"] = [str(x)
                                    for x in cfg["extra_sensitive_paths"]]
    markers = [str(m).lower() for m in cfg["agent_markers"]]
    cfg["agent_markers"] = list(dict.fromkeys(
        markers + cfg["extra_agent_markers"]))
    paths = [str(x) for x in cfg["sensitive_paths"]]
    cfg["sensitive_paths"] = list(dict.fromkeys(
        paths + cfg["extra_sensitive_paths"]))
    if not any(str(p).strip() for p in cfg["sensitive_paths"]):
        # Fail closed, like the markers below: with no glob the sensitive
        # factor can never score, and an agent rewriting auth.py reads as
        # one touching a README.
        raise ValueError(
            f"{CONFIG_FILE} at {base}: sensitive_paths is empty, so no file "
            f"could count as sensitive - delete the line to get the defaults "
            f"back, or list your globs")
    if not any(markers_mod.effective(m) for m in cfg["agent_markers"]):
        # Fail closed: with no marker no commit can be an agent's, every
        # line reads as human and the score can never see agent code. That
        # is a broken setup, not a clean pull request.
        raise ValueError(
            f"{CONFIG_FILE} at {base}: agent_markers is empty, so no commit "
            f"could be recognised as an agent's - delete the line to get the "
            f"defaults back, or list your markers")
    cfg["gates"] = [_as_gate(g) for g in cfg["gates"]]
    cfg["risk_class_ignore_paths"] = [str(x) for x in cfg["risk_class_ignore_paths"]]
    cfg["risk_class_off"] = [str(x) for x in cfg["risk_class_off"]]
    bad = [c for c in cfg["risk_class_off"] if c not in riskclass.CLASSES]
    if bad:
        raise ValueError(
            f"{CONFIG_FILE} at {base}: risk_class_off names unknown class "
            f"{bad[0]!r} (classes: {', '.join(riskclass.CLASSES)})")
    cfg["blame_detect_moves"] = _as_bool("blame_detect_moves",
                                         cfg["blame_detect_moves"])
    cfg["policy"] = policy_mod.validate(cfg["policy"],
                                        f"{CONFIG_FILE} at {base}")
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
        "# To ADD markers and keep every default, list them here instead:",
        *_yaml_list("extra_agent_markers", DEFAULTS["extra_agent_markers"]),
        "",
        "# Globs for security-sensitive files, matched against the repo-relative",
        "# path and the bare file name, without regard to case.",
        *_yaml_list("sensitive_paths", DEFAULTS["sensitive_paths"]),
        "",
        "# To ADD globs and keep every default, list them here instead:",
        *_yaml_list("extra_sensitive_paths", DEFAULTS["extra_sensitive_paths"]),
        "",
        "# Policy gates: commands run from the repo root, without a shell. A",
        "# failing gate fails the check. None by default; for example:",
        "#   gates:",
        '#     - "python -m pytest -x -q"',
        *_yaml_list("gates", DEFAULTS["gates"]),
        "",
        "# A gate runs the pull request's code, so it does not get environment",
        "# variables whose names look like secrets (TOKEN, SECRET, PASSWORD, KEY,",
        "# AUTH ...). Name the ones a gate really needs, e.g. [NPM_TOKEN].",
        *_yaml_list("gate_env_pass", DEFAULTS["gate_env_pass"]),
        "",
        "# Files the risk-class scan skips (vendored or generated code), and",
        "# classes it should not report (see the README for their names).",
        *_yaml_list("risk_class_ignore_paths", DEFAULTS["risk_class_ignore_paths"]),
        *_yaml_list("risk_class_off", DEFAULTS["risk_class_off"]),
        "",
        "# Policy rules the tool checks itself; a violation fails the check.",
        "# None by default. For example:",
        "#   policy:",
        "#     max_files: 40",
        "#     max_agent_lines: 600",
        "#     require_tests_for_agent_code: true",
        "#     agent_deny_paths:",
        '#       - ".github/workflows/**"',
        "#     deny_classes:",
        "#       - hidden_text",
        "#       - secret",
        "policy:",
        "",
        "# git blame sees through re-indents and moved blocks when it names the",
        "# writer of a line; false turns that off (faster on huge repositories).",
        f"blame_detect_moves: {'true' if DEFAULTS['blame_detect_moves'] else 'false'}",
        "",
        "# The score at which the check fails (score >= this; --min-score",
        "# overrides), and the seconds each gate may take.",
        f"risk_threshold: {DEFAULTS['risk_threshold']}",
        f"timeout: {DEFAULTS['timeout']}",
        "",
    ]
    return "\n".join(lines)
