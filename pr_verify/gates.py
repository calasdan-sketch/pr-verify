"""Policy gates: run configured commands, capture pass/fail.

Security: commands are executed WITHOUT a shell. Each gate string is
split into an argv list and run directly, so shell metacharacters (;, &&,
$(), backticks, pipes) are passed as literal arguments and never
interpreted. Gate config itself is loaded from the base ref (see
config.py), never from the worktree under review.

Windows: `shlex.split` in POSIX mode eats the backslashes of an unquoted
`C:\\Python311\\python.exe`, so the split follows the platform
(`posix=False` on Windows, with the surrounding quotes shlex leaves on
tokens stripped), and argv[0] is resolved with `shutil.which` because
CreateProcess does not look up PATHEXT shims (`npx.cmd`, `npm.cmd`,
`tsc.cmd`). A gate may also be given as a YAML list, which is used as the
argv without any splitting.
"""

from __future__ import annotations

import dataclasses
import os
import shlex
import shutil
import subprocess


@dataclasses.dataclass
class GateResult:
    command: str
    passed: bool
    returncode: int
    output_tail: str
    timed_out: bool = False

    def as_dict(self) -> dict:
        return dataclasses.asdict(self)


def _strip_quotes(tok: str) -> str:
    if len(tok) >= 2 and tok[0] == tok[-1] and tok[0] in "\"'":
        return tok[1:-1]
    return tok


def split_command(cmd: str | list[str]) -> list[str]:
    """Gate -> argv. Strings are split by the platform's rules; lists are
    taken as-is."""
    if isinstance(cmd, list):
        return [str(x) for x in cmd]
    posix = os.name != "nt"
    argv = shlex.split(cmd, posix=posix)
    if not posix:
        argv = [_strip_quotes(a) for a in argv]
    return argv


def resolve_executable(argv: list[str]) -> list[str]:
    """argv with argv[0] looked up on PATH (PATHEXT-aware on Windows).
    Unresolvable names are left alone so the OS error names them."""
    if not argv:
        return argv
    found = shutil.which(argv[0])
    if found:
        return [found, *argv[1:]]
    return argv


def display(cmd: str | list[str]) -> str:
    if isinstance(cmd, list):
        return " ".join(cmd)
    return cmd


def run_gates(root: str, commands: list,
              timeout: int = 300) -> list[GateResult]:
    results: list[GateResult] = []
    for cmd in commands:
        if not cmd or (isinstance(cmd, str) and not cmd.strip()):
            continue
        try:
            argv = resolve_executable(split_command(cmd))
        except ValueError as e:
            results.append(GateResult(
                command=display(cmd), passed=False, returncode=127,
                output_tail=f"gate could not be parsed: {e}"[-2000:]))
            continue
        if not argv:
            continue
        shown = display(cmd)
        try:
            p = subprocess.run(argv, shell=False, cwd=root,
                               capture_output=True, text=True,
                               encoding="utf-8", errors="replace",
                               timeout=timeout)
            tail = (p.stdout + p.stderr)[-2000:]
            results.append(GateResult(
                command=shown, passed=p.returncode == 0,
                returncode=p.returncode, output_tail=tail))
        except subprocess.TimeoutExpired as e:
            out = ""
            if e.stdout:
                out += e.stdout.decode(errors="replace") \
                    if isinstance(e.stdout, bytes) else e.stdout
            if e.stderr:
                err = e.stderr.decode(errors="replace") \
                    if isinstance(e.stderr, bytes) else e.stderr
                out += err
            results.append(GateResult(
                command=shown, passed=False, returncode=-1,
                output_tail=out[-2000:], timed_out=True))
        except (OSError, ValueError) as e:
            # argv[0] not found / not executable: a failed gate, not a crash.
            results.append(GateResult(
                command=shown, passed=False, returncode=127,
                output_tail=f"gate could not run: {e}"[-2000:]))
    return results
