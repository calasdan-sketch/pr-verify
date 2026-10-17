"""Policy gates: run configured commands, capture pass/fail.

Security: commands are executed WITHOUT a shell. Each gate string is
split with shlex into an argv list and run directly, so shell
metacharacters (;, &&, $(), backticks, pipes) are passed as literal
arguments and never interpreted. Gate config itself is loaded from the
base ref (see config.py), never from the worktree under review.
"""

from __future__ import annotations

import dataclasses
import shlex
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


def run_gates(root: str, commands: list[str],
              timeout: int = 300) -> list[GateResult]:
    results: list[GateResult] = []
    for cmd in commands:
        if not cmd or not cmd.strip():
            continue
        argv = shlex.split(cmd)
        if not argv:
            continue
        try:
            p = subprocess.run(argv, shell=False, cwd=root,
                               capture_output=True, text=True,
                               encoding="utf-8", errors="replace",
                               timeout=timeout)
            tail = (p.stdout + p.stderr)[-2000:]
            results.append(GateResult(
                command=cmd, passed=p.returncode == 0,
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
                command=cmd, passed=False, returncode=-1,
                output_tail=out[-2000:], timed_out=True))
        except (OSError, ValueError) as e:
            # argv[0] not found / not executable: a failed gate, not a crash.
            results.append(GateResult(
                command=cmd, passed=False, returncode=127,
                output_tail=f"gate could not run: {e}"[-2000:]))
    return results
