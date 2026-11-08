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

import collections
import dataclasses
import os
import re
import shlex
import shutil
import subprocess
import threading


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


#: Environment variables a gate does not inherit: anything whose name says it
#: holds a token, a secret, a password, a credential, a key or an auth
#: socket (GITHUB_TOKEN, ACTIONS_RUNTIME_TOKEN, AWS_SECRET_ACCESS_KEY,
#: NPM_TOKEN, SSH_AUTH_SOCK ...). A gate runs the pull request's own code
#: (a test file is code), so whatever is in its environment is readable by
#: the PR. `gate_env_pass` in the config lets a named variable through.
_SECRET_NAME = re.compile(
    r"TOKEN(?!IZERS)|SECRET|PASSW|CREDENTIAL|PRIVATE_?KEY|API_?KEY|"
    r"ACCESS_?KEY|SESSION_?KEY|(^|_)AUTH(_|$)|_KEY$|^KEY$|BEARER|COOKIE|"
    r"AUTHORIZATION", re.IGNORECASE)

#: How much of a gate's output is kept while it runs (the report shows the
#: last 2,000 characters). A test run that prints gigabytes costs this much.
_TAIL_BYTES = 64 * 1024
OUTPUT_TAIL_CHARS = 2000


def gate_env(passthrough=(), environ=None) -> dict:
    """The environment a gate runs in: the current one without the variables
    whose names look like secrets (see _SECRET_NAME), except those named in
    `passthrough` (compared without regard to case)."""
    env = os.environ if environ is None else environ
    keep = {str(n).casefold() for n in passthrough or ()}
    return {k: v for k, v in env.items()
            if k.casefold() in keep or not _SECRET_NAME.search(k)}


def stripped_names(passthrough=(), environ=None) -> list[str]:
    """Names of the variables gate_env leaves out, sorted."""
    env = os.environ if environ is None else environ
    kept = gate_env(passthrough, env)
    return sorted(k for k in env if k not in kept)


def _kill_tree(proc) -> None:
    """Kill the gate and what it started (its process group on POSIX,
    taskkill /T on Windows); never raises."""
    try:
        if os.name == "nt":
            subprocess.run(["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                           capture_output=True, timeout=15)
        else:
            import signal
            os.killpg(proc.pid, signal.SIGKILL)
    except (OSError, subprocess.SubprocessError):
        pass
    try:
        proc.kill()
    except OSError:
        pass


def _run_one(argv, root, timeout, env):
    """(returncode, tail text, timed_out). stdout and stderr share one pipe,
    so their lines stay in the order the gate wrote them; only the last
    _TAIL_BYTES are kept, so a gate that prints without end cannot fill
    memory. A timeout kills the whole process group (POSIX) / tree (Windows),
    so a grandchild that holds the pipe cannot make the run outlive it."""
    kwargs = {}
    if os.name != "nt":
        kwargs["start_new_session"] = True
    proc = subprocess.Popen(
        argv, shell=False, cwd=root, env=env, stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, **kwargs)
    chunks: collections.deque = collections.deque()
    size = 0

    def pump():
        nonlocal size
        try:
            while True:
                data = proc.stdout.read1(65536)
                if not data:
                    return
                chunks.append(data)
                size += len(data)
                while size - len(chunks[0]) >= _TAIL_BYTES:
                    size -= len(chunks.popleft())
        except (OSError, ValueError):
            return

    reader = threading.Thread(target=pump, daemon=True)
    reader.start()
    timed_out = False
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        _kill_tree(proc)
        proc.wait()
    reader.join(timeout=5)
    if reader.is_alive():
        try:
            proc.stdout.close()
        except OSError:
            pass
    text = b"".join(chunks)[-_TAIL_BYTES:].decode("utf-8", errors="replace")
    return (-1 if timed_out else proc.returncode), text[-OUTPUT_TAIL_CHARS:], timed_out


def run_gates(root: str, commands: list, timeout: int = 300,
              env_pass=()) -> list[GateResult]:
    results: list[GateResult] = []
    env = gate_env(env_pass)
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
            rc, tail, timed_out = _run_one(argv, root, timeout, env)
            results.append(GateResult(
                command=shown, passed=(rc == 0 and not timed_out),
                returncode=rc, output_tail=tail, timed_out=timed_out))
        except (OSError, ValueError) as e:
            # argv[0] not found / not executable: a failed gate, not a crash.
            results.append(GateResult(
                command=shown, passed=False, returncode=127,
                output_tail=f"gate could not run: {e}"[-2000:]))
    return results
