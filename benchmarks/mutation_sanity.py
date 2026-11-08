"""Mutation sanity: does the fast test subset notice when a key condition is
flipped? Each mutation edits one line of a COPY of the package, runs the
subset, and must see a failure ("killed"). A mutation that survives means a
test is missing. Run: python benchmarks/mutation_sanity.py

Not a full mutation tester (no automatic mutant generation): a hand-picked
list of the conditions that decide verdicts, secrets handling and escaping.
"""

import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SUBSET = ["test_units", "test_miniyaml", "test_gate", "test_r5_experts",
          "test_expert2", "test_cli"]

MUTATIONS = [
    ("risk.py", "total = min(100, sum(", "total = min(1000, sum("),
    ("risk.py", "round(cap * min(1.0, math.log10(1 + n) / 2))",
     "round(cap * min(2.0, math.log10(1 + n) / 2))"),
    ("markers.py", "        return body_words == mw", "        return body_words != mw"),
    ("markers.py", "if github_bot:\n        local_part = True", "if False:\n        local_part = True"),
    ("markers.py", "return email.strip().lower() == marker.strip().lower()",
     "return True"),
    ("textsafe.py", "0x2028, 0x2029, *range(0x202A, 0x202F),", "0x2029, *range(0x202A, 0x202F),"),
    ("textsafe.py", "*range(0x7F, 0xA0),", "*range(0x80, 0xA0),"),
    ("gates.py", "if k.casefold() in keep or not _SECRET_NAME.search(k)}",
     "if k.casefold() in keep or _SECRET_NAME.search(k)}"),
    ("gates.py", "passed=(rc == 0 and not timed_out)", "passed=(rc == 0 or timed_out)"),
    ("gates.py", "stdin=subprocess.DEVNULL", "stdin=None"),
    ("gates.py", "os.killpg(proc.pid, signal.SIGKILL)", "pass"),
    ("gates.py", "while size - len(chunks[0]) >= _TAIL_BYTES:",
     "while False:"),
    ("pathglob.py", "pat[p] == \"?\" or pat[p] == name[n]", "pat[p] == name[n]"),
    ("config.py", "\"gate_env_pass\": [],", "\"gate_env_pass\": [\"X\"],"),
    ("cli.py", "gate_results = (gates_mod.run_gates(root, cfg[\"gates\"], cfg[\"timeout\"],\n                                         cfg[\"gate_env_pass\"])",
     "gate_results = (gates_mod.run_gates(root, cfg[\"gates\"], cfg[\"timeout\"])"),
]


def run_subset(work: str) -> bool:
    """True when every test in the subset passes."""
    for name in SUBSET:
        p = subprocess.run(
            [sys.executable, "-m", "unittest", "discover", "-s", "tests",
             "-p", name + ".py"], cwd=work, capture_output=True, text=True)
        if p.returncode != 0:
            return False
    return True


def main() -> int:
    survived = []
    ran = 0
    for fname, old, new in MUTATIONS:
        if new is None:
            continue
        work = tempfile.mkdtemp(prefix="prv-mut-")
        try:
            shutil.copytree(os.path.join(ROOT, "pr_verify"),
                            os.path.join(work, "pr_verify"),
                            ignore=shutil.ignore_patterns("__pycache__"))
            shutil.copytree(os.path.join(ROOT, "tests"), os.path.join(work, "tests"),
                            ignore=shutil.ignore_patterns("__pycache__"))
            path = os.path.join(work, "pr_verify", fname)
            with open(path, encoding="utf-8") as f:
                src = f.read()
            if src.count(old) != 1:
                print(f"SKIP  {fname}: pattern not found exactly once: {old[:50]!r}")
                continue
            with open(path, "w", encoding="utf-8", newline="") as f:
                f.write(src.replace(old, new))
            ran += 1
            ok = run_subset(work)
            print(("SURVIVED " if ok else "killed   ") + f"{fname}: {old[:60]!r}")
            if ok:
                survived.append((fname, old))
        finally:
            shutil.rmtree(work, ignore_errors=True)
    print(f"\n{ran - len(survived)}/{ran} mutations killed")
    return 1 if survived else 0


if __name__ == "__main__":
    sys.exit(main())
