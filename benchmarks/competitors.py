"""Run three open-source scanners on the same corpus, for a side-by-side.

    python -m venv /tmp/v && /tmp/v/bin/pip install detect-secrets bandit zizmor
    /tmp/v/bin/python benchmarks/competitors.py

zizmor (GitHub Actions) is installed by the line above but not scored: it
refuses fragments of a workflow ("no audit was performed"), and the corpus
holds diff fragments, not whole files.

Each tool answers a narrower question than pr-verify, so each is scored only
on its own: detect-secrets on "is a secret committed", bandit on "is this Python line an unsafe call"
(unsafe_exec, weak_crypto, weak_control, over .py files only). A tool is
given the added lines of each case written to files. Cases are the same
hand-written ones as riskclass_bench.py; read its limits.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)
import riskclass_bench as rb  # noqa: E402
import riskclass_corpus as corpus  # noqa: E402

BIN = os.path.dirname(sys.executable)


def exe(name):
    p = os.path.join(BIN, name)
    return p if os.path.exists(p) else shutil.which(name)


def materialize(files, root):
    for path, spec in files.items():
        full = os.path.join(root, path)
        os.makedirs(os.path.dirname(full) or root, exist_ok=True)
        with open(full, "w", encoding="utf-8") as f:
            f.write("\n".join(spec.get("add", [])) + "\n")


def detect_secrets(root):
    out = subprocess.run([exe("detect-secrets"), "scan", "--all-files", "."],
                         cwd=root, capture_output=True, text=True).stdout
    return bool(json.loads(out or "{}").get("results"))


def zizmor(root):
    wf = os.path.join(root, ".github", "workflows")
    if not os.path.isdir(wf):
        return False
    r = subprocess.run([exe("zizmor"), "--offline", "--format", "json", wf],
                       capture_output=True, text=True)
    try:
        return bool(json.loads(r.stdout or "[]"))
    except ValueError:
        return r.returncode not in (0,)


def bandit(root):
    r = subprocess.run([exe("bandit"), "-r", "-q", "-f", "json", root],
                       capture_output=True, text=True)
    try:
        return bool(json.loads(r.stdout).get("results"))
    except ValueError:
        return False


def prf(tp, fp, fn):
    p = tp / (tp + fp) if tp + fp else 1.0
    r = tp / (tp + fn) if tp + fn else 1.0
    return p, r


def main():
    tasks = {
        "secret": (detect_secrets, lambda files: True, {"secret"}),
        "unsafe python call": (bandit, lambda files: any(p.endswith(".py") for p in files),
                               {"unsafe_exec", "weak_crypto", "weak_control"}),
    }
    for name, (fn, eligible, classes) in tasks.items():
        mine = [0, 0, 0]
        theirs = [0, 0, 0]
        for case, files, expect in corpus.C:
            if not eligible(files):
                continue
            truth = bool(expect & classes)
            if name.startswith("ci_workflow"):
                # zizmor judges safety, not "changed": only the unsafe ones count
                truth = any("injection" in f.why or "pull_request_target" in f.why
                            or "pinned" in f.why or "write" in f.why
                            for f in rb.run_case(files) if f.cls == "ci_workflow") or \
                    bool(expect & {"permissions", "test_weakening"} and "ci_workflow" in expect)
            got_mine = any(f.cls in classes for f in rb.run_case(files)) if not name.startswith("ci_") \
                else any(f.cls == "ci_workflow" and f.severity != "medium" or
                         (f.cls == "ci_workflow" and "pinned" in f.why) for f in rb.run_case(files))
            d = tempfile.mkdtemp()
            try:
                materialize(files, d)
                got_theirs = fn(d)
            finally:
                shutil.rmtree(d, ignore_errors=True)
            for acc, got in ((mine, got_mine), (theirs, got_theirs)):
                acc[0] += got and truth
                acc[1] += got and not truth
                acc[2] += (not got) and truth
        pm, rm = prf(*mine)
        pt, rt = prf(*theirs)
        print(f"{name:32} pr-verify P {pm:.2f} R {rm:.2f} | tool P {pt:.2f} R {rt:.2f}")


if __name__ == "__main__":
    main()
