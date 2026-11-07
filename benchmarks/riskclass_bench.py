"""Risk-class detection benchmark.

    python benchmarks/riskclass_bench.py            # print the table
    python benchmarks/riskclass_bench.py --json     # machine readable
    python benchmarks/riskclass_bench.py --misses   # list every wrong case

Compares pr-verify's risk-class scanner with the check that 0.2.0 had: the
`sensitive_paths` globs (a file is flagged when its name matches). The
question both answer is "should a person be told this change is risky, and
why?". Cases: benchmarks/riskclass_corpus.py (hand-written by the tool's
author: read the limits in the README).
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)

from pr_verify import config, provenance, risk, riskclass  # noqa: E402
import riskclass_corpus  # noqa: E402


def to_patch(files):
    out = []
    for path, spec in files.items():
        add, rm = spec.get("add", []), spec.get("rm", [])
        out += [f"diff --git a/{path} b/{path}", f"--- a/{path}", f"+++ b/{path}",
                f"@@ -1,{len(rm)} +1,{len(add)} @@"]
        out += ["-" + t for t in rm] + ["+" + t for t in add]
    return "\n".join(out) + "\n"


def run_case(files, ignore=()):
    added, removed = {}, {}
    provenance._walk_patch(to_patch(files), added, removed)
    gone = [p for p, spec in files.items() if spec.get("deleted")]
    found, _ = riskclass.scan(added, removed, deleted=gone,
                              ignore_paths=list(ignore))
    return found


def evaluate():
    sens = config.DEFAULTS["sensitive_paths"]
    rows = []
    per = {c: [0, 0, 0] for c in riskclass.CLASSES}   # tp, fp, fn
    base = [0, 0, 0]
    new = [0, 0, 0]
    exact = 0
    for name, files, expect in riskclass_corpus.C:
        got = {f.cls for f in run_case(files)}
        for c in riskclass.CLASSES:
            tp = c in got and c in expect
            per[c][0] += tp
            per[c][1] += (c in got) and (c not in expect)
            per[c][2] += (c in expect) and (c not in got)
        exact += got == expect
        risky = bool(expect)
        b = bool(risk._sensitive_hits(list(files), sens))
        n = bool(got)
        for acc, pred in ((base, b), (new, n)):
            acc[0] += pred and risky
            acc[1] += pred and not risky
            acc[2] += (not pred) and risky
        rows.append((name, expect, got))
    return rows, per, base, new, exact


def prf(tp, fp, fn):
    p = tp / (tp + fp) if tp + fp else 1.0
    r = tp / (tp + fn) if tp + fn else 1.0
    f = 2 * p * r / (p + r) if p + r else 0.0
    return p, r, f


def main():
    rows, per, base, new, exact = evaluate()
    tp = sum(v[0] for v in per.values())
    fp = sum(v[1] for v in per.values())
    fn = sum(v[2] for v in per.values())
    summary = {
        "cases": len(rows),
        "risky_cases": sum(1 for r in rows if r[1]),
        "exact_match": exact,
        "class_micro": dict(zip(("precision", "recall", "f1"), prf(tp, fp, fn))),
        "any_risk_new": dict(zip(("precision", "recall", "f1"), prf(*new))),
        "any_risk_path_only_0_2_0": dict(zip(("precision", "recall", "f1"), prf(*base))),
        "per_class": {c: dict(zip(("precision", "recall", "f1"), prf(*v)),
                              support=v[0] + v[2])
                      for c, v in per.items()},
    }
    if "--json" in sys.argv:
        print(json.dumps(summary, indent=2))
        return 0
    print(f"cases {summary['cases']} ({summary['risky_cases']} risky), "
          f"exact class-set match {exact}/{len(rows)}")
    print(f"{'':34}{'precision':>10}{'recall':>8}{'f1':>6}")
    for label, key in (("path-only check (0.2.0), any risk", "any_risk_path_only_0_2_0"),
                       ("risk classes, any risk", "any_risk_new"),
                       ("risk classes, class by class (micro)", "class_micro")):
        v = summary[key]
        print(f"{label:34}{v['precision']:>10.2f}{v['recall']:>8.2f}{v['f1']:>6.2f}")
    if "--misses" in sys.argv:
        for name, expect, got in rows:
            if got != expect:
                print(f"  MISS {name}: expected {sorted(expect)} got {sorted(got)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
