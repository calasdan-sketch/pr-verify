# PR Verify

Deterministic trust for agent-authored PRs. Not another AI reviewer —
**verification, not opinion.** Agents now write more code than seniors can
review; this tells a senior exactly how deep to review, from observable
facts: which lines an agent wrote, what could break, and whether policy
gates pass.

## Install

```bash
git clone <repo> && cd pr-verify
pip install .   # provides the `pr-verify` console script
```

Or run without installing: `python3 -m pr_verify` from the repo root.

## Quick start

```bash
cd your-repo
python3 -m pr_verify init        # write an example .pr-verify.yaml
python3 -m pr_verify check --base main
```

## What it reports

**Provenance** — every added line labeled agent/human via `git blame` +
commit-author analysis (configurable markers: claude, codex, cursor,
copilot, bot…). Per file: `agent` / `mixed` / `human`, with the detected
agent identities.

**Blast radius** — reverse dependency graph: for each changed file, the
transitive set of in-repo dependents that could break. Python via AST;
JS/TS/Go/Rust/Java/Ruby/PHP via heuristic fallback.

**Policy gates** — commands from `.pr-verify.yaml` (tests, typecheck,
lint), run with timeout, pass/fail captured. The config is read from the
base ref (never the worktree under review) and gates run **without** a
shell — `;`, `&&`, `$()`, pipes and the rest are literal arguments, never
interpreted. A failing gate fails the verification (nonzero exit).

**Risk score** — deterministic 0–100 from six public factors:

| Factor | Max | What it measures |
|---|---|---|
| agent_share | 40 | % of added lines agent-authored |
| blast | 25 | log-scaled transitive dependents |
| sensitive | 20 | changed files under sensitive globs (auth, crypto, payments, migrations…); deleted files match like touched ones |
| gates | 10 | any policy gate failed |
| no_tests | 5 | source changed with no test changes |
| deletion | 50 | agent-attributed deletions: 45 if any deleted file is sensitive, else 10 for deleting tracked files at all, plus log-scaled points for the deleted files' dependents — pure-deletion PRs can trip the threshold too |

Bands: 0–29 low · 30–69 medium · 70–100 high. The formula is documented so
teams can argue with it and tune it — a black-box score is just another
opinion.

## CI

```bash
python3 -m pr_verify check --base origin/main --format json --fail-on high
```

`--fail-on high` (default) exits 1 when score ≥ `risk_threshold` (70).
`--fail-on any-risk` / `--fail-on never` available. A GitHub Action is
included at `.github/workflows/pr-verify.yml`.

## Example output

```
════════════════════════════════════════════════════════
  PR VERIFY  risk 57/100 (MEDIUM)
════════════════════════════════════════════════════════

  provenance: 9/13 added lines agent-authored
    agent   app/auth.py (4/4 agent) [claude-bot]
    mixed   app/core.py (4/8 agent) [claude-bot]
    agent   app/views.py (1/1 agent) [claude-bot]

  blast radius:
    app/core.py: 1 downstream dependent(s)
      direct: app/views.py

  risk factors:
     28 pts  agent_share  9/13 added lines agent-authored (69%)
      4 pts  blast        largest blast radius: 1 downstream dependent(s)
     20 pts  sensitive    sensitive files touched: app/auth.py
      0 pts  gates        no gates configured
      5 pts  no_tests     source changed with no test changes

  ✓ score 57 < threshold 70
════════════════════════════════════════════════════════
```

## Honest limits

- Provenance depends on commit authorship — squashed or rebased PRs lose
  per-commit attribution (tune `agent_markers` for your workflow).
  Uncommitted working-tree changes are included in `check`, but with no
  commit to blame they are counted as human-written, never agent-written.
- Non-Python blast-radius extraction is heuristic.
- The risk formula is a starting point, not a verdict — tune the threshold
  per team.

## Tests

55/55 pass: `python3 -m unittest discover -s tests`
