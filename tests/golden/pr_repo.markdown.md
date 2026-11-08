## PR Verify: risk 57/100 (MEDIUM)

**✅ pass** - score 57 < min-score 70

Base ` <sha40> ` · merge-base ` <sha> ` · head ` HEAD `

### Risk factors

| Factor | Points | Detail |
|---|---:|---|
| agent_share | 28 | ` 9/13 added lines agent-authored (69%) ` |
| blast | 4 | ` largest blast radius: 1 downstream dependent(s) ` |
| sensitive | 20 | ` sensitive files touched: app/auth.py ` |
| gates | 0 | ` no gates configured ` |
| no_tests | 5 | ` source changed with no test changes ` |
| deletion | 0 | ` no agent-attributed deletions ` |
| risk_classes | 0 | ` no risk class found in the changed lines ` |

### Policy gates

None configured.

### Review plan

**standard**, at least 1 reviewer(s).

Read first:

- ` app/core.py:7-10 ` - agent_written: ` 4 line(s) written by an agent; 1 dependent(s) `
- ` app/auth.py:3-6 ` - agent_written: ` 4 line(s) written by an agent `
- ` app/views.py:1 ` - agent_written: ` 1 line(s) written by an agent `

### Provenance

9/13 added lines agent-authored

| | File | Agent lines | Agents |
|---|---|---|---|
| agent | ` app/auth.py ` | 4/4 added | ` claude-bot (claude) ` |
| mixed | ` app/core.py ` | 4/8 added | ` claude-bot (claude) ` |
| agent | ` app/views.py ` | 1/1 added | ` claude-bot (claude) ` |

### Blast radius

- ` app/core.py `: 1 downstream dependent(s)
  - direct: ` app/views.py `
- ` app/auth.py `: 0 downstream dependent(s)
- ` app/views.py `: 0 downstream dependent(s)

---
<sub>pr-verify 0.3.0: deterministic, no LLM. `--format json` has every number.</sub>
