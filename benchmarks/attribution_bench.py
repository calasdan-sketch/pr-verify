"""Line attribution benchmark: does `provenance.analyze` credit the right lines
to the right writer on synthetic histories?

    python benchmarks/attribution_bench.py            # table
    python benchmarks/attribution_bench.py --json
    python benchmarks/attribution_bench.py --misses   # every wrong line

Every scenario builds a throwaway repository: a base commit, then a pull
request of commits whose authors we choose, and says for each added line of
the final diff who truly wrote it (the ground truth is in the scenario, by
construction). The score is line level: precision and recall of "an agent
wrote this line".

Two groups: `scored` scenarios are things git history can answer; `limits`
are cases no history-based tool can answer (a squash merge that keeps one
author, a human who rewrote an agent's line and committed under the agent's
name) and are printed but not scored, so the headline is not flattered.
Signature names for tools other than Claude Code and Copilot's
`Agent-Logs-Url:` trailer are the author names those tools' pull requests
show publicly; this machine did not run those tools.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

from pr_verify import config, provenance  # noqa: E402

ENV = dict(os.environ, GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1")


def git(tmp, *args):
    return subprocess.run(["git", "-C", tmp, *args], check=True, env=ENV,
                          capture_output=True, text=True).stdout.strip()


def commit(tmp, who, msg, files, committer=None):
    """who = (name, email). files: path -> full text (None deletes)."""
    for rel, text in files.items():
        p = os.path.join(tmp, rel)
        if text is None:
            os.remove(p)
            continue
        os.makedirs(os.path.dirname(p) or tmp, exist_ok=True)
        with open(p, "w", encoding="utf-8", newline="") as f:
            f.write(text)
    git(tmp, "add", "-A")
    c = committer or who
    env = dict(ENV, GIT_AUTHOR_NAME=who[0], GIT_AUTHOR_EMAIL=who[1],
               GIT_COMMITTER_NAME=c[0], GIT_COMMITTER_EMAIL=c[1])
    subprocess.run(["git", "-C", tmp, "commit", "-qm", msg], check=True, env=env,
                   capture_output=True)


H = ("Dan Calas", "dan@example.com")
HUMAN2 = ("Sam Lee", "sam@example.com")
CLAUDE_CODE_TRAILER = "\n\nCo-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>"
AGENTS = {
    "claude-code trailer on a human author": (H, "work" + CLAUDE_CODE_TRAILER),
    "claude as author": (("Claude", "noreply@anthropic.com"), "work"),
    "codex bot": (("chatgpt-codex-connector[bot]", "1+chatgpt-codex-connector[bot]@users.noreply.github.com"), "work"),
    "copilot coding agent": (("copilot-swe-agent[bot]", "198982749+Copilot@users.noreply.github.com"), "work"),
    "copilot Agent-Logs-Url trailer": (H, "work\n\nAgent-Logs-Url: https://github.com/o/r/copilot/tasks/1"),
    "cursor agent": (("Cursor Agent", "cursoragent@cursor.com"), "work"),
    "devin": (("devin-ai-integration[bot]", "158243242+devin-ai-integration[bot]@users.noreply.github.com"), "work"),
    "jules": (("google-labs-jules[bot]", "161369871+google-labs-jules[bot]@users.noreply.github.com"), "work"),
    "aider tag": (("Dan Calas (aider)", "dan@example.com"), "work"),
    "aider subject prefix": (H, "aider: work"),
    "openhands": (("openhands", "openhands@all-hands.dev"), "work"),
    "claude-session trailer": (H, "work\n\nClaude-Session: https://claude.ai/code/session_x"),
}
HUMANS = {
    "Claude Dupont": (("Claude Dupont", "claude.dupont@example.fr"), "work"),
    "Cody Smith": (("Cody Smith", "cody@example.com"), "work"),
    "Tim Abbott": (("Tim Abbott", "tim@example.com"), "work"),
    "Devin Patel": (("Devin Patel", "devin.patel@example.com"), "work"),
    "Jules Verne": (("Jules Verne", "jules@example.com"), "work"),
    "message mentions Claude": (H, "Fix the Claude Code docs page typo"),
    "message mentions cursor": (H, "Fix cursor jump in editor"),
    "pairing sentence": (H, "work\n\nPaired with Claude <noreply@anthropic.com> on the design"),
    "Robert (not a bot)": (("Robert Abbott", "robert@example.com"), "work"),
}


def body(n, indent=""):
    return "".join(f"{indent}line {i}\n" for i in range(n))


def sc_identity(who, msg):
    def build(tmp):
        commit(tmp, H, "base", {"f.py": "x = 0\n"})
        base = git(tmp, "rev-parse", "HEAD")
        commit(tmp, who, msg, {"f.py": "x = 0\nnew_line_a = 1\nnew_line_b = 2\n"})
        return base, {"f.py": {"new_line_a = 1", "new_line_b = 2"}}
    return build


def sc_human_reindents_agent(tmp):
    commit(tmp, H, "base", {"f.py": "def f():\n    pass\n"})
    base = git(tmp, "rev-parse", "HEAD")
    a, _ = AGENTS["claude as author"]
    commit(tmp, ("Claude", "noreply@anthropic.com"), "agent block",
           {"f.py": "def f():\n    pass\n\n\ndef g():\n    a = compute_one()\n    b = compute_two()\n    return a + b\n"})
    commit(tmp, H, "wrap in class (whitespace only)",
           {"f.py": "def f():\n    pass\n\n\nclass K:\n    def g():\n        a = compute_one()\n        b = compute_two()\n        return a + b\n"})
    return base, {"f.py": {"a = compute_one()", "b = compute_two()", "return a + b", "def g():", ""}}


def sc_agent_reindents_human(tmp):
    commit(tmp, H, "base", {"f.py": "x = 0\n"})
    base = git(tmp, "rev-parse", "HEAD")
    commit(tmp, H, "human block", {"f.py": "x = 0\ndef g():\n    a = human_one()\n    b = human_two()\n"})
    commit(tmp, ("Claude", "noreply@anthropic.com"), "reformat",
           {"f.py": "x = 0\nclass K:\n    def g():\n        a = human_one()\n        b = human_two()\n"})
    # the agent wrote `class K:` and nothing else
    return base, {"f.py": {"class K:"}}


def sc_agent_moves_human_block_in_file(tmp):
    commit(tmp, H, "base", {"f.py": "top = 1\n"})
    base = git(tmp, "rev-parse", "HEAD")
    block = "".join(f"human_stmt_{i} = {i}\n" for i in range(6))
    commit(tmp, H, "human block", {"f.py": "top = 1\n" + block + "end = 2\n"})
    commit(tmp, ("Claude", "noreply@anthropic.com"), "move block to the end",
           {"f.py": "top = 1\nend = 2\n" + block})
    return base, {"f.py": {f"human_stmt_{i} = {i}" for i in range(0)} | {"end = 2"}}


def sc_agent_moves_human_block_across_files(tmp):
    block = "".join(f"human_stmt_{i} = {i}\n" for i in range(6))
    commit(tmp, H, "base", {"a.py": "top = 1\n", "b.py": "other = 1\n"})
    base = git(tmp, "rev-parse", "HEAD")
    commit(tmp, H, "human block", {"a.py": "top = 1\n" + block})
    commit(tmp, ("Claude", "noreply@anthropic.com"), "move block to b.py",
           {"a.py": "top = 1\n", "b.py": "other = 1\n" + block})
    return base, {"a.py": set(), "b.py": set()}


def sc_agent_edits_part_of_human_line(tmp):
    commit(tmp, H, "base", {"f.py": "x = 0\n"})
    base = git(tmp, "rev-parse", "HEAD")
    commit(tmp, H, "human", {"f.py": "x = 0\nresult = compute(a, b)\nother_line = 1\n"})
    commit(tmp, ("Claude", "noreply@anthropic.com"), "tweak",
           {"f.py": "x = 0\nresult = compute(a, b, c)\nother_line = 1\n"})
    return base, {"f.py": {"result = compute(a, b, c)"}}


def sc_rebased_agent_commit(tmp):
    commit(tmp, H, "base", {"f.py": "x = 0\n"})
    base = git(tmp, "rev-parse", "HEAD")
    commit(tmp, ("Claude", "noreply@anthropic.com"), "agent work",
           {"f.py": "x = 0\nagent_line = 1\n"}, committer=HUMAN2)
    return base, {"f.py": {"agent_line = 1"}}


def sc_crlf_agent_file(tmp):
    commit(tmp, H, "base", {"f.txt": "a\r\n"})
    base = git(tmp, "rev-parse", "HEAD")
    commit(tmp, ("Claude", "noreply@anthropic.com"), "crlf",
           {"f.txt": "a\r\nagent crlf line\r\n"})
    return base, {"f.txt": {"agent crlf line\r"}}


def sc_mixed_pr(tmp):
    commit(tmp, H, "base", {"f.py": "x = 0\n", "g.py": "y = 0\n"})
    base = git(tmp, "rev-parse", "HEAD")
    commit(tmp, H, "human", {"f.py": "x = 0\nhuman_a = 1\nhuman_b = 2\n"})
    commit(tmp, ("Claude", "noreply@anthropic.com"), "agent",
           {"f.py": "x = 0\nhuman_a = 1\nhuman_b = 2\nagent_a = 3\n", "g.py": "y = 0\nagent_g = 1\n"})
    commit(tmp, HUMAN2, "human again", {"g.py": "y = 0\nagent_g = 1\nhuman_g = 2\n"})
    return base, {"f.py": {"agent_a = 3"}, "g.py": {"agent_g = 1"}}


def sc_squash_keeps_one_author(tmp):
    commit(tmp, H, "base", {"f.py": "x = 0\n"})
    base = git(tmp, "rev-parse", "HEAD")
    commit(tmp, H, "Squashed PR (#7)\n\n* human part\n* agent part\n",
           {"f.py": "x = 0\nhuman_part = 1\nagent_part = 2\n"})
    return base, {"f.py": {"agent_part = 2"}}


def sc_squash_lists_agent_trailer(tmp):
    commit(tmp, H, "base", {"f.py": "x = 0\n"})
    base = git(tmp, "rev-parse", "HEAD")
    commit(tmp, H, "Squashed PR (#7)\n\n* human part\n* agent part\n\n"
           "Co-authored-by: Claude <noreply@anthropic.com>",
           {"f.py": "x = 0\nhuman_part = 1\nagent_part = 2\n"})
    return base, {"f.py": {"agent_part = 2"}}


def sc_human_rewrites_agent_line_under_agent_name(tmp):
    commit(tmp, H, "base", {"f.py": "x = 0\n"})
    base = git(tmp, "rev-parse", "HEAD")
    commit(tmp, H, "human", {"f.py": "x = 0\nhuman_line = 1\n"})
    return base, {"f.py": set()}


SCORED = {}
for _k, (_who, _msg) in AGENTS.items():
    SCORED["agent: " + _k] = sc_identity(_who, _msg)
for _k, (_who, _msg) in HUMANS.items():
    def _b(tmp, _who=_who, _msg=_msg):
        commit(tmp, H, "base", {"f.py": "x = 0\n"})
        base = git(tmp, "rev-parse", "HEAD")
        commit(tmp, _who, _msg, {"f.py": "x = 0\nnew_line_a = 1\nnew_line_b = 2\n"})
        return base, {"f.py": set()}
    SCORED["human: " + _k] = _b
SCORED.update({
    "history: human re-indents agent lines": sc_human_reindents_agent,
    "history: agent re-indents human lines": sc_agent_reindents_human,
    "history: agent moves a human block in a file": sc_agent_moves_human_block_in_file,
    "history: agent moves a human block to another file": sc_agent_moves_human_block_across_files,
    "history: agent edits part of a human line": sc_agent_edits_part_of_human_line,
    "history: rebased agent commit (committer differs)": sc_rebased_agent_commit,
    "history: CRLF file": sc_crlf_agent_file,
    "history: mixed human and agent PR": sc_mixed_pr,
})
LIMITS = {
    "limit: squash keeps one human author, no trailer": sc_squash_keeps_one_author,
    "limit: squash lists an agent trailer for some commits": sc_squash_lists_agent_trailer,
}


def run_scenario(build, markers=None):
    tmp = tempfile.mkdtemp(prefix="prv-attr-")
    try:
        git(tmp, "init", "-qb", "main")
        base, truth = build(tmp)
        head = git(tmp, "rev-parse", "HEAD")
        prov = provenance.analyze(tmp, base, head,
                                  markers or config.DEFAULTS["agent_markers"])
        text = provenance.patch_text(tmp, base, head)[0]
        tp = fp = fn = tn = 0
        wrong = []
        for rel, lines in text.items():
            agent = {text[rel][n].strip() for n in (prov[rel].agent_lines if rel in prov else [])}
            for n, t in lines.items():
                truly = t.strip() in {x.strip() for x in truth.get(rel, set())}
                said = t.strip() in agent
                if truly and said:
                    tp += 1
                elif said:
                    fp += 1
                    wrong.append((rel, t, "credited to an agent, not its work"))
                elif truly:
                    fn += 1
                    wrong.append((rel, t, "agent line missed"))
                else:
                    tn += 1
        return tp, fp, fn, tn, wrong
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def prf(tp, fp, fn):
    p = tp / (tp + fp) if tp + fp else 1.0
    r = tp / (tp + fn) if tp + fn else 1.0
    return p, r, (2 * p * r / (p + r) if p + r else 0.0)


def evaluate():
    rows = []
    tot = [0, 0, 0, 0]
    for group, scen in (("scored", SCORED), ("limits", LIMITS)):
        for name, build in scen.items():
            tp, fp, fn, tn, wrong = run_scenario(build)
            rows.append((group, name, tp, fp, fn, tn, wrong))
            if group == "scored":
                for i, v in enumerate((tp, fp, fn, tn)):
                    tot[i] += v
    return rows, tot


def main():
    rows, tot = evaluate()
    p, r, f = prf(*tot[:3])
    scored = [x for x in rows if x[0] == "scored"]
    ok = sum(1 for x in scored if not x[6])
    summary = {"scenarios": len(scored), "scenarios_exact": ok,
               "lines": sum(tot), "precision": p, "recall": r, "f1": f,
               "wrong": {x[1]: [w[1:] for w in x[6]] for x in rows if x[6]}}
    if "--json" in sys.argv:
        print(json.dumps(summary, indent=2))
        return 0
    print(f"scored scenarios {len(scored)}, exactly right {ok}; "
          f"lines {sum(tot)}: precision {p:.3f} recall {r:.3f} f1 {f:.3f}")
    for g, name, tp, fp, fn, tn, wrong in rows:
        if wrong and ("--misses" in sys.argv or g == "limits"):
            print(f"  [{g}] {name}")
            for rel, t, why in wrong:
                print(f"      {rel}: {t.strip()!r} - {why}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
