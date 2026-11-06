"""The Markdown report: `check --format markdown`, and the GitHub Actions job
summary the Action writes to $GITHUB_STEP_SUMMARY.

Everything a pull request controls -- file names, author names, the output
of a gate -- is Markdown the PR's author wrote, and GitHub renders it: a
name like `![x](https://tracker.example/p.png)` would load an image from
their server for everyone who opens the run, `[click](https://...)` would be
a link that reads as ours, `<details open>` or a stray `|` would reshape the
report. So no such text is ever written as Markdown. It goes into a code
span (inline) or a fenced code block (a gate's output), where GitHub shows it
literally: no link, no image, no HTML, no autolink. The fence is always
longer than any run of backticks in the text, so the text cannot close it,
and in a table a `|` is escaped as `\\|`, the one escape GFM reads inside a
code span in a table cell. A backslash in a cell is written as the escape
\\x5c first: GitHub's cmark-gfm reads `\\\\|` as a backslash and an
escaped `|`, but a Markdown reader that reads it as an escaped backslash and
a real `|` would end the cell there, and a name like `x\\|![i](https://...)`
would put an image in the next one. (Defensive: the report may be pasted
into GitLab, Gitea or a wiki.)
Control and bidirectional characters are shown
as the same escapes as in the human report (textsafe.py), a newline as
\\x0a.

Size: the report stays under MAX_CHARS. GitHub takes up to 1 MiB of step
summary per step and far less in a pull request comment, which is where a
`--format markdown` report usually goes; a pull request that touches
thousands of files lists the first MAX_FILES of them, says how many it left
out, and points at `--format json` for all of them.
"""

from __future__ import annotations

import os
import re

from . import blastradius as br_mod
from .textsafe import neutralize

#: The report never grows past this many characters (a PR comment body must
#: stay under GitHub's limit, which is lower than a step summary's).
MAX_CHARS = 60_000
#: Rows in the files table and entries in the blast radius list.
MAX_FILES = 100
MAX_BLAST = 8
#: A name longer than this is shortened in the middle.
MAX_NAME = 200
#: Lines of a failed gate's output that are shown, and for how many gates.
MAX_GATE_LINES = 30
MAX_GATE_OUTPUTS = 5

_BACKTICKS = re.compile(r"`+")


def _plain(text) -> str:
    """One line of untrusted text with nothing a reader acts on."""
    return neutralize(str(text)).replace("\n", "\\x0a").replace("\r", "\\x0d")


def _shorten(text: str, limit: int = MAX_NAME) -> str:
    if len(text) <= limit:
        return text
    keep = (limit - 1) // 2
    return text[:keep] + "…" + text[-keep:]


#: Notes and factor details are sentences, longer than a name.
MAX_SENTENCE = 1000


def code(text, table: bool = False, limit: int = MAX_NAME) -> str:
    """text as an inline code span that nothing in it can end or escape.

    The fence is one backtick more than the longest run in the text, and
    the text is padded with a space on each side (CommonMark strips exactly
    one from each side, so a text that starts or ends with a backtick still
    works). In a table cell a `|` would end the cell: it is written `\\|`,
    after every backslash is written \\x5c (see the module's docstring)."""
    text = str(text)
    if table:
        # before the other escapes, whose backslashes are always followed
        # by x or u and so never pair with a |
        text = text.replace("\\", "\\x5c")
    body = _shorten(_plain(text), limit)
    if table:
        body = body.replace("|", "\\|")
    longest = max((len(m) for m in _BACKTICKS.findall(body)), default=0)
    fence = "`" * (longest + 1)
    return f"{fence} {body} {fence}"


def fenced(text: str, max_lines: int = MAX_GATE_LINES) -> list[str]:
    """Lines of a fenced code block holding text (its last max_lines
    lines). The fence is longer than any run of backticks in the text, so no
    line of it can close the block; a ~~~ line cannot either, a block opened
    with backticks is only closed by backticks."""
    # \r\n (a gate on Windows) is one line end, not a \x0d on every line
    lines = [_plain(line.rstrip("\r")).rstrip()
             for line in str(text).split("\n")]
    while lines and not lines[-1]:
        lines.pop()
    if len(lines) > max_lines:
        lines = [f"… ({len(lines) - max_lines} earlier line(s) not shown)"] \
            + lines[-max_lines:]
    longest = max((len(m) for line in lines
                   for m in _BACKTICKS.findall(line)), default=0)
    fence = "`" * max(3, longest + 1)
    return [fence + "text", *lines, fence]


def blast_note(b) -> str:
    """Why a changed file shows no dependents when the scan could not see
    it, or "" (shared with the human report)."""
    if not b.external_only:
        return ""
    if b.scan == "not_source":
        ext = os.path.splitext(b.file)[1].lower()
        what = f"{ext} files are" if ext else "this file type is"
        return f"{what} not scanned for imports"
    if b.scan == "not_in_worktree":
        why = "not in the worktree"
    elif b.scan == "skipped_dir":
        why = f"in {br_mod.skipped_dir(b.file)}/, which the import scan skips"
    else:
        why = "not reached by the import scan"
    return f"{why}; nothing in-repo imports it"


def verdict(result) -> tuple[bool, str]:
    """(passed, sentence) -- the same verdict as the exit status."""
    br, min_score = result.breakdown, result.min_score
    failed = [g.command for g in result.gates if not g.passed]
    if failed:
        return False, "policy gate failed"
    if min_score is None:
        return True, f"score {br.score}: score gate disabled (--fail-on never)"
    if br.requires_review:
        return False, (f"score {br.score} >= min-score {min_score}: needs "
                       f"senior review")
    return True, f"score {br.score} < min-score {min_score}"


def _header(result) -> list[str]:
    br = result.breakdown
    passed, why = verdict(result)
    mark = "✅ pass" if passed else "❌ fail"
    base = code(result.payload["base"])
    if result.base_detected:
        base += " (auto-detected)"
    fork = result.payload.get("merge_base")
    lines = [f"## PR Verify: risk {br.score}/100 ({br.band.upper()})", "",
             f"**{mark}** - {why}", "",
             f"Base {base}" + (f" · merge-base {code(fork[:12])}" if fork
                               else "")
             + f" · head {code(result.payload['head'])}"]
    for note in result.notes:
        lines += ["", f"> **note:** {code(note, limit=MAX_SENTENCE)}"]
    return lines


def _factors(result) -> list[str]:
    lines = ["", "### Risk factors", "", "| Factor | Points | Detail |",
             "|---|---:|---|"]
    for name, fac in result.breakdown.factors.items():
        lines.append(f"| {name} | {fac['points']} | "
                     f"{code(fac['detail'], table=True, limit=MAX_SENTENCE)} |")
    return lines


def _files(result) -> list[str]:
    prov = result.prov
    total_added = sum(f.added for f in prov.values())
    agent_added = sum(f.agent_added for f in prov.values())
    total_removed = sum(f.removed for f in prov.values())
    agent_removed = sum(f.agent_removed for f in prov.values())
    summary = f"{agent_added}/{total_added} added lines agent-authored"
    if total_removed:
        summary += f"; {agent_removed}/{total_removed} removed lines"
    lines = ["", "### Provenance", "", summary, "",
             "| | File | Agent lines | Agents |", "|---|---|---|---|"]
    names = sorted(prov)
    for rel in names[:MAX_FILES]:
        f = prov[rel]
        if f.deleted:
            who = ", ".join(f.deleted_by) or "unknown"
            lines.append(f"| deleted | {code(rel, True)} | - | "
                         f"{code(who, True)} |")
            continue
        if not (f.added or f.removed):
            continue
        counts = f"{f.agent_added}/{f.added} added" if f.added else ""
        if f.removed:
            gone = f"{f.agent_removed}/{f.removed} removed"
            counts = f"{counts}, {gone}" if counts else gone
        who = ", ".join(sorted(f.agents)) if f.agents else "human"
        lines.append(f"| {f.label()} | {code(rel, True)} | {counts} | "
                     f"{code(who, True)} |")
    if len(names) > MAX_FILES:
        lines += ["", f"… and {len(names) - MAX_FILES} more file(s): "
                      f"`--format json` lists all of them."]
    return lines


def _blast(result) -> list[str]:
    lines = ["", "### Blast radius", ""]
    ranked = sorted(result.blast.values(), key=lambda b: b.size,
                    reverse=True)[:MAX_BLAST]
    if not ranked:
        lines.append("No files changed.")
    for b in ranked:
        note = blast_note(b)
        line = f"- {code(b.file)}: {b.size} downstream dependent(s)"
        if note:
            line += f" ({note})"
        lines.append(line)
        if b.direct:
            shown = ", ".join(code(d) for d in b.direct[:5])
            more = f" and {len(b.direct) - 5} more" if len(b.direct) > 5 else ""
            lines.append(f"  - direct: {shown}{more}")
    return lines


def _gates(result) -> list[str]:
    lines = ["", "### Policy gates", ""]
    if not result.gates:
        lines.append("None configured.")
        return lines
    for g in result.gates:
        mark = "PASS" if g.passed else ("TIMEOUT" if g.timed_out else "FAIL")
        lines.append(f"- **{mark}** {code(g.command)}")
    failed = [(i, g) for i, g in enumerate(result.gates, 1) if not g.passed]
    for i, g in failed[:MAX_GATE_OUTPUTS]:
        lines += ["", f"<details><summary>Output of gate {i} (exit "
                      f"{int(g.returncode)})</summary>", ""]
        lines += fenced(g.output_tail or "(no output)")
        lines += ["", "</details>"]
    if len(failed) > MAX_GATE_OUTPUTS:
        lines += ["", f"The output of {len(failed) - MAX_GATE_OUTPUTS} more "
                      f"failed gate(s) is in `--format json`."]
    return lines


def render(result) -> str:
    """The whole report, a string that ends with a newline."""
    from . import cli    # the version, without an import cycle at load time
    footer = ["", "---", f"<sub>pr-verify {cli.VERSION}: deterministic, no "
                         f"LLM. `--format json` has every number.</sub>"]
    if result.nothing:
        body = _header(result) + [
            "", f"No added or removed lines between {code(result.payload['base'])}"
                f" and {code(result.payload['head'])}: nothing to verify."]
        return "\n".join(body + footer) + "\n"
    out: list[str] = []
    size = 0
    budget = MAX_CHARS - 400      # room for the footer and the cut notice
    for section in (_header, _factors, _gates, _files, _blast):
        lines = section(result)
        chunk = sum(len(line) + 1 for line in lines)
        if size + chunk > budget:
            out += ["", "_The rest of this report was cut to stay under "
                        f"{MAX_CHARS:,} characters: `--format json` has "
                        "all of it._"]
            break
        out += lines
        size += chunk
    return "\n".join(out + footer) + "\n"
