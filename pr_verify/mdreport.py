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
#: Lines of a failed gate's output that are shown, and for how many gates;
#: the characters one block may take and one line of it, counted after the
#: escapes; and the notes shown.
MAX_GATE_LINES = 30
MAX_GATE_OUTPUTS = 5
MAX_BLOCK_CHARS = 4000
MAX_LINE = 400
MAX_NOTES = 10

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


def fenced(text: str, max_lines: int = MAX_GATE_LINES,
           max_chars: int = MAX_BLOCK_CHARS) -> list[str]:
    """Lines of a fenced code block holding the end of text. The limits are
    applied AFTER escaping (an escape is up to six characters for one, so a
    limit counted before it could be outgrown sixfold): each line is at
    most MAX_LINE characters, and the block keeps the last lines that fit in
    max_lines and max_chars. The fence is longer than any run of backticks
    in what is kept, so no line of it can close the block; a ~~~ line cannot
    either, a block opened with backticks is only closed by backticks."""
    # \r\n (a gate on Windows) is one line end, not a \x0d on every line
    lines = [_shorten(_plain(line.rstrip("\r")).rstrip(), MAX_LINE)
             for line in str(text).split("\n")]
    while lines and not lines[-1]:
        lines.pop()
    kept: list[str] = []
    used = 0
    for line in reversed(lines):
        if len(kept) >= max_lines or used + len(line) + 1 > max_chars:
            break
        kept.append(line)
        used += len(line) + 1
    kept.reverse()
    if len(kept) < len(lines):
        kept.insert(0, f"… ({len(lines) - len(kept)} earlier line(s) not "
                       f"shown)")
    longest = max((len(m) for line in kept
                   for m in _BACKTICKS.findall(line)), default=0)
    fence = "`" * max(3, longest + 1)
    return [fence + "text", *kept, fence]


def blast_note(b, quote=lambda text: text) -> str:
    """Why a changed file shows no dependents when the scan could not see
    it, or "" (shared with the human report). The one part of it that comes
    from the PR, a file's extension, goes through quote: the Markdown report
    passes code(), as `p.![i](https:1572395042)` has the extension
    `.![i](https:1572395042)`, an image in Markdown."""
    if not b.external_only:
        return ""
    if b.scan == "not_source":
        ext = os.path.splitext(b.file)[1].lower()
        what = f"{quote(ext)} files are" if ext else "this file type is"
        return f"{what} not scanned for imports"
    if b.scan == "not_in_worktree":
        why = "not in the worktree"
    elif b.scan == "skipped_dir":
        # one of blastradius.SKIP_DIRS, a fixed name; quoted all the same
        why = (f"in {quote(br_mod.skipped_dir(b.file) + '/')}, which the "
               f"import scan skips")
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
    for note in result.notes[:MAX_NOTES]:
        lines += ["", f"> **note:** {code(note, limit=MAX_SENTENCE)}"]
    return lines


def _factors(result) -> list[str]:
    lines = ["", "### Risk factors", "", "| Factor | Points | Detail |",
             "|---|---:|---|"]
    for name, fac in result.breakdown.factors.items():
        lines.append(f"| {name} | {fac['points']} | "
                     f"{code(fac['detail'], table=True, limit=MAX_SENTENCE)} |")
    return lines


def _gate_list(result) -> list[str]:
    lines = ["", "### Policy gates", ""]
    if not result.gates:
        lines.append("None configured.")
    for g in result.gates:
        mark = "PASS" if g.passed else ("TIMEOUT" if g.timed_out else "FAIL")
        lines.append(f"- **{mark}** {code(g.command)} (exit "
                     f"{int(g.returncode)})")
    return lines


def _gate_outputs(result) -> list[list[str]]:
    """One collapsed block per failed gate (none when gate output is to be
    left out of the report)."""
    if getattr(result, "hide_gate_output", False):
        return []
    blocks = []
    failed = [(i, g) for i, g in enumerate(result.gates, 1) if not g.passed]
    for i, g in failed:
        blocks.append(["", f"<details><summary>Output of gate {i} (exit "
                           f"{int(g.returncode)})</summary>", "",
                       *fenced(g.output_tail or "(no output)"),
                       "", "</details>"])
    return blocks


def _file_rows(result) -> list[list[str]]:
    rows = []
    prov = result.prov
    for rel in sorted(prov):
        f = prov[rel]
        if f.deleted:
            who = ", ".join(f.deleted_by) or "unknown"
            rows.append([f"| deleted | {code(rel, True)} | - | "
                         f"{code(who, True)} |"])
            continue
        if not (f.added or f.removed):
            continue
        counts = f"{f.agent_added}/{f.added} added" if f.added else ""
        if f.removed:
            gone = f"{f.agent_removed}/{f.removed} removed"
            counts = f"{counts}, {gone}" if counts else gone
        who = ", ".join(sorted(f.agents)) if f.agents else "human"
        rows.append([f"| {f.label()} | {code(rel, True)} | {counts} | "
                     f"{code(who, True)} |"])
    return rows


def _files_head(result) -> list[str]:
    prov = result.prov
    total_added = sum(f.added for f in prov.values())
    agent_added = sum(f.agent_added for f in prov.values())
    total_removed = sum(f.removed for f in prov.values())
    agent_removed = sum(f.agent_removed for f in prov.values())
    summary = f"{agent_added}/{total_added} added lines agent-authored"
    if total_removed:
        summary += f"; {agent_removed}/{total_removed} removed lines"
    return ["", "### Provenance", "", summary, "",
            "| | File | Agent lines | Agents |", "|---|---|---|---|"]


def _blast_entries(result) -> list[list[str]]:
    entries = []
    ranked = sorted(result.blast.values(), key=lambda b: b.size,
                    reverse=True)
    for b in ranked:
        note = blast_note(b, quote=code)
        line = f"- {code(b.file)}: {b.size} downstream dependent(s)"
        if note:
            line += f" ({note})"
        entry = [line]
        if b.direct:
            shown = ", ".join(code(d) for d in b.direct[:5])
            more = f" and {len(b.direct) - 5} more" if len(b.direct) > 5 else ""
            entry.append(f"  - direct: {shown}{more}")
        entries.append(entry)
    return entries


def _size(lines: list[str]) -> int:
    return sum(len(line) + 1 for line in lines)


def render(result) -> str:
    """The whole report, a string that ends with a newline, never longer
    than MAX_CHARS.

    The header, the factor table and the list of gates with their verdicts
    are always there (each is small whatever the PR holds: names are
    shortened after they are escaped, notes and gates are few and come from
    this tool and the base's config). The rest -- the gates' output, the
    file rows, the blast radius entries -- is added an entry at a time while
    it fits, and each section says how many of its entries it left out, so
    a PR cannot make the report drop a section by making one entry huge."""
    from . import cli    # the version, without an import cycle at load time
    footer = ["", "---", f"<sub>pr-verify {cli.VERSION}: deterministic, no "
                         f"LLM. `--format json` has every number.</sub>"]
    if result.nothing:
        body = _header(result) + [
            "", f"No added or removed lines between {code(result.payload['base'])}"
                f" and {code(result.payload['head'])}: nothing to verify."]
        return "\n".join(body + footer) + "\n"
    out = _header(result) + _factors(result) + _gate_list(result)
    # room for the footer and for one "left out" line per section
    budget = MAX_CHARS - _size(footer) - 3 * 200

    def add(entries, limit, what):
        nonlocal out
        shown = 0
        for entry in entries[:limit]:
            if _size(out) + _size(entry) > budget:
                break
            out += entry
            shown += 1
        left = len(entries) - shown
        if left:
            out += ["", f"… {left} more {what} not shown here: "
                        f"`--format json` has all of them."]

    if getattr(result, "hide_gate_output", False):
        if any(not g.passed for g in result.gates):
            out += ["", "Gate output is left out of this report "
                        "(`--hide-gate-output`)."]
    else:
        add(_gate_outputs(result), MAX_GATE_OUTPUTS, "failed gate output(s)")
    out += _files_head(result)
    add(_file_rows(result), MAX_FILES, "file(s)")
    out += ["", "### Blast radius", ""]
    entries = _blast_entries(result)
    if not entries:
        out.append("No files changed.")
    add(entries, MAX_BLAST, "blast radius entr(ies)")
    return "\n".join(out + footer) + "\n"
