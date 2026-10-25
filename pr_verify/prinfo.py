"""What the pull request itself says: labels, author account, branch name,
title and description -- and the agent signals found in the first three.

Commit trailers are one place an agent leaves its name (markers.py). The pull
request is another: Copilot's coding agent opens `copilot/...` branches from
a bot account, Claude Code's GitHub integration and Cursor and Codex do the
same under their own names, and teams label what an agent wrote. None of that
is in the commits, so it is read here, from facts handed to the check and
matched against patterns from the BASE ref's config (config.py: agent_labels,
agent_authors, agent_branches). Matching is plain and deterministic: a
case-insensitive glob (`*` also matches `/`) against the whole value; no
scoring, no guessing.

Where the facts come from, in this order of precedence (later wins, labels
add up): the GitHub event file (`--event-file`, `$GITHUB_EVENT_PATH` in an
Action: pull_request.labels / user.login / head.ref / title / body), then the
flags (`--pr-label`, `--pr-author`, `--pr-branch`, `--pr-title`,
`--pr-body-file`), and for the branch the checked-out branch when nothing else
names one. The values are the pull request author's own words: they are only
ever compared with a glob or searched for file names (descdiff.py), never
executed or put in a command.

A signal can only RAISE scrutiny: when one matches, the lines of the pull
request are scored as agent-written (provenance.analyze), which is the
cautious reading of "an agent opened this".
"""

from __future__ import annotations

import dataclasses
import json
import re

#: sizes beyond which the event file is not read / text is cut
MAX_EVENT_BYTES = 8 * 1024 * 1024
MAX_TITLE = 1000
MAX_BODY = 100_000


@dataclasses.dataclass
class PRInfo:
    labels: list = dataclasses.field(default_factory=list)
    author: str = ""
    branch: str = ""
    title: str = ""
    body: str = ""
    number: int | None = None

    def text(self) -> str:
        return f"{self.title}\n\n{self.body}".strip()


def _str(value, limit: int) -> str:
    return value[:limit] if isinstance(value, str) else ""


def from_event(path: str) -> PRInfo:
    """The pull request in a GitHub event payload (a file). A payload without
    a pull_request, or one that is not JSON, gives an empty PRInfo; an
    unreadable file raises OSError."""
    with open(path, "rb") as f:
        raw = f.read(MAX_EVENT_BYTES + 1)
    if len(raw) > MAX_EVENT_BYTES:
        raise ValueError(f"{path} is larger than {MAX_EVENT_BYTES} bytes")
    try:
        data = json.loads(raw.decode("utf-8", "replace"))
    except (ValueError, RecursionError):
        return PRInfo()
    pr = data.get("pull_request") if isinstance(data, dict) else None
    if not isinstance(pr, dict):
        return PRInfo()
    labels = []
    for item in pr.get("labels") or []:
        name = item.get("name") if isinstance(item, dict) else None
        if isinstance(name, str) and name:
            labels.append(name[:200])
    user = pr.get("user") if isinstance(pr.get("user"), dict) else {}
    head = pr.get("head") if isinstance(pr.get("head"), dict) else {}
    number = pr.get("number")
    return PRInfo(
        labels=labels, author=_str(user.get("login"), 200),
        branch=_str(head.get("ref"), 500),
        title=_str(pr.get("title"), MAX_TITLE),
        body=_str(pr.get("body"), MAX_BODY),
        number=number if isinstance(number, int)
        and not isinstance(number, bool) else None)


def merge(base: PRInfo, over: PRInfo) -> PRInfo:
    """`over` wins where it says something; labels from both are kept."""
    labels = list(base.labels)
    labels += [x for x in over.labels if x not in labels]
    return PRInfo(
        labels=labels, author=over.author or base.author,
        branch=over.branch or base.branch, title=over.title or base.title,
        body=over.body or base.body, number=over.number or base.number)


def _glob(value: str, pattern: str) -> bool:
    """`*` is any text (slashes too) and `?` one character; everything else is
    literal, so a bot name like `claude[bot]` means exactly that (fnmatch would
    read `[bot]` as a set of letters)."""
    rx = "".join(".*" if c == "*" else "." if c == "?" else re.escape(c)
                 for c in str(pattern).casefold())
    return re.fullmatch(rx, value.casefold(), re.S) is not None


def detect_signals(info: PRInfo, cfg: dict) -> list[dict]:
    """The agent signals in `info`, in a fixed order (labels in the order
    given, then author, then branch): [{"kind", "value", "rule"}]. `rule` is
    the config pattern that matched; the first match of each value is kept."""
    found = []
    for label in info.labels:
        rule = next((p for p in cfg.get("agent_labels", []) if _glob(label, p)),
                    None)
        if rule is not None:
            found.append({"kind": "label", "value": label, "rule": rule})
    if info.author:
        rule = next((p for p in cfg.get("agent_authors", [])
                     if _glob(info.author, p)), None)
        if rule is not None:
            found.append({"kind": "author", "value": info.author,
                          "rule": rule})
    if info.branch:
        branch = info.branch
        for prefix in ("refs/heads/", "origin/"):
            if branch.startswith(prefix):
                branch = branch[len(prefix):]
        rule = next((p for p in cfg.get("agent_branches", [])
                     if _glob(branch, p)), None)
        if rule is not None:
            found.append({"kind": "branch", "value": branch, "rule": rule})
    return found


def signal_marker(signal: dict) -> str:
    """The text the report shows next to an agent for this signal, like a
    commit marker: `label:ai-generated`."""
    return f"{signal['kind']}:{signal['value']}"
