"""`pr-verify trend`: read earlier `check --format json` reports and show how
the score and the agent share moved. Pure reading: no git, no network."""

from __future__ import annotations

import json
import os

from . import render as render_mod

MAX_REPORT_BYTES = 8 * 1024 * 1024


def load(path: str) -> dict:
    """One report; ValueError when it is not a pr-verify JSON document."""
    with open(path, "rb") as f:
        raw = f.read(MAX_REPORT_BYTES + 1)
    if len(raw) > MAX_REPORT_BYTES:
        raise ValueError(f"{path}: larger than {MAX_REPORT_BYTES} bytes")
    try:
        doc = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError) as e:
        raise ValueError(f"{path}: not JSON ({e.__class__.__name__})") from None
    if not isinstance(doc, dict) or doc.get("tool") != "pr-verify":
        raise ValueError(f"{path}: not a pr-verify JSON report")
    return doc


def point(path: str, doc: dict) -> dict:
    risk = doc.get("risk") or {}
    files = doc.get("files") or {}
    return {
        "report": os.path.basename(path),
        "score": risk.get("score", 0),
        "band": risk.get("band", ""),
        "agent_share": render_mod.agent_share_pct(files),
        "files": len(files),
        "review_depth": (doc.get("review_depth") or {}).get("depth", ""),
        "unverified": len(doc.get("unverified_files") or []),
    }


def build(paths: list[str]) -> dict:
    """Points in the order the paths are given (shell globs sort by name;
    name reports by date to get a timeline)."""
    points = [point(p, load(p)) for p in paths]
    out = {"points": points, "count": len(points)}
    if points:
        out["score_change"] = points[-1]["score"] - points[0]["score"]
        out["agent_share_change"] = (points[-1]["agent_share"]
                                     - points[0]["agent_share"])
    return out


def to_text(trend: dict) -> list[str]:
    lines = [f"{'report':30} {'score':>5} {'agent%':>6} {'files':>5}  depth"]
    for p in trend["points"]:
        lines.append(f"{p['report'][:30]:30} {p['score']:>5} "
                     f"{p['agent_share']:>5}% {p['files']:>5}  "
                     f"{p['review_depth']}"
                     + (f" ({p['unverified']} unverified)"
                        if p["unverified"] else ""))
    if trend["count"] > 1:
        lines.append(f"change: score {trend['score_change']:+d}, "
                     f"agent share {trend['agent_share_change']:+d} points")
    return lines
