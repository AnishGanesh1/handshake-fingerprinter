"""Reporting layer — JSON + pretty terminal table.  [Day 11]"""

from __future__ import annotations

import json
from typing import Dict, List

# Verdict -> rich style.
STYLE = {"malicious": "bold red", "suspicious": "yellow", "benign": "green"}


def to_json(rows: List[dict], path: str) -> None:
    """Write structured per-flow verdicts to a JSON file."""
    with open(path, "w") as f:
        json.dump(rows, f, indent=2)


def summary(rows: List[dict]) -> Dict[str, int]:
    """Count rows by verdict."""
    out: Dict[str, int] = {}
    for r in rows:
        out[r["verdict"]] = out.get(r["verdict"], 0) + 1
    return out


def render(rows: List[dict]) -> None:
    """Print a color-coded verdict table (falls back to plain text)."""
    counts = summary(rows)
    try:
        from rich.console import Console
        from rich.table import Table

        t = Table(title="TLS handshake verdicts")
        for col in ("#", "SNI", "JA4", "verdict", "score", "source"):
            t.add_column(col, overflow="fold")
        for r in rows:
            style = STYLE.get(r["verdict"], "white")
            t.add_row(
                str(r["index"]), r["sni"] or "-", r["ja4"],
                f"[{style}]{r['verdict']}[/]",
                f"{r['score']:.2f}", r["source"],
            )
        Console().print(t)
    except ImportError:
        for r in rows:
            print(f"{r['index']:>5}  {(r['sni'] or '-'):30} {r['ja4']:28} "
                  f"{r['verdict']:10} {r['score']:.2f}")
    print("summary:", ", ".join(f"{k}={v}" for k, v in counts.items()) or "none")
