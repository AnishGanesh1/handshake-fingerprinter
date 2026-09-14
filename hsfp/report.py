"""Reporting layer — JSON + pretty terminal table.  [Implemented on Day 11]"""

from __future__ import annotations

import json
from typing import List

# Verdict -> rich style, used by the Day 11 table renderer.
STYLE = {"malicious": "bold red", "suspicious": "yellow", "benign": "green"}


def to_json(rows: List[dict], path: str) -> None:
    """Write structured per-flow verdicts to a JSON file."""
    with open(path, "w") as f:
        json.dump(rows, f, indent=2)


def render(rows: List[dict]) -> None:
    """Print a color-coded verdict table.  TODO(Day 11)."""
    raise NotImplementedError("render is implemented on Day 11")
