"""Fingerprint database — sqlite store of known fingerprints.  [Day 5]

Seeded from the abuse.ch SSLBL JA3 blocklist; lookups return a label + malware
family for known-bad fingerprints. The schema is defined now so early code can
create the DB file; the loader lands on Day 5.
"""

from __future__ import annotations

import sqlite3
from typing import Optional

SCHEMA = """
CREATE TABLE IF NOT EXISTS fp (
    hash    TEXT,
    kind    TEXT,        -- 'ja3' | 'ja4'
    label   TEXT,        -- 'malicious' | 'benign' | ...
    family  TEXT,
    source  TEXT,
    PRIMARY KEY (hash, kind)
);
"""


def connect(path: str = "data/fp.db") -> sqlite3.Connection:
    con = sqlite3.connect(path)
    con.execute(SCHEMA)
    return con


def lookup(con: sqlite3.Connection, h: str, kind: str) -> Optional[dict]:
    row = con.execute(
        "SELECT label, family FROM fp WHERE hash=? AND kind=?", (h, kind)
    ).fetchone()
    return {"label": row[0], "family": row[1]} if row else None


def load_sslbl(con: sqlite3.Connection, csv_path: str) -> int:
    """Ingest the abuse.ch SSLBL JA3 blocklist CSV.  TODO(Day 5)."""
    raise NotImplementedError("load_sslbl is implemented on Day 5")
