"""Fingerprint database — sqlite store of known fingerprints.  [Day 5]

Seeded from the abuse.ch SSLBL JA3 blocklist; lookups return a label + malware
family for known-bad fingerprints.
"""

from __future__ import annotations

import csv
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


def add(con, h: str, kind: str, label: str, family: str, source: str) -> None:
    con.execute(
        "INSERT OR IGNORE INTO fp VALUES (?,?,?,?,?)",
        (h, kind, label, family, source),
    )


def lookup(con, h: str, kind: str) -> Optional[dict]:
    row = con.execute(
        "SELECT label, family FROM fp WHERE hash=? AND kind=?", (h, kind)
    ).fetchone()
    return {"label": row[0], "family": row[1]} if row else None


def load_sslbl(con, csv_path: str) -> int:
    """Ingest the abuse.ch SSLBL JA3 blocklist CSV.

    Format (comment lines start with '#'):
        ja3_md5,Firstseen,Lastseen,Listingreason
    Returns the number of fingerprints inserted.
    """
    n = 0
    with open(csv_path, newline="") as f:
        for row in csv.reader(f):
            if not row or row[0].startswith("#"):
                continue
            md5 = row[0].strip()
            if len(md5) != 32:            # skip header / malformed rows
                continue
            family = row[-1].strip() if len(row) > 1 else "unknown"
            add(con, md5, "ja3", "malicious", family, "sslbl")
            n += 1
    con.commit()
    return n
