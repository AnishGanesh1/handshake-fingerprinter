"""Day 5 tests: fingerprint DB add/lookup round-trips."""

from hsfp import db


def test_db_add_and_lookup():
    con = db.connect(":memory:")
    db.add(con, "abc123", "ja3", "malicious", "TestBot", "unit")
    hit = db.lookup(con, "abc123", "ja3")
    assert hit and hit["family"] == "TestBot" and hit["label"] == "malicious"


def test_db_miss_returns_none():
    con = db.connect(":memory:")
    assert db.lookup(con, "does-not-exist", "ja3") is None


def test_db_ignores_duplicates():
    con = db.connect(":memory:")
    db.add(con, "dup", "ja3", "malicious", "A", "s")
    db.add(con, "dup", "ja3", "malicious", "B", "s")   # INSERT OR IGNORE
    assert db.lookup(con, "dup", "ja3")["family"] == "A"
