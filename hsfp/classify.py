"""Verdict logic — ties the DB lookup and the ML model together.  [Day 7 / 9]

A fingerprint is:
    malicious  if its JA3 (or JA4) is in the known-bad database
    suspicious if unknown but the ML model scores it above a threshold
    benign     otherwise
"""

from __future__ import annotations

from typing import Optional

from . import db, model as model_mod
from .features import featurize
from .ja3 import ja3_hash
from .ja4 import ja4


def classify(con, ch: dict, clf=None, threshold: float = 0.5) -> dict:
    """Return a verdict row for one parsed ClientHello."""
    j3 = ja3_hash(ch)
    j4 = ja4(ch)

    hit = db.lookup(con, j3, "ja3") or db.lookup(con, j4, "ja4")
    if hit:
        return {"sni": ch["sni"], "ja3": j3, "ja4": j4,
                "verdict": "malicious", "score": 1.0,
                "source": f"db:{hit['family']}"}

    score = 0.0
    if clf is not None:
        score = model_mod.predict_proba(clf, featurize(ch))
    verdict = "suspicious" if score >= threshold else "benign"
    return {"sni": ch["sni"], "ja3": j3, "ja4": j4,
            "verdict": verdict, "score": score, "source": "ml" if clf else "-"}
