"""Classifier training / prediction.  [Implemented on Day 9]

A RandomForest trained on featurized ClientHellos labelled malware vs benign,
used to score unknown fingerprints. Kept separate from features.py so the model
file and the feature schema can evolve independently.
"""

from __future__ import annotations

from typing import List, Sequence


def train(X: Sequence[Sequence[float]], y: Sequence[int],
          out: str = "models/rf.pkl"):
    """Train + persist the classifier, printing precision/recall.  TODO(Day 9)."""
    raise NotImplementedError("train is implemented on Day 9")


def predict_proba(clf, ch_features: List[float]) -> float:
    """Malware-likelihood score in [0, 1] for one feature vector.  TODO(Day 9)."""
    raise NotImplementedError("predict_proba is implemented on Day 9")
