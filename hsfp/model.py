"""Classifier training / prediction.  [Day 9]

A RandomForest trained on featurized ClientHellos labelled malware vs benign,
used to score unknown fingerprints.
"""

from __future__ import annotations

from typing import List, Sequence

import joblib


def train(X: Sequence[Sequence[float]], y: Sequence[int],
          out: str = "models/rf.pkl"):
    """Train + persist the classifier, printing precision/recall.

    Imports sklearn lazily so the rest of the package works without it.
    """
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.metrics import classification_report
    from sklearn.model_selection import train_test_split

    Xtr, Xte, ytr, yte = train_test_split(
        X, y, test_size=0.25, stratify=y, random_state=42
    )
    clf = RandomForestClassifier(
        n_estimators=300, class_weight="balanced", random_state=42
    ).fit(Xtr, ytr)
    print(classification_report(yte, clf.predict(Xte)))   # -> numbers for README
    joblib.dump(clf, out)
    return clf


def load(path: str = "models/rf.pkl"):
    return joblib.load(path)


def predict_proba(clf, features: List[float]) -> float:
    """Malware-likelihood score in [0, 1] for one feature vector."""
    return float(clf.predict_proba([features])[0][1])
