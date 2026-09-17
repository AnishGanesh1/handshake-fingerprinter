#!/usr/bin/env python3
"""Build a dataset from labelled pcaps and train the classifier.

Expected layout:
    data/malware/*.pcap    (automated / tool / malicious captures)
    data/benign/*.pcap     (browser captures)

    python scripts/train.py

Reports two evaluations:
  1. a random split — optimistic, because identical fingerprints can land in
     both train and test (leakage);
  2. a fingerprint-grouped split — the honest measure of generalization, where
     the test set contains client fingerprints unseen during training.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import glob

from hsfp.capture import tls_payloads
from hsfp.features import featurize
from hsfp.ja4 import ja4
from hsfp.parse import parse_client_hello


def _client_id(ch) -> str:
    """Client identity = the stable part of JA4 (a_b), ignoring the volatile c hash."""
    return "_".join(ja4(ch).split("_")[:2])


def collect(pattern, label, X, y, groups) -> int:
    n = 0
    for path in glob.glob(pattern):
        for _i, _pkt, raw in tls_payloads(path):
            ch = parse_client_hello(raw)
            if ch:
                X.append(featurize(ch))
                y.append(label)
                groups.append(_client_id(ch))
                n += 1
    return n


def main() -> None:
    import joblib
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.metrics import classification_report
    from sklearn.model_selection import GroupShuffleSplit, train_test_split

    X, y, groups = [], [], []
    m = collect("data/malware/*.pcap", 1, X, y, groups)
    b = collect("data/benign/*.pcap", 0, X, y, groups)
    print(f"collected {len(X)} samples: {m} automated, {b} benign")
    if m == 0 or b == 0:
        print("need pcaps in BOTH data/malware/ and data/benign/ — see README")
        return

    ub = len({g for g, l in zip(groups, y) if l == 0})
    um = len({g for g, l in zip(groups, y) if l == 1})
    print(f"distinct client fingerprints: {ub} browser, {um} automated\n")

    def rf():
        return RandomForestClassifier(n_estimators=300, class_weight="balanced",
                                      random_state=42)

    # 1) random split — optimistic (identical fingerprints can be in train AND test)
    Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.25, stratify=y,
                                          random_state=42)
    print("=== random split (OPTIMISTIC — shares fingerprints across train/test) ===")
    print(classification_report(yte, rf().fit(Xtr, ytr).predict(Xte), digits=2))

    # 2) fingerprint-grouped split — honest generalization
    print("=== fingerprint-grouped split (HONEST — test fingerprints unseen in train) ===")
    if ub >= 2 and um >= 2:
        tr, te = next(GroupShuffleSplit(n_splits=1, test_size=0.3,
                                        random_state=42).split(X, y, groups))
        Xg, yg = [X[i] for i in tr], [y[i] for i in tr]
        Xt, yt = [X[i] for i in te], [y[i] for i in te]
        if len(set(yg)) < 2 or len(set(yt)) < 2:
            print("  grouped split left a class empty — too few distinct browser")
            print("  fingerprints for a fair split. Collect more browsers / real browsing.")
        else:
            print(classification_report(yt, rf().fit(Xg, yg).predict(Xt), digits=2))
    else:
        print(f"  SKIPPED: need >=2 distinct fingerprints per class "
              f"(have browser={ub}, automated={um}).")
        print("  Cannot evaluate without leakage on this dataset — collect more"
              " browsers / real browsing.")

    # final model trained on all data
    clf = rf().fit(X, y)
    os.makedirs("models", exist_ok=True)
    joblib.dump(clf, "models/rf.pkl")
    print("\nsaved models/rf.pkl")


if __name__ == "__main__":
    main()
