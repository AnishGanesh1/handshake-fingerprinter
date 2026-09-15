#!/usr/bin/env python3
"""Build a dataset from labelled pcaps and train the classifier.  [Day 9]

Expected layout:
    data/malware/*.pcap    (malicious captures — Stratosphere IPS, etc.)
    data/benign/*.pcap     (your own benign browsing captures)

    python scripts/train.py
"""

from __future__ import annotations

import glob

from hsfp.capture import tls_payloads
from hsfp.features import featurize
from hsfp.model import train
from hsfp.parse import parse_client_hello


def collect(pattern: str, label: int, X, y) -> int:
    n = 0
    for path in glob.glob(pattern):
        for _index, _pkt, raw in tls_payloads(path):
            ch = parse_client_hello(raw)
            if ch:
                X.append(featurize(ch))
                y.append(label)
                n += 1
    return n


def main() -> None:
    X, y = [], []
    m = collect("data/malware/*.pcap", 1, X, y)
    b = collect("data/benign/*.pcap", 0, X, y)
    print(f"collected {len(X)} samples: {m} malware, {b} benign")
    if m == 0 or b == 0:
        print("need pcaps in BOTH data/malware/ and data/benign/ — see README")
        return
    train(X, y)
    print("saved models/rf.pkl")


if __name__ == "__main__":
    main()
