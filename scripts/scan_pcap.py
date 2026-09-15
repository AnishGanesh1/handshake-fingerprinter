#!/usr/bin/env python3
"""Quick scan: fingerprint every ClientHello in a pcap and count DB hits. [Day 6]

    python scripts/scan_pcap.py data/malware/sample.pcap

Use this on real malware captures (Stratosphere IPS, malware-traffic-analysis)
to get your first concrete "N/M flows matched known C2" number for the README.
"""

from __future__ import annotations

import sys

from hsfp import db
from hsfp.capture import tls_payloads
from hsfp.ja3 import ja3_hash
from hsfp.ja4 import ja4
from hsfp.parse import parse_client_hello


def main(path: str) -> None:
    con = db.connect()
    total = hits = 0
    for _i, _pkt, raw in tls_payloads(path):
        ch = parse_client_hello(raw)
        if not ch:
            continue
        total += 1
        j3 = ja3_hash(ch)
        hit = db.lookup(con, j3, "ja3") or db.lookup(con, ja4(ch), "ja4")
        if hit:
            hits += 1
            print(f"[MALICIOUS] {ch.get('sni') or '-':30} {j3}  {hit['family']}")
    print(f"\n{hits}/{total} flows matched known C2")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: python scripts/scan_pcap.py <pcap>")
        raise SystemExit(1)
    main(sys.argv[1])
