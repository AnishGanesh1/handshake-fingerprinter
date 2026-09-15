#!/usr/bin/env python3
"""Handshake Fingerprinter — CLI (Day 7 integration).

Parses each ClientHello, fingerprints it (JA3 + JA4), and prints a verdict by
looking it up in the known-bad database.

    python cli.py data/sample.pcap
    python cli.py data/sample.pcap --limit 20

(The richer color table + JSON output + live sniffing arrive on Day 11 / Day 8.)
"""

from __future__ import annotations

import argparse

from hsfp import __version__, db
from hsfp.capture import endpoints, tls_payloads
from hsfp.classify import classify
from hsfp.parse import parse_client_hello


def cmd_scan(args) -> int:
    con = db.connect(args.db)
    print(f"{'#':>5}  {'SNI':<28} {'JA4':<28} {'verdict':<10} source")
    print("-" * 88)
    n = mal = 0
    for index, pkt, raw in tls_payloads(args.pcap):
        ch = parse_client_hello(raw)
        if not ch:
            continue
        row = classify(con, ch)                 # no ML yet (that's Day 9)
        print(f"{index:>5}  {(row['sni'] or '-'):<28} {row['ja4']:<28} "
              f"{row['verdict']:<10} {row['source']}")
        n += 1
        mal += row["verdict"] == "malicious"
        if args.limit and n >= args.limit:
            break
    print("-" * 88)
    print(f"{n} handshake(s), {mal} malicious")
    return 0


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="hsfp", description="Passive TLS (JA3/JA4) handshake fingerprinter"
    )
    ap.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    ap.add_argument("pcap", help="pcap file to scan")
    ap.add_argument("--db", default="data/fp.db", help="fingerprint database path")
    ap.add_argument("--limit", type=int, default=0, help="stop after N handshakes")
    return ap


def main(argv=None) -> int:
    return cmd_scan(build_parser().parse_args(argv))


if __name__ == "__main__":
    raise SystemExit(main())
