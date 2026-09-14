#!/usr/bin/env python3
"""Handshake Fingerprinter — command-line entrypoint.

Day 1 capability: read a pcap and list every TLS ClientHello it contains.
As the project grows, the fingerprinting and verdict logic (Days 3-11) plugs
into the loop marked below.

Usage:
    python cli.py data/benign.pcap
    python cli.py data/benign.pcap --limit 20
"""

from __future__ import annotations

import argparse
import sys

from hsfp import __version__
from hsfp.capture import endpoints, record_length, tls_payloads


def cmd_scan(args: argparse.Namespace) -> int:
    count = 0
    print(f"{'#':>5}  {'source':<21} -> {'destination':<21}  {'SNI/len':<12}")
    print("-" * 72)
    for index, pkt, raw in tls_payloads(args.pcap):
        src, dst, sport, dport = endpoints(pkt)
        # --- fingerprinting plugs in here (Day 3+) -------------------------
        #   ch = parse_client_hello(raw)          # Day 2
        #   j3 = ja3_hash(ch); j4 = ja4(ch)       # Day 3-4
        #   verdict = classify(ch, j3, j4)        # Day 5-9
        # ------------------------------------------------------------------
        print(
            f"{index:>5}  {src + ':' + str(sport):<21} -> "
            f"{dst + ':' + str(dport):<21}  {record_length(raw)} bytes"
        )
        count += 1
        if args.limit and count >= args.limit:
            break

    print("-" * 72)
    print(f"found {count} ClientHello handshake(s)")
    if count == 0:
        print("(no TLS ClientHellos — is this an HTTPS capture on tcp/443?)",
              file=sys.stderr)
    return 0


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="hsfp", description="Passive TLS (JA3/JA4) handshake fingerprinter"
    )
    ap.add_argument("--version", action="version",
                    version=f"%(prog)s {__version__}")
    ap.add_argument("pcap", help="path to a .pcap/.pcapng capture file")
    ap.add_argument("--limit", type=int, default=0,
                    help="stop after N handshakes (0 = no limit)")
    ap.set_defaults(func=cmd_scan)
    return ap


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
