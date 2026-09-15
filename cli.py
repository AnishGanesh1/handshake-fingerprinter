#!/usr/bin/env python3
"""Handshake Fingerprinter — command-line entrypoint.

    python cli.py data/sample.pcap                 # fingerprint + verdicts
    python cli.py data/sample.pcap --json out.json # also write JSON
    python cli.py data/sample.pcap --model models/rf.pkl
    python cli.py --live eth0                       # live sniff (needs Npcap on Windows)
"""

from __future__ import annotations

import argparse
import sys

from hsfp import __version__, db
from hsfp.capture import endpoints, live, tls_payloads
from hsfp.classify import classify
from hsfp.parse import parse_client_hello
from hsfp.report import render, to_json


def _load_model(path):
    if not path:
        return None
    try:
        from hsfp import model
        return model.load(path)
    except Exception as e:                       # noqa: BLE001
        print(f"warning: could not load model {path}: {e}", file=sys.stderr)
        return None


def cmd_scan(args) -> int:
    con = db.connect(args.db)
    clf = _load_model(args.model)
    rows = []
    for index, pkt, raw in tls_payloads(args.pcap):
        ch = parse_client_hello(raw)
        if not ch:
            continue
        row = classify(con, ch, clf, args.threshold)
        src, dst, sport, dport = endpoints(pkt)
        row.update(index=index, src=f"{src}:{sport}", dst=f"{dst}:{dport}")
        rows.append(row)
        if args.limit and len(rows) >= args.limit:
            break

    render(rows)
    if args.json:
        to_json(rows, args.json)
        print(f"wrote {args.json}")
    return 0


def cmd_live(args) -> int:
    con = db.connect(args.db)
    clf = _load_model(args.model)

    def on_hello(pkt, raw):
        ch = parse_client_hello(raw)
        if not ch:
            return
        row = classify(con, ch, clf, args.threshold)
        print(f"{(row['sni'] or '-'):30} {row['ja4']:28} "
              f"{row['verdict']:10} {row['score']:.2f} {row['source']}")

    print(f"[*] sniffing {args.live} (Ctrl-C to stop)...")
    live(args.live, on_hello)
    return 0


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="hsfp", description="Passive TLS (JA3/JA4) handshake fingerprinter"
    )
    ap.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    ap.add_argument("pcap", nargs="?", help="pcap file to scan")
    ap.add_argument("--live", metavar="IFACE", help="sniff a live interface instead")
    ap.add_argument("--db", default="data/fp.db", help="fingerprint database path")
    ap.add_argument("--model", help="trained classifier .pkl (optional)")
    ap.add_argument("--json", help="write verdicts to this JSON file")
    ap.add_argument("--threshold", type=float, default=0.5, help="ML suspicious cutoff")
    ap.add_argument("--limit", type=int, default=0, help="stop after N handshakes")
    return ap


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    if args.live:
        return cmd_live(args)
    if not args.pcap:
        build_parser().error("provide a pcap file or --live IFACE")
    return cmd_scan(args)


if __name__ == "__main__":
    raise SystemExit(main())
