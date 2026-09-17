#!/usr/bin/env python3
"""Passive TLS honeypot.  [Day 10]

Listens on a port, reads the raw ClientHello off each incoming connection,
fingerprints it, and logs it — then closes. No certificate needed: we never
complete the TLS handshake, we just read the client's opening message.

Run on a VPS on port 443 to collect real internet scanners/bots. Locally,
use a high port (no admin needed):

    python scripts/honeypot.py --port 8443
    # from another terminal / machine:  curl -k https://HOST:8443

Only run this on a host you control.
"""

from __future__ import annotations

import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import argparse
import socket
from datetime import datetime, timezone

from hsfp.ja3 import ja3_hash
from hsfp.ja4 import ja4
from hsfp.parse import parse_client_hello


def serve(host: str, port: int, logpath: str) -> None:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, port))
    srv.listen(64)
    print(f"[*] honeypot listening on {host}:{port} — logging to {logpath}")
    while True:
        conn, addr = srv.accept()
        try:
            conn.settimeout(3)
            data = conn.recv(8192)
            ch = parse_client_hello(data)
            if ch:
                line = (f"{datetime.now(timezone.utc).isoformat()}\t{addr[0]}\t"
                        f"{ja4(ch)}\t{ja3_hash(ch)}\t{ch.get('sni') or '-'}")
                print(line)
                with open(logpath, "a") as f:
                    f.write(line + "\n")
        except Exception:                       # noqa: BLE001 — keep serving
            pass
        finally:
            conn.close()


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=8443)
    ap.add_argument("--log", default="data/honeypot.tsv")
    a = ap.parse_args()
    try:
        serve(a.host, a.port, a.log)
    except KeyboardInterrupt:
        print("\n[*] stopped")
