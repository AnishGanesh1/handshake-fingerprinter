#!/usr/bin/env python3
"""Passive TLS honeypot.

Listens on a port, reads the raw ClientHello off each incoming connection,
fingerprints it, and logs it — then closes. No certificate needed: it never
completes the TLS handshake, it just reads the client's opening message.

    python scripts/honeypot.py --port 8443
    python scripts/honeypot.py --port 8443 --pcap data/benign/browser.pcap

With --pcap, every captured ClientHello is also written to a pcap file you can
scan later or use as a training set. Only run this on a host you control.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import argparse
import socket
import struct
import time
from datetime import datetime, timezone

from hsfp.ja3 import ja3_hash
from hsfp.ja4 import ja4
from hsfp.parse import parse_client_hello


def _pcap_global_header() -> bytes:
    return struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)  # Ethernet


def _pcap_record(raw: bytes, i: int) -> bytes:
    eth = b"\x02\x00\x00\x00\x00\x02\x02\x00\x00\x00\x00\x01\x08\x00"
    tcp = struct.pack("!HHIIBBHHH", 40000 + (i % 20000), 443, 1, 0, 0x50, 0x18, 65535, 0, 0)
    iplen = 20 + len(tcp) + len(raw)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, iplen, i + 1, 0, 64, 6, 0,
                     bytes([10, 0, 0, (i % 254) + 1]), bytes([93, 184, 216, 34]))
    pkt = eth + ip + tcp + raw
    return struct.pack("<IIII", int(time.time()), i, len(pkt), len(pkt)) + pkt


def serve(host: str, port: int, logpath: str, pcappath: str | None = None) -> None:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, port))
    srv.listen(64)
    pf = None
    i = 0
    if pcappath:
        os.makedirs(os.path.dirname(pcappath) or ".", exist_ok=True)
        pf = open(pcappath, "wb")
        pf.write(_pcap_global_header())
        pf.flush()
    print(f"[*] honeypot listening on {host}:{port} — logging to {logpath}"
          + (f", pcap -> {pcappath}" if pcappath else ""))
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
                if pf:
                    pf.write(_pcap_record(data, i))
                    pf.flush()
                    i += 1
        except Exception:                       # noqa: BLE001 — keep serving
            pass
        finally:
            conn.close()


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=8443)
    ap.add_argument("--log", default="data/honeypot.tsv")
    ap.add_argument("--pcap", default=None, help="also save raw ClientHellos to this pcap")
    a = ap.parse_args()
    try:
        serve(a.host, a.port, a.log, a.pcap)
    except KeyboardInterrupt:
        print("\n[*] stopped")
