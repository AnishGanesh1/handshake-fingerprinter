#!/usr/bin/env bash
# Capture a short benign baseline of YOUR OWN HTTPS traffic (Day 1).
# Only capture on a machine/network you control.
#
# Usage:  sudo ./scripts/capture_baseline.sh [iface] [seconds]
set -euo pipefail

IFACE="${1:-any}"
SECONDS_TO_RUN="${2:-300}"
OUT="data/benign.pcap"

echo "[*] capturing tcp/443 on '$IFACE' for ${SECONDS_TO_RUN}s -> $OUT"
echo "[*] browse a few HTTPS sites now..."
timeout "${SECONDS_TO_RUN}" tcpdump -i "$IFACE" -w "$OUT" 'tcp port 443' || true
echo "[+] done. inspect with:  python cli.py $OUT"
