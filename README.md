# Handshake Fingerprinter

**Passive TLS (JA3/JA4) malware command-and-control detection — no decryption required.**

Encrypted traffic hides the *payload*, not the *handshake*. This tool fingerprints
the TLS `ClientHello` that every HTTPS connection begins with, and flags clients
whose fingerprints match known — or statistically suspicious — malware C2 tooling.

![status](https://img.shields.io/badge/status-day%201%20scaffold-blue)
![python](https://img.shields.io/badge/python-3.11%2B-blue)
<!-- add once CI is green (Day 12):
![ci](https://github.com/<you>/handshake-fp/actions/workflows/ci.yml/badge.svg) -->

---

## Quickstart

```bash
git clone <your-fork-url> handshake-fp && cd handshake-fp
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# capture a short benign baseline of your OWN traffic
sudo ./scripts/capture_baseline.sh any 120

# list every TLS ClientHello in the capture
python cli.py data/benign.pcap
```

Example output (Day 1):

```
    #  source                -> destination            SNI/len
------------------------------------------------------------------------
    3  192.168.1.10:51514    -> 142.250.0.14:443       517 bytes
    9  192.168.1.10:51516    -> 151.101.0.223:443      508 bytes
------------------------------------------------------------------------
found 2 ClientHello handshake(s)
```

## What works today

This is the **Day 1 scaffold**. Capture and handshake detection are implemented
and tested; fingerprinting, the known-bad database, the ML classifier, and the
reporting layer are stubbed with clear signatures and land over the 14-day plan.

| Module | Purpose | Status |
|---|---|---|
| `hsfp/capture.py` | pcap iteration + live sniff | ✅ Day 1 |
| `hsfp/parse.py` | ClientHello byte parser | ⬜ Day 2 |
| `hsfp/ja3.py` | JA3 string + MD5 | ⬜ Day 3 |
| `hsfp/ja4.py` | JA4 `a_b_c` fingerprint | ⬜ Day 4 |
| `hsfp/db.py` | sqlite fingerprint store | ⬜ Day 5 |
| `hsfp/features.py` / `model.py` | ML on unknown fingerprints | ⬜ Day 9 |
| `hsfp/report.py` | JSON + terminal report | ⬜ Day 11 |

See [`PROJECT_OVERVIEW.md`](PROJECT_OVERVIEW.md) for the full concept, architecture,
and day-by-day roadmap.

## Development

```bash
pip install pytest
pytest -q          # Day 1 tests: handshake detection
```

## Ethics & legal

Only capture traffic on machines and networks **you own or are explicitly
authorized to monitor** — your own host, your own honeypot, or published research
datasets. Passive fingerprinting of third-party networks may be illegal in your
jurisdiction. This project is for defensive research and education.

## References

- FoxIO — JA4+ TLS fingerprinting specification
- abuse.ch SSLBL — JA3 fingerprint blocklist
- Stratosphere IPS / malware-traffic-analysis.net — malware pcap datasets

## License

MIT (add a `LICENSE` file before publishing).
