# Handshake Fingerprinter

**Passive TLS (JA3/JA4) malware command-and-control detection — no decryption required.**

![ci](https://github.com/AnishGanesh1/handshake-fingerprinter/actions/workflows/ci.yml/badge.svg)
![python](https://img.shields.io/badge/python-3.11%2B-blue)
![license](https://img.shields.io/badge/license-MIT-green)

Encrypted traffic hides the *payload*, not the *handshake*. Every HTTPS connection
opens with an unencrypted `ClientHello` that reveals exactly which software is
speaking — its TLS versions, cipher suites, extensions, and curves. This tool
fingerprints that handshake (JA3 and JA4) and flags clients whose fingerprints
match known — or statistically suspicious — malware C2 tooling, **without
decrypting a single byte**.

---

## What it does

```
  capture  ->  parse  ->  fingerprint  ->  +-- DB lookup (known C2) --+  ->  verdict
 pcap/live   ClientHello    JA3 / JA4        +-- ML score (unknown fp) -+       report
```

- **Parses** TLS ClientHellos by hand, straight off the wire (no TLS library).
- **Fingerprints** each one with both **JA3** (MD5) and **JA4** (FoxIO's modern scheme).
- **Classifies** it — a lookup against the abuse.ch SSLBL known-bad database, plus
  a RandomForest that scores *unknown* fingerprints on malware-likelihood.
- **Reports** a per-flow verdict (`malicious` / `suspicious` / `benign`) as a
  color-coded table and machine-readable JSON.
- **Collects its own data** via a passive TLS honeypot that fingerprints every
  client that connects — no certificate needed.

## Quickstart

```powershell
git clone https://github.com/AnishGanesh1/handshake-fingerprinter.git
cd handshake-fingerprinter
python -m venv .venv
.\.venv\Scripts\Activate.ps1        # Windows  (source .venv/bin/activate on Linux/Mac)
pip install -r requirements.txt

python cli.py samples\demo.pcap                # scan a capture (4 real clients)
python cli.py samples\demo.pcap --json out.json # + machine-readable output
python scripts\honeypot.py --port 8443         # passive honeypot
```

## Example: different clients, different fingerprints

Four different TLS clients connecting to the honeypot — each produces a distinct
JA4, captured live (`samples/honeypot-sample.tsv`):

| client | JA4 | SNI |
|---|---|---|
| curl | `t13i3112h2_e8f1e7e78f70_ce5650b735ce` | – |
| wget | `t13i751000_479067518aa3_fb8d5ffd48c1` | – |
| openssl | `t13i310900_e8f1e7e78f70_1f22a2ca17c4` | – |
| python | `t13d181100_85036bcba153_d41ae481755e` | example.test |

Reading a JA4 like `t13i3112h2`: **T**CP, TLS 1.**3**, **i** = *no SNI*, 31 ciphers,
12 extensions, ALPN `h2`. Two things stand out immediately: every client has a
different cipher/extension hash, and the command-line tools omit SNI (`i`) while the
Python client sends it (`d` = `t13d…`). That separability — telling software apart by
its handshake alone, without decryption — is the entire premise. `samples/demo.pcap`
contains these four real ClientHellos so anyone can reproduce it:

```
python cli.py samples\demo.pcap
```

## ML classifier (proof-of-concept)

Beyond the known-bad database, a RandomForest scores *unknown* fingerprints on how
automated (non-browser) they look. Trained on a small, self-collected dataset:

| class | samples | distinct client fingerprints |
|---|---|---|
| browser (benign) | 284 | 2 |
| automated / tools (curl, wget, openssl, python) | 106 | 28 |

On a random train/test split the model scores ~1.00 precision/recall — but that number
is **deliberately reported as optimistic**: browser and tool fingerprints don't overlap,
and identical ClientHellos appear in both train and test, so the model is largely
memorizing. The honest takeaways:

- The end-to-end ML pipeline works: `featurize()` -> RandomForest -> per-flow scoring in the CLI (`--model`).
- The dataset is too small and low-diversity (only ~2 real browser fingerprints) to be a rigorous benchmark.
- `scripts/train.py` therefore **also reports a fingerprint-grouped split**, where test
  fingerprints are unseen in training — the fair way to measure generalization, and the
  reason not to trust the headline 1.00.

*Future work: capture diverse real browsing (many browsers/sites via Npcap) and real
malware C2 to turn this into a genuine benchmark.*

## How it works (the interesting parts)

- **Hand-rolled ClientHello parser** (`hsfp/parse.py`) walks the record →
  handshake → extensions structure and pulls ciphers, extensions, curves,
  signature algorithms, ALPN, SNI, and `supported_versions`. It never raises on
  malformed input — one bad packet is skipped, not fatal.
- **GREASE stripping** (`hsfp/ja3.py`) — browsers inject random reserved values
  (RFC 8701) into the handshake; without filtering them, every fingerprint drifts.
- **JA4** (`hsfp/ja4.py`) reads the true TLS version from the
  `supported_versions` extension (TLS 1.3 masquerades as 1.2 on the wire) and
  sorts its inputs so trivial reordering can't evade it.

## Project layout

| Module | Purpose |
|---|---|
| `hsfp/capture.py` | pcap iteration + live sniffing with TCP-segment reassembly |
| `hsfp/parse.py` | ClientHello byte parser |
| `hsfp/ja3.py` / `ja4.py` | fingerprint algorithms |
| `hsfp/db.py` | sqlite known-bad fingerprint store (SSLBL loader) |
| `hsfp/features.py` / `model.py` | ML feature vectors + RandomForest |
| `hsfp/classify.py` | verdict logic |
| `hsfp/report.py` | color table + JSON output |
| `scripts/honeypot.py` | passive TLS honeypot |
| `scripts/train.py` | build dataset from labelled pcaps + train |

## Testing

```powershell
pip install pytest
python -m pytest -q      # 26 tests
```

Fingerprints are pinned by regression tests; the parser is fuzzed with truncated
and malformed input to prove it degrades gracefully. CI runs the suite on every push.

## Status & roadmap

- [x] ClientHello parsing, JA3, JA4 (validated by tests)
- [x] known-bad DB lookup (abuse.ch SSLBL)
- [x] live capture + passive honeypot (real fingerprints captured)
- [x] color report + JSON output, CLI, CI
- [x] ML classifier implemented (`features.py` / `model.py`)
- [x] trained the classifier on a small self-collected dataset (see "ML classifier" above);
      larger, more diverse data is future work
- [ ] JA4+ suite (JA4S server, JA4H HTTP), Zeek/Suricata alert export

## What I learned / hardest parts

- **GREASE** — the first fingerprints I generated for Chrome never matched anything
  because I wasn't stripping the random RFC 8701 values it injects. Filtering GREASE
  from ciphers, extensions, and curves was the fix.
- **TLS 1.3 hides its version** — the record and legacy fields still say "1.2" for
  compatibility; the real version lives inside the `supported_versions` extension,
  and JA3 and JA4 treat this deliberately differently.
- **JA4 spec fidelity** — sorted lists, ALPN edge cases, and the version rule all
  have to be exactly right, so I pinned the output with regression tests and
  cross-checked the structure field by field.
- **A codec bug worth remembering** — decoding SNI with Python's `idna` codec threw
  `UnicodeError` on perfectly valid hostnames because that codec ignores the error
  handler. SNI is ASCII on the wire, so UTF-8 decoding is the correct, robust choice.

## Ethics & legal

Only capture traffic on machines and networks **you own or are explicitly authorized
to monitor** — your own host, your own honeypot, or published research datasets. This
tool reads only the unencrypted handshake metadata every client broadcasts by design;
it never decrypts traffic. For defensive research and education.

## References

- FoxIO — JA4+ TLS fingerprinting specification
- abuse.ch SSLBL — JA3 fingerprint blocklist
- Stratosphere IPS / malware-traffic-analysis.net — malware pcap datasets
- RFC 8446 (TLS 1.3), RFC 8701 (GREASE)

## License

MIT — see [LICENSE](LICENSE).
