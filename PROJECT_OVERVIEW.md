# Project Overview — Handshake Fingerprinter

*A passive TLS fingerprinting engine that detects malware command-and-control
traffic without decrypting anything.*

---

## 1. The problem

More than 90% of web traffic is now encrypted with TLS. That is good for privacy
and terrible for defenders: once a connection is encrypted, the traditional way of
catching malware — inspecting the payload for known-bad signatures — stops working.
Malware authors know this. Modern families route their command-and-control (C2)
channels over ordinary-looking HTTPS on port 443, and the actual instructions,
stolen data, and beacons are all hidden inside the encrypted stream.

Decrypting that traffic at scale is invasive, expensive, often legally fraught, and
increasingly impossible (certificate pinning, TLS 1.3). So the interesting question
is: **can you tell malicious traffic from benign traffic without ever decrypting it?**

## 2. The insight

Yes — because of *how* the encrypted conversation begins.

Every TLS connection opens with a **`ClientHello`**: an unencrypted message where the
client announces exactly how it wants to talk — which TLS versions it supports, which
cipher suites and in what order, which extensions, elliptic curves, signature
algorithms, and ALPN protocols. This list is remarkably specific to the *software*
that generated it. Chrome produces a different `ClientHello` than Firefox, which
differs from Python's `requests`, which differs from a Cobalt Strike beacon or a
Sliver implant.

If you hash that combination of fields into a compact string, you get a **fingerprint**
of the client software — and you never had to see a single byte of the encrypted
payload. Two well-known schemes do exactly this:

- **JA3** (Salesforce, 2017) — an MD5 of `version, ciphers, extensions, curves,
  point-formats`. Simple, widely catalogued, but coarse.
- **JA4** (FoxIO, 2023) — a structured, human-readable fingerprint (`a_b_c`) that
  sorts its inputs (so it resists trivial randomization), encodes TLS version, SNI
  presence, cipher/extension counts and ALPN in a readable prefix, and hashes the
  rest. More robust and the current standard.

Malware, and the tooling attackers use, frequently produces distinctive fingerprints —
and the same fingerprint reappears across infections. Threat-intel feeds publish
blocklists of known-bad JA3/JA4 values. That turns C2 detection into a lookup, and
for fingerprints nobody has catalogued yet, into a machine-learning problem.

## 3. What this project builds

A command-line tool (and reusable Python package) that:

1. **Captures** TLS handshakes from a pcap file or a live network interface.
2. **Parses** each `ClientHello` down to its constituent fields.
3. **Fingerprints** it with both JA3 and JA4.
4. **Classifies** it:
   - a **database lookup** against known-bad fingerprints (abuse.ch SSLBL), and
   - a **machine-learning model** that scores *unknown* fingerprints on how
     malware-like they look, so novel tooling doesn't sail through.
5. **Reports** a verdict per flow — `malicious` / `suspicious` / `benign` — as both
   machine-readable JSON and a color-coded terminal table.

### Architecture

```
  capture  ->  parse  ->  fingerprint  ->  +-- DB lookup (known C2) --+  ->  verdict
 pcap/live   ClientHello    JA3 / JA4        +-- ML score (unknown fp) -+       report
```

Everything downstream is a pure transform on the parsed `ClientHello`, which keeps the
code easy to test and easy to reason about.

## 4. Validating it on real data

A detector is only credible if it's tested on real traffic, so the project uses three
data sources:

- **Benign baseline** — a capture of your own browsing, for the negative class.
- **Real malware captures** — free research datasets from Stratosphere IPS (CTU-13)
  and malware-traffic-analysis.net, to prove the tool catches known C2.
- **Your own honeypot** — an HTTPS listener on a cheap VPS. Within hours, internet
  scanners and bots connect to it, giving you a live, self-collected dataset of
  real-world client fingerprints (many with telltale JA4s, e.g. mass scanners).

The headline result to aim for: *"detected N known-C2 handshakes across M real
malware captures, plus a classifier scoring unknown fingerprints at precision P /
recall R, validated against live traffic collected from my own honeypot."*

## 5. Tech stack

| Concern | Choice | Why |
|---|---|---|
| Language | Python 3.11+ | fastest path to a working detector |
| Packet parsing | scapy (+ dpkt) | mature pcap + live sniffing |
| Fingerprints | hand-rolled JA3/JA4 | understanding the wire format *is* the point |
| ML | scikit-learn (RandomForest) | strong baseline, interpretable |
| Storage | sqlite | zero-setup fingerprint store |
| Output | rich | readable, screenshot-friendly reports |
| CI | GitHub Actions + pytest | signals real engineering discipline |

## 6. 14-day roadmap

**Week 1 — core engine & fingerprinting**

| Day | Deliverable |
|---|---|
| 1 | Environment, repo scaffold, pcap capture + handshake detection *(this scaffold)* |
| 2 | `ClientHello` byte parser |
| 3 | JA3 implementation, validated against reference hashes |
| 4 | JA4 implementation, validated against FoxIO vectors |
| 5 | sqlite fingerprint DB + known-bad lookup |
| 6 | Run against real malware pcaps; first real numbers |
| 7 | End-to-end CLI; tag `v0.1`; weekly buffer |

**Week 2 — depth, live validation & polish**

| Day | Deliverable |
|---|---|
| 8 | Live capture; TLS 1.3 + fragmentation edge cases |
| 9 | ML classifier for unknown fingerprints |
| 10 | Honeypot; collect live client fingerprints |
| 11 | JSON + color-coded reporting |
| 12 | Tests + CI green |
| 13 | Documentation, architecture diagram, demo GIF |
| 14 | Polish, `v1.0` release, "what I learned" write-up |

## 7. The hard parts (and why they're worth it)

These are the details that make the project non-trivial — and exactly what makes it
a strong talking point in an interview:

- **GREASE** — modern browsers deliberately inject random reserved values into the
  handshake. Fail to strip them and every browser fingerprint drifts and never
  matches. Getting this right is a rite of passage.
- **TLS 1.3 version hiding** — for backward compatibility the record still claims
  "TLS 1.2"; the real version lives inside the `supported_versions` extension. JA3
  and JA4 treat this differently on purpose.
- **JA4 spec fidelity** — sorted lists, ALPN edge cases, the version rule. A silent
  bug here quietly invalidates all your results, so validating against published
  test vectors is mandatory, not optional.
- **Robust parsing** — real network captures are full of truncated, fragmented, and
  malformed packets. The parser must degrade gracefully (return `None`), never crash.

## 8. What you'll be able to say you learned

Network protocol internals (TLS handshake on the wire), passive traffic analysis,
threat intelligence and fingerprinting, a practical ML pipeline on self-labelled
data, and the engineering hygiene (tests, CI, docs) that turns a script into a tool.
It sits squarely in network-defense / detection-engineering territory — a domain
with real hiring demand and relatively few strong student portfolio projects.

## 9. Ethics & legal

Passive TLS fingerprinting is a defensive technique, but capturing traffic is still
capturing traffic. **Only monitor networks and hosts you own or are explicitly
authorized to test.** Use your own machine, your own honeypot, or published research
datasets. Nothing in this project decrypts traffic or attempts to; it reads only the
unencrypted handshake metadata that every client broadcasts by design.

## 10. References

- **FoxIO** — JA4+ suite specification and test vectors
- **Salesforce** — original JA3 specification
- **abuse.ch SSLBL** — JA3 fingerprint blocklist
- **Stratosphere IPS** — labelled malware traffic datasets (CTU-13)
- **malware-traffic-analysis.net** — annotated malware pcaps
- **RFC 8446** (TLS 1.3), **RFC 8701** (GREASE)
