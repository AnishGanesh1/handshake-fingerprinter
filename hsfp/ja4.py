"""JA4 fingerprint.  [Day 4]

JA4 has three underscore-separated parts:  a_b_c
    a  protocol + TLS version + SNI flag + cipher count + ext count + ALPN
    b  first 12 hex of sha256(sorted cipher list, comma-joined 4-hex)
    c  first 12 hex of sha256(sorted extensions minus SNI/ALPN, comma-joined,
       then '_' + signature algorithms in original order)

IMPORTANT: validate this against FoxIO's official test vectors before trusting
results. Subtle rules (ALPN edge cases, version pulled from supported_versions)
make silent bugs easy. The regression test pins the output of THIS
implementation; the FoxIO vectors confirm the implementation is correct.
"""

from __future__ import annotations

import hashlib

from .ja3 import GREASE, _clean

# Map a TLS version number to its 2-char JA4 code.
_VER = {0x0304: "13", 0x0303: "12", 0x0302: "11", 0x0301: "10", 0x0300: "s3"}


def _sha12(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()[:12]


def _version_code(ch: dict) -> str:
    """Highest offered TLS version -> JA4 code. Prefers supported_versions."""
    highest = max(_clean(ch["sup_ver"]), default=ch["client_version"])
    return _VER.get(highest, "00")


def _alpn_code(ch: dict) -> str:
    """First ALPN value's first+last char, or '00' if none."""
    if not ch["alpn"]:
        return "00"
    a = ch["alpn"][0]
    if not a:
        return "00"
    return (a[0] + a[-1]) if len(a) > 1 else (a[0] + a[0])


def ja4(ch: dict, quic: bool = False) -> str:
    """Build the JA4 fingerprint string for a parsed ClientHello."""
    ciphers = _clean(ch["ciphers"])
    exts = _clean(ch["extensions"])

    proto = "q" if quic else "t"
    sni = "d" if ch["sni"] else "i"
    a = (
        f"{proto}{_version_code(ch)}{sni}"
        f"{min(len(ciphers), 99):02d}{min(len(exts), 99):02d}{_alpn_code(ch)}"
    )

    b = _sha12(",".join(f"{c:04x}" for c in sorted(ciphers)))

    # c: sorted extensions excluding SNI (0x0000) and ALPN (0x0010),
    #    then '_' + signature algorithms in the order they appeared.
    exts_c = sorted(e for e in exts if e not in (0x0000, 0x0010))
    ext_str = ",".join(f"{e:04x}" for e in exts_c)
    sig_str = ",".join(f"{s:04x}" for s in ch["sig_algs"])
    c = _sha12(f"{ext_str}_{sig_str}" if sig_str else ext_str)

    return f"{a}_{b}_{c}"
