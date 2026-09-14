"""JA3 fingerprint.  [Implemented on Day 3]

JA3 = md5( SSLVersion,Ciphers,Extensions,EllipticCurves,ECPointFormats )
with values in decimal, joined by '-' inside a field and ',' between fields.

GREASE values MUST be stripped from ciphers/extensions/curves or fingerprints
for modern browsers will drift. The GREASE set is defined here now because
both ja3 and ja4 (and the ML features) import it.
"""

from __future__ import annotations

# RFC 8701 GREASE values.
GREASE = {
    0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A,
    0x8A8A, 0x9A9A, 0xAAAA, 0xBABA, 0xCACA, 0xDADA, 0xEAEA, 0xFAFA,
}


def _clean(xs):
    """Drop GREASE placeholder values from a list of ints."""
    return [x for x in xs if x not in GREASE]


def ja3_string(ch: dict) -> str:
    """Build the canonical JA3 string from a parsed ClientHello dict.

    TODO(Day 3): implement using ch fields and _clean().
    """
    raise NotImplementedError("ja3_string is implemented on Day 3")


def ja3_hash(ch: dict) -> str:
    """MD5 hex digest of ja3_string(ch).  TODO(Day 3)."""
    raise NotImplementedError("ja3_hash is implemented on Day 3")
