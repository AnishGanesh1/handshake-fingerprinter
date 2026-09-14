"""JA4 fingerprint.  [Implemented on Day 4]

JA4 has three underscore-separated parts:  a_b_c
    a  protocol + TLS version + SNI flag + cipher count + ext count + ALPN
    b  first 12 hex of sha256(sorted cipher list)
    c  first 12 hex of sha256(sorted extensions minus SNI/ALPN + sig algs)

Validate your implementation against FoxIO's official test vectors before
trusting any results — subtle rules (ALPN edge cases, version pulled from the
supported_versions extension) make silent bugs easy.
"""

from __future__ import annotations

from .ja3 import GREASE, _clean  # noqa: F401  (used by the Day 4 implementation)


def ja4(ch: dict, quic: bool = False) -> str:
    """Build the JA4 fingerprint string for a parsed ClientHello.

    TODO(Day 4): implement the a_b_c construction (see the build plan).
    """
    raise NotImplementedError("ja4 is implemented on Day 4")
