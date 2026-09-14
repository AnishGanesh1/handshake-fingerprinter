"""ClientHello byte parser.  [Day 2]

Turns the raw handshake bytes from capture.tls_payloads() into a dict with
every field the fingerprints need: ciphers, extensions, elliptic curves,
EC point formats, signature algorithms, ALPN, SNI, supported_versions.

Wire layout of a TLS ClientHello (offsets from the start of the record):

    0       content type            0x16 (handshake)
    1-2     record version          e.g. 0x0301
    3-4     record length
    5       handshake type          0x01 (ClientHello)
    6-8     handshake length (3B)
    9-10    client_version          legacy, e.g. 0x0303
    11-42   random                  32 bytes
    43      session_id length (1B)  followed by session_id
    ...     cipher_suites length (2B) + suites (2B each)
    ...     compression length (1B)  + methods
    ...     extensions length (2B)   + extensions

Each extension is: type (2B), length (2B), body.

The parser NEVER raises on malformed input — it returns None so a single bad
packet can't kill a whole capture scan.
"""

from __future__ import annotations

import struct
from typing import List, Optional


def u16(b: bytes, i: int) -> int:
    """Read a big-endian uint16 at offset i."""
    return (b[i] << 8) | b[i + 1]


def _u16_list(body: bytes, count_bytes: int) -> List[int]:
    """Parse a length-prefixed vector of uint16s.

    count_bytes = width of the length prefix (1 or 2). The length gives the
    number of *bytes* of uint16 entries that follow it.
    """
    n = body[0] if count_bytes == 1 else u16(body, 0)
    start = count_bytes
    return [u16(body, start + j) for j in range(0, n, 2)]


def _parse_sni(body: bytes) -> Optional[str]:
    """server_name extension (0): list_len(2), entry_type(1), name_len(2), name."""
    if len(body) < 5:
        return None
    name_len = u16(body, 3)
    # SNI is ASCII on the wire (IDNs are already punycode / A-labels).
    return body[5:5 + name_len].decode("utf-8", "ignore") or None


def _parse_alpn(body: bytes) -> List[str]:
    """ALPN extension (16): list_len(2), then repeated [len(1)][proto bytes]."""
    protos: List[str] = []
    j = 2
    while j < len(body):
        n = body[j]
        protos.append(body[j + 1:j + 1 + n].decode("ascii", "ignore"))
        j += 1 + n
    return protos


def parse_client_hello(data: bytes) -> Optional[dict]:
    """Parse a TLS ClientHello record into a field dict, or None if malformed."""
    try:
        ch = {
            "client_version": u16(data, 9),
            "ciphers": [],
            "extensions": [],
            "groups": [],      # supported_groups / curves (ext 10)
            "ec_fmt": [],      # ec_point_formats (ext 11)
            "sig_algs": [],    # signature_algorithms (ext 13)
            "alpn": [],        # ext 16
            "sni": None,       # ext 0
            "sup_ver": [],     # supported_versions (ext 43)
        }

        i = 43                                   # skip to session_id length
        sid_len = data[i]; i += 1 + sid_len

        cs_len = u16(data, i); i += 2
        ch["ciphers"] = [u16(data, i + j) for j in range(0, cs_len, 2)]
        i += cs_len

        comp_len = data[i]; i += 1 + comp_len    # compression methods (ignored)

        if i + 2 > len(data):                    # no extensions block
            return ch
        ext_total = u16(data, i); i += 2
        end = min(i + ext_total, len(data))

        while i + 4 <= end:
            etype = u16(data, i)
            elen = u16(data, i + 2)
            body = data[i + 4:i + 4 + elen]
            i += 4 + elen
            ch["extensions"].append(etype)

            if etype == 0:      ch["sni"] = _parse_sni(body)
            elif etype == 10:   ch["groups"] = _u16_list(body, 2)
            elif etype == 11:   ch["ec_fmt"] = list(body[1:1 + body[0]])
            elif etype == 13:   ch["sig_algs"] = _u16_list(body, 2)
            elif etype == 16:   ch["alpn"] = _parse_alpn(body)
            elif etype == 43:   ch["sup_ver"] = _u16_list(body, 1)

        return ch
    except (IndexError, struct.error, UnicodeError):
        return None
