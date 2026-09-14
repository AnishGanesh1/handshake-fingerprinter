"""Day 2 tests: the ClientHello parser extracts every field, and never crashes.

We hand-build a realistic ClientHello with known values so the assertions are
exact — including a GREASE cipher (which the parser keeps; JA3/JA4 strip it later).
"""

import struct

from hsfp.parse import parse_client_hello


def _ext(etype: int, body: bytes) -> bytes:
    return struct.pack("!HH", etype, len(body)) + body


def build_client_hello() -> bytes:
    client_version = b"\x03\x03"                       # TLS 1.2 legacy
    random = b"\x00" * 32
    session_id = b"\x00"                               # length 0

    ciphers = [0x0A0A, 0x1301, 0xC02F]                # GREASE + TLS1.3 + ECDHE
    cs = struct.pack("!H", len(ciphers) * 2) + b"".join(struct.pack("!H", c) for c in ciphers)

    compression = b"\x01\x00"                          # 1 method: null

    # --- extensions ---
    name = b"example.com"
    sni_entry = b"\x00" + struct.pack("!H", len(name)) + name
    ext_sni = _ext(0, struct.pack("!H", len(sni_entry)) + sni_entry)

    groups = [0x001D, 0x0017]                          # x25519, secp256r1
    ext_groups = _ext(10, struct.pack("!H", len(groups) * 2) + b"".join(struct.pack("!H", g) for g in groups))

    ext_ecpf = _ext(11, b"\x01\x00")                   # 1 format: uncompressed

    sigs = [0x0403, 0x0804]
    ext_sigs = _ext(13, struct.pack("!H", len(sigs) * 2) + b"".join(struct.pack("!H", s) for s in sigs))

    protos = [b"h2", b"http/1.1"]
    alpn_list = b"".join(bytes([len(p)]) + p for p in protos)
    ext_alpn = _ext(16, struct.pack("!H", len(alpn_list)) + alpn_list)

    supver = [0x0304, 0x0303]                          # TLS 1.3, 1.2
    ext_supver = _ext(43, bytes([len(supver) * 2]) + b"".join(struct.pack("!H", v) for v in supver))

    exts = ext_sni + ext_groups + ext_ecpf + ext_sigs + ext_alpn + ext_supver
    ext_block = struct.pack("!H", len(exts)) + exts

    body = client_version + random + session_id + cs + compression + ext_block
    handshake = b"\x01" + struct.pack("!I", len(body))[1:] + body     # type + 3-byte len
    record = b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake
    return record


CH = build_client_hello()


def test_client_version():
    assert parse_client_hello(CH)["client_version"] == 0x0303


def test_ciphers_include_grease():
    assert parse_client_hello(CH)["ciphers"] == [0x0A0A, 0x1301, 0xC02F]


def test_sni():
    assert parse_client_hello(CH)["sni"] == "example.com"


def test_groups_and_point_formats():
    ch = parse_client_hello(CH)
    assert ch["groups"] == [0x001D, 0x0017]
    assert ch["ec_fmt"] == [0]


def test_signature_algorithms():
    assert parse_client_hello(CH)["sig_algs"] == [0x0403, 0x0804]


def test_alpn():
    assert parse_client_hello(CH)["alpn"] == ["h2", "http/1.1"]


def test_supported_versions():
    assert parse_client_hello(CH)["sup_ver"] == [0x0304, 0x0303]


def test_extension_order():
    assert parse_client_hello(CH)["extensions"] == [0, 10, 11, 13, 16, 43]


def test_no_extensions_still_parses():
    # ClientHello with an empty extensions block: fields default to empty.
    cv = b"\x03\x03" + b"\x00" * 32 + b"\x00"
    cs = struct.pack("!H", 2) + struct.pack("!H", 0x1301)
    body = cv + cs + b"\x01\x00" + struct.pack("!H", 0)
    hs = b"\x01" + struct.pack("!I", len(body))[1:] + body
    rec = b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs
    ch = parse_client_hello(rec)
    assert ch["ciphers"] == [0x1301] and ch["sni"] is None and ch["alpn"] == []


def test_never_crashes_on_junk():
    for junk in (b"", b"\x16\x03\x01", b"\x16" + b"\x00" * 44, CH[:20], CH[:50]):
        parse_client_hello(junk)   # must not raise (may return dict or None)
