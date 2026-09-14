"""Day 3 tests: JA3 is correct, deterministic, and strips GREASE."""

from hsfp.ja3 import ja3_hash, ja3_string
from hsfp.parse import parse_client_hello
from tests.test_parse import build_client_hello

CH = parse_client_hello(build_client_hello())


def test_grease_is_stripped():
    # 0x0a0a (GREASE, == 2570 decimal) is in the raw ciphers but not in JA3.
    assert 0x0A0A in CH["ciphers"]
    assert "2570" not in ja3_string(CH)


def test_ja3_string_shape():
    s = ja3_string(CH)
    assert s.count(",") == 4            # five comma-separated fields
    assert s.startswith("771,")         # client_version 0x0303


def test_ja3_hash_is_md5_hex():
    h = ja3_hash(CH)
    assert len(h) == 32 and all(c in "0123456789abcdef" for c in h)


def test_ja3_deterministic():
    assert ja3_hash(CH) == ja3_hash(parse_client_hello(build_client_hello()))
