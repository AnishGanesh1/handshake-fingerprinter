"""Day 4 tests: JA4 has the right structure and is deterministic.

Regression-pinned to THIS implementation. ALSO validate against FoxIO's
published vectors before trusting results (see IMPLEMENTATION_PLAN.md, Day 4).
"""

from hsfp.ja4 import ja4
from hsfp.parse import parse_client_hello
from tests.test_parse import build_client_hello

CH = parse_client_hello(build_client_hello())


def test_ja4_format():
    a, b, c = ja4(CH).split("_")
    assert a.startswith("t13d")         # TCP, TLS1.3 (from supported_versions), SNI present
    assert a[4:6] == "02"               # 2 non-GREASE ciphers
    assert a[6:8] == "06"               # 6 extensions
    assert a.endswith("h2")             # first ALPN "h2" -> h + 2
    assert len(b) == 12 and len(c) == 12


def test_ja4_deterministic():
    assert ja4(CH) == ja4(parse_client_hello(build_client_hello()))
