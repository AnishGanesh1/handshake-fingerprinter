"""Day 1 tests: ClientHello detection is correct and never crashes."""

from hsfp.capture import is_client_hello, record_length

# A minimal well-formed TLS handshake record header carrying a ClientHello:
#   0x16          content type = handshake
#   0x03 0x01     record version (TLS 1.0 legacy)
#   0x00 0x2a     record length = 42
#   0x01          handshake type = ClientHello
CLIENT_HELLO = bytes([0x16, 0x03, 0x01, 0x00, 0x2A, 0x01]) + bytes(42)


def test_detects_client_hello():
    assert is_client_hello(CLIENT_HELLO) is True


def test_record_length():
    assert record_length(CLIENT_HELLO) == 42


def test_rejects_application_data():
    # 0x17 = application_data, not a handshake
    assert is_client_hello(bytes([0x17, 0x03, 0x03, 0x00, 0x10, 0x01])) is False


def test_rejects_server_hello():
    # handshake record but type 0x02 = ServerHello
    assert is_client_hello(bytes([0x16, 0x03, 0x03, 0x00, 0x10, 0x02])) is False


def test_never_crashes_on_junk():
    for junk in (b"", b"\x16", b"\x16\x03", b"\x16\x03\x01\xff", b"\x00" * 3):
        assert is_client_hello(junk) is False
