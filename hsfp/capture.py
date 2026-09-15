"""Packet capture and TLS-handshake extraction.  [Day 1, extended Day 8]

- tls_payloads(pcap): iterate ClientHello records from a capture file.
- live(iface, on_hello): sniff an interface in real time, reassembling
  ClientHellos that span multiple TCP segments.

A TLS record on the wire:
    byte 0      content type   0x16 = handshake
    byte 1-2    record version (legacy)
    byte 3-4    record length
    byte 5      handshake type 0x01 = ClientHello
"""

from __future__ import annotations

from typing import Callable, Iterator, Optional, Tuple

from scapy.all import IP, IPv6, Raw, TCP, PcapReader, sniff

CONTENT_TYPE_HANDSHAKE = 0x16
HANDSHAKE_CLIENT_HELLO = 0x01


def is_client_hello(data: bytes) -> bool:
    """True if data starts a TLS handshake record carrying a ClientHello."""
    return (
        len(data) > 5
        and data[0] == CONTENT_TYPE_HANDSHAKE
        and data[5] == HANDSHAKE_CLIENT_HELLO
    )


def record_length(data: bytes) -> int:
    """Declared TLS record length (bytes 3-4). Assumes len(data) >= 5."""
    return (data[3] << 8) | data[4]


def is_complete(data: bytes) -> bool:
    """True if data holds the whole TLS record (header + declared body)."""
    return len(data) >= 5 and len(data) >= record_length(data) + 5


def endpoints(pkt) -> Tuple[str, str, int, int]:
    """(src_ip, dst_ip, src_port, dst_port); handles IPv4 + IPv6."""
    if pkt.haslayer(IP):
        ip = pkt[IP]
    elif pkt.haslayer(IPv6):
        ip = pkt[IPv6]
    else:
        return ("?", "?", 0, 0)
    tcp = pkt[TCP]
    return (ip.src, ip.dst, int(tcp.sport), int(tcp.dport))


def tls_payloads(path: str) -> Iterator[Tuple[int, "object", bytes]]:
    """Yield (index, packet, raw_bytes) for every ClientHello packet in a pcap."""
    with PcapReader(path) as pcap:
        for index, pkt in enumerate(pcap):
            if not (pkt.haslayer(Raw) and pkt.haslayer(TCP)):
                continue
            data = bytes(pkt[Raw].load)
            if is_client_hello(data):
                yield index, pkt, data


def live(iface: str, on_hello: Callable[["object", bytes], None],
         bpf: str = "tcp port 443") -> None:
    """Sniff iface and call on_hello(pkt, raw) for each complete ClientHello.

    Buffers per-flow so a ClientHello split across TCP segments reassembles.
    """
    buf = {}   # (src_ip, sport) -> accumulated bytes

    def handle(pkt) -> None:
        if not (pkt.haslayer(Raw) and pkt.haslayer(TCP)):
            return
        src, _dst, sport, _dport = endpoints(pkt)
        key = (src, sport)
        data = buf.get(key, b"") + bytes(pkt[Raw].load)
        if len(data) > 5 and data[0] == CONTENT_TYPE_HANDSHAKE:
            if not is_complete(data):        # keep buffering
                buf[key] = data
                return
            buf.pop(key, None)
            if data[5] == HANDSHAKE_CLIENT_HELLO:
                on_hello(pkt, data)

    sniff(iface=iface, prn=handle, store=False, filter=bpf)
