"""Packet capture and TLS-handshake extraction.

Day 1 scope: read a pcap and yield the raw bytes of every packet that begins
a TLS handshake record carrying a ClientHello. The live sniffer (Day 8) reuses
the same detection logic.

A TLS record on the wire looks like:

    byte 0      content type   0x16 = handshake
    byte 1-2    record version (legacy, e.g. 0x0301)
    byte 3-4    record length
    byte 5      handshake type 0x01 = ClientHello   <-- what we key on
    ...

We only need a cheap predicate here; full field parsing lands on Day 2.
"""

from __future__ import annotations

from typing import Callable, Iterator, Optional, Tuple

from scapy.all import IP, IPv6, Raw, TCP, PcapReader, sniff

# TLS content type / handshake type markers
CONTENT_TYPE_HANDSHAKE = 0x16
HANDSHAKE_CLIENT_HELLO = 0x01


def is_client_hello(data: bytes) -> bool:
    """True if `data` starts a TLS handshake record carrying a ClientHello.

    Pure and side-effect free so it can be unit-tested without a pcap.
    """
    return (
        len(data) > 5
        and data[0] == CONTENT_TYPE_HANDSHAKE
        and data[5] == HANDSHAKE_CLIENT_HELLO
    )


def record_length(data: bytes) -> int:
    """Declared TLS record length (bytes 3-4). Assumes len(data) >= 5."""
    return (data[3] << 8) | data[4]


def endpoints(pkt) -> Tuple[str, str, int, int]:
    """(src_ip, dst_ip, src_port, dst_port) for display; handles IPv4 + IPv6."""
    if pkt.haslayer(IP):
        ip = pkt[IP]
    elif pkt.haslayer(IPv6):
        ip = pkt[IPv6]
    else:
        return ("?", "?", 0, 0)
    tcp = pkt[TCP]
    return (ip.src, ip.dst, int(tcp.sport), int(tcp.dport))


def tls_payloads(path: str) -> Iterator[Tuple[int, "object", bytes]]:
    """Yield (index, packet, raw_bytes) for every ClientHello packet in a pcap.

    `index` is the 0-based packet number in the capture, useful for reporting.
    """
    with PcapReader(path) as pcap:
        for index, pkt in enumerate(pcap):
            if not (pkt.haslayer(Raw) and pkt.haslayer(TCP)):
                continue
            data = bytes(pkt[Raw].load)
            if is_client_hello(data):
                yield index, pkt, data


def live(iface: str, on_hello: Callable[["object", bytes], None],
         bpf: str = "tcp port 443") -> None:
    """Sniff `iface` and call on_hello(pkt, raw) for each ClientHello.

    Day 1 provides a simple version (no reassembly). Day 8 upgrades this to
    buffer fragmented ClientHellos across TCP segments.
    """
    def handle(pkt) -> None:
        if not (pkt.haslayer(Raw) and pkt.haslayer(TCP)):
            return
        data = bytes(pkt[Raw].load)
        if is_client_hello(data):
            on_hello(pkt, data)

    sniff(iface=iface, prn=handle, store=False, filter=bpf)
