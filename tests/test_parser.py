"""
Phase 3 tests — packet parser.

No real network needed. We craft raw bytes manually and verify
the parser reads them correctly. This is exactly how Wireshark
tests its dissectors.
"""

import struct
import socket
import pytest

from netprobe.sniffer.parser import (
    parse_ip_header,
    parse_tcp_header,
    parse_udp_header,
    parse_icmp_header,
    parse_packet,
    tcp_flags_str,
    PROTO_TCP,
    PROTO_UDP,
    PROTO_ICMP,
)


# ---------------------------------------------------------------------------
# Helpers — craft raw header bytes
# ---------------------------------------------------------------------------

def make_ip_bytes(
    src: str = "192.168.1.1",
    dst: str = "192.168.1.2",
    protocol: int = PROTO_TCP,
    ttl: int = 64,
) -> bytes:
    """Build a minimal 20-byte IP header."""
    ihl_version = (4 << 4) | 5          # IPv4, IHL=5 (no options)
    src_raw = socket.inet_aton(src)
    dst_raw = socket.inet_aton(dst)
    return struct.pack(
        "! B B H H H B B H 4s 4s",
        ihl_version,    # version + IHL
        0,              # DSCP/ECN
        40,             # total length (20 IP + 20 TCP)
        0,              # identification
        0,              # flags + fragment offset
        ttl,            # TTL
        protocol,       # protocol
        0,              # checksum (0 = not verified here)
        src_raw,
        dst_raw,
    )


def make_tcp_bytes(
    src_port: int = 12345,
    dst_port: int = 80,
    flags: int = 0x02,   # SYN by default
) -> bytes:
    """Build a minimal 20-byte TCP header."""
    return struct.pack(
        "! H H L L B B H H H",
        src_port,
        dst_port,
        1000,       # seq
        0,          # ack
        0x50,       # data offset (5 words = 20 bytes)
        flags,
        65535,      # window
        0,          # checksum
        0,          # urgent
    )


def make_udp_bytes(
    src_port: int = 54321,
    dst_port: int = 53,
    length: int = 12,
) -> bytes:
    """Build an 8-byte UDP header."""
    return struct.pack("! H H H H", src_port, dst_port, length, 0)


def make_icmp_bytes(icmp_type: int = 8, code: int = 0) -> bytes:
    """Build a 4-byte ICMP header."""
    return struct.pack("! B B H", icmp_type, code, 0)


# ---------------------------------------------------------------------------
# IP header tests
# ---------------------------------------------------------------------------

class TestParseIPHeader:
    def test_src_ip(self):
        ip = parse_ip_header(make_ip_bytes(src="10.0.0.1"))
        assert ip.src_ip == "10.0.0.1"

    def test_dst_ip(self):
        ip = parse_ip_header(make_ip_bytes(dst="172.16.0.1"))
        assert ip.dst_ip == "172.16.0.1"

    def test_ttl(self):
        ip = parse_ip_header(make_ip_bytes(ttl=128))
        assert ip.ttl == 128

    def test_protocol_tcp(self):
        ip = parse_ip_header(make_ip_bytes(protocol=PROTO_TCP))
        assert ip.protocol == PROTO_TCP

    def test_protocol_udp(self):
        ip = parse_ip_header(make_ip_bytes(protocol=PROTO_UDP))
        assert ip.protocol == PROTO_UDP

    def test_header_length(self):
        # IHL=5 → 5 * 4 = 20 bytes
        ip = parse_ip_header(make_ip_bytes())
        assert ip.header_len == 20

    def test_version(self):
        ip = parse_ip_header(make_ip_bytes())
        assert ip.version == 4


# ---------------------------------------------------------------------------
# TCP header tests
# ---------------------------------------------------------------------------

class TestParseTCPHeader:
    def test_src_port(self):
        tcp = parse_tcp_header(make_tcp_bytes(src_port=9999))
        assert tcp.src_port == 9999

    def test_dst_port(self):
        tcp = parse_tcp_header(make_tcp_bytes(dst_port=443))
        assert tcp.dst_port == 443

    def test_syn_flag(self):
        tcp = parse_tcp_header(make_tcp_bytes(flags=0x02))
        assert tcp.flags & 0x02  # SYN bit set

    def test_ack_flag(self):
        tcp = parse_tcp_header(make_tcp_bytes(flags=0x10))
        assert tcp.flags & 0x10  # ACK bit set

    def test_syn_ack_flags(self):
        tcp = parse_tcp_header(make_tcp_bytes(flags=0x12))
        assert tcp.flags & 0x02  # SYN
        assert tcp.flags & 0x10  # ACK


# ---------------------------------------------------------------------------
# UDP header tests
# ---------------------------------------------------------------------------

class TestParseUDPHeader:
    def test_src_port(self):
        udp = parse_udp_header(make_udp_bytes(src_port=12345))
        assert udp.src_port == 12345

    def test_dst_port_dns(self):
        udp = parse_udp_header(make_udp_bytes(dst_port=53))
        assert udp.dst_port == 53

    def test_length(self):
        udp = parse_udp_header(make_udp_bytes(length=28))
        assert udp.length == 28


# ---------------------------------------------------------------------------
# ICMP header tests
# ---------------------------------------------------------------------------

class TestParseICMPHeader:
    def test_echo_request(self):
        icmp = parse_icmp_header(make_icmp_bytes(icmp_type=8, code=0))
        assert icmp.type == 8
        assert icmp.code == 0

    def test_echo_reply(self):
        icmp = parse_icmp_header(make_icmp_bytes(icmp_type=0))
        assert icmp.type == 0

    def test_dest_unreachable(self):
        icmp = parse_icmp_header(make_icmp_bytes(icmp_type=3, code=1))
        assert icmp.type == 3
        assert icmp.code == 1


# ---------------------------------------------------------------------------
# tcp_flags_str
# ---------------------------------------------------------------------------

class TestTCPFlagsStr:
    def test_syn(self):
        assert "SYN" in tcp_flags_str(0x02)

    def test_syn_ack(self):
        result = tcp_flags_str(0x12)
        assert "SYN" in result
        assert "ACK" in result

    def test_fin(self):
        assert "FIN" in tcp_flags_str(0x01)

    def test_rst(self):
        assert "RST" in tcp_flags_str(0x04)

    def test_no_flags(self):
        assert tcp_flags_str(0x00) == ""


# ---------------------------------------------------------------------------
# parse_packet integration — Windows path (IP layer directly)
# ---------------------------------------------------------------------------

class TestParsePacket:
    def test_tcp_packet_parsed(self, monkeypatch):
        monkeypatch.setattr("netprobe.sniffer.parser.sys.platform", "win32")
        raw = make_ip_bytes(protocol=PROTO_TCP) + make_tcp_bytes()
        packet = parse_packet(raw)
        assert packet is not None
        assert packet.tcp is not None
        assert packet.udp is None
        assert packet.icmp is None

    def test_udp_packet_parsed(self, monkeypatch):
        monkeypatch.setattr("netprobe.sniffer.parser.sys.platform", "win32")
        raw = make_ip_bytes(protocol=PROTO_UDP) + make_udp_bytes()
        packet = parse_packet(raw)
        assert packet is not None
        assert packet.udp is not None

    def test_icmp_packet_parsed(self, monkeypatch):
        monkeypatch.setattr("netprobe.sniffer.parser.sys.platform", "win32")
        raw = make_ip_bytes(protocol=PROTO_ICMP) + make_icmp_bytes()
        packet = parse_packet(raw)
        assert packet is not None
        assert packet.icmp is not None

    def test_ip_fields_correct(self, monkeypatch):
        monkeypatch.setattr("netprobe.sniffer.parser.sys.platform", "win32")
        raw = make_ip_bytes(src="10.0.0.5", dst="10.0.0.9", ttl=128) + make_tcp_bytes()
        packet = parse_packet(raw)
        assert packet.ip.src_ip == "10.0.0.5"
        assert packet.ip.dst_ip == "10.0.0.9"
        assert packet.ip.ttl    == 128

    def test_malformed_packet_returns_none(self, monkeypatch):
        monkeypatch.setattr("netprobe.sniffer.parser.sys.platform", "win32")
        packet = parse_packet(b"\x00\x01\x02")   # too short to be a valid IP header
        assert packet is None