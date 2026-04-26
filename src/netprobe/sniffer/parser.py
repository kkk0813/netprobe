"""
netprobe.sniffer.parser
------------------------
Manually unpacks raw packet bytes into structured data using struct.

Why struct.unpack and not a library?
  Network protocols are just bytes arranged in a documented order.
  struct.unpack lets you read exactly N bytes at an offset and interpret
  them as integers, chars, etc. This is what Scapy does internally —
  we're just doing it ourselves to understand the layout.

Protocol stack we handle:
  [IP header] → [TCP | UDP | ICMP header] → [payload]

On Windows, raw sockets give us packets starting at the IP layer.
On Linux, AF_PACKET gives us Ethernet frames — we skip the 14-byte
Ethernet header to get to IP.

Relevant RFCs if you want to go deeper:
  IP   → RFC 791
  TCP  → RFC 793
  UDP  → RFC 768
  ICMP → RFC 792
"""

import socket
import struct
import sys
from dataclasses import dataclass


# ---------------------------------------------------------------------------
# Protocol constants — these match the IP protocol number field
# ---------------------------------------------------------------------------

PROTO_ICMP = 1
PROTO_TCP  = 6
PROTO_UDP  = 17


# ---------------------------------------------------------------------------
# Data classes — one per header type
# ---------------------------------------------------------------------------

@dataclass
class IPHeader:
    version:     int
    ihl:         int      # Internet Header Length in 32-bit words
    ttl:         int      # Time To Live — decremented each hop
    protocol:    int      # what's inside: 1=ICMP, 6=TCP, 17=UDP
    src_ip:      str
    dst_ip:      str
    header_len:  int      # byte offset where the payload starts


@dataclass
class TCPHeader:
    src_port:  int
    dst_port:  int
    seq:       int
    ack:       int
    flags:     int        # SYN, ACK, FIN, RST etc packed into bits
    window:    int


@dataclass
class UDPHeader:
    src_port:  int
    dst_port:  int
    length:    int


@dataclass
class ICMPHeader:
    type:      int        # 0=echo reply, 8=echo request, 3=dest unreachable
    code:      int
    checksum:  int


@dataclass
class Packet:
    ip:      IPHeader
    tcp:     TCPHeader  | None = None
    udp:     UDPHeader  | None = None
    icmp:    ICMPHeader | None = None
    payload: bytes = b""


# ---------------------------------------------------------------------------
# TCP flag helpers
# ---------------------------------------------------------------------------

_TCP_FLAGS = {
    "FIN": 0x01,
    "SYN": 0x02,
    "RST": 0x04,
    "PSH": 0x08,
    "ACK": 0x10,
    "URG": 0x20,
}


def tcp_flags_str(flags: int) -> str:
    """Return a compact string of active TCP flags, e.g. 'SYN ACK'."""
    return " ".join(name for name, bit in _TCP_FLAGS.items() if flags & bit)


# ---------------------------------------------------------------------------
# Parsers
# ---------------------------------------------------------------------------

def parse_ip_header(data: bytes) -> IPHeader:
    """Parse a 20-byte IP header.

    Byte layout (big-endian / network order):
      Offset 0  : version (4 bits) + IHL (4 bits)
      Offset 1  : DSCP/ECN (ignored)
      Offset 2-3: total length
      Offset 4-5: identification
      Offset 6-7: flags + fragment offset
      Offset 8  : TTL
      Offset 9  : protocol
      Offset 10-11: header checksum
      Offset 12-15: source IP
      Offset 16-19: destination IP
    """
    # '!' = network (big-endian) byte order
    # 'B' = unsigned char (1 byte)
    # 'H' = unsigned short (2 bytes)
    # '4s' = 4-byte string (raw bytes)
    # Format produces exactly 10 values:
    # B=ihl_version, B=dscp, H=total_len, H=ident, H=flags_frag,
    # B=ttl, B=protocol, H=checksum, 4s=src, 4s=dst
    ihl_version, _, _, _, _, ttl, protocol, _, src_raw, dst_raw = struct.unpack(
        "! B B H H H B B H 4s 4s", data[:20]
    )

    version    = ihl_version >> 4           # top 4 bits
    ihl        = ihl_version & 0xF          # bottom 4 bits
    header_len = ihl * 4                    # IHL is in 32-bit words → multiply by 4

    return IPHeader(
        version    = version,
        ihl        = ihl,
        ttl        = ttl,
        protocol   = protocol,
        src_ip     = socket.inet_ntoa(src_raw),
        dst_ip     = socket.inet_ntoa(dst_raw),
        header_len = header_len,
    )


def parse_tcp_header(data: bytes) -> TCPHeader:
    """Parse a 20-byte TCP header.

    Byte layout:
      Offset 0-1: source port
      Offset 2-3: destination port
      Offset 4-7: sequence number
      Offset 8-11: acknowledgement number
      Offset 12  : data offset (4 bits) + reserved (4 bits)
      Offset 13  : flags (SYN/ACK/FIN/RST/PSH/URG)
      Offset 14-15: window size
      Offset 16-17: checksum
      Offset 18-19: urgent pointer
    """
    src_port, dst_port, seq, ack, offset_flags, flags, window, _, _ = struct.unpack(
        "! H H L L B B H H H", data[:20]
    )
    return TCPHeader(
        src_port = src_port,
        dst_port = dst_port,
        seq      = seq,
        ack      = ack,
        flags    = flags,
        window   = window,
    )


def parse_udp_header(data: bytes) -> UDPHeader:
    """Parse an 8-byte UDP header.

    Byte layout:
      Offset 0-1: source port
      Offset 2-3: destination port
      Offset 4-5: length (header + payload)
      Offset 6-7: checksum
    """
    src_port, dst_port, length, _ = struct.unpack("! H H H H", data[:8])
    return UDPHeader(src_port=src_port, dst_port=dst_port, length=length)


def parse_icmp_header(data: bytes) -> ICMPHeader:
    """Parse the first 4 bytes of an ICMP header.

    Byte layout:
      Offset 0: type
      Offset 1: code
      Offset 2-3: checksum
    """
    icmp_type, code, checksum = struct.unpack("! B B H", data[:4])
    return ICMPHeader(type=icmp_type, code=code, checksum=checksum)


def parse_packet(raw: bytes) -> Packet | None:
    """Parse a full raw packet into a Packet dataclass.

    On Linux we receive Ethernet frames — skip the 14-byte Ethernet header.
    On Windows we receive IP packets directly — no skip needed.
    Returns None if the packet cannot be parsed.
    """
    try:
        # Skip Ethernet header on Linux (AF_PACKET gives us the full frame)
        ip_start = 0 if sys.platform == "win32" else 14
        ip = parse_ip_header(raw[ip_start:])
        payload_start = ip_start + ip.header_len
        payload = raw[payload_start:]

        tcp  = None
        udp  = None
        icmp = None

        if ip.protocol == PROTO_TCP and len(payload) >= 20:
            tcp = parse_tcp_header(payload)
        elif ip.protocol == PROTO_UDP and len(payload) >= 8:
            udp = parse_udp_header(payload)
        elif ip.protocol == PROTO_ICMP and len(payload) >= 4:
            icmp = parse_icmp_header(payload)

        return Packet(ip=ip, tcp=tcp, udp=udp, icmp=icmp, payload=payload)

    except struct.error:
        return None