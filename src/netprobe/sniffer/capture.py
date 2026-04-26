"""
netprobe.sniffer.capture
-------------------------
Raw socket setup and the packet capture loop.

Why raw sockets need admin/root:
  A normal socket (SOCK_STREAM, SOCK_DGRAM) only sees traffic addressed
  TO your process. A raw socket (SOCK_RAW) sees ALL traffic passing through
  an interface — other processes, other hosts, everything. The OS restricts
  this to privileged users because it's a powerful surveillance capability.

Platform differences:
  Linux  → AF_PACKET + SOCK_RAW: receives full Ethernet frames
  Windows → AF_INET  + SOCK_RAW + SIO_RCVALL: receives IP packets
             (Windows strips the Ethernet header before giving you the data)
"""

import socket
import sys
from collections.abc import Iterator

from netprobe.sniffer.parser import Packet, parse_packet


# ---------------------------------------------------------------------------
# Socket creation
# ---------------------------------------------------------------------------

def _get_local_ip() -> str:
    """Get the machine's primary outbound IP address.

    On Windows we need to bind the raw socket to a real local IP, not 0.0.0.0.
    This trick connects a UDP socket (no data sent) just to resolve routing.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        try:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
        except OSError:
            return "127.0.0.1"


def _create_socket_windows() -> socket.socket:
    """Create a promiscuous raw socket on Windows.

    SIO_RCVALL puts the NIC into promiscuous mode so we receive all IP
    packets on the interface, not just ones addressed to us.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
    sock.bind((_get_local_ip(), 0))
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
    return sock


def _create_socket_linux(interface: str) -> socket.socket:
    """Create a promiscuous raw socket on Linux.

    AF_PACKET + ETH_P_ALL receives every Ethernet frame regardless of
    protocol or destination — including frames not meant for this host.
    ntohs(0x0003) = ETH_P_ALL in network byte order.
    """
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    sock.bind((interface, 0))
    return sock


def create_raw_socket(interface: str) -> socket.socket:
    """Create a raw socket appropriate for the current platform."""
    if sys.platform == "win32":
        return _create_socket_windows()
    else:
        return _create_socket_linux(interface)


# ---------------------------------------------------------------------------
# Capture loop
# ---------------------------------------------------------------------------

def capture_packets(
    interface: str,
    proto_filter: str,
    count: int,
) -> Iterator[Packet]:
    """Yield parsed Packet objects from the wire.

    This is a generator — it yields one packet at a time so the caller
    (sniffer/__init__.py) can decide when to stop, how to display, etc.
    Using a generator here keeps capture logic separate from display logic.

    Args:
        interface:    Network interface name (Linux) or ignored (Windows)
        proto_filter: "tcp" | "udp" | "icmp" | "all"
        count:        Max packets to yield. 0 = unlimited.
    """
    sock = create_raw_socket(interface)
    captured = 0

    try:
        while True:
            if count > 0 and captured >= count:
                break

            raw, _ = sock.recvfrom(65535)
            packet = parse_packet(raw)

            if packet is None:
                continue

            # Apply protocol filter
            if proto_filter == "tcp"  and packet.tcp  is None: continue
            if proto_filter == "udp"  and packet.udp  is None: continue
            if proto_filter == "icmp" and packet.icmp is None: continue

            captured += 1
            yield packet

    finally:
        # Always clean up promiscuous mode on Windows
        if sys.platform == "win32":
            try:
                sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            except OSError:
                pass
        sock.close()