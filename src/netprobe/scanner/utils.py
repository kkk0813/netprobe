"""
netprobe.scanner.utils
----------------------------
Input parsing and validation for the scanner. No networking happens here - pure data transformation
"""

import ipaddress
import socket

class PortParseError(ValueError):
    """Raised when a port string cannot be parsed."""
    pass

def parse_ports(ports_str: str) -> list[int]:
    """Parse a port string into a sorted list of unique integers.
    
    Supports:
        "80"            -> [80]
        "22,80,443"     -> [22, 80, 443]
        "1-1024"        -> [1, 2, ..., 1024]
        "22,30,100-200" -> mixed
    """

    result: set[int] = set()

    for segment in ports_str.split(","):
        segment = segment.strip()
        if not segment:
            continue

        if "-" in segment:
            parts = segment.split("-")
            if len(parts) != 2:
                raise PortParseError(f"Invalid range: '{segment}'")
            try:
                start, end = int(parts[0]), int(parts[1])
            except ValueError:
                raise PortParseError(f"Non-numeric port in range: '{segment}'")
            if not (1 <= start <= 65535 and 1 <= end <= 65535):
                raise PortParseError(f"Ports must be 1-65535, got: '{segment}'")
            if start > end:
                raise PortParseError(f"Range start > end: '{segment}'")
            result.update(range(start, end + 1))

        else:
            try:
                port = int(segment)
            except ValueError:
                raise PortParseError(f"Non-numeric port: '{segment}'")
            if not (1 <= port <= 65535):
                raise PortParseError(f"Port out of range: {port}")
            result.add(port)

    if not result:
        raise PortParseError("No valid ports found in input")

    return sorted(result)

def resolve_target(target: str) -> str:
    """Resolve a hostname to an IP, or validate a raw IP string.
    
    Returns the IP string on success.
    Raises ValueError if target cannot be resolved.
    """
    # Try parsing as a raw IP first (no DNS lookup needed)
    try:
        ipaddress.ip_address(target)
        return target
    except ValueError:
        pass

    # Treat as hostname - attempt DNS resolution
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        raise ValueError(f"Cannot resolve target: '{target}'")