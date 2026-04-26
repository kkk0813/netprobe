"""
netprobe.scanner.tcp
--------------------------
Core TCP connect scan logic.

Why TCP connect scan?
    A full 3-way handshake (SYN -> SYN-ACK -> ACK) is attempted on each port.
    If it completes -> port is open.
    If the target resets it (RST) -> port is closed.
    If nothing replies before timeout -> port is filtered (firewall likely).

This is the same technique as 'nmap -sT'.
No raw sockets needed - the OS handles the handshake via socket.connect().
The tradeoff: it is logged by the target. Louder than a SYN scan, but requires no root/admin privileges.
"""

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from enum import Enum

class PortState(Enum):
    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"

@dataclass
class PortResult:
    port: int
    state: PortState

def scan_port(target_ip: str, port: int, timeout: float) -> PortResult:
    """Attempt a TCP connect to a single port.
    
    Returns a PortResult with the detected state.
    """

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            code = sock.connect_ex((target_ip, port))
            # connect_ex returns 0 on success (open), errno otherwise
            if code == 0:
                return PortResult(port=port, state=PortState.OPEN)
            else:
                return PortResult(port=port, state=PortState.CLOSED)
    except socket.timeout:
        return PortResult(port=port, state=PortState.FILTERED)
    except OSError:
        return PortResult(port=port, state=PortState.FILTERED)

def scan_ports(target_ip: str, ports: list[int], timeout: float, max_workers: int = 100) -> list[PortResult]:
    """Scan multiple ports concurrently using a thread pool.
    
    Why threads and not async?
        socket.connect_ex is a blocking call. Threads let the OS handle the waiting in parallet.
        For I/0-bound work like this, threads are simpler and just as effective as async.

    max_workers = 100 is a safe default. Too high and you'll hit OS file descriptor limits or trigger rate limiting on the target.
    """
    results: list[PortResult] = []

    with ThreadPoolExecutor(max_workers=min(max_workers, len(ports))) as executor:
        futures = {
            executor.submit(scan_port, target_ip, port, timeout): ports
            for port in ports
        }
        for future in as_completed(futures):
            results.append(future.result())

    # Return sorted by port number for consistent output
    return sorted(results, key=lambda r: r.port)