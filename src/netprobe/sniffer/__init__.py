"""
netprobe.sniffer
----------------
Orchestrates packet capture and display.
cli.py calls run_sniff() and knows nothing beyond that.
"""

import sys

from rich.live import Live
from rich.table import Table

from netprobe.output.formatter import make_console, term
from netprobe.sniffer.capture import capture_packets
from netprobe.sniffer.parser import Packet, tcp_flags_str


def run_sniff(
    interface: str,
    proto_filter: str,
    count: int,
    unhinged: bool,
) -> None:
    console = make_console(unhinged)

    # Windows doesn't use interface names — it binds to the local IP
    if sys.platform == "win32":
        console.print(f"[dim]Windows detected — binding to primary interface IP[/dim]")

    console.print(
        f"[info]{term('sniff_start', unhinged)}[/info] "
        f"[value]{interface}[/value] "
        f"[dim](filter: {proto_filter}, "
        f"count: {'unlimited' if count == 0 else count})[/dim]\n"
        f"[dim]Press Ctrl+C to stop.[/dim]\n"
    )

    try:
        _capture_loop(interface, proto_filter, count, unhinged, console)
    except KeyboardInterrupt:
        console.print(f"\n[warning]{term('sniff_stopped', unhinged)}[/warning]")
    except PermissionError:
        console.print(f"\n[error]{term('err_permission', unhinged)}[/error]")
    except OSError as e:
        console.print(f"\n[error]Failed to open interface '{interface}': {e}[/error]")


# ---------------------------------------------------------------------------
# Display
# ---------------------------------------------------------------------------

def _make_table(unhinged: bool) -> Table:
    table = Table(
        show_header=True,
        header_style="label",
        box=None,
        padding=(0, 2),
    )
    table.add_column("PROTO",    style="info",    no_wrap=True, width=6)
    table.add_column("SRC",      style="value",   no_wrap=True, width=22)
    table.add_column("DST",      style="value",   no_wrap=True, width=22)
    table.add_column("INFO",     style="dim",     no_wrap=True)
    return table


def _format_packet(packet: Packet, unhinged: bool) -> tuple[str, str, str, str]:
    """Return (proto, src, dst, info) strings for a packet row."""
    ip = packet.ip

    if packet.tcp:
        t    = packet.tcp
        proto = "TCP"
        src  = f"{ip.src_ip}:{t.src_port}"
        dst  = f"{ip.dst_ip}:{t.dst_port}"
        flags = tcp_flags_str(t.flags)
        info  = f"{term('packet_captured', unhinged)} | flags={flags} ttl={ip.ttl}"

    elif packet.udp:
        u     = packet.udp
        proto = "UDP"
        src   = f"{ip.src_ip}:{u.src_port}"
        dst   = f"{ip.dst_ip}:{u.dst_port}"
        info  = f"{term('packet_captured', unhinged)} | len={u.length} ttl={ip.ttl}"

    elif packet.icmp:
        i     = packet.icmp
        proto = "ICMP"
        src   = ip.src_ip
        dst   = ip.dst_ip
        info  = f"{term('packet_captured', unhinged)} | type={i.type} code={i.code} ttl={ip.ttl}"

    else:
        proto = f"IP/{ip.protocol}"
        src   = ip.src_ip
        dst   = ip.dst_ip
        info  = f"ttl={ip.ttl}"

    return proto, src, dst, info


def _capture_loop(
    interface: str,
    proto_filter: str,
    count: int,
    unhinged: bool,
    console,
) -> None:
    """Run capture with a live-updating Rich table."""
    total = 0
    table = _make_table(unhinged)

    with Live(table, console=console, refresh_per_second=10):
        for packet in capture_packets(interface, proto_filter, count):
            proto, src, dst, info = _format_packet(packet, unhinged)
            table.add_row(proto, src, dst, info)
            total += 1

    console.print(
        f"\n[dim]{term('summary', unhinged)}: "
        f"{total} {term('packet_captured', unhinged).lower()}[/dim]"
    )