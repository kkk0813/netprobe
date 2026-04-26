"""
netprobe.cli
------------
Entry point for the netprobe CLI.

Rule: This file handles ONLY argument wiring and context passing.
      No networking logic. No string literals for user output.
      All user-facing text comes from output.formatter.
"""

import click
from netprobe.output.formatter import banner, make_console, term
from netprobe.scanner import run_scan
from netprobe.sniffer import run_sniff

# ---------------------------------------------------------------------------
# Root group — injects unhinged flag into ctx.obj for all subcommands
# ---------------------------------------------------------------------------
@click.group()
@click.option("--unhinged", is_flag=True, default=False, help="Switch from professional to peak brainrot output.",)
@click.version_option(version="0.1.0", prog_name="netprobe")
@click.pass_context
def main(ctx: click.Context, unhinged: bool) -> None:
    """netprobe — network scanner and packet sniffer."""
    ctx.ensure_object(dict)
    ctx.obj["unhinged"] = unhinged

    console = make_console(unhinged)
    console.print(banner(unhinged))

# ---------------------------------------------------------------------------
# scan subcommand
# ---------------------------------------------------------------------------
@main.command()
@click.option("--target", "-t", required=True,      help="Target IP or hostname.")
@click.option("--ports",  "-p", default="1-1024",   show_default=True, help="Port range, e.g. 1-1024 or 22,80,443.")
@click.option("--timeout",      default=1.0,        show_default=True, type=float, help="Connection timeout in seconds.")
@click.option("--output", "-o", type=click.Choice(["table", "json"]), default="table", show_default=True)
@click.pass_context
def scan(ctx: click.Context, target: str, ports: str, timeout: float, output: str) -> None:
    """Scan open TCP ports on a target host."""
    unhinged = ctx.obj["unhinged"]
    console  = make_console(unhinged)

    console.print(f"\n[label]{term('scan_start', unhinged)}[/label] [value]{target}[/value]")
    console.print(f"  [label]{term('ports', unhinged)}:[/label] [value]{ports}[/value]")
    console.print(f"  [label]{term('timeout', unhinged)}:[/label] [value]{timeout}s[/value]\n")

    run_scan(target=target, ports=ports, timeout=timeout, output_format=output, unhinged=unhinged)

# ---------------------------------------------------------------------------
# sniff subcommand
# ---------------------------------------------------------------------------
@main.command()
@click.option("--interface", "-i", default="eth0",  show_default=True, help="Network interface to listen on.")
@click.option("--filter",    "-f", "proto_filter",
              type=click.Choice(["tcp", "udp", "icmp", "all"]),
              default="all", show_default=True,      help="Protocol filter.")
@click.option("--count",     "-c", default=0,        show_default=True, type=int, help="Packets to capture (0 = unlimited).")
@click.pass_context
def sniff(ctx: click.Context, interface: str, proto_filter: str, count: int) -> None:
    """Capture and display live network packets."""
    unhinged = ctx.obj["unhinged"]
    console  = make_console(unhinged)

    console.print(f"\n[label]{term('sniff_start', unhinged)}[/label] [value]{interface}[/value]")
    console.print(f"  [label]{term('filter', unhinged)}   :[/label] [value]{proto_filter}[/value]")
    console.print(f"  [label]{term('duration', unhinged)} :[/label] [value]{'unlimited' if count == 0 else f'{count} packets'}[/value]\n")

    run_sniff(interface=interface, proto_filter=proto_filter, count=count, unhinged=unhinged)