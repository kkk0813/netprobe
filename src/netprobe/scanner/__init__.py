"""
netprobe.scanner
----------------
Orchestrates a full scan: parse → resolve → scan → display.
cli.py calls run_scan() and knows nothing beyond that.
"""

import time

from rich.table import Table

from netprobe.output.formatter import make_console, term
from netprobe.scanner.tcp import PortState, scan_ports
from netprobe.scanner.utils import PortParseError, parse_ports, resolve_target

def run_scan(target: str, ports: str, timeout: float, output_format: str, unhinged: bool) -> None:
    console = make_console(unhinged)

    # --- parse ports ---
    try:
        port_list = parse_ports(ports)
    except PortParseError as e:
        console.print(f"[error]{term('err_invalid_ports', unhinged)}: {e}[/error]")
        return

    # --- resolve target ---
    try:
        target_ip = resolve_target(target)
    except ValueError:
        console.print(f"[error]{term('err_invalid_target', unhinged)}: {target}[/error]")
        return

    if target_ip != target:
        console.print(f"[dim]resolved {target} → {target_ip}[/dim]")

    # --- scan ---
    console.print(f"[info]{term('scanning', unhinged)} {len(port_list)} ports...[/info]")
    start = time.perf_counter()
    results = scan_ports(target_ip, port_list, timeout)
    elapsed = time.perf_counter() - start

    # --- filter to open only for display (closed spam is noise) ---
    open_ports = [r for r in results if r.state == PortState.OPEN]
    filtered_ports = [r for r in results if r.state == PortState.FILTERED]

    # --- output ---
    if output_format == "table":
        _print_table(open_ports, filtered_ports, unhinged, console)
    else:
        _print_json(results, unhinged, console)

    # --- summary ---
    if not open_ports:
        console.print(f"\n[warning]{term('no_open_ports', unhinged)}[/warning]")
    else:
        console.print(
            f"\n[dim]{term('summary', unhinged)}: "
            f"{len(open_ports)} {term('open', unhinged)}, "
            f"{len(filtered_ports)} {term('filtered', unhinged)}, "
            f"{len(results) - len(open_ports) - len(filtered_ports)} {term('closed', unhinged)} "
            f"— {elapsed:.2f}s[/dim]"
        )

# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------

_STATE_STYLE = {
    PortState.OPEN:     "success",
    PortState.CLOSED:   "dim",
    PortState.FILTERED: "warning",
}


def _print_table(open_ports, filtered_ports, unhinged: bool, console) -> None:
    display = open_ports + filtered_ports
    if not display:
        return

    table = Table(show_header=True, header_style="label", box=None, padding=(0, 2))
    table.add_column("PORT", style="value", no_wrap=True)
    table.add_column("STATE", no_wrap=True)
    table.add_column(term("summary", unhinged).upper(), style="dim")

    state_labels = {
        PortState.OPEN: term("open", unhinged),
        PortState.FILTERED: term("filtered", unhinged),
    }

    for result in display:
        style = _STATE_STYLE[result.state]
        label = state_labels.get(result.state, result.state.value)
        table.add_row(
            str(result.port),
            f"[{style}]{label}[/{style}]",
            "",
        )

    console.print(table)


def _print_json(results, unhinged: bool, console) -> None:
    import json
    data = [
        {"port": r.port, "state": r.state.value}
        for r in results
        if r.state == PortState.OPEN
    ]
    console.print(json.dumps(data, indent=2))