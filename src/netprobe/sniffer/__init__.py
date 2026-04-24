from netprobe.output.formatter import make_console, term


def run_sniff(
    interface: str,
    proto_filter: str,
    count: int,
    unhinged: bool,
) -> None:
    console = make_console(unhinged)
    console.print(f"[dim][ stub ] {term('sniffing', unhinged)} {interface}... coming in Phase 3.[/dim]")