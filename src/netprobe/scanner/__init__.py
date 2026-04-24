from netprobe.output.formatter import make_console, term


def run_scan(
    target: str,
    ports: str,
    timeout: float,
    output_format: str,
    unhinged: bool,
) -> None:
    console = make_console(unhinged)
    console.print(f"[dim][ stub ] {term('scanning', unhinged)} {target}... coming in Phase 2.[/dim]")