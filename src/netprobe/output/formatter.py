"""
netprobe.output.formatter
--------------------------
All user-facing strings live here. Nowhere else.

Two voices:
  - professional : sounds like a CISSP wrote it
  - unhinged     : sounds like it was written at 3am on a caffeine binge

To add a new term: add a key to VOCAB. That's it.
"""

from rich.console import Console
from rich.theme import Theme

# ---------------------------------------------------------------------------
# Vocabulary table
# Each key maps to (professional, unhinged)
# ---------------------------------------------------------------------------
VOCAB: dict[str, tuple[str, str]] = {
    # port states
    "open":                ("open",                    "built different"),
    "closed":              ("closed",                  "cooked"),
    "filtered":            ("filtered",                "lowkey sus"),

    # scan lifecycle
    "scanning":            ("Scanning",                "interrogating"),
    "scan_complete":       ("Scan complete",           "mission accomplished bestie"),
    "scan_start":          ("Starting scan on",        "snitching on"),
    "no_open_ports":       ("No open ports found",     "bro is in full lockdown mode"),

    # sniffer lifecycle
    "sniffing":            ("Sniffing on",             "eavesdropping on"),
    "sniff_start":         ("Listening on interface",  "wiretapping"),
    "packet_captured":     ("Packet captured",         "caught in 4k"),
    "sniff_stopped":       ("Capture stopped",         "ok we're done being nosy"),

    # errors
    "err_invalid_target":  ("Invalid target address",  "bro typed a fake IP"),
    "err_invalid_ports":   ("Invalid port range",      "those port numbers are not it chief"),
    "err_timeout":         ("Connection timed out",    "left on read"),
    "err_permission":      ("Permission denied — try running with sudo", "ur not built for this (try sudo)"),

    # generic
    "target":              ("Target",                  "victim"),
    "ports":               ("Ports",                   "doors we're knocking on"),
    "timeout":             ("Timeout",                 "ghosting threshold"),
    "interface":           ("Interface",               "the wire we're tapping"),
    "filter":              ("Filter",                  "vibe check"),
    "duration":            ("Duration",                "time spent being unethical"),
    "summary":             ("Summary",                 "the tea"),
}

# ---------------------------------------------------------------------------
# Theme
# ---------------------------------------------------------------------------
PRO_THEME = Theme({
    "info":    "cyan",
    "success": "green",
    "warning": "yellow",
    "error":   "red bold",
    "label":   "bold white",
    "value":   "yellow",
    "dim":     "dim white",
})

UNHINGED_THEME = Theme({
    "info":    "bright_magenta",
    "success": "bright_green bold",
    "warning": "bright_yellow bold",
    "error":   "bright_red bold",
    "label":   "bold bright_cyan",
    "value":   "bright_yellow",
    "dim":     "dim magenta",
})

# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
def make_console(unhinged: bool) -> Console:
    """Return a themed Console for the current mode."""
    return Console(theme=UNHINGED_THEME if unhinged else PRO_THEME)

def term(key: str, unhinged: bool) -> str:
    """Resolve a vocabulary key to the correct voice."""
    if key not in VOCAB:
        raise KeyError(f"Unknown vocab key: '{key}' — add it to formatter.VOCAB")
    professional, brainrot = VOCAB[key]
    return brainrot if unhinged else professional

def banner(unhinged: bool) -> str:
    if unhinged:
        return (
            "[bold bright_magenta]"
            "netprobe 🔥 — no cap network inspector"
            "[/bold bright_magenta]"
        )
    return "[bold cyan]netprobe[/bold cyan] — network scanner & packet sniffer"