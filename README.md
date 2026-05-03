# netprobe

A CLI network scanner and packet sniffer built from scratch in Python —
no Scapy, no shortcuts, just raw sockets and `struct`.

Built as a learning project to understand networking fundamentals at the
byte level before moving into reverse engineering and malware analysis.

---

## The gimmick

Every output string has two voices, toggled with `--unhinged`:

```
# professional
netprobe scan --target 192.168.1.1

Starting scan on 192.168.1.1
  Ports   : 1-1024
  Timeout : 1.0s

PORT    STATE
22      open
80      open
443     open

Summary: 3 open, 0 filtered, 1021 closed — 2.31s
```

```
# unhinged
netprobe --unhinged scan --target 192.168.1.1

netprobe 🔥 — no cap network inspector
snitching on 192.168.1.1
  doors we're knocking on : 1-1024
  ghosting threshold      : 1.0s

PORT    STATE
22      built different
80      built different
443     built different

the tea: 3 built different, 0 lowkey sus, 1021 cooked — 2.31s
```

The dual-mode is a first-class design constraint, not a cosmetic option.
It forces you to understand every concept precisely enough to describe it absurdly.

---

## Installation

Requires Python 3.12+ and [uv](https://docs.astral.sh/uv/).

```bash
git clone https://github.com/yourname/netprobe
cd netprobe
uv sync
uv pip install -e .
```

> **Windows:** The sniffer requires an Administrator PowerShell session.
> Raw sockets need elevated privileges on all platforms.

---

## Usage

### Port scanner

```bash
# scan common ports
netprobe scan --target 192.168.1.1

# custom port range
netprobe scan --target 192.168.1.1 --ports 1-65535

# comma-separated ports
netprobe scan --target 192.168.1.1 --ports 22,80,443,8080

# JSON output
netprobe scan --target 192.168.1.1 --output json

# unhinged mode
netprobe --unhinged scan --target 192.168.1.1
```

### Packet sniffer

```bash
# sniff all traffic (requires admin/root)
netprobe sniff --interface eth0

# filter by protocol
netprobe sniff --interface eth0 --filter tcp
netprobe sniff --interface eth0 --filter udp
netprobe sniff --interface eth0 --filter icmp

# capture exactly 50 packets then stop
netprobe sniff --interface eth0 --count 50

# unhinged mode
netprobe --unhinged sniff --interface eth0 --filter tcp
```

---

## What's actually happening

### Scanner — TCP connect scan

For each port, the scanner attempts a full TCP 3-way handshake via `socket.connect_ex()`:
- Returns `0` → port is **open** (handshake completed)
- Returns an errno → port is **closed** (connection refused)
- Raises `socket.timeout` → port is **filtered** (firewall likely dropping packets)

1024 ports scan concurrently using `ThreadPoolExecutor`. Each thread owns one socket.
This is equivalent to `nmap -sT` — no raw sockets required, no root needed.

### Sniffer — raw socket capture

A raw socket (`SOCK_RAW`) is opened on the interface, receiving every packet
that passes through — not just traffic addressed to this machine.

Each packet is parsed manually from bytes using `struct.unpack`:
```
raw bytes → IP header → TCP / UDP / ICMP header → payload
```

The IP header layout (RFC 791), TCP header layout (RFC 793), UDP (RFC 768),
and ICMP (RFC 792) are implemented field-by-field. No external libraries.

Platform note: Linux gives you full Ethernet frames (skip 14-byte header to reach IP).
Windows gives you IP packets directly.

---

## Project structure

```
src/netprobe/
├── cli.py               # Click entry points only — no logic
├── scanner/
│   ├── tcp.py           # socket.connect_ex(), PortResult, threading
│   └── utils.py         # parse_ports(), resolve_target()
├── sniffer/
│   ├── capture.py       # raw socket setup, capture_packets() generator
│   └── parser.py        # struct.unpack of IP/TCP/UDP/ICMP headers
└── output/
    └── formatter.py     # VOCAB dict — every user-facing string lives here
```

---

## Development

```bash
uv run pytest              # 61 tests, no network required
uv run ruff check .        # lint
uv run mypy src/           # type check
```

Tests craft raw packet bytes with `struct.pack` and feed them directly to the parser.
No real network traffic, no external fixtures, no flaky tests.

---

## Build phases

| Phase | Feature | Status |
|-------|---------|--------|
| 1 | CLI skeleton, `--unhinged` mode, VOCAB system | ✅ |
| 2 | TCP connect scanner, threading, port/IP parsing | ✅ |
| 3 | Raw socket sniffer, struct packet parser | ✅ |
| 4 | Rich output polish, JSON export | 🔲 |
| 5 | DNS reverse lookup, banner grabbing, TTL hints | 🔲 |

---

## Stack

| Concern | Tool |
|---|---|
| CLI | `click` |
| Terminal output | `rich` |
| Networking | stdlib `socket` + `struct` |
| Concurrency | stdlib `concurrent.futures` |
| Tests | `pytest` |
| Lint | `ruff` |
| Types | `mypy` |
| Packaging | `uv` |