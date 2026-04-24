# netprobe

A CLI packet sniffer and port scanner built from scratch for learning networking fundamentals.

## Setup

```bash
# Install dependencies
uv sync

# Install in editable mode so `netprobe` command works
uv pip install -e .
```

## Usage

```bash
# Port scan
netprobe scan --target 192.168.1.1 --ports 1-1024

# Packet sniff
netprobe sniff --interface eth0 --filter tcp

# Help
netprobe --help
netprobe scan --help
netprobe sniff --help
```

## Dev Workflow

```bash
uv run ruff check .          # lint
uv run mypy src/             # type check
uv run pytest                # run tests
```

## Build Phases

| Phase | Feature | Status |
|-------|---------|--------|
| 1 | CLI skeleton + project structure | ✅ |
| 2 | TCP connect scanner | 🔲 |
| 3 | Raw socket packet sniffer | 🔲 |
| 4 | Rich output + JSON export | 🔲 |
| 5 | DNS lookup, banner grabbing, TTL hints | 🔲 |