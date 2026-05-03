# AGENTS.md

Context file for AI agents (Claude, Codex, etc.) working on this codebase.
Read this before touching any file.

---

## What this project is

`netprobe` is a CLI network scanner and packet sniffer built from scratch in Python.
It is a learning project — the explicit goal is to understand networking fundamentals
at the byte level before moving into reverse engineering and malware analysis.

There are two output modes controlled by a single `--unhinged` flag:
- **Professional** — standard networking terminology
- **Unhinged** — deliberately absurd brainrot language that mocks industry jargon

This dual-mode is not a joke feature bolted on. It is a first-class design constraint.
Every user-facing string must support both voices.

---

## Architecture rules — do not violate these

### 1. `cli.py` is a wiring file only
It contains Click decorators, argument definitions, and calls to module entry points.
It never contains business logic, networking code, or string literals for user output.
If you find yourself writing an `if` statement in `cli.py` that isn't about argument
validation, you are in the wrong file.

### 2. All user-facing strings live in `output/formatter.py`
The `VOCAB` dict is the single source of truth for every string a user will ever see.
Adding output to any module means adding a key to `VOCAB` first, then calling `term(key, unhinged)`.
Never hardcode a display string outside of `formatter.py`.

### 3. Each module has one job — enforce this
```
cli.py              → argument parsing and context passing only
scanner/utils.py    → input parsing and validation (no networking)
scanner/tcp.py      → TCP socket logic only
scanner/__init__.py → orchestration: parse → resolve → scan → display
sniffer/parser.py   → struct unpacking of raw bytes into dataclasses
sniffer/capture.py  → raw socket setup and capture loop (generator)
sniffer/__init__.py → orchestration: open socket → capture → display
output/formatter.py → all user-facing strings, themes, console factory
```

If a file needs "and" to describe its job, it needs to be split.

### 4. No Scapy, no dpkt, no external packet libraries
All packet parsing uses stdlib `struct` and `socket` only. This is intentional.
The learning objective is to understand byte-level protocol layout.
Do not introduce packet parsing libraries even for convenience.

### 5. `ctx.obj["unhinged"]` is how the mode flag travels
The `--unhinged` flag is set once in the root Click group and stored in `ctx.obj`.
Subcommands read it from context and pass it as a parameter to module functions.
Module functions accept `unhinged: bool` and call `make_console(unhinged)` locally.
Do not add a global state object or singleton for this.

---

## Project structure

```
netprobe/
├── src/
│   └── netprobe/
│       ├── __init__.py
│       ├── __main__.py          # enables python -m netprobe
│       ├── cli.py               # Click entry points only
│       ├── scanner/
│       │   ├── __init__.py      # run_scan() orchestrator
│       │   ├── tcp.py           # TCP connect scan, PortResult, PortState
│       │   └── utils.py         # parse_ports(), resolve_target()
│       ├── sniffer/
│       │   ├── __init__.py      # run_sniff() orchestrator
│       │   ├── capture.py       # raw socket factory, capture_packets() generator
│       │   └── parser.py        # parse_packet(), IPHeader, TCPHeader, etc.
│       └── output/
│           ├── __init__.py
│           └── formatter.py     # VOCAB, term(), make_console(), banner()
├── tests/
│   ├── test_cli.py              # Click argument parsing, both modes
│   ├── test_scanner.py          # parse_ports, resolve_target, scan_port
│   └── test_parser.py           # struct parsing with crafted raw bytes
├── AGENTS.md                    # this file
├── README.md
└── pyproject.toml
```

---

## Dev commands

```bash
uv run pytest                  # run all tests
uv run ruff check .            # lint
uv run mypy src/               # type check
uv run netprobe --help         # run CLI
```

On Windows, the sniffer requires an Administrator PowerShell session
(raw sockets need elevated privileges).

---

## Testing conventions

- **No external network dependencies in unit tests.** Use `unittest.mock` to simulate
  socket behaviour. Use `192.0.2.0/24` (TEST-NET) only with a mock, never live.
- **Parser tests craft raw bytes manually** using `struct.pack` helpers defined in
  `test_parser.py`. Never use real captured packets as test fixtures.
- **CLI tests use `click.testing.CliRunner`** — never subprocess, never real sockets.
- Tests that need platform-specific behaviour use `monkeypatch.setattr` on
  `sys.platform`, not `@pytest.mark.skipif`.

---

## Adding a new feature — checklist

1. Does it belong in an existing file? Check the responsibility list above.
   If it needs "and" to describe where it fits, make a new file.
2. Add `VOCAB` keys to `formatter.py` for every new user-facing string.
   Add both professional and unhinged variants. No placeholders.
3. Write the test first if it's pure logic (utils, parser).
   Write the implementation first if it's I/O (capture, scan) — mock the I/O in tests.
4. Run `uv run ruff check .` and `uv run mypy src/` before committing.
5. Update the phase table in `README.md`.

---

## What is intentionally absent

- No async. Threading via `concurrent.futures` is used for the scanner.
  The sniffer uses a blocking generator. Keeping it synchronous is deliberate —
  async would obscure the I/O model during learning.
- No Scapy. See rule 4 above.
- No config file. `--unhinged` is the only persistent-style flag and it is
  passed explicitly per invocation.
- No logging framework. `rich.Console` is the output layer for everything.