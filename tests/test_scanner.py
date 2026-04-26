"""
Phase 2 tests — scanner logic.

Network tests use 127.0.0.1 (localhost) only.
No external hosts. No flaky internet-dependent assertions.
"""

import pytest
from netprobe.scanner.utils import parse_ports, resolve_target, PortParseError
from netprobe.scanner.tcp import scan_port, PortState


# ---------------------------------------------------------------------------
# parse_ports
# ---------------------------------------------------------------------------

class TestParsePorts:
    def test_single_port(self):
        assert parse_ports("80") == [80]

    def test_comma_list(self):
        assert parse_ports("22,80,443") == [22, 80, 443]

    def test_range(self):
        result = parse_ports("1-5")
        assert result == [1, 2, 3, 4, 5]

    def test_mixed(self):
        result = parse_ports("22,80,100-103")
        assert result == [22, 80, 100, 101, 102, 103]

    def test_deduplication(self):
        result = parse_ports("80,80,80")
        assert result == [80]

    def test_sorted_output(self):
        result = parse_ports("443,22,80")
        assert result == [22, 80, 443]

    def test_invalid_range_reversed(self):
        with pytest.raises(PortParseError):
            parse_ports("100-1")

    def test_port_zero_rejected(self):
        with pytest.raises(PortParseError):
            parse_ports("0")

    def test_port_above_65535_rejected(self):
        with pytest.raises(PortParseError):
            parse_ports("65536")

    def test_non_numeric_rejected(self):
        with pytest.raises(PortParseError):
            parse_ports("abc")

    def test_empty_string_rejected(self):
        with pytest.raises(PortParseError):
            parse_ports("")


# ---------------------------------------------------------------------------
# resolve_target
# ---------------------------------------------------------------------------

class TestResolveTarget:
    def test_valid_ip_passthrough(self):
        assert resolve_target("127.0.0.1") == "127.0.0.1"

    def test_localhost_resolves(self):
        result = resolve_target("localhost")
        assert result in ("127.0.0.1", "::1")

    def test_invalid_hostname_raises(self):
        with pytest.raises(ValueError):
            resolve_target("this.host.does.not.exist.invalid")


# ---------------------------------------------------------------------------
# scan_port — uses localhost only
# ---------------------------------------------------------------------------

class TestScanPort:
    def test_closed_port_on_localhost(self):
        # Port 1 is almost never open on any machine
        result = scan_port("127.0.0.1", port=1, timeout=0.5)
        assert result.state in (PortState.CLOSED, PortState.FILTERED)

    def test_result_has_correct_port_number(self):
        result = scan_port("127.0.0.1", port=9999, timeout=0.5)
        assert result.port == 9999

    def test_filtered_on_timeout(self):
        # Simulate a socket timeout without real network dependency
        import socket
        from unittest.mock import MagicMock, patch
        mock_sock = MagicMock()
        mock_sock.__enter__ = lambda s: s
        mock_sock.__exit__ = MagicMock(return_value=False)
        mock_sock.connect_ex.side_effect = socket.timeout

        with patch("netprobe.scanner.tcp.socket.socket", return_value=mock_sock):
            result = scan_port("192.0.2.1", port=80, timeout=0.3)
        assert result.state == PortState.FILTERED