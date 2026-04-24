"""
Phase 1 tests — CLI argument parsing and mode switching.
"""

from click.testing import CliRunner
from netprobe.cli import main

runner = CliRunner()

# ---------------------------------------------------------------------------
# scan — professional mode
# ---------------------------------------------------------------------------
class TestScanProfessional:
    def test_requires_target(self) -> None:
        result = runner.invoke(main, ["scan"])
        assert result.exit_code != 0
        assert "Missing option '--target'" in result.output

    def test_default_ports_shown(self) -> None:
        result = runner.invoke(main, ["scan", "--target", "127.0.0.1"])
        assert result.exit_code == 0
        assert "1-1024" in result.output

    def test_custom_ports(self) -> None:
        result = runner.invoke(main, ["scan", "-t", "10.0.0.1", "-p", "22,80,443"])
        assert result.exit_code == 0
        assert "22,80,443" in result.output

    def test_professional_vocab(self) -> None:
        result = runner.invoke(main, ["scan", "--target", "127.0.0.1"])
        assert "Target" in result.output or "Scanning" in result.output
        assert "victim" not in result.output

# ---------------------------------------------------------------------------
# scan — unhinged mode
# ---------------------------------------------------------------------------
class TestScanUnhinged:
    def test_unhinged_flag_accepted(self) -> None:
        result = runner.invoke(main, ["--unhinged", "scan", "--target", "127.0.0.1"])
        assert result.exit_code == 0

    def test_unhinged_vocab_used(self) -> None:
        result = runner.invoke(main, ["--unhinged", "scan", "--target", "127.0.0.1"])
        # "victim" or "snitching" should appear instead of "Target" / "Scanning"
        assert "victim" in result.output or "snitching" in result.output

    def test_unhinged_banner(self) -> None:
        result = runner.invoke(main, ["--unhinged", "scan", "--target", "127.0.0.1"])
        assert "no cap" in result.output

# ---------------------------------------------------------------------------
# sniff — professional mode
# ---------------------------------------------------------------------------
class TestSniffProfessional:
    def test_default_interface(self) -> None:
        result = runner.invoke(main, ["sniff"])
        assert result.exit_code == 0
        assert "eth0" in result.output

    def test_custom_interface(self) -> None:
        result = runner.invoke(main, ["sniff", "--interface", "wlan0"])
        assert result.exit_code == 0
        assert "wlan0" in result.output

    def test_invalid_filter_rejected(self) -> None:
        result = runner.invoke(main, ["sniff", "--filter", "ftp"])
        assert result.exit_code != 0

    def test_professional_vocab(self) -> None:
        result = runner.invoke(main, ["sniff"])
        assert "wiretapping" not in result.output

# ---------------------------------------------------------------------------
# sniff — unhinged mode
# ---------------------------------------------------------------------------
class TestSniffUnhinged:
    def test_unhinged_vocab_used(self) -> None:
        result = runner.invoke(main, ["--unhinged", "sniff"])
        assert "wiretapping" in result.output or "eavesdropping" in result.output

    def test_unhinged_does_not_affect_filter_validation(self) -> None:
        # --unhinged should never bypass arg validation
        result = runner.invoke(main, ["--unhinged", "sniff", "--filter", "ftp"])
        assert result.exit_code != 0

# ---------------------------------------------------------------------------
# formatter
# ---------------------------------------------------------------------------
class TestFormatter:
    def test_unknown_vocab_key_raises(self) -> None:
        from netprobe.output.formatter import term
        import pytest
        with pytest.raises(KeyError):
            term("nonexistent_key", False)

    def test_professional_returns_first(self) -> None:
        from netprobe.output.formatter import term
        assert term("open", False) == "open"

    def test_unhinged_returns_second(self) -> None:
        from netprobe.output.formatter import term
        assert term("open", True) == "built different"