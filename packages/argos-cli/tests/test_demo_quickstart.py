"""Tests for the onboarding commands ``argos demo`` and
``argos quickstart``."""

from __future__ import annotations

import pytest
from argos_cli.app import app
from typer.testing import CliRunner


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


# ---------------------------------------------------------------------------
# argos demo
# ---------------------------------------------------------------------------


class TestDemo:
    def test_demo_exits_zero_and_completes_all_steps(self, runner: CliRunner) -> None:
        """Full 10-second guided tour. Asserts every step ran AND printed
        its observable signal."""
        result = runner.invoke(app, ["demo"])
        assert result.exit_code == 0, result.stdout
        out = result.stdout
        # Every step header.
        assert "1. argos scan" in out
        assert "2. argos eval" in out
        assert "3. argos proxy" in out
        assert "4. argos compliance" in out
        # Final summary table.
        assert "argos demo: results" in out
        # Pinned canonical numbers (these are regression sentinels: a
        # change here means the lab benchmark or scanner output drifted).
        assert "20 findings" in out
        assert "TP=20" in out
        assert "FP=0" in out
        assert "TN=100" in out
        assert "FN=0" in out
        assert "5 frameworks" in out

    def test_demo_quick_skips_proxy_bench(self, runner: CliRunner) -> None:
        result = runner.invoke(app, ["demo", "--quick"])
        assert result.exit_code == 0, result.stdout
        out = result.stdout
        assert "skipped (--quick)" in out
        # The other three steps still ran.
        assert "1. argos scan" in out
        assert "2. argos eval" in out
        assert "4. argos compliance" in out

    def test_demo_help_lists_quick_flag(self, runner: CliRunner) -> None:
        result = runner.invoke(app, ["demo", "--help"])
        assert result.exit_code == 0
        assert "--quick" in result.stdout


# ---------------------------------------------------------------------------
# argos quickstart
# ---------------------------------------------------------------------------


class TestQuickstart:
    def test_quickstart_prints_seven_sections(self, runner: CliRunner) -> None:
        result = runner.invoke(app, ["quickstart"])
        assert result.exit_code == 0, result.stdout
        out = result.stdout
        # Seven canonical sections.
        for n in range(1, 8):
            assert f"{n}. " in out, f"missing section {n}"
        # Headline of every section is human-readable.
        assert "See ARGOS in action" in out
        assert "Audit a static MCP config" in out
        assert "Red-team an agent endpoint" in out
        assert "Run the empirical benchmark" in out
        assert "Audit live MCP traffic via proxy" in out
        assert "Render a report" in out
        assert "Inspect inventory and mappings" in out

    def test_quickstart_examples_are_real_commands(self, runner: CliRunner) -> None:
        """Every fenced command starts with ``argos`` so a copy-paste
        is immediately runnable."""
        result = runner.invoke(app, ["quickstart"])
        assert result.exit_code == 0
        # Pick a few canonical commands that MUST appear verbatim.
        for cmd in (
            "argos demo",
            "argos status",
            "argos scan",
            "argos doctor",
            "argos redteam -t",
            "argos eval",
            "argos proxy run",
            "argos proxy bench",
            "argos report",
            "argos rules list",
            "argos compliance list",
        ):
            assert cmd in result.stdout, f"missing canonical command: {cmd}"


# ---------------------------------------------------------------------------
# Top-level help mentions onboarding commands.
# ---------------------------------------------------------------------------


def test_top_level_help_promotes_demo_and_quickstart(runner: CliRunner) -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "argos demo" in result.stdout
    assert "argos quickstart" in result.stdout


def test_status_promotes_demo(runner: CliRunner) -> None:
    """``argos status`` ends with a hint pointing at ``argos demo``."""
    result = runner.invoke(app, ["status"])
    assert result.exit_code == 0
    assert "argos demo" in result.stdout
    assert "argos quickstart" in result.stdout
