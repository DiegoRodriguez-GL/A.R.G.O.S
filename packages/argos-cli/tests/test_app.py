"""End-to-end smoke tests for the Typer app."""

from __future__ import annotations

from argos_cli import __version__
from argos_cli.app import app
from typer.testing import CliRunner

runner = CliRunner()


def test_help_mentions_all_subcommands() -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    output = result.stdout + (result.stderr or "")
    for sub in ("scan", "redteam", "proxy", "report"):
        assert sub in output


def test_version_flag_prints_version() -> None:
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.stdout


def test_no_args_shows_help() -> None:
    result = runner.invoke(app, [])
    combined = result.stdout + (result.stderr or "")
    assert "Usage" in combined


def test_subcommands_without_required_args_exit_two() -> None:
    # Every subcommand with a required argument must exit with code 2
    # when invoked bare. proxy is still the only placeholder left.
    for sub in ("scan", "redteam", "proxy", "report"):
        result = runner.invoke(app, [sub])
        assert result.exit_code == 2, f"{sub} should exit 2 without its required args"
