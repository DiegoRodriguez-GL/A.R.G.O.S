"""Smoke tests for ``argos proxy`` subcommands.

Two layers:

- ``argos proxy bench --no-detectors`` runs in-memory and exits 0
  under any reasonable budget (p95 in microseconds).
- ``argos proxy bench`` with detectors enforces the RNF-02 50 ms
  budget. The test runs only 200 iterations so it stays under 1s.
"""

from __future__ import annotations

import os
from pathlib import Path

from argos_cli.app import app
from typer.testing import CliRunner

_REPO_ROOT = Path(__file__).resolve().parents[3]


def _python_with_argos_installed() -> str:
    """Return the venv Python (not the system one) under ``uv run``."""
    venv = os.environ.get("VIRTUAL_ENV")
    if venv:
        for candidate in (
            Path(venv, "Scripts", "python.exe"),
            Path(venv, "bin", "python"),
        ):
            if candidate.is_file():
                return str(candidate)
    import sys

    return sys.executable


def test_proxy_bench_no_detectors_passes() -> None:
    runner = CliRunner()
    result = runner.invoke(
        app,
        ["proxy", "bench", "--no-detectors", "-n", "200"],
    )
    assert result.exit_code == 0, result.stdout
    assert "bench pass" in result.stdout


def test_proxy_bench_with_detectors_passes_under_budget() -> None:
    runner = CliRunner()
    result = runner.invoke(
        app,
        ["proxy", "bench", "--detectors", "-n", "200"],
    )
    assert result.exit_code == 0, result.stdout
    # Confirm the report mentions the budget header so a regression in
    # the latency reporter surfaces here too.
    assert "budget p95" in result.stdout


def test_proxy_bench_fails_when_budget_is_zero() -> None:
    """A zero budget guarantees failure; this confirms exit code 1
    on a budget miss (the property CI relies on)."""
    runner = CliRunner()
    result = runner.invoke(
        app,
        ["proxy", "bench", "--budget-ms", "0", "-n", "100"],
    )
    assert result.exit_code == 1
    assert "bench fail" in result.stdout or "bench fail" in (result.stderr or "")


def test_proxy_bench_iterations_bounds() -> None:
    runner = CliRunner()
    # Below the floor.
    too_few = runner.invoke(app, ["proxy", "bench", "-n", "1"])
    assert too_few.exit_code != 0
    # Above the ceiling.
    too_many = runner.invoke(app, ["proxy", "bench", "-n", "1000000"])
    assert too_many.exit_code != 0


def test_proxy_help_lists_subcommands() -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["proxy", "--help"])
    assert result.exit_code == 0
    assert "bench" in result.stdout
    assert "run" in result.stdout


def test_proxy_run_without_upstream_fails_fast() -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["proxy", "run"])
    assert result.exit_code == 2
