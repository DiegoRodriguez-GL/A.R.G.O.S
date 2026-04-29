"""Smoke tests for ``argos proxy`` subcommands.

Two layers:

- ``argos proxy bench --no-detectors`` runs in-memory and exits 0
  under any reasonable budget (p95 in microseconds).
- ``argos proxy bench`` with detectors enforces the RNF-02 50 ms
  budget. The test runs only 200 iterations so it stays under 1s.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest
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


def test_proxy_run_invalid_listen_address_rejected() -> None:
    runner = CliRunner()
    result = runner.invoke(
        app,
        ["proxy", "run", "--listen", "not-a-host-port", "--upstream", "stdio:python --version"],
    )
    assert result.exit_code != 0


def test_proxy_run_invalid_upstream_scheme_rejected() -> None:
    runner = CliRunner()
    result = runner.invoke(
        app,
        ["proxy", "run", "--listen", "127.0.0.1:0", "--upstream", "ftp://nope"],
    )
    assert result.exit_code != 0


def test_proxy_run_e2e_with_fake_mcp_subprocess(tmp_path: Path) -> None:
    """End-to-end: spawn ``argos proxy run`` as a real subprocess
    bound on ``127.0.0.1:0`` (ephemeral port, output captured), let
    it run for 1.5 seconds against the fake MCP server, then verify
    the listener stopped cleanly and the SQLite forensics db exists."""
    py = _python_with_argos_installed()
    fixture = (
        Path(__file__).resolve().parents[2]
        / "argos-proxy"
        / "tests"
        / "fixtures"
        / "fake_mcp_server.py"
    )
    if not fixture.is_file():
        pytest.skip(f"fixture not found: {fixture}")

    db = tmp_path / "forensics.db"
    # Run the CLI; --duration 1 limits the listener lifetime so the
    # test cannot hang.
    result = subprocess.run(
        [
            py,
            "-m",
            "argos_cli",
            "proxy",
            "run",
            "--listen",
            "127.0.0.1:0",
            "--upstream",
            f"stdio:{py} {fixture}",
            "--forensics-db",
            str(db),
            "--no-otel",
            "--no-drift",
            "--no-pii",
            "--duration",
            "1.0",
        ],
        capture_output=True,
        text=True,
        check=False,
        timeout=30.0,
    )
    # Listener exits 0 on duration timeout (graceful stop).
    assert result.returncode == 0, f"stdout={result.stdout!r} stderr={result.stderr!r}"
    assert "argos proxy:" in result.stdout
    assert "proxy stopped:" in result.stdout
    # Forensics db file was created.
    assert db.is_file()
