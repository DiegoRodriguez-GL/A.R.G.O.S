"""Integration tests for the `argos scan` sub-command."""

from __future__ import annotations

import json
from pathlib import Path

from argos_cli.app import app
from typer.testing import CliRunner

SCANNER_FIXTURES = Path(__file__).resolve().parents[2] / "argos-scanner" / "tests" / "fixtures"

runner = CliRunner()


def test_scan_clean_config_exits_zero() -> None:
    result = runner.invoke(app, ["scan", str(SCANNER_FIXTURES / "clean.claude_desktop.json")])
    assert result.exit_code == 0
    assert "No findings" in result.stdout + (result.stderr or "")


def test_scan_risky_config_exits_nonzero() -> None:
    result = runner.invoke(app, ["scan", str(SCANNER_FIXTURES / "risky.claude_desktop.json")])
    assert result.exit_code == 1


def test_scan_jsonl_output_is_parseable(tmp_path: Path) -> None:
    out = tmp_path / "findings.jsonl"
    result = runner.invoke(
        app,
        [
            "scan",
            str(SCANNER_FIXTURES / "risky.claude_desktop.json"),
            "--format",
            "jsonl",
            "--output",
            str(out),
        ],
    )
    assert result.exit_code == 1
    lines = out.read_text(encoding="utf-8").splitlines()
    assert lines
    for line in lines:
        payload = json.loads(line)
        assert payload["rule_id"].startswith("MCP-SEC-")
        assert payload["producer"] == "argos-scanner"


def test_scan_rule_glob_narrows_output() -> None:
    result = runner.invoke(
        app,
        [
            "scan",
            str(SCANNER_FIXTURES / "risky.claude_desktop.json"),
            "--rules",
            "MCP-SEC-DOCKER-*",
            "--format",
            "jsonl",
        ],
    )
    assert result.exit_code == 1
    for line in result.stdout.splitlines():
        payload = json.loads(line)
        assert payload["rule_id"].startswith("MCP-SEC-DOCKER-")


def test_scan_severity_floor_drops_low() -> None:
    result = runner.invoke(
        app,
        [
            "scan",
            str(SCANNER_FIXTURES / "risky.claude_desktop.json"),
            "--severity",
            "critical",
            "--format",
            "jsonl",
        ],
    )
    # There are Critical findings in the risky fixture so output is non-empty.
    assert result.exit_code == 1
    for line in result.stdout.splitlines():
        payload = json.loads(line)
        assert payload["severity"] == "critical"


def test_scan_rejects_missing_file(tmp_path: Path) -> None:
    missing = tmp_path / "nope.json"
    result = runner.invoke(app, ["scan", str(missing)])
    assert result.exit_code != 0
