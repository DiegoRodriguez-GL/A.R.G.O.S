"""Integration tests for `argos rules validate` and `argos scan --rules-dir`."""

from __future__ import annotations

from pathlib import Path

from argos_cli.app import app
from typer.testing import CliRunner

runner = CliRunner()

PACKAGES = Path(__file__).resolve().parents[2]
EXAMPLES = PACKAGES / "argos-rules" / "examples"
SCANNER_FIXTURES = PACKAGES / "argos-scanner" / "tests" / "fixtures"


def test_rules_validate_on_examples_exits_zero() -> None:
    r = runner.invoke(app, ["rules", "validate", str(EXAMPLES)])
    assert r.exit_code == 0
    assert "5 rule(s) validated" in r.stdout


def test_rules_validate_single_file() -> None:
    r = runner.invoke(
        app,
        ["rules", "validate", str(EXAMPLES / "custom-internal-host-remote.yaml")],
    )
    assert r.exit_code == 0
    assert "CUSTOM-INTERNAL-HOST-REMOTE" in r.stdout


def test_rules_validate_invalid_file_exits_nonzero(tmp_path: Path) -> None:
    bad = tmp_path / "bad.yaml"
    bad.write_text("id: lowercase\ninfo:\n  name: x\n  severity: low\nmatchers: []\n")
    r = runner.invoke(app, ["rules", "validate", str(bad)])
    assert r.exit_code == 1


def test_scan_with_rules_dir_adds_yaml_findings(tmp_path: Path) -> None:
    cfg = tmp_path / "cfg.json"
    cfg.write_text(
        '{"mcpServers": {"bad": {"url": "https://svc.internal.acme.com/mcp"}}}',
        encoding="utf-8",
    )
    r = runner.invoke(
        app,
        [
            "scan",
            str(cfg),
            "--rules-dir",
            str(EXAMPLES),
            "--format",
            "jsonl",
        ],
    )
    assert r.exit_code == 1
    assert "CUSTOM-INTERNAL-HOST-REMOTE" in r.stdout


def test_scan_with_rules_dir_on_clean_fixture_stays_zero() -> None:
    r = runner.invoke(
        app,
        [
            "scan",
            str(SCANNER_FIXTURES / "clean.claude_desktop.json"),
            "--rules-dir",
            str(EXAMPLES),
        ],
    )
    assert r.exit_code == 0


def test_scan_with_malformed_rules_dir_exits_two(tmp_path: Path) -> None:
    bad = tmp_path / "rules"
    bad.mkdir()
    (bad / "bad.yaml").write_text("id: lowercase\n")
    cfg = tmp_path / "cfg.json"
    cfg.write_text('{"mcpServers": {}}', encoding="utf-8")
    r = runner.invoke(app, ["scan", str(cfg), "--rules-dir", str(bad)])
    assert r.exit_code == 2
