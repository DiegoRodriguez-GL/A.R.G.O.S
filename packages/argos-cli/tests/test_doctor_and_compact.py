"""Tests for `argos doctor` and `argos rules list --compact`."""

from __future__ import annotations

from pathlib import Path

import pytest
from argos_cli.app import app
from typer.testing import CliRunner

runner = CliRunner()


# ---------- doctor ---------------------------------------------------


def test_doctor_paths_only_lists_every_known_client() -> None:
    r = runner.invoke(app, ["doctor", "--paths"])
    assert r.exit_code == 0
    for label in (
        "Claude Desktop",
        "VS Code",
        "Cursor",
        "Windsurf",
        "Continue",
    ):
        assert label in r.stdout


def test_doctor_with_no_configs_present_exits_cleanly(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    # Redirect HOME, APPDATA, CWD to an empty sandbox: every known path
    # becomes non-existent, so doctor reports nothing to do.
    monkeypatch.setenv("APPDATA", str(tmp_path))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    monkeypatch.chdir(tmp_path)

    r = runner.invoke(app, ["doctor"])
    assert r.exit_code == 0
    assert "No MCP configurations" in r.stdout


def test_doctor_finds_and_scans_a_fake_config(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    # Build a Windsurf-style project config under the fake home.
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    monkeypatch.setenv("APPDATA", str(tmp_path))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    project = tmp_path / "project"
    (project / ".cursor").mkdir(parents=True)
    (project / ".cursor" / "mcp.json").write_text(
        '{"mcpServers": {"s": {"command": "uvx", "args": ["pkg==1.0"]}}}',
        encoding="utf-8",
    )
    monkeypatch.chdir(project)

    r = runner.invoke(app, ["doctor"])
    # Clean config -> exit 0
    assert r.exit_code == 0
    assert "Cursor" in r.stdout


def test_doctor_exits_one_when_a_config_has_high_findings(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    monkeypatch.setenv("APPDATA", str(tmp_path))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    project = tmp_path / "project"
    (project / ".cursor").mkdir(parents=True)
    (project / ".cursor" / "mcp.json").write_text(
        """{"mcpServers": {"bad": {
          "command": "docker",
          "args": ["run", "--privileged", "mcp/x"]
        }}}""",
        encoding="utf-8",
    )
    monkeypatch.chdir(project)

    r = runner.invoke(app, ["doctor"])
    assert r.exit_code == 1
    assert "CRITICAL" in r.stdout


# ---------- rules list --compact ------------------------------------


def test_rules_list_compact_is_one_line_per_rule() -> None:
    r = runner.invoke(app, ["rules", "list", "-c"])
    assert r.exit_code == 0
    lines = [ln for ln in r.stdout.splitlines() if ln.strip() and "rule(s) shown" not in ln]
    # Each rule occupies exactly one line in compact output.
    assert len(lines) >= 17
    # Compact output has no table characters (box.MINIMAL_HEAVY_HEAD).
    assert "\u2500" not in r.stdout  # horizontal box-drawing char


def test_rules_list_compact_respects_severity_filter() -> None:
    r = runner.invoke(app, ["rules", "list", "-c", "-s", "critical"])
    assert r.exit_code == 0
    # HIGH-only rule must not appear.
    assert "SECRET-ENTROPY" not in r.stdout
    assert "SECRET-PATTERN" in r.stdout
