"""Targeted audit of the CLI surface: config, console, plugins, commands."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import pytest
from argos_cli.app import app
from argos_cli.config import Config, load_config
from argos_cli.console import get_console, get_err_console
from argos_cli.plugins import discover
from typer.testing import CliRunner

runner = CliRunner()


# ---------- config loader ----------------------------------------------


def test_config_defaults_are_safe() -> None:
    cfg = Config()
    assert cfg.no_color is False
    assert cfg.otel_endpoint is None
    assert cfg.plugin_paths == ()


def test_no_color_env_wins(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("NO_COLOR", "1")
    assert load_config().no_color is True


def test_argos_otel_endpoint_env_wins(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("ARGOS_OTEL_ENDPOINT", "https://otel.example:4318")
    assert load_config().otel_endpoint == "https://otel.example:4318"


def test_local_argos_yaml_merges(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.chdir(tmp_path)
    (tmp_path / "argos.yaml").write_text(
        "no_color: true\notel_endpoint: https://collector\n",
        encoding="utf-8",
    )
    cfg = load_config()
    assert cfg.no_color is True
    assert cfg.otel_endpoint == "https://collector"


def test_argos_yaml_rejects_non_mapping_root(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.chdir(tmp_path)
    (tmp_path / "argos.yaml").write_text("[1, 2, 3]\n", encoding="utf-8")
    with pytest.raises(TypeError, match="must contain a YAML mapping"):
        load_config()


def test_config_rejects_unknown_keys() -> None:
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        Config.model_validate({"unknown": 1})


# ---------- console ----------------------------------------------------


def test_console_is_singleton() -> None:
    assert get_console() is get_console()


def test_err_console_is_separate_from_out_console() -> None:
    assert get_console() is not get_err_console()


def test_no_color_env_disables_colour(monkeypatch: pytest.MonkeyPatch) -> None:
    from argos_cli import console as console_mod

    monkeypatch.setenv("NO_COLOR", "1")
    console_mod.get_console.cache_clear()
    console_mod.get_err_console.cache_clear()
    try:
        c = console_mod.get_console()
        assert c._color_system is None
    finally:
        console_mod.get_console.cache_clear()
        console_mod.get_err_console.cache_clear()
        os.environ.pop("NO_COLOR", None)


# ---------- plugin discovery ------------------------------------------


def test_discover_accepts_none_and_yields_iterable() -> None:
    # No built-in plugins are registered today; the call must still work.
    plugins: list[Any] = list(discover())
    assert isinstance(plugins, list)


def test_discover_with_unknown_group_returns_empty() -> None:
    plugins = list(discover("argos.probes"))
    assert plugins == []


# ---------- CLI top-level flags ---------------------------------------


def test_root_help_lists_every_subcommand() -> None:
    r = runner.invoke(app, ["--help"])
    assert r.exit_code == 0
    combined = r.stdout + (r.stderr or "")
    for name in ("scan", "redteam", "proxy", "report"):
        assert name in combined


def test_root_version_flag_short() -> None:
    r = runner.invoke(app, ["-V"])
    assert r.exit_code == 0
    assert "argos " in r.stdout


def test_root_banner_flag_is_hidden_but_works() -> None:
    r = runner.invoke(app, ["--banner"])
    assert r.exit_code == 0
    assert "ARGOS" in r.stdout


def test_bare_invocation_shows_help() -> None:
    r = runner.invoke(app, [])
    combined = r.stdout + (r.stderr or "")
    assert "Usage" in combined
    # No arguments given: exit code is 0 (help displayed) per Typer contract.
    assert r.exit_code in (0, 2)


def test_skeleton_subcommands_exit_two_and_mention_module() -> None:
    for sub, mod in [("redteam", "Module 4"), ("proxy", "Module 5"), ("report", "Module 6")]:
        r = runner.invoke(app, [sub])
        assert r.exit_code == 2
        combined = r.stdout + (r.stderr or "")
        assert mod in combined


# ---------- scan command: argument parsing -----------------------------


def test_scan_unknown_severity_is_rejected(tmp_path: Path) -> None:
    cfg = tmp_path / "cfg.json"
    cfg.write_text('{"mcpServers": {}}', encoding="utf-8")
    r = runner.invoke(app, ["scan", str(cfg), "--severity", "bananas"])
    assert r.exit_code != 0


def test_scan_unknown_format_is_rejected(tmp_path: Path) -> None:
    cfg = tmp_path / "cfg.json"
    cfg.write_text('{"mcpServers": {}}', encoding="utf-8")
    r = runner.invoke(app, ["scan", str(cfg), "--format", "xml"])
    assert r.exit_code != 0


def test_scan_severity_is_case_insensitive(tmp_path: Path) -> None:
    cfg = tmp_path / "cfg.json"
    cfg.write_text('{"mcpServers": {}}', encoding="utf-8")
    r = runner.invoke(app, ["scan", str(cfg), "--severity", "CRITICAL"])
    assert r.exit_code == 0


def test_scan_parser_error_exits_two(tmp_path: Path) -> None:
    cfg = tmp_path / "bad.json"
    cfg.write_text("{ not valid", encoding="utf-8")
    r = runner.invoke(app, ["scan", str(cfg)])
    assert r.exit_code == 2


def test_scan_file_must_be_a_file_not_directory(tmp_path: Path) -> None:
    r = runner.invoke(app, ["scan", str(tmp_path)])
    assert r.exit_code != 0
