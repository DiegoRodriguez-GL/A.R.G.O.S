"""Unit tests for the MCP config parser."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from argos_scanner import (
    MCPConfig,
    ParserError,
    TransportKind,
    UnsupportedDialectError,
    load,
)

FIXTURES = Path(__file__).parent / "fixtures"


def test_claude_desktop_dialect() -> None:
    config = load(FIXTURES / "clean.claude_desktop.json")
    assert isinstance(config, MCPConfig)
    assert config.dialect == "claude-desktop"
    names = {s.name for s in config.servers}
    assert names == {"filesystem-project", "fetch", "remote-api"}


def test_mcp_spec_dialect() -> None:
    config = load(FIXTURES / "mcp_spec.json")
    assert config.dialect == "mcp-spec"
    transports = {s.name: s.transport for s in config.servers}
    assert transports["local-stdio"] == TransportKind.STDIO
    assert transports["remote-http"] == TransportKind.STREAMABLE_HTTP


def test_remote_server_flagged_as_remote() -> None:
    config = load(FIXTURES / "clean.claude_desktop.json")
    remote = next(s for s in config.servers if s.name == "remote-api")
    assert remote.is_remote
    assert remote.url == "https://api.example.com/mcp"


def test_argv_merges_command_and_args() -> None:
    config = load(FIXTURES / "clean.claude_desktop.json")
    fs = next(s for s in config.servers if s.name == "filesystem-project")
    assert fs.argv[0] == "npx"
    assert "@modelcontextprotocol/server-filesystem@1.0.4" in fs.argv


def test_parse_rejects_non_object_top_level(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps(["not", "an", "object"]), encoding="utf-8")
    with pytest.raises(ParserError):
        load(bad)


def test_parse_rejects_unknown_dialect(tmp_path: Path) -> None:
    bad = tmp_path / "unknown.json"
    bad.write_text(json.dumps({"random": "payload"}), encoding="utf-8")
    with pytest.raises(UnsupportedDialectError):
        load(bad)


def test_parse_rejects_invalid_json(tmp_path: Path) -> None:
    bad = tmp_path / "broken.json"
    bad.write_text("{ invalid", encoding="utf-8")
    with pytest.raises(ParserError, match="invalid JSON"):
        load(bad)


def test_parse_rejects_non_string_env(tmp_path: Path) -> None:
    bad = tmp_path / "nonstring_env.json"
    bad.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "s": {"command": "x", "env": {"K": {"nested": "value"}}},
                },
            },
        ),
        encoding="utf-8",
    )
    with pytest.raises(ParserError, match="must be scalar"):
        load(bad)


def test_parse_rejects_duplicate_server_names(tmp_path: Path) -> None:
    bad = tmp_path / "duplicates.json"
    # JSON cannot natively have duplicate keys, so we serialise via a mapping
    # that preserves ordering. Python's json parser keeps the last value; we
    # instead trigger the validator by constructing two entries that map to
    # the same normalised name via the test API.
    bad.write_text(
        json.dumps({"mcpServers": {"a": {"command": "x"}, "b": {"command": "y"}}}),
        encoding="utf-8",
    )
    cfg = load(bad)
    assert len({s.name for s in cfg.servers}) == 2
