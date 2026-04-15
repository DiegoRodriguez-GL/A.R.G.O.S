"""Targeted audit of the parser: edge cases that rules will eventually see."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from argos_scanner import ParserError, TransportKind, load


def _write(tmp_path: Path, body: object, name: str = "cfg.json") -> Path:
    p = tmp_path / name
    if isinstance(body, (dict, list)):
        p.write_text(json.dumps(body), encoding="utf-8")
    else:
        p.write_text(str(body), encoding="utf-8")
    return p


# ---------- file-level resilience ---------------------------------------


def test_empty_file_rejected(tmp_path: Path) -> None:
    p = _write(tmp_path, "")
    with pytest.raises(ParserError):
        load(p)


def test_utf8_bom_is_tolerated(tmp_path: Path) -> None:
    p = tmp_path / "bom.json"
    p.write_bytes(b"\xef\xbb\xbf" + json.dumps({"mcpServers": {}}).encode("utf-8"))
    cfg = load(p)
    assert cfg.servers == ()


def test_missing_file_rejected(tmp_path: Path) -> None:
    with pytest.raises(ParserError):
        load(tmp_path / "does-not-exist.json")


def test_top_level_list_rejected(tmp_path: Path) -> None:
    p = _write(tmp_path, [1, 2, 3])
    with pytest.raises(ParserError):
        load(p)


def test_yaml_dialect_loads(tmp_path: Path) -> None:
    p = tmp_path / "cfg.yaml"
    p.write_text("mcpServers:\n  x:\n    command: uvx\n    args: [pkg==1.0]\n", encoding="utf-8")
    cfg = load(p)
    assert cfg.dialect == "claude-desktop"
    assert cfg.servers[0].command == "uvx"


# ---------- transport detection -----------------------------------------


def test_transport_inferred_from_url(tmp_path: Path) -> None:
    p = _write(tmp_path, {"mcpServers": {"s": {"url": "https://x.example"}}})
    assert load(p).servers[0].transport == TransportKind.HTTP


def test_transport_inferred_from_command(tmp_path: Path) -> None:
    p = _write(tmp_path, {"mcpServers": {"s": {"command": "uvx", "args": ["x==1"]}}})
    assert load(p).servers[0].transport == TransportKind.STDIO


def test_unknown_transport_falls_through(tmp_path: Path) -> None:
    p = _write(tmp_path, {"mcpServers": {"s": {"type": "unheard-of"}}})
    assert load(p).servers[0].transport == TransportKind.UNKNOWN


def test_streamable_http_recognised(tmp_path: Path) -> None:
    p = _write(
        tmp_path,
        {"servers": {"s": {"type": "streamable-http", "url": "https://x"}}},
    )
    assert load(p).servers[0].transport == TransportKind.STREAMABLE_HTTP


# ---------- env / headers sanitisation ----------------------------------


def test_env_list_value_rejected(tmp_path: Path) -> None:
    p = _write(tmp_path, {"mcpServers": {"s": {"command": "x", "env": {"K": ["a", "b"]}}}})
    with pytest.raises(ParserError, match="must be scalar"):
        load(p)


def test_env_none_coerced_to_empty_string(tmp_path: Path) -> None:
    p = _write(tmp_path, {"mcpServers": {"s": {"command": "x", "env": {"K": None}}}})
    cfg = load(p)
    assert cfg.servers[0].env["K"] == ""


def test_env_numeric_coerced_to_string(tmp_path: Path) -> None:
    p = _write(tmp_path, {"mcpServers": {"s": {"command": "x", "env": {"PORT": 8080}}}})
    assert load(p).servers[0].env["PORT"] == "8080"


def test_args_must_be_list(tmp_path: Path) -> None:
    p = _write(tmp_path, {"mcpServers": {"s": {"command": "x", "args": "string-not-list"}}})
    with pytest.raises(ParserError, match="must be a list"):
        load(p)


# ---------- server-level invariants -------------------------------------


def test_server_name_with_control_char_rejected(tmp_path: Path) -> None:
    # JSON allows escaped control chars; our MCPServer validator rejects them.
    p = tmp_path / "ctrl.json"
    p.write_text(
        '{"mcpServers": {"bad\\u0001name": {"command": "x"}}}',
        encoding="utf-8",
    )
    with pytest.raises(Exception, match="control characters"):
        load(p)


def test_empty_server_block_is_valid(tmp_path: Path) -> None:
    p = _write(tmp_path, {"mcpServers": {}})
    cfg = load(p)
    assert cfg.servers == ()


def test_server_raw_preserves_unknown_fields(tmp_path: Path) -> None:
    p = _write(
        tmp_path,
        {"mcpServers": {"s": {"command": "x", "vendorField": {"extra": 42}}}},
    )
    cfg = load(p)
    assert cfg.servers[0].raw.get("vendorField") == {"extra": 42}


def test_argv_returns_empty_when_no_command(tmp_path: Path) -> None:
    p = _write(tmp_path, {"mcpServers": {"s": {"url": "https://x"}}})
    cfg = load(p)
    assert cfg.servers[0].argv == ()
