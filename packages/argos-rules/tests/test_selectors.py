"""Selector resolution over MCPConfig and MCPServer."""

from __future__ import annotations

from pathlib import Path

import pytest
from argos_rules.selectors import select
from argos_scanner.models import MCPConfig, MCPServer, TransportKind


@pytest.fixture
def cfg() -> MCPConfig:
    return MCPConfig(
        path=Path("demo.json"),
        dialect="claude-desktop",
        servers=(
            MCPServer(
                name="alice",
                transport=TransportKind.STDIO,
                command="npx",
                args=("-y", "@scope/pkg@1.0"),
                env={"DEBUG": "1", "TOKEN": "abc"},
                raw={"command": "npx", "args": ["-y", "@scope/pkg@1.0"]},
            ),
            MCPServer(
                name="bob",
                transport=TransportKind.HTTP,
                url="https://api.example.com/mcp",
                headers={"Authorization": "Bearer xyz"},
                raw={"url": "https://api.example.com/mcp"},
            ),
        ),
        raw={"mcpServers": {}},
    )


def test_server_simple_fields(cfg: MCPConfig) -> None:
    alice = cfg.servers[0]
    assert select(cfg, alice, "server.name") == ["alice"]
    assert select(cfg, alice, "server.command") == ["npx"]
    assert select(cfg, alice, "server.transport") == ["stdio"]


def test_server_argv_is_joined(cfg: MCPConfig) -> None:
    alice = cfg.servers[0]
    assert select(cfg, alice, "server.argv") == ["npx -y @scope/pkg@1.0"]


def test_server_args_list_and_index(cfg: MCPConfig) -> None:
    alice = cfg.servers[0]
    assert select(cfg, alice, "server.args") == ["-y", "@scope/pkg@1.0"]
    assert select(cfg, alice, "server.args[0]") == ["-y"]
    assert select(cfg, alice, "server.args[1]") == ["@scope/pkg@1.0"]
    assert select(cfg, alice, "server.args[99]") == []


def test_server_env_lookup(cfg: MCPConfig) -> None:
    alice = cfg.servers[0]
    assert select(cfg, alice, "server.env.DEBUG") == ["1"]
    assert select(cfg, alice, "server.env.MISSING") == []
    assert set(select(cfg, alice, "server.env.*")) == {"1", "abc"}
    assert set(select(cfg, alice, "server.env.keys")) == {"DEBUG", "TOKEN"}


def test_server_url_and_headers(cfg: MCPConfig) -> None:
    bob = cfg.servers[1]
    assert select(cfg, bob, "server.url") == ["https://api.example.com/mcp"]
    assert select(cfg, bob, "server.headers.Authorization") == ["Bearer xyz"]


def test_config_fields(cfg: MCPConfig) -> None:
    alice = cfg.servers[0]
    assert select(cfg, alice, "config.dialect") == ["claude-desktop"]
    assert select(cfg, alice, "config.path") == [str(Path("demo.json"))]


def test_unknown_selector_returns_empty(cfg: MCPConfig) -> None:
    alice = cfg.servers[0]
    assert select(cfg, alice, "nope.whatever") == []
    assert select(cfg, alice, "server.nope") == []
    assert select(cfg, alice, "") == []


def test_server_with_no_command_returns_empty_argv() -> None:
    bob = MCPServer(name="bob", url="https://x", transport=TransportKind.HTTP)
    cfg = MCPConfig(path=Path("x.json"), dialect="claude-desktop", servers=(bob,), raw={})
    assert select(cfg, bob, "server.argv") == []
    assert select(cfg, bob, "server.command") == []
