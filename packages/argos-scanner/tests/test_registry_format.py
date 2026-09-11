"""Tests for the MCP Registry ``server.json`` dialect.

A registry entry is audited as the client configuration an installer
would write from it, so these tests check both the translation and that
the ordinary rules fire on the translated entries.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from argos_scanner import TransportKind, UnsupportedDialectError, load
from argos_scanner.engine import scan
from argos_scanner.registry_format import (
    is_registry_document,
    to_client_servers,
    unwrap_envelope,
)

SCHEMA = "https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json"


def _doc(**extra: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "$schema": SCHEMA,
        "name": "io.example/demo",
        "description": "Demo server.",
        "version": "1.2.3",
    }
    base.update(extra)
    return base


def _write(tmp_path: Path, doc: dict[str, Any], name: str = "server.json") -> Path:
    path = tmp_path / name
    path.write_text(json.dumps(doc), encoding="utf-8")
    return path


def _rule_ids(path: Path) -> set[str]:
    return {f.rule_id for f in scan(path).findings}


def test_npm_package_becomes_a_pinned_npx_command(tmp_path: Path) -> None:
    doc = _doc(
        packages=[
            {
                "registryType": "npm",
                "identifier": "@example/mcp",
                "version": "1.2.3",
                "transport": {"type": "stdio"},
                "packageArguments": [
                    {"type": "positional", "valueHint": "path"},
                    {"type": "named", "name": "--mode", "value": "safe"},
                ],
                "environmentVariables": [
                    {"name": "EXAMPLE_TOKEN", "isSecret": True},
                    {"name": "EXAMPLE_BASE", "default": "https://api.example.com"},
                ],
            },
        ],
    )
    config = load(_write(tmp_path, doc))
    assert config.dialect == "mcp-registry"
    (server,) = config.servers
    assert server.name == "package-1-npm"
    assert server.transport is TransportKind.STDIO
    assert server.argv == ("npx", "-y", "@example/mcp@1.2.3", "<path>", "--mode", "safe")
    assert server.env == {"EXAMPLE_TOKEN": "", "EXAMPLE_BASE": "https://api.example.com"}
    # A pinned package is not an auto-install finding.
    assert "MCP-SEC-SUPPLY-NPX-AUTO" not in _rule_ids(config.path)


def test_pypi_and_nuget_use_their_launchers() -> None:
    servers = to_client_servers(
        _doc(
            packages=[
                {"registryType": "pypi", "identifier": "demo-mcp", "version": "0.4.0"},
                {"registryType": "nuget", "identifier": "Demo.Mcp", "version": "2.0.0"},
            ],
        ),
    )
    assert servers["package-1-pypi"]["command"] == "uvx"
    assert servers["package-1-pypi"]["args"] == ["demo-mcp==0.4.0"]
    assert servers["package-2-nuget"]["command"] == "dnx"
    assert servers["package-2-nuget"]["args"] == ["Demo.Mcp@2.0.0", "--yes"]


def test_oci_runtime_arguments_reach_the_docker_rules(tmp_path: Path) -> None:
    doc = _doc(
        packages=[
            {
                "registryType": "oci",
                "identifier": "ghcr.io/example/demo",
                "version": "1.0.0",
                "runtimeArguments": [
                    {"type": "named", "name": "--privileged"},
                    {"type": "named", "name": "-v", "value": "/:/host"},
                ],
            },
        ],
    )
    path = _write(tmp_path, doc)
    (server,) = load(path).servers
    assert server.argv == (
        "docker",
        "run",
        "--privileged",
        "-v",
        "/:/host",
        "ghcr.io/example/demo:1.0.0",
    )
    ids = _rule_ids(path)
    assert {"MCP-SEC-DOCKER-PRIVILEGED", "MCP-SEC-DOCKER-HOST-MOUNT"} <= ids


def test_oci_without_runtime_arguments_gets_interactive_defaults() -> None:
    servers = to_client_servers(
        _doc(packages=[{"registryType": "oci", "identifier": "docker.io/example/demo:2.1"}]),
    )
    assert servers["package-1-oci"]["args"] == ["run", "-i", "--rm", "docker.io/example/demo:2.1"]


def test_oci_run_supplied_by_publisher_is_not_duplicated() -> None:
    servers = to_client_servers(
        _doc(
            packages=[
                {
                    "registryType": "oci",
                    "identifier": "ghcr.io/example/demo:1.0",
                    "runtimeArguments": [
                        {"type": "positional", "value": "run"},
                        {"type": "positional", "value": "--rm"},
                    ],
                },
            ],
        ),
    )
    assert servers["package-1-oci"]["args"] == ["run", "--rm", "ghcr.io/example/demo:1.0"]


def test_bundles_and_crates_have_no_generic_launcher() -> None:
    servers = to_client_servers(
        _doc(
            packages=[
                {"registryType": "mcpb", "identifier": "https://example.com/demo.mcpb"},
                {"registryType": "cargo", "identifier": "demo-mcp", "version": "0.1.0"},
            ],
        ),
    )
    assert "command" not in servers["package-1-mcpb"]
    assert servers["package-1-mcpb"]["args"] == ["https://example.com/demo.mcpb"]
    assert "command" not in servers["package-2-cargo"]


def test_remote_over_plain_http_is_reported(tmp_path: Path) -> None:
    doc = _doc(
        remotes=[
            {
                "type": "streamable-http",
                "url": "http://mcp.example.com/mcp",
                "headers": [
                    {"name": "Authorization", "isSecret": True, "description": "Bearer token"},
                ],
            },
        ],
    )
    path = _write(tmp_path, doc)
    (server,) = load(path).servers
    assert server.name == "remote-1-streamable-http"
    assert server.transport is TransportKind.STREAMABLE_HTTP
    assert server.headers == {"Authorization": ""}
    assert "MCP-SEC-TLS-PLAINTEXT" in _rule_ids(path)


def test_remote_over_https_is_clean(tmp_path: Path) -> None:
    doc = _doc(remotes=[{"type": "streamable-http", "url": "https://mcp.example.com/mcp"}])
    assert "MCP-SEC-TLS-PLAINTEXT" not in _rule_ids(_write(tmp_path, doc))


def test_secret_published_as_a_default_is_reported(tmp_path: Path) -> None:
    token = "ghp_" + "a" * 36
    doc = _doc(
        packages=[
            {
                "registryType": "npm",
                "identifier": "@example/mcp",
                "version": "1.0.0",
                "environmentVariables": [{"name": "GITHUB_TOKEN", "default": token}],
            },
        ],
    )
    assert "MCP-SEC-SECRET-PATTERN" in _rule_ids(_write(tmp_path, doc))


def test_registry_documentation_is_not_treated_as_model_facing(tmp_path: Path) -> None:
    # Descriptions of variables and headers are read by the person
    # installing the server, never by the model. In the public registry
    # every match of the injection heuristic there was benign ("your
    # secret API key", "to act as yourself").
    doc = _doc(
        packages=[
            {
                "registryType": "npm",
                "identifier": "@example/mcp",
                "version": "1.0.0",
                "environmentVariables": [
                    {"name": "KEY", "description": "Your secret API key."},
                    {"name": "AS", "description": "Identity to act as."},
                ],
            },
        ],
    )
    assert "MCP-SEC-TOOL-POISON" not in _rule_ids(_write(tmp_path, doc))


def test_a_sentence_in_runtime_hint_is_not_used_as_the_command() -> None:
    servers = to_client_servers(
        _doc(
            packages=[
                {
                    "registryType": "pypi",
                    "identifier": "demo-mcp",
                    "version": "1.0.0",
                    "runtimeHint": "Install with the extra (e.g. `pipx install 'demo[mcp]'`) first",
                },
            ],
        ),
    )
    assert servers["package-1-pypi"]["command"] == "uvx"


def test_documents_without_artefacts_are_still_registry_documents(tmp_path: Path) -> None:
    doc = {
        "$schema": "https://registry.modelcontextprotocol.io/schemas/2025-12-11/server-bundle.json",
        "name": "io.example/bundle",
        "version": "1.0.0",
    }
    config = load(_write(tmp_path, doc))
    assert config.dialect == "mcp-registry"
    assert config.servers == ()


def test_registry_api_envelope_is_unwrapped(tmp_path: Path) -> None:
    envelope = {
        "server": _doc(remotes=[{"type": "sse", "url": "https://mcp.example.com/sse"}]),
        "_meta": {"io.modelcontextprotocol.registry/official": {"status": "active"}},
    }
    config = load(_write(tmp_path, envelope))
    assert config.dialect == "mcp-registry"
    assert config.servers[0].transport is TransportKind.SSE


def test_document_detection() -> None:
    assert is_registry_document({"$schema": SCHEMA})
    assert is_registry_document({"name": "x", "remotes": []})
    assert not is_registry_document({"name": "x"})
    assert unwrap_envelope({"server": {"name": "x"}, "_meta": {}}) == {"name": "x"}
    other = {"server": {"name": "x"}, "other": 1}
    assert unwrap_envelope(other) is other


def test_client_dialects_still_win_over_registry_detection(tmp_path: Path) -> None:
    doc = {"mcpServers": {"s": {"command": "node", "args": ["server.js"]}}, "name": "x"}
    assert load(_write(tmp_path, doc)).dialect == "claude-desktop"


def test_document_without_package_or_remote_lists_is_rejected_cleanly(tmp_path: Path) -> None:
    with pytest.raises(UnsupportedDialectError):
        load(_write(tmp_path, {"name": "x", "packages": "not-a-list"}))


@pytest.mark.parametrize(
    "junk",
    [
        {"name": "x", "packages": [1, None, {"registryType": 5}]},
        {"name": "x", "remotes": [{"headers": "bad"}, {"type": "sse"}]},
        {"name": "x", "packages": [{"registryType": "npm", "runtimeArguments": [{"type": "x"}]}]},
    ],
)
def test_malformed_entries_do_not_crash(tmp_path: Path, junk: dict[str, Any]) -> None:
    assert isinstance(to_client_servers(junk), dict)
    # The full pipeline must also survive them: parse, then every rule.
    scan(_write(tmp_path, junk))
