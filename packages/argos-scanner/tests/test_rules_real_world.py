"""Rule behaviour on patterns observed in the public MCP Registry.

Every case comes from the manual validation of findings produced by
scanning each server published in the official registry: either a false
positive that the rule has to stop producing, or the true positive next
to it that it must keep reporting.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from argos_scanner.engine import scan

BEARER = "MCP-SEC-REMOTE-BEARER-HARDCODED"
ENTROPY = "MCP-SEC-SECRET-ENTROPY"
TLS = "MCP-SEC-TLS-PLAINTEXT"
MOUNT = "MCP-SEC-DOCKER-HOST-MOUNT"
NPX = "MCP-SEC-SUPPLY-NPX-AUTO"
UVX = "MCP-SEC-SUPPLY-UVX-AUTO"


def _ids(tmp_path: Path, servers: dict[str, dict[str, Any]]) -> set[str]:
    path = tmp_path / "claude_desktop_config.json"
    path.write_text(json.dumps({"mcpServers": servers}), encoding="utf-8")
    return {f.rule_id for f in scan(path).findings}


def _remote(url: str, **headers: str) -> dict[str, dict[str, Any]]:
    return {"remote": {"url": url, "headers": headers}}


def _env(**env: str) -> dict[str, dict[str, Any]]:
    return {"local": {"command": "node", "args": ["server.js"], "env": env}}


def _cmd(command: str, *args: str) -> dict[str, dict[str, Any]]:
    return {"local": {"command": command, "args": list(args)}}


# --- bearer tokens ------------------------------------------------------------


@pytest.mark.parametrize(
    "value",
    [
        "Bearer {api_key}",
        "Bearer {smithery_api_key}",
        "Bearer ${GITHUB_TOKEN}",
        "Bearer $TOKEN",
        "Bearer <token>",
        "Bearer {{token}}",
        "Bearer %API_TOKEN%",
        "Bearer $(op read op://vault/item/token)",
    ],
)
def test_bearer_placeholders_are_not_literal_tokens(tmp_path: Path, value: str) -> None:
    assert BEARER not in _ids(tmp_path, _remote("https://api.example.com/mcp", Authorization=value))


def test_literal_bearer_token_is_still_reported(tmp_path: Path) -> None:
    token = "kbr7Qm2xZ9pL4vT8nW1sY6uE3oA5iC0dFh"
    headers = {"Authorization": f"Bearer {token}"}
    assert BEARER in _ids(tmp_path, _remote("https://api.example.com/mcp", **headers))


# --- entropy ------------------------------------------------------------------


@pytest.mark.parametrize(
    "value",
    [
        "https://api.mundane.market/v1",
        "https://bulks-faostat.fao.org/production",
        "https://your-helix-instance.onbmc.com/api/arsys/v1/entry/",
        "~/.image-generation-mcp/styles",
        "./certs/helix-client.pem",
        "sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2",
    ],
)
def test_structured_values_are_not_secrets(tmp_path: Path, value: str) -> None:
    assert ENTROPY not in _ids(tmp_path, _env(SETTING=value))


@pytest.mark.parametrize(
    "value",
    [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) paimon-mcp-fetch/1.0",
        "(nws-weather-mcp-server, contact@example.org)",
        "Shared Documents Library 2026",
        "{publicdata_max_response_length}",
        "noreply-bot-account@example.org",
        "0xfD4228a1B6c05e12D7e9F3aC4b8e6D02c9A1f7E3",
    ],
)
def test_user_agents_templates_emails_and_addresses_are_not_secrets(
    tmp_path: Path,
    value: str,
) -> None:
    assert ENTROPY not in _ids(tmp_path, _env(SETTING=value))


def test_a_64_hex_private_key_is_still_reported(tmp_path: Path) -> None:
    key = "0x" + "9f3c1a7e5b2d8c4f6a0e1b3d5c7f9a2e4b6d8f0c1e3a5b7d9f2c4e6a8b0d1f3e"
    assert ENTROPY in _ids(tmp_path, _env(SETTING=key))


def test_opaque_token_still_trips_the_entropy_rule(tmp_path: Path) -> None:
    assert ENTROPY in _ids(tmp_path, _env(SETTING="Zx9QwL3mP8vT2nR7kY4sB6hJ1dF5gC0"))


def test_credentials_inside_a_url_are_not_excused(tmp_path: Path) -> None:
    url = "https://svc:Zx9QwL3mP8vT2nR7kY4sB6hJ1@api.example.com/v1"
    assert ENTROPY in _ids(tmp_path, _env(SETTING=url))


# --- plaintext transport ------------------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "http://{host}:{port}/mcp",
        "http://{HOST_CONTROL_PANEL}:{PORT_CONTROL_PANEL}/mcp",
        "http://0.0.0.0:8080/mcp",
        "http://127.0.0.1:3000/mcp",
    ],
)
def test_loopback_and_templated_hosts_are_not_reported(tmp_path: Path, url: str) -> None:
    assert TLS not in _ids(tmp_path, _remote(url))


@pytest.mark.parametrize("url", ["http://80.91.65.91:8082/sse", "http://mcp.example.net/mcp"])
def test_plaintext_to_a_real_host_is_reported(tmp_path: Path, url: str) -> None:
    assert TLS in _ids(tmp_path, _remote(url))


# --- docker mounts ------------------------------------------------------------


def _docker(*args: str) -> dict[str, dict[str, Any]]:
    return _cmd("docker", "run", "-i", "--rm", *args, "example/image:1.0")


@pytest.mark.parametrize(
    "spec",
    [
        "/:/host",
        "$HOME:/home/me",
        "~:/root",
        "~/.ssh:/root/.ssh:ro",
        "${HOME}/.aws:/root/.aws",
        "~/.kube:/root/.kube",
    ],
)
def test_root_home_and_credential_stores_are_reported(tmp_path: Path, spec: str) -> None:
    assert MOUNT in _ids(tmp_path, _docker("-v", spec))


@pytest.mark.parametrize(
    "spec",
    [
        "~/.config/gws:/app/config",
        "~/mcp_custom_messages:/messages",
        "~/.hapi:/app/.hapi",
        "/data/projects:/work",
    ],
)
def test_scoped_mounts_are_not_reported(tmp_path: Path, spec: str) -> None:
    assert MOUNT not in _ids(tmp_path, _docker("-v", spec))


def test_bind_mount_syntax_of_the_root_is_reported(tmp_path: Path) -> None:
    assert MOUNT in _ids(tmp_path, _docker("--mount", "type=bind,source=/,target=/host"))


# --- npx / uvx ----------------------------------------------------------------


@pytest.mark.parametrize(
    ("args", "flagged"),
    [
        (("-y", "--package=gridstamp", "gridstamp-mcp"), True),
        (("-y", "--package=gridstamp@1.2.0", "gridstamp-mcp"), False),
        (("-y", "-p", "@scope/tool@0.38", "tool-mcp"), False),
        (("-y", "-p", "@scope/tool", "tool-mcp"), True),
        (("-y", "some-mcp"), True),
        (("-y", "some-mcp@1.0.0"), False),
        (("some-mcp",), False),
    ],
)
def test_npx_resolves_the_installed_package(
    tmp_path: Path, args: tuple[str, ...], flagged: bool
) -> None:
    assert (NPX in _ids(tmp_path, _cmd("npx", *args))) is flagged


@pytest.mark.parametrize(
    ("command", "args", "flagged"),
    [
        ("uvx", ("--with", "mcp>=2.2,<3", "tool==0.4.2"), False),
        ("uvx", ("--from", "tool[mcp]", "tool-mcp"), True),
        ("uvx", ("--from", "tool[mcp]==1.2.1", "tool-mcp"), False),
        ("uvx", ("--from=tool", "tool-mcp"), True),
        ("uvx", ("tool@1.0.0",), False),
        ("uvx", ("tool",), True),
        ("pipx", ("run", "tool"), True),
        ("pipx", ("run", "tool==2.0"), False),
    ],
)
def test_uvx_resolves_the_installed_package(
    tmp_path: Path,
    command: str,
    args: tuple[str, ...],
    flagged: bool,
) -> None:
    assert (UVX in _ids(tmp_path, _cmd(command, *args))) is flagged
