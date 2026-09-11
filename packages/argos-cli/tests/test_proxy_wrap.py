"""``argos proxy wrap``: the proxy as a stdio server inside an MCP client.

The session tests drive the real code path with pipes in place of the
process streams and the stdio fixture server as the upstream, so the
client -> ARGOS -> server chain is exercised end to end.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import sqlite3
import sys
from pathlib import Path
from typing import Any

import pytest
import typer
from argos_cli.app import app
from argos_cli.commands.proxy import _parse_headers, _parse_upstream_url, _run_wrap
from argos_proxy import StdioServerTransport, StdioUpstreamFactory
from typer.testing import CliRunner

_FIXTURE = (
    Path(__file__).resolve().parents[2]
    / "argos-proxy"
    / "tests"
    / "fixtures"
    / "fake_mcp_server.py"
)

runner = CliRunner()


def _line(message: dict[str, Any]) -> bytes:
    return (json.dumps(message) + "\n").encode("utf-8")


class _Client:
    """Pipes standing in for the stdio of an MCP client."""

    def __init__(self) -> None:
        to_argos_r, to_argos_w = os.pipe()
        from_argos_r, from_argos_w = os.pipe()
        self.argos_in = os.fdopen(to_argos_r, "rb")
        self.feeder = os.fdopen(to_argos_w, "wb")
        self.argos_out = os.fdopen(from_argos_w, "wb")
        self.replies = os.fdopen(from_argos_r, "rb")

    def transport(self) -> StdioServerTransport:
        return StdioServerTransport(reader=self.argos_in, writer=self.argos_out)

    def send(self, message: dict[str, Any]) -> None:
        self.feeder.write(_line(message))
        self.feeder.flush()

    async def reply(self) -> dict[str, Any]:
        raw = await asyncio.wait_for(asyncio.to_thread(self.replies.readline), timeout=30)
        return dict(json.loads(raw))

    def close(self) -> None:
        for stream in (self.feeder, self.argos_in, self.argos_out, self.replies):
            with contextlib.suppress(OSError):
                stream.close()


async def _session(tmp_path: Path, allowed: tuple[str, ...] = ()) -> tuple[_Client, Any, Path]:
    client = _Client()
    db = tmp_path / "wrap.sqlite3"
    task = asyncio.create_task(
        _run_wrap(
            factory=StdioUpstreamFactory([sys.executable, str(_FIXTURE)]),
            upstream_repr="fixture",
            forensics_db=db,
            enable_otel=False,
            enable_drift=True,
            enable_pii=True,
            allowed_tools=allowed,
            client=client.transport(),
        ),
    )
    return client, task, db


@pytest.mark.asyncio
async def test_wrap_relays_a_full_session_and_records_it(tmp_path: Path) -> None:
    client, task, db = await _session(tmp_path)
    try:
        client.send({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
        init = await client.reply()
        client.send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        client.send({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        listed = await client.reply()
        client.feeder.close()
        assert await asyncio.wait_for(task, timeout=30) == 0
    finally:
        client.close()
    assert init["result"]["serverInfo"]["name"] == "fake-mcp"
    assert listed["result"]["tools"][0]["name"] == "echo"
    with sqlite3.connect(db) as conn:
        detectors = {row[0] for row in conn.execute("select detector_id from findings")}
    assert "argos.proxy.tool_drift" in detectors


@pytest.mark.asyncio
async def test_wrap_blocks_tools_outside_the_allowlist(tmp_path: Path) -> None:
    client, task, _ = await _session(tmp_path, allowed=("safe_*",))
    try:
        client.send({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
        await client.reply()
        client.send(
            {
                "jsonrpc": "2.0",
                "id": 7,
                "method": "tools/call",
                "params": {"name": "echo", "arguments": {"text": "hi"}},
            },
        )
        blocked = await client.reply()
        client.feeder.close()
        await asyncio.wait_for(task, timeout=30)
    finally:
        client.close()
    assert blocked["id"] == 7
    assert "error" in blocked
    assert "result" not in blocked


@pytest.mark.asyncio
async def test_wrap_reports_an_unreachable_upstream(tmp_path: Path) -> None:
    client = _Client()
    try:
        code = await _run_wrap(
            factory=StdioUpstreamFactory(["argos-definitely-not-installed-xyz"]),
            upstream_repr="missing",
            forensics_db=tmp_path / "x.sqlite3",
            enable_otel=False,
            enable_drift=False,
            enable_pii=False,
            allowed_tools=(),
            client=client.transport(),
        )
    finally:
        client.close()
    assert code == 1


def test_wrap_needs_exactly_one_upstream() -> None:
    assert runner.invoke(app, ["proxy", "wrap"]).exit_code == 2
    both = runner.invoke(app, ["proxy", "wrap", "--upstream", "https://x.example/mcp", "node"])
    assert both.exit_code == 2


def test_wrap_rejects_an_unknown_stdio_framing() -> None:
    result = runner.invoke(app, ["proxy", "wrap", "--stdio-framing", "grpc", "node", "s.js"])
    assert result.exit_code == 2


def test_header_values_can_come_from_the_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ARGOS_TEST_UPSTREAM_TOKEN", "Bearer abc")
    parsed = _parse_headers(["Authorization: env:ARGOS_TEST_UPSTREAM_TOKEN", "X-Team: blue"])
    assert parsed == {"Authorization": "Bearer abc", "X-Team": "blue"}
    with pytest.raises(typer.BadParameter):
        _parse_headers(["no-colon-here"])
    with pytest.raises(typer.BadParameter):
        _parse_headers(["X-Key: env:ARGOS_TEST_VARIABLE_THAT_IS_NOT_SET"])


def test_sse_over_tls_scheme() -> None:
    assert _parse_upstream_url("sse+https://mcp.example.com/sse") == (
        "sse",
        ("https://mcp.example.com/sse", None),
    )
    assert _parse_upstream_url("https://mcp.example.com/mcp") == (
        "http",
        ("https://mcp.example.com/mcp",),
    )
