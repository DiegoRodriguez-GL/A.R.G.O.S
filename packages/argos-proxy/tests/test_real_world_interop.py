"""Interoperability with MCP servers as they behave in the wild.

Each test pins a defect found while running the proxy against published
MCP servers (the reference servers on npm and public streamable-HTTP
endpoints) rather than against the project's own fixtures:

1. stdio servers speak newline-delimited JSON, not ``Content-Length``;
2. launchers such as ``npx`` are ``.cmd`` shims on Windows;
3. chatty servers print banners on stdout and flood stderr;
4. one socket read can carry several messages and none may be dropped;
5. streamable HTTP answers a request inside the POST response (JSON or
   SSE), binds a session with ``Mcp-Session-Id`` and may refuse the GET
   stream.
"""

from __future__ import annotations

import asyncio
import contextlib
import io
import json
import os
import sys
from pathlib import Path
from typing import Any

import pytest
from argos_proxy import (
    HttpStreamableTransport,
    Notification,
    PIIDetector,
    Request,
    Response,
    StdioServerTransport,
    StdioTransport,
    TcpAcceptedTransport,
    TcpTransport,
    parse_payload,
)
from argos_proxy.jsonrpc.http_framing import parse_request_head
from argos_proxy.transport._base import ClosedTransportError, TransportError
from argos_proxy.transport.http import UPSTREAM_TRANSPORT_ERROR
from argos_proxy.transport.stdio import normalise_framing, resolve_executable

pytestmark = [pytest.mark.asyncio]

_FIXTURE = Path(__file__).parent / "fixtures" / "fake_mcp_server.py"
_CRLF = "\r\n"


async def _handshake_and_list(transport: Any) -> tuple[Any, Any]:
    await transport.send(Request(method="initialize", id=1, params={}))
    init = await asyncio.wait_for(transport.receive(), timeout=15)
    await transport.send(Notification(method="notifications/initialized"))
    await transport.send(Request(method="tools/list", id=2))
    listed = await asyncio.wait_for(transport.receive(), timeout=15)
    return init, listed


# ---------------------------------------------------------------------------
# 1-3. stdio
# ---------------------------------------------------------------------------


class TestStdioInterop:
    @pytest.mark.parametrize("framing", ["ndjson", "content-length"])
    async def test_both_framings_round_trip(self, framing: str) -> None:
        transport = StdioTransport([sys.executable, str(_FIXTURE)], framing=framing)
        try:
            init, listed = await _handshake_and_list(transport)
            assert init.result["serverInfo"]["name"] == "fake-mcp"
            assert listed.id == 2
            assert listed.result["tools"][0]["name"] == "echo"
            assert transport.framing == framing
        finally:
            await transport.close()

    async def test_banner_on_stdout_and_stderr_flood_are_survived(self) -> None:
        env = {**os.environ, "FAKE_MCP_NOISE": "1"}
        transport = StdioTransport([sys.executable, str(_FIXTURE)], env=env)
        try:
            _, listed = await _handshake_and_list(transport)
            assert listed.id == 2
            # The banner was skipped, not parsed; the stderr flood (400
            # long lines, far beyond a pipe buffer) was drained.
            assert transport.stdout_noise_lines == 1
            assert len(transport.stderr_tail) > 0
        finally:
            await transport.close()

    async def test_close_ends_the_child_process(self) -> None:
        transport = StdioTransport([sys.executable, str(_FIXTURE)])
        await transport.start()
        assert transport.pid is not None
        await transport.close()
        assert transport.is_closed
        with pytest.raises(ClosedTransportError):
            await transport.receive()

    async def test_missing_executable_is_a_transport_error(self) -> None:
        transport = StdioTransport(["argos-definitely-not-installed-xyz"])
        with pytest.raises(TransportError, match="cannot start upstream"):
            await transport.start()

    async def test_bare_launcher_name_resolves_through_path(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        suffix = ".cmd" if sys.platform == "win32" else ""
        launcher = tmp_path / f"argos-fake-launcher{suffix}"
        launcher.write_text("@echo off\n" if suffix else "#!/bin/sh\n", encoding="ascii")
        launcher.chmod(0o755)
        monkeypatch.setenv("PATH", f"{tmp_path}{os.pathsep}{os.environ.get('PATH', '')}")
        resolved = resolve_executable(["argos-fake-launcher", "--flag"])
        assert os.path.normcase(resolved[0]) == os.path.normcase(str(launcher))
        assert resolved[1:] == ("--flag",)

    async def test_explicit_paths_and_unknown_names_are_kept(self) -> None:
        explicit = str(Path("local") / "server")
        assert resolve_executable([explicit, "x"]) == (explicit, "x")
        assert resolve_executable(["argos-not-installed-xyz"]) == ("argos-not-installed-xyz",)

    async def test_framing_names(self) -> None:
        assert normalise_framing("NDJSON") == "ndjson"
        assert normalise_framing("Content-Length") == "stdio"
        with pytest.raises(ValueError, match="unsupported stdio framing"):
            StdioTransport(["x"], framing="grpc")


# ---------------------------------------------------------------------------
# 4. No message is dropped when several share one read.
# ---------------------------------------------------------------------------


_BURST = (
    json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"})
    + "\n"
    + json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    + "\n\n"
    + json.dumps({"jsonrpc": "2.0", "id": 3, "method": "ping"})
    + "\n"
).encode("utf-8")


class TestNoMessageDropped:
    async def test_accepted_transport_delivers_every_message_of_one_write(self) -> None:
        received: list[Any] = []
        done = asyncio.Event()

        async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            transport = TcpAcceptedTransport(reader, writer)
            for _ in range(3):
                received.append(await asyncio.wait_for(transport.receive(), timeout=5))
            done.set()
            await transport.close()

        server = await asyncio.start_server(handler, "127.0.0.1", 0)
        host, port = server.sockets[0].getsockname()[:2]
        _, writer = await asyncio.open_connection(host, port)
        try:
            writer.write(_BURST)
            await writer.drain()
            await asyncio.wait_for(done.wait(), timeout=5)
        finally:
            writer.close()
            server.close()
        assert [m.method for m in received] == ["notifications/initialized", "tools/list", "ping"]

    async def test_client_transport_delivers_every_message_of_one_write(self) -> None:
        async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            writer.write(_BURST)
            await writer.drain()
            await reader.read(1)

        server = await asyncio.start_server(handler, "127.0.0.1", 0)
        host, port = server.sockets[0].getsockname()[:2]
        transport = TcpTransport(host, port)
        try:
            await transport.connect()
            methods = [(await asyncio.wait_for(transport.receive(), timeout=5)) for _ in range(3)]
        finally:
            await transport.close()
            server.close()
        assert [m.method for m in methods] == ["notifications/initialized", "tools/list", "ping"]


# ---------------------------------------------------------------------------
# Downstream stdio (argos proxy wrap).
# ---------------------------------------------------------------------------


class TestPrintedIban:
    """A document read through the reference filesystem server showed the
    IBAN in its printed form (a space every four characters) and the PII
    detector missed it while it caught the e-mail and the DNI next to it."""

    async def test_grouped_and_compact_forms_are_detected(self) -> None:
        for text in (
            "Cuenta de cargo: ES91 2100 0418 4502 0005 1332\n",
            "Cuenta: ES9121000418450200051332.",
            "IBAN ES91 2100 0418 4502 0005 1332 DNI del titular",
        ):
            assert [m.kind for m in PIIDetector._scan_iban(text)] == ["iban"], text

    async def test_invalid_checksum_is_ignored(self) -> None:
        assert list(PIIDetector._scan_iban("ES00 2100 0418 4502 0005 1332")) == []


class TestParamsAreNeverNull:
    async def test_absent_params_stay_absent_on_the_wire(self) -> None:
        # The MCP Inspector sends ``{"method":"tools/list","id":2}``; the
        # TypeScript SDK server silently drops ``"params": null``.
        for raw in (
            b'{"jsonrpc":"2.0","method":"tools/list","id":2}',
            b'{"jsonrpc":"2.0","method":"notifications/initialized"}',
        ):
            message = parse_payload(raw)
            assert "params" not in json.loads(message.model_dump_json())

    async def test_present_params_are_preserved(self) -> None:
        message = parse_payload(b'{"jsonrpc":"2.0","method":"tools/list","params":{},"id":2}')
        assert json.loads(message.model_dump_json())["params"] == {}


class TestStdioServerTransport:
    async def test_reads_lines_and_writes_ndjson(self) -> None:
        read_fd, write_fd = os.pipe()
        client_in = os.fdopen(read_fd, "rb")
        feeder = os.fdopen(write_fd, "wb")
        out = io.BytesIO()
        transport = StdioServerTransport(reader=client_in, writer=out)
        try:
            feeder.write(_BURST)
            feeder.flush()
            got = [await asyncio.wait_for(transport.receive(), timeout=5) for _ in range(3)]
            assert [m.method for m in got] == ["notifications/initialized", "tools/list", "ping"]
            await transport.send(Response(result={}, id=3))
            wire = out.getvalue()
            assert wire.endswith(b"\n")
            assert json.loads(wire)["id"] == 3
            feeder.close()
            with pytest.raises(ClosedTransportError):
                await asyncio.wait_for(transport.receive(), timeout=5)
        finally:
            with contextlib.suppress(OSError):
                feeder.close()
            await transport.close()
            client_in.close()


# ---------------------------------------------------------------------------
# 5. Streamable HTTP as the 2025-06-18 specification describes it.
# ---------------------------------------------------------------------------


class _SpecServer:
    """Minimal streamable-HTTP server that follows the specification.

    ``mode="json"`` answers requests with ``application/json``;
    ``mode="sse"`` answers with a chunked ``text/event-stream`` that
    carries a log notification before the response. GET is refused with
    405, notifications get 202, and every request after ``initialize``
    must carry the session header.
    """

    def __init__(self, mode: str = "json") -> None:
        self.mode = mode
        self.requests: list[tuple[str, Any, bytes]] = []
        self.connections = 0
        self._server: asyncio.base_events.Server | None = None

    async def start(self) -> tuple[str, int]:
        self._server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
        host, port = self._server.sockets[0].getsockname()[:2]
        return host, port

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            with contextlib.suppress(Exception):
                await asyncio.wait_for(self._server.wait_closed(), timeout=1)

    def headers_of(self, method: str) -> list[Any]:
        found = []
        for http_method, headers, body in self.requests:
            if http_method == "POST" and body and json.loads(body).get("method") == method:
                found.append(headers)
        return found

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self.connections += 1
        try:
            while True:
                head = await reader.readuntil(b"\r\n\r\n")
                request = parse_request_head(head[:-4])
                length = int(request.headers.get("Content-Length") or 0)
                body = await reader.readexactly(length) if length else b""
                self.requests.append((request.method, request.headers, body))
                await self._respond(request, body, writer)
        except (asyncio.IncompleteReadError, ConnectionError, asyncio.LimitOverrunError):
            return

    async def _send(
        self,
        writer: asyncio.StreamWriter,
        status: int,
        reason: str,
        body: bytes = b"",
        headers: dict[str, str] | None = None,
    ) -> None:
        lines = [f"HTTP/1.1 {status} {reason}", f"Content-Length: {len(body)}"]
        lines += [f"{k}: {v}" for k, v in (headers or {}).items()]
        writer.write((_CRLF.join(lines) + _CRLF + _CRLF).encode("ascii") + body)
        await writer.drain()

    async def _respond(self, request: Any, body: bytes, writer: asyncio.StreamWriter) -> None:
        if request.method == "GET":
            await self._send(writer, 405, "Method Not Allowed")
            return
        if request.method == "DELETE":
            await self._send(writer, 204, "No Content")
            return
        message = json.loads(body)
        if "id" not in message:
            await self._send(writer, 202, "Accepted")
            return
        headers: dict[str, str] = {}
        method = message["method"]
        if method == "initialize":
            headers["Mcp-Session-Id"] = "sess-123"
            result: dict[str, Any] = {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "serverInfo": {"name": "spec-fake", "version": "1"},
            }
        elif request.headers.get("Mcp-Session-Id") != "sess-123":
            await self._send(writer, 400, "Bad Request", b"missing session")
            return
        elif method == "boom":
            await self._send(writer, 500, "Internal Server Error", b"kaboom")
            return
        else:
            result = {"tools": [{"name": "t1", "inputSchema": {"type": "object"}}]}
        response = json.dumps({"jsonrpc": "2.0", "id": message["id"], "result": result})
        if self.mode == "json":
            headers["Content-Type"] = "application/json"
            await self._send(writer, 200, "OK", response.encode(), headers)
            return
        note = json.dumps(
            {"jsonrpc": "2.0", "method": "notifications/message", "params": {"data": "working"}},
        )
        events = f"event: message\ndata: {note}\n\nevent: message\ndata: {response}\n\n".encode()
        head = ["HTTP/1.1 200 OK", "Content-Type: text/event-stream", "Transfer-Encoding: chunked"]
        head += [f"{k}: {v}" for k, v in headers.items()]
        writer.write((_CRLF.join(head) + _CRLF + _CRLF).encode("ascii"))
        for piece in (events[:17], events[17:]):
            writer.write(f"{len(piece):x}".encode() + b"\r\n" + piece + b"\r\n")
        writer.write(b"0\r\n\r\n")
        await writer.drain()


class TestStreamableHttpSpec:
    async def test_json_answers_session_and_protocol_headers(self) -> None:
        server = _SpecServer("json")
        host, port = await server.start()
        transport = HttpStreamableTransport(f"http://{host}:{port}/mcp")
        try:
            await transport.connect()
            assert not transport.server_stream_open  # GET refused with 405
            init, listed = await _handshake_and_list(transport)
            assert init.result["serverInfo"]["name"] == "spec-fake"
            assert transport.session_id == "sess-123"
            assert transport.protocol_version == "2025-06-18"
            assert listed.result["tools"][0]["name"] == "t1"
            (list_headers,) = server.headers_of("tools/list")
            assert list_headers.get("Mcp-Session-Id") == "sess-123"
            assert list_headers.get("Mcp-Protocol-Version") == "2025-06-18"
            assert "text/event-stream" in (list_headers.get("Accept") or "")
        finally:
            await transport.close()
            await server.stop()
        # Leaving the session is announced with DELETE.
        deletes = [h for m, h, _ in server.requests if m == "DELETE"]
        assert deletes
        assert deletes[0].get("Mcp-Session-Id") == "sess-123"

    async def test_chunked_sse_answer_delivers_notification_then_response(self) -> None:
        server = _SpecServer("sse")
        host, port = await server.start()
        transport = HttpStreamableTransport(f"http://{host}:{port}/mcp")
        try:
            await transport.send(Request(method="initialize", id=1, params={}))
            first = await asyncio.wait_for(transport.receive(), timeout=5)
            second = await asyncio.wait_for(transport.receive(), timeout=5)
            assert isinstance(first, Notification)
            assert first.method == "notifications/message"
            assert isinstance(second, Response)
            assert second.id == 1
        finally:
            await transport.close()
            await server.stop()

    async def test_http_failure_is_answered_as_a_jsonrpc_error(self) -> None:
        server = _SpecServer("json")
        host, port = await server.start()
        transport = HttpStreamableTransport(f"http://{host}:{port}/mcp")
        try:
            await _handshake_and_list(transport)
            await transport.send(Request(method="boom", id=9))
            reply = await asyncio.wait_for(transport.receive(), timeout=5)
            assert isinstance(reply, Response)
            assert reply.id == 9
            assert reply.error is not None
            assert reply.error.code == UPSTREAM_TRANSPORT_ERROR
            assert "500" in reply.error.message
            assert "kaboom" in reply.error.message
        finally:
            await transport.close()
            await server.stop()

    async def test_keep_alive_connections_are_reused(self) -> None:
        server = _SpecServer("json")
        host, port = await server.start()
        transport = HttpStreamableTransport(f"http://{host}:{port}/mcp", open_server_stream=False)
        try:
            await _handshake_and_list(transport)
            for i in range(10, 15):
                await transport.send(Request(method="tools/list", id=i))
                await asyncio.wait_for(transport.receive(), timeout=5)
            posts = [m for m, _, _ in server.requests if m == "POST"]
            assert len(posts) == 8
            assert server.connections <= 3
        finally:
            await transport.close()
            await server.stop()

    async def test_unreachable_upstream_fails_fast(self) -> None:
        server = _SpecServer("json")
        host, port = await server.start()
        await server.stop()
        transport = HttpStreamableTransport(f"http://{host}:{port}/mcp")
        with pytest.raises(TransportError):
            await transport.connect()

    async def test_header_values_cannot_inject_lines(self) -> None:
        with pytest.raises(ValueError, match="line break"):
            HttpStreamableTransport("https://example.com/mcp", headers={"X-A": "1\r\nX-B: 2"})
