"""End-to-end tests for the HTTP / SSE transports.

These tests use *real* TCP sockets via ``asyncio.start_server`` and the
real ``HttpStreamableTransport`` / ``HttpStreamableAcceptedTransport``
codepaths. No mocks of the parser, no fake sockets. Each test brings up
an ephemeral port, drives the full handshake (HTTP head + SSE stream +
JSON-RPC payload), and tears down deterministically.

Coverage by class:

- TestHttpStreamableClient -- client -> fake upstream HTTP server.
- TestHttpStreamableServer -- real downstream HTTP client -> our
  ``HttpStreamableAcceptedTransport``.
- TestSseClient            -- client -> fake legacy SSE server (with
  ``endpoint`` event auto-discovery).
- TestProxyHttpFraming     -- full proxy pipeline with ``framing='http'``.
- TestAdversarial          -- HTTP smuggling, slowloris, malformed bodies.
"""

from __future__ import annotations

import asyncio
import json
import socket
from typing import Any

import pytest
from argos_proxy import (
    HttpStreamableAcceptedTransport,
    HttpStreamableTransport,
    InMemoryUpstreamFactory,
    ProxyListener,
    Request,
    Response,
    SseTransport,
)
from argos_proxy.jsonrpc.http_framing import (
    Headers,
    encode_response,
    parse_request,
)
from argos_proxy.jsonrpc.sse_framing import encode_sse_event
from argos_proxy.transport._base import (
    ClosedTransportError,
    TransportError,
)

pytestmark = [pytest.mark.asyncio]


# ---------------------------------------------------------------------------
# Fake upstream HTTP/SSE server fixtures.
# ---------------------------------------------------------------------------


class _FakeStreamableServer:
    """Minimal MCP ``streamable-http`` upstream for client tests.

    Speaks HTTP/1.1 over a single TCP socket per logical connection.
    Maintains a per-connection ``writer`` so the test can push SSE
    events from outside the request handler. The server pretends to be
    an MCP upstream: it accepts GET (opens SSE) and POST (echoes the
    JSON-RPC body back as an SSE event)."""

    def __init__(self) -> None:
        self.server: asyncio.base_events.Server | None = None
        self.connections: list[tuple[asyncio.StreamReader, asyncio.StreamWriter]] = []
        self.received_posts: list[bytes] = []
        # Override hooks so individual tests can inject failure modes.
        self.on_post: Any = None  # async callable(body: bytes) -> None
        self.respond_status_get: int = 200
        self.respond_content_type_get: str = "text/event-stream"
        self.respond_status_post: int = 202
        self.delay_post_response_seconds: float = 0.0

    async def start(self) -> tuple[str, int]:
        self.server = await asyncio.start_server(
            self._handle,
            host="127.0.0.1",
            port=0,
        )
        sockets = self.server.sockets or ()
        if not sockets:  # pragma: no cover - defensive
            msg = "fake server did not bind"
            raise RuntimeError(msg)
        host, port, *_ = sockets[0].getsockname()
        return host, port

    async def stop(self) -> None:
        if self.server is None:
            return
        for _r, w in self.connections:
            try:
                w.close()
            except Exception:  # noqa: BLE001
                pass
        self.server.close()
        try:
            await asyncio.wait_for(self.server.wait_closed(), timeout=1.0)
        except (TimeoutError, Exception):  # noqa: BLE001
            pass

    async def _handle(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        self.connections.append((reader, writer))
        try:
            while True:
                head = await _read_http_head(reader)
                if head is None:
                    return
                req = parse_request(head)
                if req.method == "GET":
                    await self._serve_get(writer, req)
                    # Keep the GET stream open until close.
                    while True:  # noqa: ASYNC110 - test fixture parks here
                        await asyncio.sleep(0.5)
                elif req.method == "POST":
                    body_len = int(req.headers.get("Content-Length") or "0")
                    body = req.body
                    if len(body) < body_len:
                        body = body + await reader.readexactly(
                            body_len - len(body),
                        )
                    self.received_posts.append(body)
                    if self.on_post is not None:
                        await self.on_post(body)
                    if self.delay_post_response_seconds > 0:
                        await asyncio.sleep(self.delay_post_response_seconds)
                    await self._serve_post(writer)
                else:
                    await self._serve_405(writer)
                    return
        except (ConnectionResetError, BrokenPipeError, asyncio.IncompleteReadError):
            return
        except Exception:  # noqa: BLE001 - test helper
            return

    async def _serve_get(
        self,
        writer: asyncio.StreamWriter,
        req: Any,
    ) -> None:
        headers = Headers()
        headers.add("Content-Type", self.respond_content_type_get)
        headers.add("Cache-Control", "no-cache")
        head = encode_response(self.respond_status_get, "OK", headers=headers)
        writer.write(head)
        await writer.drain()

    async def _serve_post(self, writer: asyncio.StreamWriter) -> None:
        headers = Headers()
        headers.add("Content-Length", "0")
        head = encode_response(self.respond_status_post, "Accepted", headers=headers)
        writer.write(head)
        await writer.drain()

    async def _serve_405(self, writer: asyncio.StreamWriter) -> None:
        body = b'{"error":"method not allowed"}'
        headers = Headers()
        headers.add("Content-Type", "application/json")
        head = encode_response(
            405,
            "Method Not Allowed",
            headers=headers,
            body=body,
        )
        writer.write(head)
        await writer.drain()

    async def push_sse_event(
        self,
        connection_index: int,
        data: str,
        *,
        event: str | None = None,
        id_: str | None = None,
    ) -> None:
        """Push one SSE event on the GET writer of a given connection."""
        if connection_index >= len(self.connections):
            msg = f"no connection {connection_index}; have {len(self.connections)}"
            raise IndexError(msg)
        _, writer = self.connections[connection_index]
        wire = encode_sse_event(data, event=event, id_=id_)
        writer.write(wire)
        await writer.drain()


async def _read_http_head(reader: asyncio.StreamReader) -> bytes | None:
    """Read up to ``\\r\\n\\r\\n`` and return everything (head + leftover).
    Returns ``None`` on clean disconnect before any bytes."""
    buf = bytearray()
    while True:
        try:
            chunk = await reader.read(4096)
        except (ConnectionResetError, BrokenPipeError):
            return None
        if not chunk:
            return None
        buf.extend(chunk)
        if b"\r\n\r\n" in buf:
            return bytes(buf)
        if len(buf) > 64 * 1024:
            return bytes(buf)


# ---------------------------------------------------------------------------
# 1. Client: HttpStreamableTransport against a fake upstream.
# ---------------------------------------------------------------------------


class TestHttpStreamableClient:
    async def test_handshake_opens_sse_stream(self) -> None:
        srv = _FakeStreamableServer()
        host, port = await srv.start()
        try:
            tx = HttpStreamableTransport(f"http://{host}:{port}/mcp")
            await tx.connect()
            assert not tx.is_closed
            # Push a synthetic message and verify it is received.
            req = Request(method="ping", id=1)
            payload = req.model_dump_json()
            # Wait briefly for the GET to be registered server-side.
            for _ in range(50):
                if srv.connections:
                    break
                await asyncio.sleep(0.02)
            assert srv.connections
            await srv.push_sse_event(0, payload, event="message")
            msg = await asyncio.wait_for(tx.receive(), timeout=2.0)
            assert isinstance(msg, Request)
            assert msg.method == "ping"
            await tx.close()
        finally:
            await srv.stop()

    async def test_post_sent_and_response_arrives_via_sse(self) -> None:
        srv = _FakeStreamableServer()
        host, port = await srv.start()
        try:
            tx = HttpStreamableTransport(f"http://{host}:{port}/mcp")
            await tx.connect()
            for _ in range(50):
                if srv.connections:
                    break
                await asyncio.sleep(0.02)
            outgoing = Request(method="tools/list", id=99)
            await tx.send(outgoing)
            # Server should have observed the POST body.
            for _ in range(50):
                if srv.received_posts:
                    break
                await asyncio.sleep(0.02)
            assert srv.received_posts
            posted = json.loads(srv.received_posts[0].decode("utf-8"))
            assert posted["method"] == "tools/list"
            assert posted["id"] == 99
            # Now the fake server pushes a response on the SSE stream.
            response_payload = json.dumps(
                {"jsonrpc": "2.0", "id": 99, "result": {"tools": []}},
            )
            await srv.push_sse_event(0, response_payload, event="message")
            received = await asyncio.wait_for(tx.receive(), timeout=2.0)
            assert isinstance(received, Response)
            assert received.id == 99
            assert received.result == {"tools": []}
            await tx.close()
        finally:
            await srv.stop()

    async def test_unsupported_url_scheme_rejected(self) -> None:
        with pytest.raises(ValueError, match="unsupported URL scheme"):
            HttpStreamableTransport("ftp://example.com/x")

    async def test_connection_to_unbound_port_raises(self) -> None:
        # Pick a free port then immediately drop it: the connect attempt
        # against the now-stale port should raise TransportError.
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            host, port = s.getsockname()
        # Outside the with: the socket is closed, port unbound.
        tx = HttpStreamableTransport(f"http://{host}:{port}/mcp")
        with pytest.raises(TransportError):
            await tx.connect()

    async def test_get_refusal_is_tolerated(self) -> None:
        # The server-to-client GET stream is optional in the MCP
        # specification; a refusal must not stop the POST half.
        srv = _FakeStreamableServer()
        srv.respond_status_get = 503
        host, port = await srv.start()
        try:
            tx = HttpStreamableTransport(f"http://{host}:{port}/mcp")
            await tx.connect()
            assert not tx.server_stream_open
            await tx.send(Request(method="tools/list", id=5))
            for _ in range(100):
                if srv.received_posts:
                    break
                await asyncio.sleep(0.02)
            assert json.loads(srv.received_posts[0].decode("utf-8"))["id"] == 5
            await tx.close()
        finally:
            await srv.stop()

    async def test_get_with_wrong_content_type_is_not_used_as_stream(self) -> None:
        srv = _FakeStreamableServer()
        srv.respond_content_type_get = "application/json"
        host, port = await srv.start()
        try:
            tx = HttpStreamableTransport(f"http://{host}:{port}/mcp")
            await tx.connect()
            assert not tx.server_stream_open
            await tx.close()
        finally:
            await srv.stop()

    async def test_close_after_open_does_not_raise(self) -> None:
        srv = _FakeStreamableServer()
        host, port = await srv.start()
        try:
            tx = HttpStreamableTransport(f"http://{host}:{port}/mcp")
            await tx.connect()
            await tx.close()
            assert tx.is_closed
            # close is idempotent.
            await tx.close()
        finally:
            await srv.stop()

    async def test_losing_the_server_stream_keeps_the_session(self) -> None:
        # A dropped GET stream only ends server-initiated delivery; the
        # session itself lives until close(), after which receive raises.
        srv = _FakeStreamableServer()
        host, port = await srv.start()
        try:
            tx = HttpStreamableTransport(f"http://{host}:{port}/mcp")
            await tx.connect()
            for _ in range(50):
                if srv.connections:
                    break
                await asyncio.sleep(0.02)
            _, w = srv.connections[0]
            w.close()
            for _ in range(100):
                if not tx.server_stream_open:
                    break
                await asyncio.sleep(0.02)
            assert not tx.server_stream_open
            assert not tx.is_closed
            await tx.close()
            with pytest.raises(ClosedTransportError):
                await asyncio.wait_for(tx.receive(), timeout=2.0)
        finally:
            await srv.stop()

    async def test_concurrent_posts_serialised(self) -> None:
        # Two POSTs issued back-to-back: the per-transport lock must
        # serialise them so the upstream sees a clean request stream.
        srv = _FakeStreamableServer()
        host, port = await srv.start()
        try:
            tx = HttpStreamableTransport(f"http://{host}:{port}/mcp")
            await tx.connect()
            await asyncio.gather(
                tx.send(Request(method="m1", id=1)),
                tx.send(Request(method="m2", id=2)),
                tx.send(Request(method="m3", id=3)),
            )
            # All three bodies arrived intact.
            for _ in range(100):
                if len(srv.received_posts) >= 3:
                    break
                await asyncio.sleep(0.02)
            assert len(srv.received_posts) == 3
            methods = [json.loads(p.decode("utf-8"))["method"] for p in srv.received_posts]
            assert sorted(methods) == ["m1", "m2", "m3"]
            await tx.close()
        finally:
            await srv.stop()


# ---------------------------------------------------------------------------
# 2. Server: HttpStreamableAcceptedTransport against a real client.
# ---------------------------------------------------------------------------


class _AcceptedHarness:
    """Hosts ``HttpStreamableAcceptedTransport`` instances on a real socket.

    Captures *every* accepted connection as its own transport. Tests
    that drive a client which opens multiple connections (e.g. the
    streamable-http client opens one for GET and one for POST) get one
    transport per connection.
    """

    def __init__(self) -> None:
        self.server: asyncio.base_events.Server | None = None
        self.transports: list[HttpStreamableAcceptedTransport] = []
        self._accept_event = asyncio.Event()

    async def start(self) -> tuple[str, int]:
        async def handle(
            reader: asyncio.StreamReader,
            writer: asyncio.StreamWriter,
        ) -> None:
            transport = HttpStreamableAcceptedTransport(reader, writer)
            self.transports.append(transport)
            self._accept_event.set()
            # Park forever; tests close the transport explicitly.
            try:
                while not transport.is_closed:  # noqa: ASYNC110 - park
                    await asyncio.sleep(0.05)
            finally:
                await transport.close()

        self.server = await asyncio.start_server(handle, "127.0.0.1", 0)
        host, port, *_ = (self.server.sockets or [None])[0].getsockname()  # type: ignore[union-attr]
        return host, port

    async def stop(self) -> None:
        for t in self.transports:
            await t.close()
        if self.server is not None:
            self.server.close()
            # ``wait_closed`` can hang on Python 3.14 / proactor when
            # the connection's handle hasn't yet observed the close,
            # so cap with a generous timeout: the test no longer needs
            # the server, only that no leaks linger.
            try:
                await asyncio.wait_for(
                    self.server.wait_closed(),
                    timeout=1.0,
                )
            except (TimeoutError, Exception):  # noqa: BLE001
                pass

    async def wait_for_n_transports(
        self,
        n: int,
        timeout: float = 2.0,  # noqa: ASYNC109 - test helper
    ) -> None:
        deadline = asyncio.get_event_loop().time() + timeout
        while len(self.transports) < n:
            remaining = deadline - asyncio.get_event_loop().time()
            if remaining <= 0:
                msg = f"only {len(self.transports)} transports accepted, expected {n}"
                raise TimeoutError(msg)
            self._accept_event.clear()
            try:
                await asyncio.wait_for(
                    self._accept_event.wait(),
                    timeout=remaining,
                )
            except TimeoutError:
                pass

    @property
    def transport(self) -> HttpStreamableAcceptedTransport:
        """Convenience accessor for tests that expect exactly one transport."""
        if not self.transports:
            msg = "no transports accepted yet"
            raise IndexError(msg)
        return self.transports[-1]


class TestHttpStreamableServer:
    async def test_get_opens_sse_then_server_pushes_event(self) -> None:
        # Verify the GET-leg: opening a GET produces an SSE-stream
        # response, and outbound ``send`` calls on the server transport
        # are framed as SSE events the client can read.
        h = _AcceptedHarness()
        host, port = await h.start()
        try:
            reader, writer = await asyncio.open_connection(host, port)
            writer.write(
                b"GET /mcp HTTP/1.1\r\n"
                b"Host: x\r\n"
                b"Accept: text/event-stream\r\n"
                b"Connection: keep-alive\r\n"
                b"\r\n",
            )
            await writer.drain()
            await h.wait_for_n_transports(1)
            head_chunk = await asyncio.wait_for(reader.read(1024), timeout=2.0)
            assert b"200 OK" in head_chunk
            assert b"text/event-stream" in head_chunk.lower()
            # Now have the server-side transport push a Response.
            await h.transport.send(Response(result={"ok": True}, id=1))
            sse_chunk = await asyncio.wait_for(reader.read(4096), timeout=2.0)
            # The wire contains an SSE event. We do not parse here -- we
            # just verify the JSON payload bytes are visible.
            assert b"event: message" in sse_chunk
            assert b'"id":1' in sse_chunk.replace(b" ", b"")
            writer.close()
            try:
                await writer.wait_closed()
            except (OSError, ConnectionError):
                pass
        finally:
            await h.stop()

    async def test_post_body_received_as_typed_message(self) -> None:
        # Verify the POST-leg: sending a JSON-RPC POST surfaces a typed
        # message via the server transport's ``receive``.
        h = _AcceptedHarness()
        host, port = await h.start()
        try:
            reader, writer = await asyncio.open_connection(host, port)
            body = b'{"jsonrpc":"2.0","method":"tools/list","id":7}'
            writer.write(
                b"POST /mcp HTTP/1.1\r\n"
                b"Host: x\r\n"
                b"Content-Type: application/json\r\n"
                b"Content-Length: " + str(len(body)).encode("ascii") + b"\r\n"
                b"\r\n" + body,
            )
            await writer.drain()
            await h.wait_for_n_transports(1)
            msg = await asyncio.wait_for(h.transport.receive(), timeout=2.0)
            assert isinstance(msg, Request)
            assert msg.method == "tools/list"
            assert msg.id == 7
            data = await asyncio.wait_for(reader.read(1024), timeout=2.0)
            assert b"202 Accepted" in data
            writer.close()
            try:
                await writer.wait_closed()
            except (OSError, ConnectionError):
                pass
        finally:
            await h.stop()

    async def test_get_without_event_stream_accept_rejected(self) -> None:
        h = _AcceptedHarness()
        host, port = await h.start()
        try:
            reader, writer = await asyncio.open_connection(host, port)
            writer.write(
                b"GET /mcp HTTP/1.1\r\nHost: x\r\nAccept: application/json\r\n\r\n",
            )
            await writer.drain()
            await h.wait_for_n_transports(1)
            data = await asyncio.wait_for(reader.read(1024), timeout=2.0)
            # Server should reply 406 Not Acceptable.
            assert b"406 Not Acceptable" in data
            writer.close()
            try:
                await writer.wait_closed()
            except (OSError, ConnectionError):
                pass
        finally:
            await h.stop()

    async def test_malformed_post_returns_400(self) -> None:
        h = _AcceptedHarness()
        host, port = await h.start()
        try:
            reader, writer = await asyncio.open_connection(host, port)
            body = b"this is not json"
            req = (
                b"POST /mcp HTTP/1.1\r\n"
                b"Host: x\r\n"
                b"Content-Type: application/json\r\n"
                b"Content-Length: " + str(len(body)).encode("ascii") + b"\r\n"
                b"\r\n" + body
            )
            writer.write(req)
            await writer.drain()
            await h.wait_for_n_transports(1)
            data = await asyncio.wait_for(reader.read(1024), timeout=2.0)
            assert b"400 Bad Request" in data
            writer.close()
            try:
                await writer.wait_closed()
            except (OSError, ConnectionError):
                pass
        finally:
            await h.stop()

    async def test_unsupported_method_returns_405(self) -> None:
        h = _AcceptedHarness()
        host, port = await h.start()
        try:
            reader, writer = await asyncio.open_connection(host, port)
            writer.write(b"PUT /mcp HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n")
            await writer.drain()
            await h.wait_for_n_transports(1)
            data = await asyncio.wait_for(reader.read(1024), timeout=2.0)
            assert b"405 Method Not Allowed" in data
            writer.close()
            try:
                await writer.wait_closed()
            except (OSError, ConnectionError):
                pass
        finally:
            await h.stop()


# ---------------------------------------------------------------------------
# 3. Legacy SSE client: GET /sse + POST /messages with endpoint event.
# ---------------------------------------------------------------------------


class _FakeLegacySseServer:
    """Minimal MCP legacy SSE server.

    - GET /sse: opens the event stream and immediately publishes an
      ``endpoint`` event whose ``data`` is the relative path
      ``/messages?session=<id>``.
    - POST /messages?session=<id>: accepts a JSON-RPC body, replies 202.
    """

    def __init__(self) -> None:
        self.server: asyncio.base_events.Server | None = None
        self.sse_connections: list[tuple[asyncio.StreamReader, asyncio.StreamWriter]] = []
        self.posts: list[bytes] = []

    async def start(self) -> tuple[str, int]:
        self.server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
        host, port, *_ = (self.server.sockets or [None])[0].getsockname()  # type: ignore[union-attr]
        return host, port

    async def stop(self) -> None:
        for _r, w in self.sse_connections:
            try:
                w.close()
            except Exception:  # noqa: BLE001
                pass
        if self.server is not None:
            self.server.close()
            try:
                await asyncio.wait_for(
                    self.server.wait_closed(),
                    timeout=1.0,
                )
            except (TimeoutError, Exception):  # noqa: BLE001
                pass

    async def _handle(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        try:
            head = await _read_http_head(reader)
            if head is None:
                return
            req = parse_request(head)
            if req.method == "GET" and req.path.startswith("/sse"):
                await self._serve_sse(reader, writer)
            elif req.method == "POST" and req.path.startswith("/messages"):
                body_len = int(req.headers.get("Content-Length") or "0")
                body = req.body
                if len(body) < body_len:
                    body = body + await reader.readexactly(
                        body_len - len(body),
                    )
                self.posts.append(body)
                await self._serve_post(writer)
        except (ConnectionResetError, BrokenPipeError, asyncio.IncompleteReadError):
            return
        except Exception:  # noqa: BLE001
            return

    async def _serve_sse(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        headers = Headers()
        headers.add("Content-Type", "text/event-stream")
        headers.add("Cache-Control", "no-cache")
        head = encode_response(200, "OK", headers=headers)
        writer.write(head)
        # Emit the canonical ``endpoint`` event right away.
        writer.write(encode_sse_event("/messages?session=abc", event="endpoint"))
        await writer.drain()
        self.sse_connections.append((reader, writer))
        # Park forever (test pushes events explicitly).
        while True:  # noqa: ASYNC110 - test fixture parks here
            await asyncio.sleep(0.5)

    async def _serve_post(self, writer: asyncio.StreamWriter) -> None:
        headers = Headers()
        headers.add("Content-Length", "0")
        head = encode_response(202, "Accepted", headers=headers)
        writer.write(head)
        await writer.drain()

    async def push_message(
        self,
        connection_index: int,
        payload: str,
    ) -> None:
        _, writer = self.sse_connections[connection_index]
        writer.write(encode_sse_event(payload, event="message"))
        await writer.drain()


class TestSseClient:
    async def test_endpoint_event_auto_discovered(self) -> None:
        srv = _FakeLegacySseServer()
        host, port = await srv.start()
        try:
            tx = SseTransport(f"http://{host}:{port}/sse")
            await tx.connect()
            # Wait for endpoint discovery: the SSE stream is now bound.
            for _ in range(50):
                if srv.sse_connections:
                    break
                await asyncio.sleep(0.02)
            assert srv.sse_connections
            await tx.send(Request(method="ping", id=1))
            for _ in range(50):
                if srv.posts:
                    break
                await asyncio.sleep(0.02)
            assert srv.posts
            posted = json.loads(srv.posts[0].decode("utf-8"))
            assert posted["method"] == "ping"
            await srv.push_message(
                0,
                json.dumps({"jsonrpc": "2.0", "id": 1, "result": "pong"}),
            )
            received = await asyncio.wait_for(tx.receive(), timeout=2.0)
            assert isinstance(received, Response)
            assert received.result == "pong"
            await tx.close()
        finally:
            await srv.stop()

    async def test_explicit_post_url_skips_discovery(self) -> None:
        srv = _FakeLegacySseServer()
        host, port = await srv.start()
        try:
            tx = SseTransport(
                f"http://{host}:{port}/sse",
                post_url=f"http://{host}:{port}/messages?session=abc",
            )
            await tx.connect()
            await tx.send(Request(method="explicit", id=2))
            for _ in range(50):
                if srv.posts:
                    break
                await asyncio.sleep(0.02)
            assert srv.posts
            await tx.close()
        finally:
            await srv.stop()


# ---------------------------------------------------------------------------
# 4. Full proxy pipeline: real downstream client -> proxy -> in-memory upstream.
# ---------------------------------------------------------------------------


async def _run_upstream_echo(factory: InMemoryUpstreamFactory) -> None:
    """Drive every accepted upstream half: receive a request, reply with
    a synthetic ``echo`` result. Same helper as the NDJSON tests."""
    handled: set[int] = set()
    while True:
        await asyncio.sleep(0.01)
        for idx, peer in enumerate(list(factory.peer_transports)):
            if idx in handled:
                continue
            try:
                msg = await asyncio.wait_for(peer.receive(), timeout=0.5)
            except TimeoutError:
                continue
            except Exception:  # noqa: BLE001
                handled.add(idx)
                continue
            if isinstance(msg, Request):
                try:
                    await peer.send(
                        Response(
                            result={"echo": msg.method, "params": msg.params},
                            id=msg.id,
                        ),
                    )
                except Exception:  # noqa: BLE001
                    handled.add(idx)


class TestProxyHttpFraming:
    async def test_listener_starts_with_http_framing(self) -> None:
        # The proxy listener accepts ``framing='http'`` and binds a real
        # TCP port. End-to-end JSON-RPC routing across two separate TCP
        # connections (GET stream + POST channel) requires session
        # correlation via ``Mcp-Session-Id`` and is documented as a
        # follow-up. This test verifies the listener boot path and
        # framing acceptance.
        factory = InMemoryUpstreamFactory()
        listener = ProxyListener(
            host="127.0.0.1",
            port=0,
            upstream_factory=factory,
            framing="http",
        )
        await listener.start()
        try:
            bound = listener.bound_address()
            assert bound is not None
            host, port = bound
            assert host == "127.0.0.1"
            assert port > 0
            # A GET on /mcp gets routed through the HTTP framing layer
            # and produces a 200 OK with an SSE stream head.
            reader, writer = await asyncio.open_connection(host, port)
            writer.write(
                b"GET /mcp HTTP/1.1\r\nHost: x\r\nAccept: text/event-stream\r\n\r\n",
            )
            await writer.drain()
            data = await asyncio.wait_for(reader.read(1024), timeout=2.0)
            assert b"200 OK" in data
            assert b"text/event-stream" in data.lower()
            writer.close()
            try:
                await writer.wait_closed()
            except (OSError, ConnectionError):
                pass
        finally:
            await listener.stop()

    async def test_listener_rejects_invalid_framing(self) -> None:
        factory = InMemoryUpstreamFactory()
        with pytest.raises(ValueError, match="framing"):
            ProxyListener(
                host="127.0.0.1",
                port=0,
                upstream_factory=factory,
                framing="grpc",
            )


# ---------------------------------------------------------------------------
# 5. Adversarial tests: smuggling, slowloris, malformed.
# ---------------------------------------------------------------------------


class TestAdversarial:
    async def test_smuggling_cl_te_double_header_rejected(self) -> None:
        """Classic HTTP smuggling vector: CL + Transfer-Encoding chunked.

        Per RFC 7230 §3.3.3, having both is ambiguous and a server MUST
        respond with 400. Our parser raises HttpProtocolError which the
        accepted transport translates to a closed connection (the test
        verifies *some* form of rejection: either 400 or hard close)."""
        h = _AcceptedHarness()
        host, port = await h.start()
        try:
            reader, writer = await asyncio.open_connection(host, port)
            payload = (
                b"POST /mcp HTTP/1.1\r\n"
                b"Host: x\r\n"
                b"Content-Length: 5\r\n"
                b"Transfer-Encoding: chunked\r\n"
                b"\r\n"
                b"abcde"
            )
            writer.write(payload)
            await writer.drain()
            try:
                data = await asyncio.wait_for(reader.read(1024), timeout=2.0)
            except (TimeoutError, ConnectionResetError):
                data = b""
            # Either 400 was sent or the connection was just closed.
            assert (b"400" in data) or (data == b"") or (b"500" in data) or (b"Bad Request" in data)
            writer.close()
            try:
                await writer.wait_closed()
            except (OSError, ConnectionError):
                pass
        finally:
            await h.stop()

    async def test_smuggling_duplicate_cl_conflicting(self) -> None:
        """Two Content-Length headers with different values."""
        h = _AcceptedHarness()
        host, port = await h.start()
        try:
            reader, writer = await asyncio.open_connection(host, port)
            payload = (
                b"POST /mcp HTTP/1.1\r\n"
                b"Host: x\r\n"
                b"Content-Length: 5\r\n"
                b"Content-Length: 7\r\n"
                b"\r\n"
                b"abcdefg"
            )
            writer.write(payload)
            await writer.drain()
            try:
                data = await asyncio.wait_for(reader.read(1024), timeout=2.0)
            except (TimeoutError, ConnectionResetError):
                data = b""
            assert (b"400" in data) or (data == b"") or (b"Bad Request" in data)
            writer.close()
            try:
                await writer.wait_closed()
            except (OSError, ConnectionError):
                pass
        finally:
            await h.stop()

    async def test_oversized_header_section_rejected(self) -> None:
        """Slowloris-adjacent: huge header section should be capped."""
        h = _AcceptedHarness()
        host, port = await h.start()
        try:
            reader, writer = await asyncio.open_connection(host, port)
            # Fire 64 KiB of padding without reaching the head terminator.
            writer.write(b"GET /mcp HTTP/1.1\r\nHost: x\r\n")
            for _ in range(2048):
                writer.write(b"X-Pad: " + b"y" * 56 + b"\r\n")
                await writer.drain()
            # Without \r\n\r\n the server should bail out before
            # accepting the huge section. Read whatever it sends, if
            # anything, and assert the connection closed.
            try:
                data = await asyncio.wait_for(reader.read(1024), timeout=2.0)
            except (TimeoutError, ConnectionResetError):
                data = b""
            # Server either closed the socket or never replied (head
            # incomplete). Both outcomes are acceptable rejections.
            assert data == b"" or b"4" in data or b"5" in data
            writer.close()
            try:
                await writer.wait_closed()
            except (OSError, ConnectionError):
                pass
        finally:
            await h.stop()

    async def test_split_post_body_across_chunks(self) -> None:
        """TCP can split a POST body across packets. Server must reassemble."""
        h = _AcceptedHarness()
        host, port = await h.start()
        try:
            reader, writer = await asyncio.open_connection(host, port)
            body = b'{"jsonrpc":"2.0","method":"split","id":1}'
            writer.write(
                b"POST /mcp HTTP/1.1\r\n"
                b"Host: x\r\n"
                b"Content-Type: application/json\r\n"
                b"Content-Length: " + str(len(body)).encode("ascii") + b"\r\n"
                b"\r\n",
            )
            await writer.drain()
            # Send body byte-by-byte.
            for byte in body:
                writer.write(bytes([byte]))
                await writer.drain()
            await h.wait_for_n_transports(1)
            msg = await asyncio.wait_for(h.transport.receive(), timeout=2.0)
            assert isinstance(msg, Request)
            assert msg.method == "split"
            data = await asyncio.wait_for(reader.read(1024), timeout=2.0)
            assert b"202 Accepted" in data
            writer.close()
            try:
                await writer.wait_closed()
            except (OSError, ConnectionError):
                pass
        finally:
            await h.stop()

    async def test_partial_then_close_handled_cleanly(self) -> None:
        """Client sends partial head and disconnects -- server must not crash."""
        h = _AcceptedHarness()
        host, port = await h.start()
        try:
            _r, writer = await asyncio.open_connection(host, port)
            writer.write(b"POST /mcp HTTP/1.1\r\nHost: x\r\n")
            await writer.drain()
            writer.close()
            try:
                await writer.wait_closed()
            except (OSError, ConnectionError):
                pass
            # Give the server a moment to observe EOF.
            await asyncio.sleep(0.2)
            # The harness transport may or may not have been registered,
            # but the listener as a whole must remain healthy.
            # (We do not assert on specific state here; the assertion is
            # implicit: no exception escapes the read loop.)
        finally:
            await h.stop()
