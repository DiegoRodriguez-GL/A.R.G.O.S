"""Server-side HTTP transport for the ARGOS proxy listener.

This module provides the building blocks needed to accept HTTP clients
on a TCP socket: a minimal HTTP/1.1 request reader and a transport
adapter that exposes the bidirectional message contract of
:class:`Transport` over the streamable-http MCP convention.

The listener (when configured with ``framing="http"`` or
``framing="sse"``) constructs one of these per accepted connection
instead of :class:`TcpAcceptedTransport`. The downstream client speaks
the chosen HTTP variant; everything else (interceptors, forensics, OTel
spans) is transport-agnostic and continues to work as before.
"""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from collections import deque
from typing import TYPE_CHECKING, Final

from argos_proxy.jsonrpc import Batch, Message, parse_payload
from argos_proxy.jsonrpc.http_framing import (
    Headers,
    HttpProtocolError,
    HttpRequest,
    encode_response,
    parse_request_head,
)
from argos_proxy.jsonrpc.sse_framing import encode_sse_event
from argos_proxy.transport._base import (
    ClosedTransportError,
    Transport,
)

if TYPE_CHECKING:
    from logging import Logger


_log: Logger = logging.getLogger("argos.proxy.http_server")

#: Maximum size of an HTTP head section the listener will buffer before
#: declaring the request malformed.
_MAX_HEAD_BYTES: Final[int] = 16 * 1024


# ---------------------------------------------------------------------------
# Streamable HTTP accepted transport (single endpoint).
# ---------------------------------------------------------------------------


class HttpStreamableAcceptedTransport(Transport):
    """Accepted-side counterpart of :class:`HttpStreamableTransport`.

    The proxy reads incoming POST bodies as ``send`` calls and produces
    outgoing messages by writing SSE events on the open GET response.
    Each accepted connection is a *single* logical session: the same
    socket carries both a long-lived GET (server-stream) and a sequence
    of POSTs.

    Implementation notes:

    - We expect the client to issue a ``GET`` with
      ``Accept: text/event-stream`` first; only after that handshake
      we begin writing SSE events.
    - POSTs from the client arrive on the *same* TCP connection in
      pipelined fashion. Each is parsed, its body dispatched through
      the normal :class:`Transport` interface, and a 202 Accepted
      reply is written back.
    - Closing the transport closes both halves.

    This server-side flavour is conservative: it does not support
    multiple parallel POSTs per session; the proxy enforces sequential
    delivery via the same per-session lock used by the stdio variant.
    """

    __slots__ = (
        "_closed",
        "_get_open",
        "_inbox",
        "_inbox_event",
        "_peer",
        "_reader",
        "_reader_task",
        "_writer",
    )

    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        *,
        peer: str | None = None,
    ) -> None:
        self._reader = reader
        self._writer = writer
        self._peer = peer or _peer_string(writer)
        self._closed = False
        self._get_open = False
        self._inbox: deque[Message | Batch] = deque()
        self._inbox_event = asyncio.Event()
        # Start the request reader eagerly so the server responds to
        # GETs / unsupported methods / malformed POSTs even when no
        # ``receive`` call is in flight. Lazy startup would block
        # 4xx/5xx replies behind a non-existent caller.
        self._reader_task: asyncio.Task[None] = asyncio.create_task(
            self._read_loop(),
            name=f"argos.proxy.http_server.read.{self._peer}",
        )

    @property
    def peer(self) -> str:
        return self._peer

    async def receive(self) -> Message | Batch:
        if self._closed:
            msg = f"transport to {self._peer} is closed"
            raise ClosedTransportError(msg)
        while not self._inbox:
            # ``_closed`` is mutated by the background read_loop. mypy's
            # flow analysis narrows it after the check above so we hide
            # the re-read behind a method call to defeat narrowing.
            self._raise_if_closed("peer {peer} closed")
            await self._inbox_event.wait()
            self._inbox_event.clear()
        return self._inbox.popleft()

    def _raise_if_closed(self, msg_tpl: str) -> None:
        if self._closed:
            raise ClosedTransportError(msg_tpl.format(peer=self._peer))

    async def send(self, message: Message | Batch) -> None:
        if self._closed:
            msg = f"transport to {self._peer} is closed"
            raise ClosedTransportError(msg)
        if not self._get_open:
            # Client has not yet issued the GET; ``_get_open`` is set
            # from the background read_loop once the GET arrives. mypy
            # narrows ``_get_open`` to False inside this branch and
            # marks subsequent reads unreachable, but they are not.
            await self._await_get_open()
        body = message.model_dump_json()
        event = encode_sse_event(body, event="message")
        try:
            self._writer.write(event)
            await self._writer.drain()
        except (ConnectionResetError, BrokenPipeError) as exc:
            self._closed = True
            self._inbox_event.set()
            msg = f"connection to {self._peer} closed: {exc}"
            raise ClosedTransportError(msg) from exc

    async def _await_get_open(self) -> None:
        """Block briefly until the client opens its GET stream.

        The background read_loop flips ``_get_open`` from False to True
        when the GET arrives. Extracted into a separate method so mypy
        does not over-narrow ``_get_open`` based on the caller's branch.
        """
        for _ in range(50):
            if self._get_open:
                return
            await asyncio.sleep(0.05)
        if not self._get_open:  # pragma: no cover - defensive
            msg = f"client {self._peer} has not opened GET stream"
            raise ClosedTransportError(msg)

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._inbox_event.set()
        self._reader_task.cancel()
        try:
            await self._reader_task
        except (asyncio.CancelledError, Exception):  # noqa: BLE001
            pass
        try:
            self._writer.close()
            try:
                await self._writer.wait_closed()
            except (OSError, ConnectionError, asyncio.IncompleteReadError):
                pass
        except Exception:  # noqa: BLE001
            pass

    @property
    def is_closed(self) -> bool:
        return self._closed

    # --- read loop --------------------------------------------------------
    async def _read_loop(self) -> None:
        try:
            while not self._closed:
                request = await self._read_one_request()
                if request is None:
                    break
                await self._handle_request(request)
        except ClosedTransportError:
            pass
        except (HttpProtocolError, OSError):
            self._closed = True
            self._inbox_event.set()
        except Exception:  # noqa: BLE001
            _log.exception("HTTP read loop crashed for %s", self._peer)
            self._closed = True
            self._inbox_event.set()
        else:
            self._closed = True
            self._inbox_event.set()

    async def _read_one_request(self) -> HttpRequest | None:
        head_bytes = await _read_head(self._reader)
        if head_bytes is None:
            return None
        # Locate the head/body boundary in what we read.
        head_str_idx = head_bytes.find(b"\r\n\r\n")
        if head_str_idx < 0:
            head_str_idx = len(head_bytes)
        try:
            request_no_body = parse_request_head(head_bytes[:head_str_idx])
        except HttpProtocolError as exc:
            await self._send_error(400, "Bad Request", str(exc))
            self._closed = True
            self._inbox_event.set()
            return None
        body_len = 0
        cl = request_no_body.headers.get("Content-Length")
        if cl is not None:
            body_len = int(cl)
        # Any leftover bytes after the head separator already buffered
        # belong to the body; read whatever else is needed off the wire.
        leftover = head_bytes[head_str_idx + 4 :]
        if len(leftover) >= body_len:
            body = leftover[:body_len]
        else:
            need = body_len - len(leftover)
            try:
                rest = await self._reader.readexactly(need)
            except asyncio.IncompleteReadError as exc:
                msg = (
                    f"connection closed mid-body: needed {need} more bytes, got {len(exc.partial)}"
                )
                raise HttpProtocolError(msg) from exc
            body = leftover + rest
        return HttpRequest(
            method=request_no_body.method,
            path=request_no_body.path,
            version=request_no_body.version,
            headers=request_no_body.headers,
            body=body,
        )

    async def _handle_request(self, request: HttpRequest) -> None:
        if request.method == "GET":
            accept = request.headers.get("Accept") or ""
            if "text/event-stream" not in accept.lower():
                await self._send_error(406, "Not Acceptable", "expect text/event-stream")
                return
            await self._open_sse_stream()
            return
        if request.method == "POST":
            try:
                msg = parse_payload(request.body or b"{}")
            except Exception as exc:  # noqa: BLE001 - protocol error
                await self._send_error(400, "Bad Request", f"invalid JSON-RPC: {exc}")
                return
            self._inbox.append(msg)
            self._inbox_event.set()
            await self._send_accepted()
            return
        await self._send_error(405, "Method Not Allowed", "use GET or POST")

    async def _open_sse_stream(self) -> None:
        headers = Headers()
        headers.add("Content-Type", "text/event-stream")
        headers.add("Cache-Control", "no-cache")
        headers.add("Connection", "keep-alive")
        # We do NOT set Content-Length so the connection stays open
        # streaming events. HTTP/1.1 allows this when neither
        # Content-Length nor Transfer-Encoding is present and the
        # response is to be terminated by closing the connection.
        # We emit a no-op comment line every send so intermediate
        # proxies do not eagerly close idle connections.
        head = encode_response(200, "OK", headers=headers)
        try:
            self._writer.write(head)
            await self._writer.drain()
        except (ConnectionResetError, BrokenPipeError):
            self._closed = True
            self._inbox_event.set()
            return
        self._get_open = True

    async def _send_accepted(self) -> None:
        headers = Headers()
        headers.add("Content-Length", "0")
        headers.add("Connection", "keep-alive")
        head = encode_response(202, "Accepted", headers=headers)
        try:
            self._writer.write(head)
            await self._writer.drain()
        except (ConnectionResetError, BrokenPipeError):
            self._closed = True
            self._inbox_event.set()

    async def _send_error(self, status: int, reason: str, body_text: str) -> None:
        body = json.dumps({"error": body_text}).encode("utf-8")
        headers = Headers()
        headers.add("Content-Type", "application/json")
        headers.add("Connection", "close")
        head = encode_response(status, reason, headers=headers, body=body)
        try:
            self._writer.write(head)
            await self._writer.drain()
        except (ConnectionResetError, BrokenPipeError):
            pass


# ---------------------------------------------------------------------------
# Helpers.
# ---------------------------------------------------------------------------


async def _read_head(reader: asyncio.StreamReader) -> bytes | None:
    """Read up to the next ``\\r\\n\\r\\n`` separator. Returns the bytes
    INCLUDING the separator and any leftover after it. ``None`` on EOF
    before the separator appears (clean disconnect)."""
    buf = bytearray()
    while True:
        try:
            chunk = await reader.read(4096)
        except (ConnectionResetError, BrokenPipeError):
            return None
        if not chunk:
            return None
        buf.extend(chunk)
        idx = buf.find(b"\r\n\r\n")
        if idx >= 0:
            return bytes(buf)
        if len(buf) > _MAX_HEAD_BYTES:
            msg = f"HTTP head exceeded {_MAX_HEAD_BYTES} bytes"
            raise HttpProtocolError(msg)


def _peer_string(writer: asyncio.StreamWriter) -> str:
    try:
        info = writer.get_extra_info("peername")
        if info:
            host, port, *_ = info
            return f"{host}:{port}"
    except Exception:  # noqa: BLE001 - best-effort
        pass
    return "unknown"


# Used by the legacy SSE listener variant to mint session ids.
def new_session_id() -> str:
    return "argos-http-" + uuid.uuid4().hex[:12]


__all__ = [
    "HttpStreamableAcceptedTransport",
    "new_session_id",
]
