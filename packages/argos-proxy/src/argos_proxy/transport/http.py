"""HTTP / SSE upstream transports for MCP.

Two flavours, both shipped here so they share the HTTP/1.1 plumbing:

- :class:`HttpStreamableTransport` -- the modern MCP transport (spec
  2025-03-26 ``streamable-http``). Single endpoint accepting POST for
  client-to-server messages and GET ``Accept: text/event-stream`` for
  server-to-client. Connection is reused (HTTP keep-alive).

- :class:`SseTransport` -- the legacy MCP transport. Two endpoints:
  ``GET /sse`` (read-only stream) and ``POST /messages`` (write-only).
  The session is identified by a query parameter received in the
  initial SSE event (``endpoint`` event) or via a configured prefix.

Both are pure ``asyncio`` plus the manual HTTP/1.1 parser in
:mod:`argos_proxy.jsonrpc.http_framing`. No third-party HTTP client
dependency.
"""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING, Final
from urllib.parse import urlsplit

from argos_proxy.jsonrpc import Batch, Message, parse_payload
from argos_proxy.jsonrpc.framing import MAX_MESSAGE_BYTES
from argos_proxy.jsonrpc.http_framing import (
    Headers,
    HttpProtocolError,
    encode_request,
    parse_response_head,
)
from argos_proxy.jsonrpc.sse_framing import SseEvent, SseEventParser
from argos_proxy.transport._base import (
    ClosedTransportError,
    Transport,
    TransportError,
)

if TYPE_CHECKING:
    from logging import Logger

_log: Logger = logging.getLogger("argos.proxy.http")

#: Default per-request timeout for the synchronous POST half of HTTP.
_POST_TIMEOUT_SECONDS: Final[float] = 30.0

#: Default chunk size when reading from the upstream socket.
_READ_CHUNK: Final[int] = 4096


# ---------------------------------------------------------------------------
# Helpers shared by HttpStreamableTransport and SseTransport.
# ---------------------------------------------------------------------------


def _split_url(url: str) -> tuple[str, int, str, bool]:
    """Return ``(host, port, path, is_https)`` from a URL.

    HTTPS support is *parsing-only*: the transport does NOT initiate
    TLS. A future iteration could wrap the asyncio reader/writer with
    ``ssl.create_default_context()`` but the proxy is local-first and
    the threat model assumes the operator controls the network path.
    """
    parts = urlsplit(url)
    if parts.scheme not in {"http", "https"}:
        msg = f"unsupported URL scheme {parts.scheme!r}; expected http or https"
        raise ValueError(msg)
    if not parts.hostname:
        msg = f"URL missing host: {url!r}"
        raise ValueError(msg)
    is_https = parts.scheme == "https"
    port = parts.port or (443 if is_https else 80)
    path = parts.path or "/"
    if parts.query:
        path = f"{path}?{parts.query}"
    return parts.hostname, port, path, is_https


async def _read_response_head(reader: asyncio.StreamReader) -> bytes:
    """Read up to the ``\\r\\n\\r\\n`` separator. Returns the head bytes
    (without the separator). Raises :class:`HttpProtocolError` if the
    head exceeds the cap before the separator appears."""
    from argos_proxy.jsonrpc.http_framing import MAX_HTTP_HEADER_BYTES  # noqa: PLC0415

    buf = bytearray()
    while True:
        chunk = await reader.read(_READ_CHUNK)
        if not chunk:
            msg = "connection closed before HTTP head completed"
            raise HttpProtocolError(msg)
        buf.extend(chunk)
        idx = buf.find(b"\r\n\r\n")
        if idx >= 0:
            head = bytes(buf[:idx])
            # Hand the bytes after the separator back via a private
            # attribute on the reader: callers cannot easily put them
            # back into the StreamReader. We return the leftover via
            # the second return value. Caller MUST consume it before
            # any subsequent ``reader.read``.
            leftover = bytes(buf[idx + 4 :])
            # Stash leftover on the reader so the caller fetches it.
            reader_leftover_setattr(reader, leftover)
            return head
        if len(buf) > MAX_HTTP_HEADER_BYTES:
            msg = f"HTTP head exceeded {MAX_HTTP_HEADER_BYTES} bytes"
            raise HttpProtocolError(msg)


def reader_leftover_setattr(reader: asyncio.StreamReader, leftover: bytes) -> None:
    """Stash leftover bytes on the reader for the body parser to pick
    up. Avoids the boilerplate of returning ``(head, leftover)`` on
    every helper."""
    reader._argos_leftover = leftover  # type: ignore[attr-defined]  # noqa: SLF001


def reader_leftover_getattr(reader: asyncio.StreamReader) -> bytes:
    """Fetch and clear the leftover stashed by :func:`reader_leftover_setattr`."""
    leftover: bytes = getattr(reader, "_argos_leftover", b"")
    if leftover:
        reader._argos_leftover = b""  # type: ignore[attr-defined]  # noqa: SLF001
    return leftover


async def _read_body_fixed(
    reader: asyncio.StreamReader,
    length: int,
) -> bytes:
    """Read exactly ``length`` bytes, honouring any leftover from the
    head parser."""
    if length < 0 or length > MAX_MESSAGE_BYTES:
        msg = f"declared body length {length} outside [0, {MAX_MESSAGE_BYTES}]"
        raise HttpProtocolError(msg)
    leftover = reader_leftover_getattr(reader)
    if len(leftover) >= length:
        rest = leftover[length:]
        if rest:
            reader_leftover_setattr(reader, rest)
        return leftover[:length]
    out = bytearray(leftover)
    remaining = length - len(leftover)
    while remaining > 0:
        chunk = await reader.read(min(_READ_CHUNK, remaining))
        if not chunk:
            msg = "connection closed before fixed body completed"
            raise HttpProtocolError(msg)
        out.extend(chunk)
        remaining -= len(chunk)
    return bytes(out)


# ---------------------------------------------------------------------------
# Streamable HTTP transport (modern MCP, single endpoint).
# ---------------------------------------------------------------------------


class HttpStreamableTransport(Transport):
    """Client-side ``streamable-http`` transport.

    The transport keeps two logical streams open against the same
    endpoint URL:

    - **GET stream** (server -> client): an open HTTP response with
      ``Content-Type: text/event-stream`` over which the upstream
      pushes events.
    - **POST per message** (client -> server): each outgoing message
      becomes an independent POST. The server replies with status 202
      (Accepted) without body; the response payload arrives over the
      GET stream as an SSE event.

    A single TCP connection per direction; ``Connection: keep-alive``
    where the upstream supports it (HTTP/1.1 default).
    """

    __slots__ = (
        "_buffered_events",
        "_closed",
        "_get_reader",
        "_get_writer",
        "_host",
        "_path",
        "_port",
        "_post_lock",
        "_post_reader",
        "_post_writer",
        "_sse_parser",
        "_url",
    )

    def __init__(self, url: str) -> None:
        self._url = url
        self._host, self._port, self._path, _ = _split_url(url)
        self._closed = False
        self._get_reader: asyncio.StreamReader | None = None
        self._get_writer: asyncio.StreamWriter | None = None
        self._post_reader: asyncio.StreamReader | None = None
        self._post_writer: asyncio.StreamWriter | None = None
        self._sse_parser = SseEventParser()
        self._buffered_events: list[SseEvent] = []
        self._post_lock = asyncio.Lock()

    # --- lifecycle --------------------------------------------------------
    async def connect(self) -> None:
        """Open both halves of the streamable HTTP transport.

        The GET half initiates the SSE stream and stays open. The POST
        half keeps a separate keep-alive socket so concurrent POSTs do
        not interleave with SSE chunks on the same connection.
        """
        if self._get_reader is not None:
            return
        try:
            self._get_reader, self._get_writer = await asyncio.open_connection(
                self._host,
                self._port,
            )
            self._post_reader, self._post_writer = await asyncio.open_connection(
                self._host,
                self._port,
            )
        except OSError as exc:
            msg = f"failed to connect to {self._host}:{self._port}: {exc}"
            raise TransportError(msg) from exc
        # Issue the GET request that opens the SSE channel.
        get_headers = Headers()
        get_headers.add("Host", _host_header(self._host, self._port))
        get_headers.add("Accept", "text/event-stream")
        get_headers.add("Cache-Control", "no-cache")
        get_headers.add("Connection", "keep-alive")
        request = encode_request("GET", self._path, headers=get_headers)
        self._get_writer.write(request)
        await self._get_writer.drain()
        # Read response head + verify content type.
        head_bytes = await _read_response_head(self._get_reader)
        head = parse_response_head(head_bytes)
        if head.status != 200:
            msg = (
                f"upstream {self._url} returned {head.status} {head.reason} "
                f"on SSE GET; expected 200"
            )
            raise TransportError(msg)
        ct = head.headers.get("Content-Type") or ""
        if "text/event-stream" not in ct.lower():
            msg = (
                f"upstream {self._url} replied with Content-Type {ct!r} "
                f"on SSE GET; expected text/event-stream"
            )
            raise TransportError(msg)
        # Any leftover bytes after the head start the SSE stream.
        leftover = reader_leftover_getattr(self._get_reader)
        if leftover:
            self._buffered_events.extend(self._sse_parser.feed(leftover))

    # --- send (POST) ------------------------------------------------------
    async def send(self, message: Message | Batch) -> None:
        if self._closed:
            msg = "transport is closed"
            raise ClosedTransportError(msg)
        if self._post_writer is None or self._post_reader is None:
            await self.connect()
        if self._post_writer is None or self._post_reader is None:  # pragma: no cover
            msg = "POST half not connected"
            raise TransportError(msg)
        body = _encode_jsonrpc(message)
        post_headers = Headers()
        post_headers.add("Host", _host_header(self._host, self._port))
        post_headers.add("Content-Type", "application/json")
        post_headers.add("Accept", "application/json, text/event-stream")
        post_headers.add("Connection", "keep-alive")
        request = encode_request(
            "POST",
            self._path,
            headers=post_headers,
            body=body,
        )
        async with self._post_lock:
            try:
                self._post_writer.write(request)
                await asyncio.wait_for(
                    self._post_writer.drain(),
                    timeout=_POST_TIMEOUT_SECONDS,
                )
            except (ConnectionResetError, BrokenPipeError) as exc:
                self._closed = True
                msg = f"upstream {self._url} POST closed: {exc}"
                raise ClosedTransportError(msg) from exc
            # Read 202 / 200 response head and discard any body. We do
            # not block on the response because the upstream may take
            # time to compute; the actual JSON-RPC response will arrive
            # via the GET SSE stream.
            head_bytes = await asyncio.wait_for(
                _read_response_head(self._post_reader),
                timeout=_POST_TIMEOUT_SECONDS,
            )
            head = parse_response_head(head_bytes)
            if head.status >= 400:
                # Surface the error so detectors can act on it.
                msg = f"upstream {self._url} POST returned {head.status} {head.reason}"
                raise TransportError(msg)
            # Drain any body the response carried (typically empty).
            cl = head.headers.get("Content-Length")
            if cl is not None:
                body_len = int(cl)
                if body_len > 0:
                    await _read_body_fixed(self._post_reader, body_len)

    # --- receive (SSE GET stream) -----------------------------------------
    async def receive(self) -> Message | Batch:
        if self._closed:
            msg = "transport is closed"
            raise ClosedTransportError(msg)
        if self._get_reader is None:
            await self.connect()
        if self._get_reader is None:  # pragma: no cover
            msg = "GET half not connected"
            raise TransportError(msg)
        while True:
            if self._buffered_events:
                event = self._buffered_events.pop(0)
                if event.event in {"message", ""}:
                    return parse_payload(event.data)
                # Other event names ("endpoint", "ping", "heartbeat") are
                # transport-level metadata; ignore and continue reading.
                _log.debug("ignoring SSE event %r", event.event)
                continue
            chunk = await self._get_reader.read(_READ_CHUNK)
            if not chunk:
                self._closed = True
                msg = f"upstream {self._url} closed the SSE stream"
                raise ClosedTransportError(msg)
            self._buffered_events.extend(self._sse_parser.feed(chunk))

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        for w in (self._get_writer, self._post_writer):
            if w is None:
                continue
            try:
                w.close()
                try:
                    await w.wait_closed()
                except (OSError, ConnectionError, asyncio.IncompleteReadError):
                    pass
            except Exception:  # noqa: BLE001
                pass

    @property
    def is_closed(self) -> bool:
        return self._closed


# ---------------------------------------------------------------------------
# Legacy SSE transport (two endpoints).
# ---------------------------------------------------------------------------


class SseTransport(Transport):
    """Client-side ``sse`` transport (MCP legacy).

    Two endpoints:

    - ``sse_url``: ``GET`` for the read-only event stream. The first
      event of type ``endpoint`` carries the URL where the client must
      POST messages (see MCP spec 2024-11-05). When the upstream does
      NOT emit such an event, the caller may pass ``post_url``
      explicitly.
    - ``post_url``: ``POST`` endpoint for client-to-server messages.

    Implementation notes:

    - The ``endpoint`` event is sometimes published as a relative URL.
      We resolve it against ``sse_url``'s scheme + authority.
    - Reconnection on transient network errors is OUT of scope; the
      proxy treats a closed SSE stream as a final disconnect and the
      :class:`ProxyServer` will tear down the session.
    """

    __slots__ = (
        "_buffered_events",
        "_closed",
        "_get_reader",
        "_get_writer",
        "_post_lock",
        "_post_url",
        "_sse_parser",
        "_sse_url",
    )

    def __init__(self, sse_url: str, *, post_url: str | None = None) -> None:
        self._sse_url = sse_url
        self._post_url = post_url
        self._closed = False
        self._get_reader: asyncio.StreamReader | None = None
        self._get_writer: asyncio.StreamWriter | None = None
        self._sse_parser = SseEventParser()
        self._buffered_events: list[SseEvent] = []
        self._post_lock = asyncio.Lock()

    # --- lifecycle --------------------------------------------------------
    async def connect(self) -> None:
        if self._get_reader is not None:
            return
        host, port, path, _ = _split_url(self._sse_url)
        try:
            self._get_reader, self._get_writer = await asyncio.open_connection(
                host,
                port,
            )
        except OSError as exc:
            msg = f"failed to connect to {host}:{port}: {exc}"
            raise TransportError(msg) from exc
        get_headers = Headers()
        get_headers.add("Host", _host_header(host, port))
        get_headers.add("Accept", "text/event-stream")
        get_headers.add("Cache-Control", "no-cache")
        get_headers.add("Connection", "keep-alive")
        request = encode_request("GET", path, headers=get_headers)
        self._get_writer.write(request)
        await self._get_writer.drain()
        head_bytes = await _read_response_head(self._get_reader)
        head = parse_response_head(head_bytes)
        if head.status != 200:
            msg = f"upstream {self._sse_url} returned {head.status}; expected 200"
            raise TransportError(msg)
        ct = head.headers.get("Content-Type") or ""
        if "text/event-stream" not in ct.lower():
            msg = f"unexpected Content-Type on SSE GET: {ct!r}"
            raise TransportError(msg)
        leftover = reader_leftover_getattr(self._get_reader)
        if leftover:
            self._buffered_events.extend(self._sse_parser.feed(leftover))
        # Auto-discover post_url if not supplied: read events until we
        # see one of type ``endpoint`` or until first ``message``.
        if self._post_url is None:
            await self._discover_post_url()

    async def _discover_post_url(self) -> None:
        """Wait for the upstream to emit an ``endpoint`` event."""
        if self._get_reader is None:
            return
        deadline = asyncio.get_event_loop().time() + 5.0
        while True:
            for event in list(self._buffered_events):
                if event.event == "endpoint":
                    self._buffered_events.remove(event)
                    candidate = event.data.strip()
                    if candidate.startswith(("http://", "https://")):
                        self._post_url = candidate
                    else:
                        # Relative path: resolve against sse URL.
                        parts = urlsplit(self._sse_url)
                        self._post_url = f"{parts.scheme}://{parts.netloc}{candidate}"
                    return
            remaining = deadline - asyncio.get_event_loop().time()
            if remaining <= 0:
                msg = (
                    "upstream did not emit an 'endpoint' event within 5 s; pass post_url explicitly"
                )
                raise TransportError(msg)
            chunk = await asyncio.wait_for(
                self._get_reader.read(_READ_CHUNK),
                timeout=remaining,
            )
            if not chunk:
                msg = "upstream closed before emitting 'endpoint' event"
                raise TransportError(msg)
            self._buffered_events.extend(self._sse_parser.feed(chunk))

    # --- send (POST) ------------------------------------------------------
    async def send(self, message: Message | Batch) -> None:
        if self._closed:
            msg = "transport is closed"
            raise ClosedTransportError(msg)
        if self._post_url is None:
            await self.connect()
        if self._post_url is None:  # pragma: no cover
            msg = "post_url not discovered yet"
            raise TransportError(msg)
        host, port, path, _ = _split_url(self._post_url)
        body = _encode_jsonrpc(message)
        post_headers = Headers()
        post_headers.add("Host", _host_header(host, port))
        post_headers.add("Content-Type", "application/json")
        post_headers.add("Connection", "close")
        request = encode_request(
            "POST",
            path,
            headers=post_headers,
            body=body,
        )
        async with self._post_lock:
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port),
                    timeout=_POST_TIMEOUT_SECONDS,
                )
            except OSError as exc:
                msg = f"failed to POST to {host}:{port}: {exc}"
                raise TransportError(msg) from exc
            try:
                writer.write(request)
                await writer.drain()
                head_bytes = await asyncio.wait_for(
                    _read_response_head(reader),
                    timeout=_POST_TIMEOUT_SECONDS,
                )
                head = parse_response_head(head_bytes)
                if head.status >= 400:
                    msg = f"POST {self._post_url} returned {head.status} {head.reason}"
                    raise TransportError(msg)
            finally:
                writer.close()
                try:
                    await writer.wait_closed()
                except (OSError, ConnectionError, asyncio.IncompleteReadError):
                    pass

    # --- receive (SSE GET stream) -----------------------------------------
    async def receive(self) -> Message | Batch:
        if self._closed:
            msg = "transport is closed"
            raise ClosedTransportError(msg)
        if self._get_reader is None:
            await self.connect()
        if self._get_reader is None:  # pragma: no cover
            msg = "GET half not connected"
            raise TransportError(msg)
        while True:
            if self._buffered_events:
                event = self._buffered_events.pop(0)
                if event.event in {"message", ""}:
                    return parse_payload(event.data)
                continue
            chunk = await self._get_reader.read(_READ_CHUNK)
            if not chunk:
                self._closed = True
                msg = f"upstream {self._sse_url} closed the SSE stream"
                raise ClosedTransportError(msg)
            self._buffered_events.extend(self._sse_parser.feed(chunk))

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        if self._get_writer is not None:
            try:
                self._get_writer.close()
                try:
                    await self._get_writer.wait_closed()
                except (OSError, ConnectionError, asyncio.IncompleteReadError):
                    pass
            except Exception:  # noqa: BLE001
                pass

    @property
    def is_closed(self) -> bool:
        return self._closed


# ---------------------------------------------------------------------------
# Helpers.
# ---------------------------------------------------------------------------


def _host_header(host: str, port: int) -> str:
    if port in {80, 443}:
        return host
    if ":" in host:
        # IPv6 literal -- bracket it.
        return f"[{host}]:{port}"
    return f"{host}:{port}"


def _encode_jsonrpc(message: Message | Batch) -> bytes:
    if isinstance(message, Batch):
        return message.model_dump_json().encode("utf-8")
    return message.model_dump_json().encode("utf-8")


__all__ = [
    "HttpStreamableTransport",
    "SseTransport",
]
