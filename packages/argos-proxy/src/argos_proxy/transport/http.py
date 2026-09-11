"""HTTP / SSE upstream transports for MCP.

Two flavours share the HTTP/1.1 plumbing in this module:

- :class:`HttpStreamableTransport` implements the client side of the
  *streamable HTTP* transport (MCP revisions 2025-03-26 and 2025-06-18).
  Every client message is its own ``POST``. A POST that carries only
  notifications or responses is acknowledged with ``202 Accepted``; a
  POST that carries a request is answered either with one
  ``application/json`` body or with a ``text/event-stream`` that
  delivers the response (possibly preceded by server requests and
  notifications) and then ends. The ``Mcp-Session-Id`` header returned
  on initialisation is echoed on every later request, and so is
  ``MCP-Protocol-Version`` once negotiated. A ``GET`` opens an optional
  server-to-client stream; ``405`` means the server does not offer one.

- :class:`SseTransport` implements the legacy *HTTP+SSE* transport
  (revision 2024-11-05): a long-lived ``GET`` event stream whose first
  ``endpoint`` event names the URL that receives the client's ``POST``
  messages.

``https://`` URLs are served over TLS with the platform trust store;
certificate and host name verification stay on unless a lab setup
turns them off explicitly. Response bodies may use ``Content-Length``,
``Transfer-Encoding: chunked`` or end with the connection, which is
how real deployments behind CDNs and ASGI servers answer.

Everything is plain :mod:`asyncio` plus the parser in
:mod:`argos_proxy.jsonrpc.http_framing`; no third-party HTTP client.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import re
import ssl
from collections.abc import AsyncIterator, Mapping
from typing import TYPE_CHECKING, Final
from urllib.parse import urlsplit

from argos_proxy.jsonrpc import Batch, ErrorObject, Message, Request, Response, parse_payload
from argos_proxy.jsonrpc.errors import JsonRpcProtocolError
from argos_proxy.jsonrpc.framing import MAX_MESSAGE_BYTES
from argos_proxy.jsonrpc.http_framing import (
    ChunkedDecoder,
    Headers,
    HttpProtocolError,
    HttpResponseHead,
    encode_request,
    parse_response_head,
)
from argos_proxy.jsonrpc.messages import RequestId
from argos_proxy.jsonrpc.sse_framing import SseEvent, SseEventParser
from argos_proxy.transport._base import (
    ClosedTransportError,
    Transport,
    TransportError,
)

if TYPE_CHECKING:
    from logging import Logger

_log: Logger = logging.getLogger("argos.proxy.http")

#: Timeout for connecting, completing the TLS handshake and writing a request.
_IO_TIMEOUT_SECONDS: Final[float] = 30.0

#: Kept for callers that imported the historical name.
_POST_TIMEOUT_SECONDS: Final[float] = _IO_TIMEOUT_SECONDS

#: How long to wait for the head of the optional server stream (GET).
_SERVER_STREAM_HEAD_TIMEOUT: Final[float] = 10.0

#: Default chunk size when reading from the upstream socket.
_READ_CHUNK: Final[int] = 65536

#: Cap on error and acknowledgement bodies, which are read only for diagnostics.
_SMALL_BODY_CAP: Final[int] = 64 * 1024

#: JSON-RPC error code the proxy uses when it must answer a request on
#: behalf of an upstream that failed at the HTTP level. The range
#: -32000..-32099 is reserved by JSON-RPC 2.0 for implementation-defined
#: server errors.
UPSTREAM_TRANSPORT_ERROR: Final[int] = -32000

_SESSION_HEADER: Final[str] = "Mcp-Session-Id"
_PROTOCOL_HEADER: Final[str] = "MCP-Protocol-Version"
_USER_AGENT: Final[str] = "argos-proxy"
_PROTOCOL_VERSION_RE: Final[re.Pattern[str]] = re.compile(r"[0-9A-Za-z._-]{1,32}")


# ---------------------------------------------------------------------------
# Helpers shared by HttpStreamableTransport and SseTransport.
# ---------------------------------------------------------------------------


def _split_url(url: str) -> tuple[str, int, str, bool]:
    """Return ``(host, port, path, is_https)`` from a URL."""
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


def _tls_context(*, verify: bool) -> ssl.SSLContext:
    """Client TLS context backed by the platform trust store."""
    context = ssl.create_default_context()
    if not verify:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    return context


async def _open_connection(
    host: str,
    port: int,
    tls: ssl.SSLContext | None,
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    try:
        return await asyncio.wait_for(
            asyncio.open_connection(
                host,
                port,
                ssl=tls,
                server_hostname=host if tls is not None else None,
            ),
            timeout=_IO_TIMEOUT_SECONDS,
        )
    except (OSError, TimeoutError) as exc:
        scheme = "https" if tls is not None else "http"
        msg = f"failed to connect to {scheme}://{host}:{port}: {exc}"
        raise TransportError(msg) from exc


async def _close_writer(writer: asyncio.StreamWriter | None) -> None:
    if writer is None:
        return
    with contextlib.suppress(Exception):
        writer.close()
        await asyncio.wait_for(writer.wait_closed(), timeout=2.0)


async def _read_response_head(reader: asyncio.StreamReader) -> bytes:
    """Read up to the ``\\r\\n\\r\\n`` separator. Returns the head bytes
    (without the separator). Raises :class:`HttpProtocolError` if the
    head exceeds the cap before the separator appears."""
    from argos_proxy.jsonrpc.http_framing import MAX_HTTP_HEADER_BYTES  # noqa: PLC0415

    buf = bytearray(reader_leftover_getattr(reader))
    while True:
        idx = buf.find(b"\r\n\r\n")
        if idx >= 0:
            head = bytes(buf[:idx])
            # The bytes after the separator belong to the body. They are
            # stashed on the reader so the body parser picks them up
            # before touching the socket again.
            reader_leftover_setattr(reader, bytes(buf[idx + 4 :]))
            return head
        if len(buf) > MAX_HTTP_HEADER_BYTES:
            msg = f"HTTP head exceeded {MAX_HTTP_HEADER_BYTES} bytes"
            raise HttpProtocolError(msg)
        chunk = await reader.read(_READ_CHUNK)
        if not chunk:
            msg = "connection closed before HTTP head completed"
            raise HttpProtocolError(msg)
        buf.extend(chunk)


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


class _BodyDecoder:
    """Turn raw socket bytes into body bytes for one HTTP response.

    Handles the three ways an HTTP/1.1 response delimits its body:
    ``Content-Length``, ``Transfer-Encoding: chunked`` and, when neither
    is present, the end of the connection.
    """

    __slots__ = ("_chunked", "_remaining", "done")

    def __init__(self, headers: Headers) -> None:
        te = (headers.get("Transfer-Encoding") or "").lower()
        cl = headers.get("Content-Length")
        self._chunked: ChunkedDecoder | None = ChunkedDecoder() if "chunked" in te else None
        self._remaining: int | None = None
        if self._chunked is None and cl is not None:
            self._remaining = int(cl)
        self.done: bool = self._remaining == 0

    @property
    def delimited_by_close(self) -> bool:
        return self._chunked is None and self._remaining is None

    def feed(self, raw: bytes) -> bytes:
        if self.done or not raw:
            return b""
        if self._chunked is not None:
            out = b"".join(self._chunked.feed(raw))
            self.done = self._chunked.at_eof
            return out
        if self._remaining is None:
            return raw
        take = raw[: self._remaining]
        self._remaining -= len(take)
        self.done = self._remaining == 0
        return take


async def _iter_body(
    reader: asyncio.StreamReader,
    headers: Headers,
) -> AsyncIterator[bytes]:
    """Yield the decoded body of one response as it arrives."""
    decoder = _BodyDecoder(headers)
    leftover = reader_leftover_getattr(reader)
    if leftover:
        piece = decoder.feed(leftover)
        if piece:
            yield piece
    while not decoder.done:
        raw = await reader.read(_READ_CHUNK)
        if not raw:
            if decoder.delimited_by_close:
                return
            msg = "connection closed before the response body completed"
            raise HttpProtocolError(msg)
        piece = decoder.feed(raw)
        if piece:
            yield piece


async def _read_body(reader: asyncio.StreamReader, headers: Headers, *, cap: int) -> bytes:
    out = bytearray()
    async for piece in _iter_body(reader, headers):
        out.extend(piece)
        if len(out) > cap:
            msg = f"response body exceeded {cap} bytes"
            raise HttpProtocolError(msg)
    return bytes(out)


def _media_type(headers: Headers) -> str:
    return (headers.get("Content-Type") or "").split(";", 1)[0].strip().lower()


def _reusable(head: HttpResponseHead) -> bool:
    """True when the connection may carry another request after this response."""
    connection = (head.headers.get("Connection") or "").lower()
    if "close" in connection:
        return False
    framed = (
        head.headers.get("Content-Length") is not None
        or "chunked" in (head.headers.get("Transfer-Encoding") or "").lower()
    )
    if not framed:
        return False
    if head.version.upper() == "HTTP/1.0":
        return "keep-alive" in connection
    return True


def _is_visible_ascii(value: str, cap: int) -> bool:
    return 0 < len(value) <= cap and all(0x21 <= ord(c) <= 0x7E for c in value)


def _request_ids(message: Message | Batch) -> tuple[RequestId, ...]:
    items = message.messages if isinstance(message, Batch) else (message,)
    return tuple(m.id for m in items if isinstance(m, Request))


def _host_header(host: str, port: int) -> str:
    if port in {80, 443}:
        return host
    if ":" in host:
        # IPv6 literal -- bracket it.
        return f"[{host}]:{port}"
    return f"{host}:{port}"


def _encode_jsonrpc(message: Message | Batch) -> bytes:
    return message.model_dump_json().encode("utf-8")


# ---------------------------------------------------------------------------
# Streamable HTTP transport (MCP 2025-03-26 / 2025-06-18).
# ---------------------------------------------------------------------------


class HttpStreamableTransport(Transport):
    """Client-side ``streamable-http`` transport.

    Messages from every response body and from the optional server
    stream land in a single inbox, so :meth:`receive` returns them in
    arrival order regardless of the connection that carried them.
    Writes happen in :meth:`send`, in call order; responses are read by
    background tasks so a slow tool call never blocks the next message.
    Idle keep-alive connections are pooled and reused.

    When the upstream fails at the HTTP level (connection refused,
    ``4xx``/``5xx``, an unparseable body) every request in the affected
    POST is answered with a JSON-RPC error carrying
    :data:`UPSTREAM_TRANSPORT_ERROR`, so the client is told instead of
    waiting forever.
    """

    __slots__ = (
        "_closed",
        "_connected",
        "_extra_headers",
        "_get_status",
        "_get_task",
        "_host",
        "_idle",
        "_inbox",
        "_open_server_stream",
        "_path",
        "_port",
        "_protocol_version",
        "_session_id",
        "_tasks",
        "_tls",
        "_url",
        "_writers",
    )

    def __init__(
        self,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        verify_tls: bool = True,
        open_server_stream: bool = True,
    ) -> None:
        self._url = url
        self._host, self._port, self._path, is_https = _split_url(url)
        self._tls = _tls_context(verify=verify_tls) if is_https else None
        self._extra_headers = dict(headers or {})
        for name, value in self._extra_headers.items():
            if any(c in name + value for c in "\r\n"):
                msg = f"header {name!r} contains a line break"
                raise ValueError(msg)
        self._open_server_stream = open_server_stream
        self._inbox: asyncio.Queue[Message | Batch | None] = asyncio.Queue()
        self._idle: list[tuple[asyncio.StreamReader, asyncio.StreamWriter]] = []
        self._writers: set[asyncio.StreamWriter] = set()
        self._tasks: set[asyncio.Task[None]] = set()
        self._get_task: asyncio.Task[None] | None = None
        self._get_status: int | None = None
        self._session_id: str | None = None
        self._protocol_version: str | None = None
        self._connected = False
        self._closed = False

    # --- introspection ----------------------------------------------------
    @property
    def url(self) -> str:
        return self._url

    @property
    def uses_tls(self) -> bool:
        return self._tls is not None

    @property
    def session_id(self) -> str | None:
        """Session identifier assigned by the upstream, if any."""
        return self._session_id

    @property
    def protocol_version(self) -> str | None:
        """Protocol revision negotiated during ``initialize``, if seen."""
        return self._protocol_version

    @property
    def server_stream_open(self) -> bool:
        """True while the optional server-to-client GET stream is open."""
        return self._get_task is not None and not self._get_task.done()

    # --- lifecycle --------------------------------------------------------
    async def connect(self) -> None:
        """Reach the upstream and, when offered, open the server stream.

        Raises :class:`TransportError` when the host cannot be reached
        (refused connection, DNS or TLS failure). A server that does not
        offer the optional GET stream is not an error.
        """
        if self._connected:
            return
        if self._closed:
            msg = "transport is closed"
            raise ClosedTransportError(msg)
        if self._open_server_stream:
            await self._open_get_stream()
        else:
            self._idle.append(await self._new_connection())
        self._connected = True

    async def _new_connection(self) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        reader, writer = await _open_connection(self._host, self._port, self._tls)
        self._writers.add(writer)
        return reader, writer

    async def _discard(self, writer: asyncio.StreamWriter | None) -> None:
        if writer is None:
            return
        self._writers.discard(writer)
        await _close_writer(writer)

    def _headers(self) -> Headers:
        headers = Headers()
        headers.add("Host", _host_header(self._host, self._port))
        headers.add("User-Agent", _USER_AGENT)
        for name, value in self._extra_headers.items():
            headers.add(name, value)
        if self._session_id is not None:
            headers.add(_SESSION_HEADER, self._session_id)
        if self._protocol_version is not None:
            headers.add(_PROTOCOL_HEADER, self._protocol_version)
        return headers

    async def _open_get_stream(self) -> bool:
        reader, writer = await self._new_connection()
        headers = self._headers()
        headers.add("Accept", "text/event-stream")
        headers.add("Cache-Control", "no-cache")
        try:
            writer.write(encode_request("GET", self._path, headers=headers))
            await asyncio.wait_for(writer.drain(), timeout=_IO_TIMEOUT_SECONDS)
            head = parse_response_head(
                await asyncio.wait_for(
                    _read_response_head(reader),
                    timeout=_SERVER_STREAM_HEAD_TIMEOUT,
                ),
            )
        except (HttpProtocolError, OSError, TimeoutError) as exc:
            _log.info("upstream %s: no server stream (%s)", self._url, exc)
            await self._discard(writer)
            return False
        self._get_status = head.status
        if head.status != 200 or _media_type(head.headers) != "text/event-stream":
            _log.info(
                "upstream %s: GET answered %s %s; continuing without a server stream",
                self._url,
                head.status,
                head.reason,
            )
            await self._discard(writer)
            return False
        self._get_task = asyncio.create_task(
            self._pump_server_stream(reader, writer, head),
            name="argos.proxy.http.server-stream",
        )
        return True

    async def _pump_server_stream(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        head: HttpResponseHead,
    ) -> None:
        try:
            await self._consume_sse(reader, head)
        except (HttpProtocolError, JsonRpcProtocolError, OSError) as exc:
            _log.info("upstream %s: server stream ended (%s)", self._url, exc)
        finally:
            await self._discard(writer)

    async def _retry_server_stream(self) -> None:
        with contextlib.suppress(TransportError):
            await self._open_get_stream()

    # --- send (POST) ------------------------------------------------------
    async def send(self, message: Message | Batch) -> None:
        if self._closed:
            msg = "transport is closed"
            raise ClosedTransportError(msg)
        if not self._connected:
            await self.connect()
        body = _encode_jsonrpc(message)
        if len(body) > MAX_MESSAGE_BYTES:
            msg = f"message of {len(body)} bytes exceeds cap {MAX_MESSAGE_BYTES}"
            raise TransportError(msg)
        ids = _request_ids(message)
        reader, writer, reused = await self._acquire()
        try:
            await self._write_post(writer, body)
        except (OSError, TimeoutError) as exc:
            await self._discard(writer)
            if not reused:
                msg = f"upstream {self._url} POST failed: {exc}"
                raise ClosedTransportError(msg) from exc
            # A pooled connection the server had already closed: use a new one.
            reader, writer = await self._new_connection()
            reused = False
            try:
                await self._write_post(writer, body)
            except (OSError, TimeoutError) as retry_exc:
                await self._discard(writer)
                msg = f"upstream {self._url} POST failed: {retry_exc}"
                raise ClosedTransportError(msg) from retry_exc
        task = asyncio.create_task(
            self._consume_post(reader, writer, body, ids, reused=reused),
            name="argos.proxy.http.post",
        )
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def _acquire(
        self,
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter, bool]:
        while self._idle:
            reader, writer = self._idle.pop()
            if reader.at_eof() or writer.is_closing():
                await self._discard(writer)
                continue
            return reader, writer, True
        reader, writer = await self._new_connection()
        return reader, writer, False

    async def _write_post(self, writer: asyncio.StreamWriter, body: bytes) -> None:
        headers = self._headers()
        headers.add("Content-Type", "application/json")
        headers.add("Accept", "application/json, text/event-stream")
        writer.write(encode_request("POST", self._path, headers=headers, body=body))
        await asyncio.wait_for(writer.drain(), timeout=_IO_TIMEOUT_SECONDS)

    async def _consume_post(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        body: bytes,
        ids: tuple[RequestId, ...],
        *,
        reused: bool,
    ) -> None:
        raw_head = b""
        for attempt in (0, 1):
            try:
                if attempt == 1:
                    reader, writer = await self._new_connection()
                    await self._write_post(writer, body)
                raw_head = await _read_response_head(reader)
                break
            except (TransportError, HttpProtocolError, OSError, TimeoutError) as exc:
                await self._discard(writer)
                if attempt == 0 and reused and not self._closed:
                    continue
                self._fail(ids, f"upstream {self._url} did not answer: {exc}")
                return
        reusable = False
        try:
            head = parse_response_head(raw_head)
            await self._handle_post_response(reader, head, ids)
            reusable = _reusable(head)
        except (HttpProtocolError, JsonRpcProtocolError, OSError, ValueError) as exc:
            self._fail(ids, f"upstream {self._url} sent an unusable response: {exc}")
        if reusable and not self._closed:
            self._idle.append((reader, writer))
        else:
            await self._discard(writer)

    async def _handle_post_response(
        self,
        reader: asyncio.StreamReader,
        head: HttpResponseHead,
        ids: tuple[RequestId, ...],
    ) -> None:
        self._capture_session(head.headers)
        status = head.status
        if status in {202, 204}:
            await _read_body(reader, head.headers, cap=_SMALL_BODY_CAP)
            return
        if not 200 <= status < 300:
            detail = ""
            with contextlib.suppress(HttpProtocolError, OSError):
                raw = await _read_body(reader, head.headers, cap=_SMALL_BODY_CAP)
                detail = " ".join(raw.decode("utf-8", errors="replace").split())[:300]
            reason = f"upstream HTTP {status} {head.reason}".rstrip()
            if status == 404 and self._session_id is not None:
                reason += " (the upstream no longer recognises this session)"
            self._fail(ids, f"{reason}: {detail}" if detail else reason)
            return
        media = _media_type(head.headers)
        if media == "text/event-stream":
            await self._consume_sse(reader, head)
            return
        data = await _read_body(reader, head.headers, cap=MAX_MESSAGE_BYTES)
        if not data.strip():
            return
        if media == "application/json" or media.endswith("+json"):
            self._deliver_payload(data, ids)
            return
        self._fail(ids, f"upstream answered with unsupported Content-Type {media!r}")

    async def _consume_sse(self, reader: asyncio.StreamReader, head: HttpResponseHead) -> None:
        parser = SseEventParser()
        async for piece in _iter_body(reader, head.headers):
            for event in parser.feed(piece):
                self._deliver_event(event)
        for event in parser.flush():
            self._deliver_event(event)

    # --- inbox --------------------------------------------------------------
    def _deliver_event(self, event: SseEvent) -> None:
        if event.event not in {"message", ""} or not event.data.strip():
            # "endpoint", "ping" and similar are transport metadata.
            return
        self._deliver_payload(event.data, ())

    def _deliver_payload(self, data: str | bytes, ids: tuple[RequestId, ...]) -> None:
        try:
            parsed = parse_payload(data)
        except (JsonRpcProtocolError, ValueError) as exc:
            _log.warning("upstream %s sent an unparseable message: %s", self._url, exc)
            self._fail(ids, f"upstream {self._url} sent an unparseable message")
            return
        self._observe(parsed)
        self._inbox.put_nowait(parsed)

    def _observe(self, parsed: Message | Batch) -> None:
        """Pick up the protocol revision from the initialize result."""
        if self._protocol_version is not None or not isinstance(parsed, Response):
            return
        result = parsed.result
        if isinstance(result, dict):
            version = result.get("protocolVersion")
            if isinstance(version, str) and _PROTOCOL_VERSION_RE.fullmatch(version):
                self._protocol_version = version

    def _capture_session(self, headers: Headers) -> None:
        value = headers.get(_SESSION_HEADER)
        if value is None or value == self._session_id:
            return
        if not _is_visible_ascii(value, 1024):
            _log.warning("ignoring malformed %s header from %s", _SESSION_HEADER, self._url)
            return
        first = self._session_id is None
        self._session_id = value
        if (
            first
            and self._open_server_stream
            and self._get_task is None
            and self._get_status != 405
            and not self._closed
        ):
            # Servers that bind the GET stream to a session refuse it
            # before initialisation; try again now that we have one.
            task = asyncio.create_task(
                self._retry_server_stream(),
                name="argos.proxy.http.server-stream-retry",
            )
            self._tasks.add(task)
            task.add_done_callback(self._tasks.discard)

    def _fail(self, ids: tuple[RequestId, ...], reason: str) -> None:
        if not ids:
            _log.warning("%s", reason)
            return
        for request_id in ids:
            self._inbox.put_nowait(
                Response(
                    error=ErrorObject(code=UPSTREAM_TRANSPORT_ERROR, message=reason[:4000]),
                    id=request_id,
                ),
            )

    # --- receive ------------------------------------------------------------
    async def receive(self) -> Message | Batch:
        if self._closed:
            msg = "transport is closed"
            raise ClosedTransportError(msg)
        if not self._connected:
            await self.connect()
        item = await self._inbox.get()
        if item is None:
            msg = f"transport to {self._url} is closed"
            raise ClosedTransportError(msg)
        return item

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._inbox.put_nowait(None)
        if self._session_id is not None:
            with contextlib.suppress(Exception):
                await asyncio.wait_for(self._terminate_session(), timeout=2.0)
        tasks = list(self._tasks)
        if self._get_task is not None:
            tasks.append(self._get_task)
        for task in tasks:
            task.cancel()
        for task in tasks:
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await task
        for writer in list(self._writers):
            await self._discard(writer)
        self._idle.clear()

    async def _terminate_session(self) -> None:
        """Tell the upstream the session is over (``DELETE``, best effort)."""
        reader, writer = await self._new_connection()
        try:
            writer.write(encode_request("DELETE", self._path, headers=self._headers()))
            await writer.drain()
            await _read_response_head(reader)
        finally:
            await self._discard(writer)

    @property
    def is_closed(self) -> bool:
        return self._closed


# ---------------------------------------------------------------------------
# Legacy SSE transport (MCP 2024-11-05, two endpoints).
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

    - The ``endpoint`` event is often a relative URL. It is resolved
      against ``sse_url``'s scheme and authority.
    - The event stream may be chunked; it is decoded before parsing.
    - Reconnection on transient network errors is out of scope; the
      proxy treats a closed SSE stream as a final disconnect and the
      :class:`ProxyServer` tears the session down.
    """

    __slots__ = (
        "_buffered_events",
        "_closed",
        "_extra_headers",
        "_get_decoder",
        "_get_reader",
        "_get_writer",
        "_post_lock",
        "_post_url",
        "_sse_parser",
        "_sse_url",
        "_verify_tls",
    )

    def __init__(
        self,
        sse_url: str,
        *,
        post_url: str | None = None,
        headers: Mapping[str, str] | None = None,
        verify_tls: bool = True,
    ) -> None:
        _split_url(sse_url)  # validate early
        self._sse_url = sse_url
        self._post_url = post_url
        self._extra_headers = dict(headers or {})
        self._verify_tls = verify_tls
        self._closed = False
        self._get_reader: asyncio.StreamReader | None = None
        self._get_writer: asyncio.StreamWriter | None = None
        self._get_decoder: _BodyDecoder | None = None
        self._sse_parser = SseEventParser()
        self._buffered_events: list[SseEvent] = []
        self._post_lock = asyncio.Lock()

    def _tls_for(self, is_https: bool) -> ssl.SSLContext | None:
        return _tls_context(verify=self._verify_tls) if is_https else None

    def _headers(self, host: str, port: int) -> Headers:
        headers = Headers()
        headers.add("Host", _host_header(host, port))
        headers.add("User-Agent", _USER_AGENT)
        for name, value in self._extra_headers.items():
            headers.add(name, value)
        return headers

    # --- lifecycle --------------------------------------------------------
    async def connect(self) -> None:
        if self._get_reader is not None:
            return
        host, port, path, is_https = _split_url(self._sse_url)
        self._get_reader, self._get_writer = await _open_connection(
            host,
            port,
            self._tls_for(is_https),
        )
        get_headers = self._headers(host, port)
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
        self._get_decoder = _BodyDecoder(head.headers)
        leftover = reader_leftover_getattr(self._get_reader)
        if leftover:
            self._feed(leftover)
        # Auto-discover post_url if not supplied: read events until we
        # see one of type ``endpoint``.
        if self._post_url is None:
            await self._discover_post_url()

    def _feed(self, raw: bytes) -> None:
        decoder = self._get_decoder
        data = decoder.feed(raw) if decoder is not None else raw
        if data:
            self._buffered_events.extend(self._sse_parser.feed(data))

    async def _discover_post_url(self) -> None:
        """Wait for the upstream to emit an ``endpoint`` event."""
        if self._get_reader is None:
            return
        loop = asyncio.get_running_loop()
        deadline = loop.time() + 5.0
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
            remaining = deadline - loop.time()
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
            self._feed(chunk)

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
        host, port, path, is_https = _split_url(self._post_url)
        body = _encode_jsonrpc(message)
        post_headers = self._headers(host, port)
        post_headers.add("Content-Type", "application/json")
        post_headers.add("Connection", "close")
        request = encode_request(
            "POST",
            path,
            headers=post_headers,
            body=body,
        )
        async with self._post_lock:
            reader, writer = await _open_connection(host, port, self._tls_for(is_https))
            try:
                writer.write(request)
                await writer.drain()
                head_bytes = await asyncio.wait_for(
                    _read_response_head(reader),
                    timeout=_IO_TIMEOUT_SECONDS,
                )
                head = parse_response_head(head_bytes)
                if head.status >= 400:
                    msg = f"POST {self._post_url} returned {head.status} {head.reason}"
                    raise TransportError(msg)
            finally:
                await _close_writer(writer)

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
                if event.event in {"message", ""} and event.data.strip():
                    return parse_payload(event.data)
                continue
            chunk = await self._get_reader.read(_READ_CHUNK)
            if not chunk:
                self._closed = True
                msg = f"upstream {self._sse_url} closed the SSE stream"
                raise ClosedTransportError(msg)
            self._feed(chunk)

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        await _close_writer(self._get_writer)

    @property
    def is_closed(self) -> bool:
        return self._closed


__all__ = [
    "UPSTREAM_TRANSPORT_ERROR",
    "HttpStreamableTransport",
    "SseTransport",
]
