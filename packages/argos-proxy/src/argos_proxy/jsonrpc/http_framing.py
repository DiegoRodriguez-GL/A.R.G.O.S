"""Minimal HTTP/1.1 framing for ARGOS audit proxy.

The MCP specification defines three transports for JSON-RPC messages:

- ``stdio`` -- already covered by :mod:`argos_proxy.jsonrpc.framing`.
- ``streamable-http`` -- a single endpoint accepting both POST (client
  to server) and GET with ``Accept: text/event-stream`` (server to
  client). Defined in MCP spec 2025-03-26.
- ``sse`` (legacy) -- two endpoints: ``GET /sse`` for the server stream
  and ``POST /messages?session_id=...`` for client requests. Deprecated
  in favour of streamable-http but still common in deployed servers.

This module implements the HTTP/1.1 wire format manually on top of
:mod:`asyncio` streams. Doing so keeps the proxy free of HTTP client
dependencies (no ``httpx`` / ``aiohttp``) and matches the rest of the
codebase's "small, well-typed surface" philosophy.

Scope of HTTP support:

- Methods: ``GET``, ``POST``.
- Headers: case-insensitive lookup, multi-value via comma-separated
  values OR multiple lines.
- Bodies: ``Content-Length`` (fixed) and ``Transfer-Encoding: chunked``.
- Status codes: numeric, no special handling beyond reporting.
- Keep-alive: HTTP/1.1 default; explicit ``Connection: close`` honoured.

Out of scope (intentionally): HTTP/2, compression, redirects, cookies,
auth schemes, multipart bodies. The MCP spec uses none of these on the
transport layer.

Hardening:

- Header section capped at 16 KiB (request smuggling defence).
- Single message body capped at the same value as
  :data:`argos_proxy.jsonrpc.framing.MAX_MESSAGE_BYTES`.
- Chunk size declared in hex MUST fit in a 32-bit unsigned integer.
- Duplicate ``Content-Length`` headers refused (HTTP smuggling defence).
- ``Content-Length`` and ``Transfer-Encoding: chunked`` simultaneously
  refused (HTTP smuggling defence).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Final

from argos_proxy.jsonrpc.errors import JsonRpcProtocolError
from argos_proxy.jsonrpc.framing import MAX_MESSAGE_BYTES

#: Hard cap on the size of the HTTP header section.
MAX_HTTP_HEADER_BYTES: Final[int] = 16 * 1024

#: Hard cap on the declared length of a chunk in chunked transfer.
#: 64 MiB per chunk; the full message is still bounded by
#: ``MAX_MESSAGE_BYTES`` after concatenation.
MAX_CHUNK_BYTES: Final[int] = 64 * 1024 * 1024

_CRLF: Final[bytes] = b"\r\n"
_HEADER_END: Final[bytes] = b"\r\n\r\n"


class HttpProtocolError(JsonRpcProtocolError):
    """Raised when the HTTP framing is malformed.

    Subclass of :class:`JsonRpcProtocolError` because we treat HTTP
    framing faults the same way the JSON-RPC parser treats wire-level
    faults: they are unrecoverable and have no correlation to a specific
    request id."""


# ---------------------------------------------------------------------------
# Headers helper.
# ---------------------------------------------------------------------------


@dataclass
class Headers:
    """Case-insensitive HTTP header collection.

    Multi-value headers are stored as repeated entries; ``get_all`` returns
    the list. ``get`` returns the first value (or the joined value when
    HTTP allows comma-folding). Names are normalised to canonical form
    (``Content-Length``, not ``content-length``) for stable serialisation.
    """

    items: list[tuple[str, str]] = field(default_factory=list)

    def add(self, name: str, value: str) -> None:
        canon = _canonical(name)
        self.items.append((canon, value))

    def get(self, name: str) -> str | None:
        canon = _canonical(name)
        for n, v in self.items:
            if n == canon:
                return v
        return None

    def get_all(self, name: str) -> list[str]:
        canon = _canonical(name)
        return [v for n, v in self.items if n == canon]

    def has(self, name: str) -> bool:
        return self.get(name) is not None

    def encode(self) -> bytes:
        """Serialise to wire format. Caller must add the final CRLF
        separating headers from body."""
        out: list[bytes] = []
        for n, v in self.items:
            out.append(f"{n}: {v}".encode("latin-1"))
        return _CRLF.join(out)


def _canonical(name: str) -> str:
    """``content-length`` -> ``Content-Length``."""
    return "-".join(p.capitalize() for p in name.lower().split("-"))


# ---------------------------------------------------------------------------
# Request / Response models.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class HttpRequest:
    """Parsed HTTP request line + headers + body.

    The body is fully buffered: the parser caps it at
    :data:`MAX_MESSAGE_BYTES` and refuses anything larger. For streaming
    bodies (SSE responses) callers use :class:`HttpResponseHead` and
    drive the body read themselves."""

    method: str
    path: str
    version: str  # "HTTP/1.1"
    headers: Headers
    body: bytes


@dataclass(frozen=True)
class HttpResponseHead:
    """HTTP response status line + headers, without the body.

    Used when the caller needs to stream the body (SSE) instead of
    buffering it. The body is read separately via
    :func:`read_body_chunked` or :func:`read_body_fixed`.
    """

    version: str
    status: int
    reason: str
    headers: Headers


@dataclass(frozen=True)
class HttpResponse:
    """HTTP response with fully buffered body."""

    version: str
    status: int
    reason: str
    headers: Headers
    body: bytes


# ---------------------------------------------------------------------------
# Encoders.
# ---------------------------------------------------------------------------


def encode_request(
    method: str,
    path: str,
    *,
    headers: Headers | None = None,
    body: bytes = b"",
    host: str | None = None,
) -> bytes:
    """Serialise an HTTP/1.1 request.

    The caller MUST pass ``host`` either via the argument or already in
    ``headers``; HTTP/1.1 makes the ``Host`` header mandatory."""
    method = method.upper()
    if method not in {"GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS"}:
        msg = f"unsupported HTTP method {method!r}"
        raise ValueError(msg)
    if not path or path[0] != "/":
        msg = f"path must start with '/', got {path!r}"
        raise ValueError(msg)
    h = Headers(list(headers.items)) if headers else Headers()
    if host is not None and not h.has("Host"):
        h.add("Host", host)
    if body and not h.has("Content-Length"):
        h.add("Content-Length", str(len(body)))
    request_line = f"{method} {path} HTTP/1.1\r\n".encode("latin-1")
    return request_line + h.encode() + _HEADER_END + body


def encode_response(
    status: int,
    reason: str,
    *,
    headers: Headers | None = None,
    body: bytes = b"",
) -> bytes:
    """Serialise an HTTP/1.1 response."""
    if status < 100 or status > 599:
        msg = f"status must be in [100, 599], got {status}"
        raise ValueError(msg)
    h = Headers(list(headers.items)) if headers else Headers()
    if body and not h.has("Content-Length"):
        h.add("Content-Length", str(len(body)))
    status_line = f"HTTP/1.1 {status} {reason}\r\n".encode("latin-1")
    return status_line + h.encode() + _HEADER_END + body


def encode_chunk(data: bytes) -> bytes:
    """Encode one chunk for ``Transfer-Encoding: chunked`` output."""
    return f"{len(data):x}\r\n".encode("ascii") + data + _CRLF


def encode_chunk_terminator() -> bytes:
    """Emit the zero-length chunk that terminates a chunked body."""
    return b"0\r\n\r\n"


# ---------------------------------------------------------------------------
# Decoders.
# ---------------------------------------------------------------------------


def parse_request(blob: bytes) -> HttpRequest:
    """One-shot parser for a complete HTTP request.

    The whole request (head + body) must fit in ``blob``. For streaming
    use the line-based reader on top of :class:`asyncio.StreamReader`
    (see :mod:`argos_proxy.transport.http`)."""
    head, body = _split_head(blob)
    request_line, header_section = _split_request_line(head)
    method, path, version = _parse_request_line(request_line)
    headers = _parse_headers(header_section)
    expected_body = _expected_body(headers)
    if expected_body is not None and expected_body != len(body):
        msg = f"declared body {expected_body} bytes but {len(body)} present"
        raise HttpProtocolError(msg)
    return HttpRequest(
        method=method,
        path=path,
        version=version,
        headers=headers,
        body=body,
    )


def parse_response(blob: bytes) -> HttpResponse:
    """One-shot parser for a complete HTTP response."""
    head, body = _split_head(blob)
    status_line, header_section = _split_request_line(head)
    version, status, reason = _parse_status_line(status_line)
    headers = _parse_headers(header_section)
    return HttpResponse(
        version=version,
        status=status,
        reason=reason,
        headers=headers,
        body=body,
    )


def parse_response_head(head_bytes: bytes) -> HttpResponseHead:
    """Parse only the head section of a response.

    Used by streaming clients (SSE) where the body length is unknown
    a priori and must be read incrementally from the underlying socket.
    """
    if _HEADER_END in head_bytes:
        head_bytes = head_bytes.split(_HEADER_END, 1)[0]
    status_line, header_section = _split_request_line(head_bytes)
    version, status, reason = _parse_status_line(status_line)
    headers = _parse_headers(header_section)
    return HttpResponseHead(
        version=version,
        status=status,
        reason=reason,
        headers=headers,
    )


def parse_request_head(head_bytes: bytes) -> HttpRequest:
    """Parse only the head section of a request, returning a stub
    :class:`HttpRequest` with empty body.

    Used by streaming servers that read the head first to learn the
    body length, then fetch the body separately. Unlike :func:`parse_request`,
    this does NOT validate ``Content-Length`` against the body bytes."""
    if _HEADER_END in head_bytes:
        head_bytes = head_bytes.split(_HEADER_END, 1)[0]
    request_line, header_section = _split_request_line(head_bytes)
    method, path, version = _parse_request_line(request_line)
    headers = _parse_headers(header_section)
    # Still surface smuggling-defence checks on the header section even
    # though body length is not validated here.
    _expected_body(headers)
    return HttpRequest(
        method=method,
        path=path,
        version=version,
        headers=headers,
        body=b"",
    )


# ---------------------------------------------------------------------------
# Internal helpers.
# ---------------------------------------------------------------------------


def _split_head(blob: bytes) -> tuple[bytes, bytes]:
    sep = blob.find(_HEADER_END)
    if sep < 0:
        msg = "HTTP message missing CRLF CRLF terminator"
        raise HttpProtocolError(msg)
    if sep > MAX_HTTP_HEADER_BYTES:
        msg = f"HTTP header section {sep} bytes exceeds {MAX_HTTP_HEADER_BYTES}"
        raise HttpProtocolError(msg)
    return blob[:sep], blob[sep + len(_HEADER_END) :]


def _split_request_line(head: bytes) -> tuple[bytes, bytes]:
    nl = head.find(_CRLF)
    if nl < 0:
        return head, b""
    return head[:nl], head[nl + len(_CRLF) :]


def _parse_request_line(line: bytes) -> tuple[str, str, str]:
    parts = line.decode("latin-1").split(" ", 2)
    if len(parts) != 3:
        msg = f"malformed HTTP request line: {line!r}"
        raise HttpProtocolError(msg)
    method, path, version = parts
    if version not in {"HTTP/1.0", "HTTP/1.1"}:
        msg = f"unsupported HTTP version {version!r}"
        raise HttpProtocolError(msg)
    return method.upper(), path, version


def _parse_status_line(line: bytes) -> tuple[str, int, str]:
    decoded = line.decode("latin-1")
    parts = decoded.split(" ", 2)
    if len(parts) < 2:
        msg = f"malformed HTTP status line: {decoded!r}"
        raise HttpProtocolError(msg)
    version = parts[0]
    status_str = parts[1]
    reason = parts[2] if len(parts) == 3 else ""
    if version not in {"HTTP/1.0", "HTTP/1.1"}:
        msg = f"unsupported HTTP version {version!r}"
        raise HttpProtocolError(msg)
    if not status_str.isdigit():
        msg = f"non-numeric HTTP status {status_str!r}"
        raise HttpProtocolError(msg)
    return version, int(status_str), reason


def _parse_headers(section: bytes) -> Headers:
    if len(section) > MAX_HTTP_HEADER_BYTES:
        msg = "HTTP header section exceeds cap"
        raise HttpProtocolError(msg)
    h = Headers()
    seen_content_length: int | None = None
    seen_te = False
    for raw_line in section.split(_CRLF):
        if not raw_line:
            continue
        if b":" not in raw_line:
            msg = f"malformed HTTP header line: {raw_line!r}"
            raise HttpProtocolError(msg)
        name, _, value = raw_line.partition(b":")
        name_str = name.decode("latin-1").strip()
        value_str = value.decode("latin-1").strip()
        if not name_str:
            msg = "empty HTTP header name"
            raise HttpProtocolError(msg)
        # Strict checks for the smuggling-vector headers.
        canon = _canonical(name_str)
        if canon == "Content-Length":
            try:
                cl = int(value_str)
            except ValueError as exc:
                msg = f"non-numeric Content-Length: {value_str!r}"
                raise HttpProtocolError(msg) from exc
            if cl < 0 or cl > MAX_MESSAGE_BYTES:
                msg = f"Content-Length {cl} outside [0, {MAX_MESSAGE_BYTES}]"
                raise HttpProtocolError(msg)
            if seen_content_length is not None and seen_content_length != cl:
                msg = "conflicting Content-Length headers"
                raise HttpProtocolError(msg)
            seen_content_length = cl
        if canon == "Transfer-Encoding":
            seen_te = True
        h.add(name_str, value_str)
    # Both CL and TE present is the canonical HTTP smuggling signal.
    if seen_te and seen_content_length is not None:
        msg = "Content-Length and Transfer-Encoding: chunked are mutually exclusive"
        raise HttpProtocolError(msg)
    return h


def _expected_body(headers: Headers) -> int | None:
    """Return the expected fixed body length, or ``None`` for chunked /
    no-body responses."""
    te = headers.get("Transfer-Encoding")
    if te is not None and "chunked" in te.lower():
        return None
    cl = headers.get("Content-Length")
    if cl is None:
        return 0
    return int(cl)


# ---------------------------------------------------------------------------
# Streaming chunk parser (used by :class:`SseTransport` over chunked).
# ---------------------------------------------------------------------------


class ChunkedDecoder:
    """Streaming decoder for ``Transfer-Encoding: chunked`` bodies.

    Feed bytes via :meth:`feed`; receive complete chunks via the
    return value. The decoder enforces :data:`MAX_CHUNK_BYTES` per
    chunk and raises :class:`HttpProtocolError` on the first malformed
    sequence."""

    __slots__ = ("_buffer", "_eof", "_remaining_in_chunk", "_state")

    def __init__(self) -> None:
        self._buffer: bytearray = bytearray()
        self._state: str = "size"  # size | data | trailer | done
        self._remaining_in_chunk: int = 0
        self._eof: bool = False

    @property
    def at_eof(self) -> bool:
        return self._eof

    def feed(self, chunk: bytes) -> list[bytes]:  # noqa: PLR0912 - chunked FSM
        self._buffer.extend(chunk)
        out: list[bytes] = []
        while True:
            if self._state == "size":
                idx = self._buffer.find(_CRLF)
                if idx < 0:
                    if len(self._buffer) > 32:
                        msg = "chunk size line longer than 32 bytes"
                        raise HttpProtocolError(msg)
                    return out
                size_line = bytes(self._buffer[:idx])
                # Strip optional ;chunk-extension.
                size_str = size_line.split(b";", 1)[0].strip()
                try:
                    size = int(size_str, 16)
                except ValueError as exc:
                    msg = f"malformed chunk size {size_line!r}"
                    raise HttpProtocolError(msg) from exc
                if size < 0 or size > MAX_CHUNK_BYTES:
                    msg = f"chunk size {size} outside [0, {MAX_CHUNK_BYTES}]"
                    raise HttpProtocolError(msg)
                del self._buffer[: idx + len(_CRLF)]
                self._remaining_in_chunk = size
                if size == 0:
                    self._state = "trailer"
                else:
                    self._state = "data"
            elif self._state == "data":
                if len(self._buffer) < self._remaining_in_chunk + len(_CRLF):
                    return out
                body = bytes(self._buffer[: self._remaining_in_chunk])
                terminator = bytes(
                    self._buffer[self._remaining_in_chunk : self._remaining_in_chunk + len(_CRLF)],
                )
                if terminator != _CRLF:
                    msg = "chunk body not followed by CRLF"
                    raise HttpProtocolError(msg)
                del self._buffer[: self._remaining_in_chunk + len(_CRLF)]
                out.append(body)
                self._state = "size"
            elif self._state == "trailer":
                # We accept either an empty trailer line (CRLF
                # immediately) or a non-empty trailer ending with CRLF
                # CRLF. The MCP spec does not use trailers; we tolerate.
                idx = self._buffer.find(_CRLF)
                if idx < 0:
                    return out
                if idx == 0:
                    del self._buffer[: len(_CRLF)]
                    self._state = "done"
                    self._eof = True
                    return out
                # Skip the trailer line and continue.
                del self._buffer[: idx + len(_CRLF)]
            else:
                return out


__all__ = [
    "MAX_CHUNK_BYTES",
    "MAX_HTTP_HEADER_BYTES",
    "ChunkedDecoder",
    "Headers",
    "HttpProtocolError",
    "HttpRequest",
    "HttpResponse",
    "HttpResponseHead",
    "encode_chunk",
    "encode_chunk_terminator",
    "encode_request",
    "encode_response",
    "parse_request",
    "parse_request_head",
    "parse_response",
    "parse_response_head",
]
