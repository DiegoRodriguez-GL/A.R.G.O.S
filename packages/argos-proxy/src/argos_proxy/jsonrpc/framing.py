"""Wire framing for JSON-RPC 2.0 streams.

MCP servers expose JSON-RPC over two common framings:

- **Content-Length headers** (LSP / MCP stdio convention):
  ``Content-Length: <n>\\r\\n\\r\\n<n bytes of UTF-8 JSON>``. Multiple
  headers are tolerated; ``Content-Type`` is optional.
- **NDJSON** (newline-delimited JSON): one JSON object per line, used
  by simpler MCP servers and by ARGOS's own test harness.

Both framings are bidirectional: the same encoder/decoder is used for
ingress (client -> proxy) and egress (proxy -> upstream). The
:class:`StdioFramer` and :class:`NDJSONFramer` classes hold the streaming
state machine; the module-level :func:`encode_message` /
:func:`decode_message` helpers are stateless one-shots used by the unit
tests and by the in-memory transport.
"""

from __future__ import annotations

import json
from typing import Any, Final

from pydantic import BaseModel

from argos_proxy.jsonrpc.errors import JsonRpcProtocolError

#: Inclusive cap on a single message's encoded length. 16 MiB is far
#: above any real MCP payload (tool definitions tend to be a few KiB)
#: yet bounded enough to refuse a length-bomb attack from an
#: untrusted upstream that claims a TB-sized message.
MAX_MESSAGE_BYTES: Final[int] = 16 * 1024 * 1024

#: Cap on the ``Content-Length`` header section. A misbehaving sender
#: could attempt to exhaust memory by feeding endless headers without
#: ever sending the blank-line separator.
MAX_HEADER_BYTES: Final[int] = 4 * 1024

#: Header / body separator per LSP / MCP convention.
_CRLF: Final[bytes] = b"\r\n"
_HEADER_END: Final[bytes] = b"\r\n\r\n"


class FrameDecodeError(JsonRpcProtocolError):
    """Raised when the wire framing is malformed.

    Subclass of :class:`JsonRpcProtocolError` because the proxy treats
    a framing fault as a parse-time protocol violation: the upstream
    cannot recover and we cannot correlate to a request id."""


def encode_message(message: BaseModel | dict[str, Any], *, framing: str = "ndjson") -> bytes:
    """Serialise a message for the wire.

    ``framing`` is one of ``"ndjson"`` or ``"stdio"``. NDJSON appends a
    single newline; stdio prepends an LSP-style ``Content-Length``
    header. The function is intentionally stateless so it composes with
    arbitrary transports.
    """
    if isinstance(message, BaseModel):
        # ``model_dump_json(by_alias=True)`` would matter if we had
        # aliases; we don't. Using model_dump_json keeps Pydantic's
        # canonical field ordering (insertion order of declaration).
        text = message.model_dump_json(exclude_none=False, exclude_unset=False)
    else:
        # ``sort_keys=False`` so we don't reorder the upstream payload
        # silently; ``ensure_ascii=False`` so unicode round-trips byte-
        # for-byte instead of being escaped.
        text = json.dumps(message, ensure_ascii=False, separators=(",", ":"))
    body = text.encode("utf-8")
    if len(body) > MAX_MESSAGE_BYTES:
        msg = f"encoded message size {len(body)} exceeds cap {MAX_MESSAGE_BYTES}"
        raise FrameDecodeError(msg)
    if framing == "ndjson":
        return body + b"\n"
    if framing == "stdio":
        header = f"Content-Length: {len(body)}\r\n\r\n".encode("ascii")
        return header + body
    msg = f"unsupported framing {framing!r}; expected 'ndjson' or 'stdio'"
    raise ValueError(msg)


def decode_message(blob: bytes, *, framing: str = "ndjson") -> bytes:
    """Strip framing from a single complete message and return the body.

    The returned bytes are NOT JSON-parsed; that is the message-layer's
    job. Splitting concerns this way means a fuzz test on the framer
    can run without the JSON decoder, isolating the failure mode.
    """
    if framing == "ndjson":
        return _decode_ndjson(blob)
    if framing == "stdio":
        return _decode_stdio(blob)
    msg = f"unsupported framing {framing!r}; expected 'ndjson' or 'stdio'"
    raise ValueError(msg)


def _decode_ndjson(blob: bytes) -> bytes:
    """NDJSON: one message per line. Trailing newline stripped."""
    if blob.endswith(b"\r\n"):
        return blob[:-2]
    if blob.endswith(b"\n"):
        return blob[:-1]
    return blob


def _decode_stdio(blob: bytes) -> bytes:
    """Stdio: ``Content-Length: N\\r\\n\\r\\n<N bytes>``."""
    sep = blob.find(_HEADER_END)
    if sep < 0:
        msg = "stdio frame missing CRLF CRLF header terminator"
        raise FrameDecodeError(msg)
    if sep > MAX_HEADER_BYTES:
        msg = f"stdio header section {sep} bytes exceeds cap {MAX_HEADER_BYTES}"
        raise FrameDecodeError(msg)
    header = blob[:sep]
    body = blob[sep + len(_HEADER_END) :]
    declared = _read_content_length(header)
    if declared != len(body):
        msg = f"stdio Content-Length declared {declared} but body is {len(body)} bytes"
        raise FrameDecodeError(msg)
    return body


def _read_content_length(header: bytes) -> int:
    """Parse the Content-Length value; reject duplicates and aliases.

    Why "duplicates and aliases"? An attacker can desync a request from
    its forensic record by sending two ``Content-Length`` headers (the
    proxy reads one, the upstream reads the other). Refusing on
    duplicate is the simple correct behaviour."""
    if len(header) > MAX_HEADER_BYTES:
        msg = "stdio header section exceeds cap"
        raise FrameDecodeError(msg)
    found: int | None = None
    for line in header.split(_CRLF):
        if not line:
            continue
        if b":" not in line:
            msg = f"malformed stdio header line: {line!r}"
            raise FrameDecodeError(msg)
        name, _, raw_value = line.partition(b":")
        # Header names are case-insensitive (RFC 7230 / 9112).
        if name.strip().lower() != b"content-length":
            continue
        if found is not None:
            msg = "duplicate Content-Length header"
            raise FrameDecodeError(msg)
        value = raw_value.strip()
        if not value or not value.isdigit():
            msg = f"non-numeric Content-Length: {raw_value!r}"
            raise FrameDecodeError(msg)
        try:
            found = int(value)
        except ValueError as exc:  # pragma: no cover (.isdigit() guarded)
            msg = f"unparseable Content-Length: {raw_value!r}"
            raise FrameDecodeError(msg) from exc
        if found < 0 or found > MAX_MESSAGE_BYTES:
            msg = f"Content-Length {found} outside [0, {MAX_MESSAGE_BYTES}]"
            raise FrameDecodeError(msg)
    if found is None:
        msg = "stdio frame missing Content-Length header"
        raise FrameDecodeError(msg)
    return found


# ---------------------------------------------------------------------------
# Streaming framers.
# ---------------------------------------------------------------------------


class _StreamingFramer:
    """Common buffer-and-emit machinery."""

    __slots__ = ("_buffer",)

    def __init__(self) -> None:
        self._buffer: bytearray = bytearray()

    def feed(self, chunk: bytes) -> list[bytes]:
        """Append ``chunk`` and return the list of complete bodies that
        became available. Bytes belonging to a partial frame remain
        buffered for the next call."""
        self._buffer.extend(chunk)
        out: list[bytes] = []
        while True:
            body = self._next_body()
            if body is None:
                break
            out.append(body)
        return out

    def buffered_bytes(self) -> int:
        """Number of bytes still in the internal buffer (for tests / metrics)."""
        return len(self._buffer)

    def _next_body(self) -> bytes | None:
        raise NotImplementedError


class NDJSONFramer(_StreamingFramer):
    """Streaming NDJSON framer: emits one body per ``\\n`` boundary."""

    def _next_body(self) -> bytes | None:
        idx = self._buffer.find(b"\n")
        if idx < 0:
            if len(self._buffer) > MAX_MESSAGE_BYTES:
                msg = f"unframed NDJSON buffer exceeded {MAX_MESSAGE_BYTES} bytes without a newline"
                raise FrameDecodeError(msg)
            return None
        body = bytes(self._buffer[:idx])
        del self._buffer[: idx + 1]  # drop body + newline
        # Tolerate a trailing CR (CRLF line endings).
        if body.endswith(b"\r"):
            body = body[:-1]
        return body


class StdioFramer(_StreamingFramer):
    """Streaming Content-Length framer: emits one body per declared length."""

    __slots__ = ("_expected", "_header_seen")

    def __init__(self) -> None:
        super().__init__()
        self._expected: int | None = None
        self._header_seen: int = 0

    def _next_body(self) -> bytes | None:
        if self._expected is None:
            sep = self._buffer.find(_HEADER_END)
            if sep < 0:
                if len(self._buffer) > MAX_HEADER_BYTES:
                    msg = f"stdio header buffer exceeded {MAX_HEADER_BYTES} bytes without CRLF CRLF"
                    raise FrameDecodeError(msg)
                return None
            header = bytes(self._buffer[:sep])
            self._expected = _read_content_length(header)
            self._header_seen = sep + len(_HEADER_END)
            del self._buffer[: self._header_seen]
        if len(self._buffer) < self._expected:
            return None
        body = bytes(self._buffer[: self._expected])
        del self._buffer[: self._expected]
        self._expected = None
        return body
