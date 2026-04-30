"""Server-Sent Events parser per the WHATWG specification.

The MCP ``sse`` transport (legacy) and ``streamable-http`` transport
both use SSE for the server-to-client direction. The format is a tiny
text protocol; this module implements it without dependencies.

Wire grammar (informally):

- The body is UTF-8 text (BOM tolerated at the very start).
- Events are separated by a blank line (``\\n\\n`` or ``\\r\\n\\r\\n``).
- Each line inside an event has the form ``field: value`` (with one
  optional space after the colon) or just ``field`` (empty value).
- Fields recognised: ``event``, ``data``, ``id``, ``retry``.
- Multiple ``data:`` lines concatenate joined by ``\\n``.
- A line starting with ``:`` is a comment and is ignored.

Hardening:

- ``MAX_EVENT_BYTES`` caps the size of a single buffered event.
- Lines without a colon are accepted as field-only-no-value (per spec).
- Invalid UTF-8 in any field replaced (lossy).
- ``retry`` field accepted but only validated as integer; the consumer
  can ignore it or use it for reconnection backoff.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

from argos_proxy.jsonrpc.errors import JsonRpcProtocolError

#: Cap on a single SSE event size. Real MCP messages fit in ~64 KB; we
#: leave a generous 8 MiB margin and refuse anything larger.
MAX_EVENT_BYTES: Final[int] = 8 * 1024 * 1024


class SseProtocolError(JsonRpcProtocolError):
    """Raised when the SSE stream is malformed beyond recovery."""


@dataclass(frozen=True)
class SseEvent:
    """One parsed SSE event.

    ``event`` defaults to ``"message"`` per the WHATWG spec when no
    ``event:`` field is present. ``data`` is the joined payload. ``id``
    and ``retry`` are optional.
    """

    event: str
    data: str
    id: str | None = None
    retry: int | None = None


class SseEventParser:
    """Streaming SSE parser. Feed bytes; receive complete events."""

    __slots__ = (
        "_buffer",
        "_data_lines",
        "_event_id",
        "_event_name",
        "_retry",
    )

    def __init__(self) -> None:
        self._buffer: bytearray = bytearray()
        self._reset_event()

    def _reset_event(self) -> None:
        self._data_lines: list[str] = []
        self._event_name: str | None = None
        self._event_id: str | None = None
        self._retry: int | None = None

    def feed(self, chunk: bytes) -> list[SseEvent]:
        """Append bytes; return any newly-completed events.

        Lines belonging to an unfinished event remain buffered. A
        ``\\n\\n`` (or ``\\r\\n\\r\\n``) closes the current event."""
        if not chunk:
            return []
        self._buffer.extend(chunk)
        out: list[SseEvent] = []
        while True:
            line, rest = _next_line(self._buffer)
            if line is None:
                break
            self._buffer = bytearray(rest)
            if not line:
                event = self._finish_event()
                if event is not None:
                    out.append(event)
                continue
            self._consume_line(line)
        # Two distinct DoS vectors to bound:
        #   1. A line longer than MAX_EVENT_BYTES with no terminator.
        #   2. Many short lines accumulated into ``data_lines`` without
        #      a blank-line event terminator.
        accumulated = (
            len(self._buffer)
            + sum(len(line) for line in self._data_lines)
            + (len(self._event_name or "") + len(self._event_id or ""))
        )
        if accumulated > MAX_EVENT_BYTES:
            msg = (
                f"SSE event accumulated {accumulated} bytes without a "
                f"blank-line terminator (cap {MAX_EVENT_BYTES})"
            )
            raise SseProtocolError(msg)
        return out

    def flush(self) -> list[SseEvent]:
        """Process any pending bytes assuming no more data will arrive.

        The streaming parser holds a trailing lone ``\\r`` in the buffer
        because it might be the start of ``\\r\\n``. Call ``flush`` when
        the upstream stream is closed so the dangling CR is interpreted
        as a real line terminator instead. Any partial line without its
        terminator gets one synthetically. An event without its
        blank-line terminator is *not* dispatched (per spec). Safe to
        call on an empty buffer."""
        if not self._buffer:
            return []
        out: list[SseEvent] = []
        # Append a synthetic LF. A trailing lone CR pairs with it into
        # a single CRLF terminator (one terminator, not two), and any
        # non-CR-terminated partial line receives a final terminator.
        self._buffer.append(0x0A)
        while True:
            line, rest = _next_line(self._buffer)
            if line is None:
                break
            self._buffer = bytearray(rest)
            if not line:
                event = self._finish_event()
                if event is not None:
                    out.append(event)
                continue
            self._consume_line(line)
        return out

    def _finish_event(self) -> SseEvent | None:
        # Spec: if the data buffer is empty and there is no event name,
        # the dispatch step is a no-op. Reset and emit nothing.
        if not self._data_lines and self._event_name is None:
            self._reset_event()
            return None
        data_joined = "\n".join(self._data_lines)
        # The "data:" lines never carry a trailing newline; one is
        # appended by the spec. Strip it for caller convenience: the
        # consumer typically wants the raw JSON payload.
        event = SseEvent(
            event=self._event_name or "message",
            data=data_joined,
            id=self._event_id,
            retry=self._retry,
        )
        self._reset_event()
        return event

    def _consume_line(self, line: str) -> None:
        if line.startswith(":"):
            # Comment line: ignore.
            return
        if ":" in line:
            field, _, value = line.partition(":")
            value = value.removeprefix(" ")
        else:
            # No colon -> field name only, empty value.
            field = line
            value = ""
        if field == "event":
            self._event_name = value
        elif field == "data":
            self._data_lines.append(value)
        elif field == "id":
            # NULs in id are forbidden by spec; if any, drop the field.
            if "\x00" not in value:
                self._event_id = value
        elif field == "retry" and value.isdigit():
            self._retry = int(value)


def _next_line(buf: bytearray) -> tuple[str | None, bytes]:
    """Cut off the next text line ending in ``\\n``, ``\\r\\n`` or
    ``\\r``. Returns ``(line, rest)`` or ``(None, buf)`` if no line is
    complete yet."""
    if not buf:
        return None, bytes(buf)
    # Search the earliest line terminator.
    nl = -1
    for i, b in enumerate(buf):
        if b in (0x0A, 0x0D):
            nl = i
            break
    if nl < 0:
        return None, bytes(buf)
    # Determine terminator length: \r\n is 2 bytes, otherwise 1.
    terminator_len = 1
    if buf[nl] == 0x0D and nl + 1 < len(buf) and buf[nl + 1] == 0x0A:
        terminator_len = 2
    elif buf[nl] == 0x0D and nl + 1 == len(buf):
        # Lone CR at end of buffer: wait for more data; might be \r\n.
        return None, bytes(buf)
    line_bytes = bytes(buf[:nl])
    rest = bytes(buf[nl + terminator_len :])
    try:
        line = line_bytes.decode("utf-8")
    except UnicodeDecodeError:
        line = line_bytes.decode("utf-8", errors="replace")
    return line, rest


# ---------------------------------------------------------------------------
# Encoder: building SSE output from messages.
# ---------------------------------------------------------------------------


def encode_sse_event(
    data: str,
    *,
    event: str | None = None,
    id_: str | None = None,
    retry_ms: int | None = None,
) -> bytes:
    """Serialise a single SSE event.

    Multi-line ``data`` values are split into multiple ``data:`` lines
    per the spec. ``event`` defaults to nothing (the consumer treats
    that as ``"message"``)."""
    lines: list[str] = []
    if event is not None:
        if "\n" in event or "\r" in event:
            msg = "event field must not contain newline characters"
            raise ValueError(msg)
        lines.append(f"event: {event}")
    if id_ is not None:
        if "\n" in id_ or "\r" in id_ or "\x00" in id_:
            msg = "id field must not contain newline or NUL characters"
            raise ValueError(msg)
        lines.append(f"id: {id_}")
    if retry_ms is not None:
        if retry_ms < 0:
            msg = "retry_ms must be non-negative"
            raise ValueError(msg)
        lines.append(f"retry: {retry_ms}")
    for chunk in data.split("\n"):
        lines.append(f"data: {chunk}")
    body = "\n".join(lines) + "\n\n"
    return body.encode("utf-8")


__all__ = [
    "MAX_EVENT_BYTES",
    "SseEvent",
    "SseEventParser",
    "SseProtocolError",
    "encode_sse_event",
]
