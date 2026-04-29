"""Server-side accepted transport.

Distinct from :class:`argos_proxy.transport.tcp.TcpTransport` (client side):
the accepted variant wraps a *pre-existing* ``StreamReader`` /
``StreamWriter`` pair handed to the ``client_connected_cb`` of
:func:`asyncio.start_server`. It does **not** initiate a connection.

The accepted transport does not own the listener; closing it shuts down
only its half of the duplex stream. The :class:`ProxyListener` (which
calls ``asyncio.start_server``) manages the listener lifecycle.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

from argos_proxy.jsonrpc import parse_payload
from argos_proxy.jsonrpc.framing import NDJSONFramer, StdioFramer, encode_message
from argos_proxy.transport._base import (
    ClosedTransportError,
    Transport,
)

if TYPE_CHECKING:
    from argos_proxy.jsonrpc import Batch, Message


_DEFAULT_READ_CHUNK: int = 4096


class TcpAcceptedTransport(Transport):
    """Wrap an accepted ``(reader, writer)`` pair into the typed transport.

    Parameters
    ----------
    reader, writer:
        The streams that ``asyncio.start_server`` passed to the
        connection handler.
    framing:
        ``"ndjson"`` (default; one JSON object per line) or ``"stdio"``
        (LSP-style ``Content-Length`` headers). Pin the framing at
        listener construction so all sessions agree.
    peer:
        Optional human-readable peer identifier (e.g. ``"127.0.0.1:53124"``)
        included in error messages and forensics.
    """

    __slots__ = (
        "_closed",
        "_framer",
        "_peer",
        "_read_lock",
        "_reader",
        "_write_lock",
        "_writer",
    )

    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        *,
        framing: str = "ndjson",
        peer: str | None = None,
    ) -> None:
        if framing not in {"ndjson", "stdio"}:
            msg = f"unsupported framing {framing!r}; expected 'ndjson' or 'stdio'"
            raise ValueError(msg)
        self._reader = reader
        self._writer = writer
        self._framer = NDJSONFramer() if framing == "ndjson" else StdioFramer()
        self._peer = peer or _peer_string(writer)
        self._read_lock = asyncio.Lock()
        self._write_lock = asyncio.Lock()
        self._closed = False

    @property
    def peer(self) -> str:
        return self._peer

    async def send(self, message: Message | Batch) -> None:
        if self._closed:
            msg = f"transport to {self._peer} is closed"
            raise ClosedTransportError(msg)
        # Encoding has to honour the framing the framer will demand on
        # the way back; stdio frame goes both ways. We pass the framer's
        # name implicitly via the constructor choice.
        framing = "ndjson" if isinstance(self._framer, NDJSONFramer) else "stdio"
        async with self._write_lock:
            try:
                self._writer.write(encode_message(message, framing=framing))
                await self._writer.drain()
            except (ConnectionResetError, BrokenPipeError) as exc:
                self._closed = True
                msg = f"connection to {self._peer} closed: {exc}"
                raise ClosedTransportError(msg) from exc

    async def receive(self) -> Message | Batch:
        if self._closed:
            msg = f"transport to {self._peer} is closed"
            raise ClosedTransportError(msg)
        async with self._read_lock:
            while True:
                # Drain any bodies the framer already buffered.
                bodies = self._framer.feed(b"")
                if bodies:
                    return parse_payload(bodies[0])
                try:
                    chunk = await self._reader.read(_DEFAULT_READ_CHUNK)
                except (ConnectionResetError, BrokenPipeError) as exc:
                    self._closed = True
                    msg = f"connection from {self._peer} reset: {exc}"
                    raise ClosedTransportError(msg) from exc
                except asyncio.IncompleteReadError as exc:
                    self._closed = True
                    msg = f"connection from {self._peer} truncated"
                    raise ClosedTransportError(msg) from exc
                if not chunk:
                    self._closed = True
                    msg = f"peer {self._peer} closed the connection"
                    raise ClosedTransportError(msg)
                ready = self._framer.feed(chunk)
                if ready:
                    return parse_payload(ready[0])

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            self._writer.close()
            try:
                await self._writer.wait_closed()
            except (ConnectionResetError, BrokenPipeError, OSError):
                # Peer may already have hung up; that is benign on close.
                pass
        except Exception:  # noqa: BLE001
            # Idempotent close must never raise.
            pass

    @property
    def is_closed(self) -> bool:
        return self._closed


def _peer_string(writer: asyncio.StreamWriter) -> str:
    """Best-effort peer-name extraction. Falls back to ``"unknown"`` when
    the underlying transport does not expose ``get_extra_info``."""
    try:
        info = writer.get_extra_info("peername")
        if info:
            host, port, *_ = info
            return f"{host}:{port}"
    except Exception:  # noqa: BLE001 - best-effort
        pass
    return "unknown"


__all__ = ["TcpAcceptedTransport"]
