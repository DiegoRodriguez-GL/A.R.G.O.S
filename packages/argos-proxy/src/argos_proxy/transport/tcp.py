"""TCP transport with NDJSON framing.

Many MCP servers expose JSON-RPC over a plain TCP socket (one JSON
object per line). The transport speaks NDJSON because Content-Length
on TCP is unusual; if a future deployment requires it the same class
can be parametrised on framing.

This transport does NOT enable TLS. The proxy is documented as
local-first (loopback only); the threat model assumes the operator
controls the network path. A TLS-enabled transport is a [EXTENSION] in
the roadmap.
"""

from __future__ import annotations

import asyncio

from argos_proxy.jsonrpc import Batch, Message, parse_payload
from argos_proxy.jsonrpc.framing import NDJSONFramer, encode_message
from argos_proxy.transport._base import (
    ClosedTransportError,
    Transport,
    TransportError,
)


class TcpTransport(Transport):
    """Client-side TCP transport over NDJSON framing."""

    __slots__ = (
        "_closed",
        "_framer",
        "_host",
        "_port",
        "_read_lock",
        "_reader",
        "_write_lock",
        "_writer",
    )

    def __init__(self, host: str, port: int) -> None:
        if not host:
            msg = "host must be a non-empty string"
            raise ValueError(msg)
        if port <= 0 or port > 65535:
            msg = f"port {port} out of range [1, 65535]"
            raise ValueError(msg)
        self._host = host
        self._port = port
        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None
        self._framer = NDJSONFramer()
        self._read_lock = asyncio.Lock()
        self._write_lock = asyncio.Lock()
        self._closed = False

    async def connect(self) -> None:
        """Open the TCP connection. Idempotent."""
        if self._reader is not None:
            return
        try:
            self._reader, self._writer = await asyncio.open_connection(
                self._host,
                self._port,
            )
        except OSError as exc:
            msg = f"failed to connect to {self._host}:{self._port}: {exc}"
            raise TransportError(msg) from exc

    async def send(self, message: Message | Batch) -> None:
        if self._closed:
            msg = "transport is closed"
            raise ClosedTransportError(msg)
        if self._writer is None:
            await self.connect()
        writer = self._writer
        if writer is None:  # pragma: no cover - guard
            msg = "writer not available"
            raise TransportError(msg)
        async with self._write_lock:
            try:
                writer.write(encode_message(message, framing="ndjson"))
                await writer.drain()
            except (ConnectionResetError, BrokenPipeError) as exc:
                self._closed = True
                msg = f"connection closed: {exc}"
                raise ClosedTransportError(msg) from exc

    async def receive(self) -> Message | Batch:
        if self._closed:
            msg = "transport is closed"
            raise ClosedTransportError(msg)
        if self._reader is None:
            await self.connect()
        reader = self._reader
        if reader is None:  # pragma: no cover - guard
            msg = "reader not available"
            raise TransportError(msg)
        async with self._read_lock:
            while True:
                bodies = self._framer.feed(b"")
                if bodies:
                    return parse_payload(bodies[0])
                chunk = await reader.read(4096)
                if not chunk:
                    self._closed = True
                    msg = "peer closed the connection"
                    raise ClosedTransportError(msg)
                ready = self._framer.feed(chunk)
                if ready:
                    return parse_payload(ready[0])

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        if self._writer is not None:
            self._writer.close()
            try:
                await self._writer.wait_closed()
            except (ConnectionResetError, BrokenPipeError):
                pass

    @property
    def is_closed(self) -> bool:
        return self._closed
