"""Stdio transport: spawns an upstream subprocess and reads/writes
JSON-RPC over its stdin/stdout pipes.

The MCP convention is ``Content-Length`` framing on stdio (mirrored
from the Language Server Protocol). Most reference MCP servers
(``npx @modelcontextprotocol/server-filesystem``, anthropic's
``mcp-server-time``, etc.) use this transport.

The transport owns the subprocess lifecycle. Calling :meth:`close`
sends ``SIGTERM`` followed by ``SIGKILL`` after a grace period.
"""

from __future__ import annotations

import asyncio
import os
from collections.abc import Sequence

from argos_proxy.jsonrpc import Batch, Message, parse_payload
from argos_proxy.jsonrpc.framing import StdioFramer, encode_message
from argos_proxy.transport._base import (
    ClosedTransportError,
    Transport,
    TransportError,
)

#: Grace period (seconds) to wait for the subprocess to exit on
#: SIGTERM before escalating to SIGKILL.
_TERMINATION_GRACE: float = 2.0


class StdioTransport(Transport):
    """Connect to an MCP server spawned as a child process.

    The transport intentionally hides ``Popen`` details: the proxy
    server never reads from ``self._process.stdout`` directly. All I/O
    flows through the typed message contract.
    """

    __slots__ = (
        "_argv",
        "_closed",
        "_env",
        "_framer",
        "_process",
        "_read_lock",
        "_write_lock",
    )

    def __init__(
        self,
        argv: Sequence[str],
        *,
        env: dict[str, str] | None = None,
    ) -> None:
        if not argv:
            msg = "argv must contain at least the executable name"
            raise ValueError(msg)
        self._argv: tuple[str, ...] = tuple(argv)
        self._env = dict(env) if env is not None else None
        self._process: asyncio.subprocess.Process | None = None
        self._framer = StdioFramer()
        self._read_lock = asyncio.Lock()
        self._write_lock = asyncio.Lock()
        self._closed = False

    async def start(self) -> None:
        """Spawn the upstream subprocess. Idempotent."""
        if self._process is not None:
            return
        # Inherit the parent environment unless an override is given.
        env = os.environ.copy() if self._env is None else self._env
        self._process = await asyncio.create_subprocess_exec(
            *self._argv,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env,
        )

    async def send(self, message: Message | Batch) -> None:
        if self._closed:
            msg = "transport is closed"
            raise ClosedTransportError(msg)
        if self._process is None:
            await self.start()
        proc = self._process
        if proc is None or proc.stdin is None:  # pragma: no cover - guard
            msg = "subprocess stdin not available"
            raise TransportError(msg)
        async with self._write_lock:
            try:
                proc.stdin.write(encode_message(message, framing="stdio"))
                await proc.stdin.drain()
            except (ConnectionResetError, BrokenPipeError) as exc:
                self._closed = True
                msg = f"upstream stdin closed: {exc}"
                raise ClosedTransportError(msg) from exc

    async def receive(self) -> Message | Batch:
        if self._closed:
            msg = "transport is closed"
            raise ClosedTransportError(msg)
        if self._process is None:
            await self.start()
        proc = self._process
        if proc is None or proc.stdout is None:  # pragma: no cover - guard
            msg = "subprocess stdout not available"
            raise TransportError(msg)
        async with self._read_lock:
            while True:
                # Pull whatever framing is already buffered.
                bodies = self._framer.feed(b"")
                if bodies:
                    return parse_payload(bodies[0])
                chunk = await proc.stdout.read(4096)
                if not chunk:
                    self._closed = True
                    msg = "upstream stdout closed"
                    raise ClosedTransportError(msg)
                ready = self._framer.feed(chunk)
                if ready:
                    return parse_payload(ready[0])

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        proc = self._process
        if proc is None:
            return
        if proc.returncode is not None:
            return
        proc.terminate()
        try:
            await asyncio.wait_for(proc.wait(), timeout=_TERMINATION_GRACE)
        except TimeoutError:
            proc.kill()
            await proc.wait()

    @property
    def is_closed(self) -> bool:
        return self._closed
