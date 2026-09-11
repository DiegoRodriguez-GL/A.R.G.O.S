"""Downstream stdio transport: this process plays the MCP server.

``argos proxy wrap`` uses it to sit inside any MCP client that launches
servers as child processes (Claude Desktop, VS Code, Cursor, the MCP
Inspector). The client starts ARGOS as if it were the server, ARGOS
starts the real server as its own child, and every message crosses the
detector chain in between. The wire format is the one the
specification defines for stdio: newline-delimited JSON.

Reading happens on a daemon thread. asyncio has no portable way to
watch the inherited standard input of the current process (the Windows
proactor loop cannot register it), and a blocking ``readline`` on a
thread behaves the same on every platform. Writes go through
:func:`asyncio.to_thread` under a lock so a slow client cannot stall the
event loop and messages never interleave.
"""

from __future__ import annotations

import asyncio
import contextlib
import sys
import threading
from typing import BinaryIO

from argos_proxy.jsonrpc import Batch, Message, parse_payload
from argos_proxy.jsonrpc.framing import MAX_MESSAGE_BYTES, FrameDecodeError, encode_message
from argos_proxy.transport._base import ClosedTransportError, Transport

#: Sentinel queued by the reader thread when the input ends.
_EOF = b""


class StdioServerTransport(Transport):
    """Serve one MCP client over this process's stdin and stdout.

    ``reader`` and ``writer`` default to the process streams; tests pass
    pipes instead. Standard output must carry protocol messages only, so
    callers route every human-readable line to stderr.
    """

    __slots__ = (
        "_closed",
        "_loop",
        "_queue",
        "_reader",
        "_thread",
        "_write_lock",
        "_writer",
    )

    def __init__(
        self,
        reader: BinaryIO | None = None,
        writer: BinaryIO | None = None,
    ) -> None:
        self._reader: BinaryIO = reader if reader is not None else sys.stdin.buffer
        self._writer: BinaryIO = writer if writer is not None else sys.stdout.buffer
        self._queue: asyncio.Queue[bytes] | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._thread: threading.Thread | None = None
        self._write_lock = asyncio.Lock()
        self._closed = False

    def _ensure_reader(self) -> asyncio.Queue[bytes]:
        if self._queue is None:
            self._loop = asyncio.get_running_loop()
            self._queue = asyncio.Queue()
            self._thread = threading.Thread(
                target=self._read_loop,
                name="argos-stdio-reader",
                daemon=True,
            )
            self._thread.start()
        return self._queue

    def _read_loop(self) -> None:
        loop, queue = self._loop, self._queue
        if loop is None or queue is None:  # pragma: no cover - guard
            return
        try:
            while True:
                line = self._reader.readline(MAX_MESSAGE_BYTES + 1)
                if not line or (len(line) > MAX_MESSAGE_BYTES and not line.endswith(b"\n")):
                    break
                loop.call_soon_threadsafe(queue.put_nowait, line)
        except (OSError, ValueError):
            pass
        finally:
            with contextlib.suppress(RuntimeError):
                loop.call_soon_threadsafe(queue.put_nowait, _EOF)

    async def receive(self) -> Message | Batch:
        if self._closed:
            msg = "transport is closed"
            raise ClosedTransportError(msg)
        queue = self._ensure_reader()
        while True:
            line = await queue.get()
            if line == _EOF:
                self._closed = True
                msg = "client closed stdin"
                raise ClosedTransportError(msg)
            body = line.strip()
            if not body:
                continue
            return parse_payload(body)

    async def send(self, message: Message | Batch) -> None:
        if self._closed:
            msg = "transport is closed"
            raise ClosedTransportError(msg)
        try:
            data = encode_message(message, framing="ndjson")
        except FrameDecodeError as exc:
            msg = f"cannot encode message for the client: {exc}"
            raise ClosedTransportError(msg) from exc
        async with self._write_lock:
            try:
                await asyncio.to_thread(self._write, data)
            except (OSError, ValueError) as exc:
                self._closed = True
                msg = f"client stdout closed: {exc}"
                raise ClosedTransportError(msg) from exc

    def _write(self, data: bytes) -> None:
        self._writer.write(data)
        self._writer.flush()

    async def close(self) -> None:
        # The process streams belong to the process; they are not closed here.
        self._closed = True

    @property
    def is_closed(self) -> bool:
        return self._closed


__all__ = ["StdioServerTransport"]
