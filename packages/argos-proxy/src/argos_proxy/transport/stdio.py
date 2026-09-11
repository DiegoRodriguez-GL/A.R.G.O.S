"""Stdio transport: spawns an upstream subprocess and reads/writes
JSON-RPC over its stdin/stdout pipes.

Framing. The MCP specification (every revision from 2024-11-05 to
2025-06-18) defines the stdio transport as newline-delimited JSON: one
UTF-8 JSON-RPC message per line, with no embedded newlines. That is the
default here and what the reference servers speak
(``@modelcontextprotocol/server-*`` on npm, ``mcp-server-*`` on PyPI).
The LSP-style ``Content-Length`` framing remains available through
``framing="content-length"`` for servers written before the
specification settled.

Process handling follows the shutdown sequence the specification
recommends: close the child's stdin, wait, then terminate, then kill.
The child's stderr is drained continuously, because a server that logs
more than the pipe buffer holds would otherwise block forever on its
next write, and the last lines are kept for diagnostics.

On Windows the executable is resolved with :func:`shutil.which`, so
launchers such as ``npx`` or ``uvx`` (``.cmd`` and ``.exe`` shims) start
exactly as they do from a shell.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import shutil
import sys
from collections import deque
from collections.abc import Sequence
from pathlib import Path
from typing import TYPE_CHECKING, Final

from argos_proxy.jsonrpc import Batch, Message, parse_payload
from argos_proxy.jsonrpc.framing import NDJSONFramer, StdioFramer, encode_message
from argos_proxy.transport._base import (
    ClosedTransportError,
    Transport,
    TransportError,
)

if TYPE_CHECKING:
    from logging import Logger

_log: Logger = logging.getLogger("argos.proxy.stdio")

#: Grace period (seconds) granted at each step of the shutdown sequence.
_TERMINATION_GRACE: float = 2.0

#: Number of stderr lines kept for diagnostics.
_STDERR_TAIL_LINES: Final[int] = 50

#: Cap on a single buffered stderr line; longer lines are cut.
_STDERR_LINE_CAP: Final[int] = 4096

_READ_CHUNK: Final[int] = 65536

#: Accepted spellings for each framing, mapped to the wire name used by
#: :func:`argos_proxy.jsonrpc.framing.encode_message`.
_FRAMINGS: Final[dict[str, str]] = {
    "ndjson": "ndjson",
    "newline": "ndjson",
    "content-length": "stdio",
    "lsp": "stdio",
    "stdio": "stdio",
}


def normalise_framing(framing: str) -> str:
    """Return the wire framing name for a user-facing spelling.

    Raises :class:`ValueError` for anything that is not NDJSON or
    ``Content-Length``.
    """
    wire = _FRAMINGS.get(framing.strip().lower())
    if wire is None:
        msg = f"unsupported stdio framing {framing!r}; expected 'ndjson' or 'content-length'"
        raise ValueError(msg)
    return wire


def resolve_executable(argv: Sequence[str]) -> tuple[str, ...]:
    """Return ``argv`` with its first element resolved through ``PATH``.

    An explicit path (anything with a directory part) is kept untouched.
    A bare name is looked up with :func:`shutil.which`, which honours
    ``PATHEXT`` on Windows; when the lookup fails the name is returned
    unchanged and process creation reports the error.
    """
    head, *rest = argv
    if Path(head).parent != Path():
        return (head, *rest)
    found = shutil.which(head)
    return (found or head, *rest)


class StdioTransport(Transport):
    """Connect to an MCP server spawned as a child process.

    The transport hides the process details: the proxy server never
    reads from the child's pipes directly. All I/O flows through the
    typed message contract.
    """

    __slots__ = (
        "_argv",
        "_closed",
        "_env",
        "_framer",
        "_framing",
        "_pending",
        "_process",
        "_read_lock",
        "_stderr_tail",
        "_stderr_task",
        "_stdout_noise",
        "_write_lock",
    )

    def __init__(
        self,
        argv: Sequence[str],
        *,
        env: dict[str, str] | None = None,
        framing: str = "ndjson",
    ) -> None:
        if not argv:
            msg = "argv must contain at least the executable name"
            raise ValueError(msg)
        self._argv: tuple[str, ...] = tuple(argv)
        self._env = dict(env) if env is not None else None
        self._framing = normalise_framing(framing)
        self._framer: NDJSONFramer | StdioFramer = (
            NDJSONFramer() if self._framing == "ndjson" else StdioFramer()
        )
        self._pending: deque[bytes] = deque()
        self._process: asyncio.subprocess.Process | None = None
        self._stderr_task: asyncio.Task[None] | None = None
        self._stderr_tail: deque[str] = deque(maxlen=_STDERR_TAIL_LINES)
        self._stdout_noise = 0
        self._read_lock = asyncio.Lock()
        self._write_lock = asyncio.Lock()
        self._closed = False

    # --- introspection ----------------------------------------------------
    @property
    def framing(self) -> str:
        """User-facing framing name: ``"ndjson"`` or ``"content-length"``."""
        return "ndjson" if self._framing == "ndjson" else "content-length"

    @property
    def pid(self) -> int | None:
        return None if self._process is None else self._process.pid

    @property
    def stderr_tail(self) -> tuple[str, ...]:
        """Last lines the child wrote to stderr (oldest first)."""
        return tuple(self._stderr_tail)

    @property
    def stdout_noise_lines(self) -> int:
        """Non-protocol lines the child printed on stdout (skipped)."""
        return self._stdout_noise

    # --- lifecycle --------------------------------------------------------
    async def start(self) -> None:
        """Spawn the upstream subprocess. Idempotent."""
        if self._process is not None:
            return
        # Inherit the parent environment unless an override is given.
        env = os.environ.copy() if self._env is None else self._env
        argv = resolve_executable(self._argv)
        try:
            self._process = await asyncio.create_subprocess_exec(
                *argv,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env,
            )
        except OSError as exc:
            msg = f"cannot start upstream {self._argv[0]!r}: {exc}"
            raise TransportError(msg) from exc
        self._stderr_task = asyncio.create_task(
            self._drain_stderr(),
            name="argos.proxy.stdio.stderr",
        )

    async def _drain_stderr(self) -> None:
        proc = self._process
        if proc is None or proc.stderr is None:  # pragma: no cover - guard
            return
        partial = bytearray()
        try:
            while True:
                chunk = await proc.stderr.read(_READ_CHUNK)
                if not chunk:
                    break
                partial.extend(chunk)
                *lines, rest = partial.split(b"\n")
                partial = bytearray(rest[:_STDERR_LINE_CAP])
                for raw in lines:
                    self._remember_stderr(bytes(raw))
        except (OSError, ValueError, asyncio.CancelledError):
            return
        if partial:
            self._remember_stderr(bytes(partial))

    def _remember_stderr(self, raw: bytes) -> None:
        text = raw[:_STDERR_LINE_CAP].decode("utf-8", errors="replace").rstrip()
        if text:
            self._stderr_tail.append(text)
            _log.debug("upstream stderr: %s", text)

    # --- I/O --------------------------------------------------------------
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
                proc.stdin.write(encode_message(message, framing=self._framing))
                await proc.stdin.drain()
            except (ConnectionResetError, BrokenPipeError) as exc:
                self._closed = True
                msg = f"upstream stdin closed: {exc}"
                raise ClosedTransportError(msg) from exc

    async def receive(self) -> Message | Batch:
        if self._closed and not self._pending:
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
                # Every complete body the framer produced is kept: a single
                # read often carries a notification and a response together.
                while self._pending:
                    body = self._pending.popleft()
                    if self._framing == "ndjson" and not _looks_like_json(body):
                        # The specification forbids non-protocol output on
                        # stdout, yet some servers print a banner there.
                        # Skip it and keep it for diagnostics instead of
                        # tearing the session down.
                        if body.strip():
                            self._stdout_noise += 1
                            self._remember_stderr(b"[stdout] " + body)
                        continue
                    return parse_payload(body)
                chunk = await proc.stdout.read(_READ_CHUNK)
                if not chunk:
                    self._closed = True
                    detail = f" (stderr: {self._stderr_tail[-1]})" if self._stderr_tail else ""
                    msg = f"upstream stdout closed{detail}"
                    raise ClosedTransportError(msg)
                self._pending.extend(self._framer.feed(chunk))

    async def close(self) -> None:
        if self._closed and self._process is None:
            return
        self._closed = True
        proc = self._process
        if proc is not None and proc.returncode is None:
            await _shutdown(proc)
        if self._stderr_task is not None:
            self._stderr_task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await self._stderr_task
            self._stderr_task = None

    @property
    def is_closed(self) -> bool:
        return self._closed


def _looks_like_json(body: bytes) -> bool:
    stripped = body.lstrip()
    return stripped[:1] in (b"{", b"[")


async def _shutdown(proc: asyncio.subprocess.Process) -> None:
    """Close stdin, then terminate, then kill, waiting between steps."""
    if proc.stdin is not None:
        with contextlib.suppress(Exception):
            proc.stdin.close()
    try:
        await asyncio.wait_for(proc.wait(), timeout=_TERMINATION_GRACE)
    except TimeoutError:
        pass
    else:
        return
    await _terminate_tree(proc)
    try:
        await asyncio.wait_for(proc.wait(), timeout=_TERMINATION_GRACE)
    except TimeoutError:
        with contextlib.suppress(ProcessLookupError):
            proc.kill()
        with contextlib.suppress(Exception):
            await proc.wait()


async def _terminate_tree(proc: asyncio.subprocess.Process) -> None:
    """Terminate the child and, on Windows, every process it started.

    Launchers such as ``npx.cmd`` run the real server as a grandchild;
    terminating only the shim would leave the server orphaned.
    """
    if sys.platform == "win32":
        try:
            killer = await asyncio.create_subprocess_exec(
                "taskkill",
                "/PID",
                str(proc.pid),
                "/T",
                "/F",
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            await asyncio.wait_for(killer.wait(), timeout=_TERMINATION_GRACE)
        except (OSError, TimeoutError):
            pass
        else:
            return
    with contextlib.suppress(ProcessLookupError):
        proc.terminate()


__all__ = [
    "StdioTransport",
    "normalise_framing",
    "resolve_executable",
]
