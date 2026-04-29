"""ARGOS audit proxy listener.

The :class:`ProxyListener` wraps :func:`asyncio.start_server` to accept
many simultaneous downstream clients, each connected to its own freshly
built upstream via the configured :class:`UpstreamFactory`. Every
session runs an independent :class:`ProxyServer` so traffic between
clients never crosses the interceptor's per-session state (e.g. the
:class:`ToolDriftDetector` baseline).

The listener provides four operational guarantees that a real MCP audit
deployment requires:

- **Bounded concurrency.** ``max_sessions`` (default 64) caps the number
  of in-flight sessions. New connections beyond the cap are rejected
  immediately with a structured \\
  ``server_busy`` notice on the wire (closing the socket would leave
  the client guessing).
- **Idle timeout.** ``session_idle_timeout`` (default 600 s) closes
  sessions that have not exchanged a message in that window. Prevents
  slow-loris exhaustion of the session table.
- **Graceful shutdown.** ``stop()`` stops accepting new connections,
  drains active sessions for ``drain_timeout`` seconds (default 5),
  then cancels any stragglers. The drain semantics match how Linux
  service managers (systemd, runit) expect a graceful daemon to behave.
- **Forensics + interceptor sharing.** A single
  :class:`ChainInterceptor` can be shared across sessions when its
  state is global (PII detector, scope detector). A per-session
  interceptor is built via the optional ``interceptor_factory`` when the
  state must NOT be shared (tool drift, which pins a per-session
  baseline).

The listener exposes :class:`SessionManager` metrics: total sessions
served, sessions active right now, bytes counters can be added by
subclassing.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Final

from argos_proxy.interceptor import ProxyInterceptor
from argos_proxy.server import ProxyServer
from argos_proxy.transport._base import ClosedTransportError, TransportError
from argos_proxy.transport.accepted import TcpAcceptedTransport

if TYPE_CHECKING:
    from logging import Logger

    from argos_proxy.transport.upstream_factory import UpstreamFactory


_log: Logger = logging.getLogger("argos.proxy.listener")

#: Hard cap on session count -- defensive ceiling regardless of caller
#: configuration. A multi-tenant deployment that needs more should run
#: multiple listener instances behind a load balancer.
_HARD_MAX_SESSIONS: Final[int] = 1024

#: Hard cap on idle timeout (24 h). Anything longer is almost certainly
#: a configuration mistake and would let a half-open session keep a
#: forensic row warm forever.
_HARD_MAX_IDLE_SECONDS: Final[float] = 86400.0


@dataclass
class SessionMetrics:
    """In-memory metrics for one accepted session.

    The dataclass is mutable on purpose: counters update across the
    session lifetime. Reading it from outside the session loop is safe
    because the listener guarantees a single writer per session."""

    session_id: str
    peer: str
    started_at: float = field(default_factory=time.monotonic)
    finished_at: float | None = None
    bytes_to_upstream: int = 0
    bytes_from_upstream: int = 0
    messages_to_upstream: int = 0
    messages_from_upstream: int = 0
    error: str | None = None

    @property
    def duration_seconds(self) -> float:
        end = self.finished_at if self.finished_at is not None else time.monotonic()
        return end - self.started_at

    @property
    def is_active(self) -> bool:
        return self.finished_at is None


class SessionManager:
    """Track live sessions, enforce concurrency cap and expose metrics.

    The manager is not thread-safe; it is consumed only from the
    listener's event loop."""

    __slots__ = ("_active", "_max_sessions", "_total_started")

    def __init__(self, *, max_sessions: int) -> None:
        if max_sessions <= 0 or max_sessions > _HARD_MAX_SESSIONS:
            msg = f"max_sessions must be in [1, {_HARD_MAX_SESSIONS}], got {max_sessions}"
            raise ValueError(msg)
        self._max_sessions = max_sessions
        self._active: dict[str, SessionMetrics] = {}
        self._total_started: int = 0

    @property
    def active_count(self) -> int:
        return len(self._active)

    @property
    def max_sessions(self) -> int:
        return self._max_sessions

    @property
    def total_started(self) -> int:
        return self._total_started

    @property
    def at_capacity(self) -> bool:
        return self.active_count >= self._max_sessions

    def open(self, peer: str) -> SessionMetrics:
        session_id = "argos-sess-" + uuid.uuid4().hex[:12]
        metrics = SessionMetrics(session_id=session_id, peer=peer)
        self._active[session_id] = metrics
        self._total_started += 1
        return metrics

    def close(self, session_id: str, *, error: str | None = None) -> SessionMetrics | None:
        metrics = self._active.pop(session_id, None)
        if metrics is not None:
            metrics.finished_at = time.monotonic()
            if error is not None:
                metrics.error = error
        return metrics

    def snapshot_active(self) -> list[SessionMetrics]:
        return list(self._active.values())


# ---------------------------------------------------------------------------
# ProxyListener
# ---------------------------------------------------------------------------


# Type alias: a function that builds a fresh interceptor per session.
InterceptorFactory = Callable[[], ProxyInterceptor]


class ProxyListener:
    """Accept downstream MCP clients on a TCP port, ferry to an upstream.

    Parameters
    ----------
    host, port:
        Listening address. Use ``"127.0.0.1"`` for local-only, ``"::"``
        for dual-stack.
    upstream_factory:
        Builder of fresh upstream transports per session.
    interceptor:
        Shared interceptor across sessions. When ``None``, a default
        pass-through interceptor is built per session via
        ``interceptor_factory``.
    interceptor_factory:
        Builder of per-session interceptors when state must not be
        shared. Mutually exclusive with ``interceptor``.
    framing:
        Wire framing for accepted clients (``"ndjson"`` default).
    max_sessions:
        Concurrency cap (default 64).
    session_idle_timeout:
        Per-session inactivity cap, seconds (default 600).
    drain_timeout:
        On shutdown, seconds to wait for active sessions to finish.

    The listener is started via :meth:`start` and stopped via
    :meth:`stop`. Calling :meth:`serve_forever` blocks until ``stop`` is
    called from another coroutine (e.g. a signal handler).
    """

    __slots__ = (
        "_drain_timeout",
        "_framing",
        "_host",
        "_idle_timeout",
        "_interceptor",
        "_interceptor_factory",
        "_port",
        "_running",
        "_server",
        "_session_tasks",
        "_sessions",
        "_started",
        "_stopped",
        "_upstream_factory",
    )

    def __init__(
        self,
        *,
        host: str,
        port: int,
        upstream_factory: UpstreamFactory,
        interceptor: ProxyInterceptor | None = None,
        interceptor_factory: InterceptorFactory | None = None,
        framing: str = "ndjson",
        max_sessions: int = 64,
        session_idle_timeout: float = 600.0,
        drain_timeout: float = 5.0,
    ) -> None:
        if interceptor is not None and interceptor_factory is not None:
            msg = "pass either ``interceptor`` or ``interceptor_factory``, not both"
            raise ValueError(msg)
        if not host:
            msg = "host must be a non-empty string"
            raise ValueError(msg)
        if port < 0 or port > 65535:
            msg = f"port {port} out of range [0, 65535]"
            raise ValueError(msg)
        if framing not in {"ndjson", "stdio"}:
            msg = f"framing must be 'ndjson' or 'stdio', got {framing!r}"
            raise ValueError(msg)
        if session_idle_timeout <= 0 or session_idle_timeout > _HARD_MAX_IDLE_SECONDS:
            msg = (
                f"session_idle_timeout must be in (0, {_HARD_MAX_IDLE_SECONDS}], "
                f"got {session_idle_timeout}"
            )
            raise ValueError(msg)
        if drain_timeout < 0:
            msg = f"drain_timeout must be >= 0, got {drain_timeout}"
            raise ValueError(msg)

        self._host = host
        self._port = port
        self._upstream_factory = upstream_factory
        self._interceptor = interceptor
        self._interceptor_factory = interceptor_factory
        self._framing = framing
        self._idle_timeout = session_idle_timeout
        self._drain_timeout = drain_timeout
        self._sessions = SessionManager(max_sessions=max_sessions)
        self._session_tasks: set[asyncio.Task[None]] = set()
        self._server: asyncio.base_events.Server | None = None
        self._started = asyncio.Event()
        self._stopped = asyncio.Event()
        self._running = False

    # --- introspection -----------------------------------------------------
    @property
    def host(self) -> str:
        return self._host

    @property
    def port(self) -> int:
        return self._port

    @property
    def sessions(self) -> SessionManager:
        return self._sessions

    @property
    def is_running(self) -> bool:
        return self._running

    def bound_address(self) -> tuple[str, int] | None:
        """Return the actual host:port the listener is bound to.

        Useful when the caller passed ``port=0`` to let the kernel
        assign an ephemeral port (typical in tests).
        """
        if self._server is None:
            return None
        sockets = self._server.sockets or ()
        if not sockets:
            return None
        host, port, *_ = sockets[0].getsockname()
        return host, port

    # --- lifecycle ---------------------------------------------------------
    async def start(self) -> None:
        if self._running:
            msg = "ProxyListener already running"
            raise RuntimeError(msg)
        self._server = await asyncio.start_server(
            self._handle_client,
            host=self._host,
            port=self._port,
            start_serving=False,
        )
        self._running = True
        await self._server.start_serving()
        self._started.set()

    async def serve_forever(self) -> None:
        if not self._running:
            await self.start()
        await self._stopped.wait()

    async def stop(self) -> None:
        """Stop accepting new connections, drain active sessions, close.

        Idempotent: calling ``stop`` after the listener has already
        stopped is a no-op.

        Order matters:

        1. ``server.close()`` so the kernel stops accepting new
           connections (existing ones survive).
        2. Drain active session tasks for ``drain_timeout`` seconds.
           If still alive, cancel them.
        3. ``server.wait_closed()`` AFTER sessions are gone (otherwise
           it blocks on accepted connections that have not been
           shut down yet).
        """
        if self._stopped.is_set():
            return
        server = self._server
        self._server = None
        if server is not None:
            server.close()
        # Drain active sessions.
        active_tasks = list(self._session_tasks)
        if active_tasks:
            try:
                await asyncio.wait_for(
                    asyncio.gather(*active_tasks, return_exceptions=True),
                    timeout=self._drain_timeout,
                )
            except TimeoutError:
                _log.warning(
                    "drain timeout (%.1fs) elapsed with %d sessions still active; "
                    "cancelling stragglers",
                    self._drain_timeout,
                    sum(1 for t in active_tasks if not t.done()),
                )
                for task in active_tasks:
                    if not task.done():
                        task.cancel()
                # Wait once more so cancellations propagate.
                with contextlib.suppress(Exception):
                    await asyncio.wait_for(
                        asyncio.gather(*active_tasks, return_exceptions=True),
                        timeout=max(self._drain_timeout, 1.0),
                    )
        # Now close the server fully.
        if server is not None:
            with contextlib.suppress(Exception):
                await asyncio.wait_for(server.wait_closed(), timeout=2.0)
        self._running = False
        self._stopped.set()

    async def __aenter__(self) -> ProxyListener:
        await self.start()
        return self

    async def __aexit__(self, *_exc: object) -> None:
        await self.stop()

    # --- per-connection handler -------------------------------------------
    async def _handle_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Single-connection coroutine.

        Created by :func:`asyncio.start_server` per accepted socket. Owns
        the lifecycle of one :class:`ProxyServer` instance and one
        upstream transport built fresh from the factory.
        """
        peer = _peer_string(writer)
        if self._sessions.at_capacity:
            await _send_busy_then_close(writer, peer)
            return

        metrics = self._sessions.open(peer)
        client_transport = TcpAcceptedTransport(
            reader,
            writer,
            framing=self._framing,
            peer=peer,
        )

        # Build upstream + interceptor for this session.
        try:
            upstream = await self._upstream_factory()
        except (TransportError, ClosedTransportError) as exc:
            _log.warning("upstream factory failed for %s: %s", peer, exc)
            await client_transport.close()
            self._sessions.close(metrics.session_id, error=f"upstream init: {exc}")
            return
        except Exception as exc:  # noqa: BLE001 - defensive, factory is user code
            _log.exception("unexpected upstream factory error for %s", peer)
            await client_transport.close()
            self._sessions.close(metrics.session_id, error=f"upstream factory: {exc}")
            return

        interceptor = self._build_interceptor()
        proxy = ProxyServer(client=client_transport, upstream=upstream, interceptor=interceptor)
        task = asyncio.current_task()
        if task is not None:
            self._session_tasks.add(task)

        try:
            run_task = asyncio.create_task(
                proxy.run(), name=f"argos.proxy.session.{metrics.session_id}"
            )
            try:
                await asyncio.wait_for(run_task, timeout=self._idle_timeout)
            except TimeoutError:
                _log.info("session %s idle-timeout (%.1fs)", metrics.session_id, self._idle_timeout)
                await proxy.stop()
                with contextlib.suppress(Exception):
                    await asyncio.wait_for(run_task, timeout=self._drain_timeout)
                self._sessions.close(metrics.session_id, error="idle_timeout")
                return
            except Exception as exc:  # noqa: BLE001
                _log.exception("session %s crashed", metrics.session_id)
                self._sessions.close(metrics.session_id, error=f"crashed: {exc}")
                return
        finally:
            await proxy.stop()
            await client_transport.close()
            with contextlib.suppress(Exception):
                await upstream.close()
            if task is not None:
                self._session_tasks.discard(task)
            # Only close metrics if not already closed by the timeout/crash branch.
            if metrics.is_active:
                self._sessions.close(metrics.session_id)

    def _build_interceptor(self) -> ProxyInterceptor | None:
        if self._interceptor is not None:
            return self._interceptor
        if self._interceptor_factory is not None:
            return self._interceptor_factory()
        return None


# ---------------------------------------------------------------------------
# Helpers shared with TcpAcceptedTransport.
# ---------------------------------------------------------------------------


def _peer_string(writer: asyncio.StreamWriter) -> str:
    try:
        info = writer.get_extra_info("peername")
        if info:
            host, port, *_ = info
            return f"{host}:{port}"
    except Exception:  # noqa: BLE001
        pass
    return "unknown"


async def _send_busy_then_close(writer: asyncio.StreamWriter, peer: str) -> None:
    """Reply ``server_busy`` (no JSON-RPC id; just a hint) and close.

    The client cannot correlate this to a specific request because the
    socket has not yet seen one; the message is informative only.
    Closing without any reply would leave the client retrying blindly.
    """
    notice = b'{"jsonrpc":"2.0","method":"argos/notice","params":{"reason":"server_busy"}}\n'
    try:
        writer.write(notice)
        await writer.drain()
    except Exception:  # noqa: BLE001 - best-effort
        _log.debug("could not send server_busy notice to %s", peer)
    try:
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()
    except Exception:  # noqa: BLE001
        pass


__all__ = [
    "InterceptorFactory",
    "ProxyListener",
    "SessionManager",
    "SessionMetrics",
]
