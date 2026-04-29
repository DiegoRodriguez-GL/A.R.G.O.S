"""Upstream transport factories.

The :class:`ProxyListener` accepts many simultaneous client connections
and needs a fresh upstream transport for each. The factory abstraction
lets the listener stay agnostic of how the upstream is reached:

- :class:`StdioUpstreamFactory` spawns a subprocess per session
  (typical for Anthropic-style MCP servers shipped as CLI binaries).
- :class:`TcpUpstreamFactory` opens a TCP connection per session
  (servers exposed on a port).
- :class:`SharedUpstreamFactory` returns the same transport across
  sessions (single-tenant deployments where the upstream is reusable;
  used by the in-memory tests).
- :class:`InMemoryUpstreamFactory` returns a fresh in-memory pair per
  session (tests).

A factory is callable: ``await factory()`` returns the transport ready
for I/O. The transport's lifecycle is owned by the session, NOT by the
factory.
"""

from __future__ import annotations

import asyncio
from abc import ABC, abstractmethod
from collections.abc import Awaitable, Callable, Sequence

from argos_proxy.transport._base import Transport
from argos_proxy.transport.memory import InMemoryTransport, make_transport_pair
from argos_proxy.transport.stdio import StdioTransport
from argos_proxy.transport.tcp import TcpTransport


class UpstreamFactory(ABC):
    """Async callable that returns a fresh upstream transport."""

    @abstractmethod
    async def __call__(self) -> Transport:
        """Build and return a new upstream transport, open and ready."""

    async def close(self) -> None:  # noqa: B027 - intentional default no-op
        """Release factory-owned resources. Idempotent. Default no-op."""


class StdioUpstreamFactory(UpstreamFactory):
    """Spawn a subprocess for each new session.

    Each session gets an isolated upstream process; killing the session
    kills its subprocess. This is the safest mode in multi-tenant
    deployments because no state is shared across sessions.
    """

    __slots__ = ("_argv", "_env")

    def __init__(
        self,
        argv: Sequence[str],
        *,
        env: dict[str, str] | None = None,
    ) -> None:
        if not argv:
            msg = "argv must contain at least the executable name"
            raise ValueError(msg)
        self._argv = tuple(argv)
        self._env = dict(env) if env is not None else None

    async def __call__(self) -> Transport:
        transport = StdioTransport(self._argv, env=self._env)
        await transport.start()
        return transport


class TcpUpstreamFactory(UpstreamFactory):
    """Open a TCP connection for each new session."""

    __slots__ = ("_host", "_port")

    def __init__(self, host: str, port: int) -> None:
        if not host:
            msg = "host must be a non-empty string"
            raise ValueError(msg)
        if port <= 0 or port > 65535:
            msg = f"port {port} out of range [1, 65535]"
            raise ValueError(msg)
        self._host = host
        self._port = port

    async def __call__(self) -> Transport:
        transport = TcpTransport(self._host, self._port)
        await transport.connect()
        return transport


class SharedUpstreamFactory(UpstreamFactory):
    """Return a fixed transport across every session.

    Use ONLY when the upstream is reentrant and stateless (typical of
    test doubles). Real MCP servers are session-stateful and require an
    isolating factory."""

    __slots__ = ("_transport",)

    def __init__(self, transport: Transport) -> None:
        self._transport = transport

    async def __call__(self) -> Transport:
        return self._transport


class CallableUpstreamFactory(UpstreamFactory):
    """Adapter so a plain async callable can be passed where a factory
    is expected. Used by tests to inject ad-hoc transport builders."""

    __slots__ = ("_callable",)

    def __init__(self, fn: Callable[[], Awaitable[Transport]]) -> None:
        self._callable = fn

    async def __call__(self) -> Transport:
        return await self._callable()


class InMemoryUpstreamFactory(UpstreamFactory):
    """Return one half of a fresh in-memory pair per session.

    Used by tests that want to drive both sides of the proxy in the same
    event loop. The matching client half is exposed on
    :attr:`peer_transports`; the test stores it to send/receive against
    the proxy's upstream side."""

    __slots__ = ("_lock", "peer_transports")

    def __init__(self) -> None:
        self._lock = asyncio.Lock()
        self.peer_transports: list[InMemoryTransport] = []

    async def __call__(self) -> Transport:
        async with self._lock:
            client, server = make_transport_pair()
            # The proxy will use ``server`` (its upstream side); the
            # test holds ``client`` to play the role of the upstream
            # in the integration scenario.
            self.peer_transports.append(client)
            return server


__all__ = [
    "CallableUpstreamFactory",
    "InMemoryUpstreamFactory",
    "SharedUpstreamFactory",
    "StdioUpstreamFactory",
    "TcpUpstreamFactory",
    "UpstreamFactory",
]
