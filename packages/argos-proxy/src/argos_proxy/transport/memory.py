"""In-memory transport pair: two endpoints connected by an asyncio queue.

Used by:

- The proxy server's unit tests (no syscalls, deterministic timing).
- The Phase 6 latency benchmark (subtracts socket overhead from the
  RNF-02 < 50 ms budget so we measure proxy logic only).
- The end-to-end integration tests where a fake upstream is needed
  in-process.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

from argos_proxy.transport._base import (
    ClosedTransportError,
    Transport,
    TransportError,
)

if TYPE_CHECKING:
    from argos_proxy.jsonrpc import Batch, Message


_SENTINEL: object = object()


class InMemoryTransport(Transport):
    """Half of a bidirectional pair; messages flow via two queues."""

    __slots__ = ("_closed", "_inbox", "_outbox")

    def __init__(
        self,
        inbox: asyncio.Queue[object],
        outbox: asyncio.Queue[object],
    ) -> None:
        self._inbox = inbox
        self._outbox = outbox
        self._closed = False

    async def send(self, message: Message | Batch) -> None:
        if self._closed:
            msg = "transport is closed"
            raise ClosedTransportError(msg)
        await self._outbox.put(message)

    async def receive(self) -> Message | Batch:
        if self._closed:
            msg = "transport is closed"
            raise ClosedTransportError(msg)
        item = await self._inbox.get()
        if item is _SENTINEL:
            self._closed = True
            msg = "peer closed the transport"
            raise ClosedTransportError(msg)
        if isinstance(item, BaseException):
            # The peer pushed an error to surface on receive (used in
            # tests to simulate a transport-layer fault mid-stream).
            raise item
        return item  # type: ignore[return-value]

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        # Wake any pending receive() on the *peer* by pushing the
        # sentinel onto the queue we write into (their inbox).
        try:
            self._outbox.put_nowait(_SENTINEL)
        except asyncio.QueueFull:  # pragma: no cover - default queues are unbounded
            pass

    @property
    def is_closed(self) -> bool:
        return self._closed

    async def inject_error(self, exc: TransportError) -> None:
        """Push a :class:`TransportError` so the peer's next ``receive``
        raises. Test-only utility; not exported in the public surface."""
        await self._outbox.put(exc)


def make_transport_pair() -> tuple[InMemoryTransport, InMemoryTransport]:
    """Return ``(client, server)`` connected via two queues.

    Messages sent on ``client`` arrive on ``server.receive()`` and vice
    versa. The pair is symmetric.
    """
    a_to_b: asyncio.Queue[object] = asyncio.Queue()
    b_to_a: asyncio.Queue[object] = asyncio.Queue()
    client = InMemoryTransport(inbox=b_to_a, outbox=a_to_b)
    server = InMemoryTransport(inbox=a_to_b, outbox=b_to_a)
    return client, server
