"""Transport abstract base class.

A transport carries already-framed JSON-RPC bytes in both directions.
Framing concerns (NDJSON vs Content-Length) live one layer down, in
:mod:`argos_proxy.jsonrpc.framing`; the transport only knows about
messages.

The contract is intentionally minimal:

- :meth:`Transport.send` enqueues an outgoing message.
- :meth:`Transport.receive` blocks until the next message arrives.
- :meth:`Transport.close` releases resources; idempotent.

Cancellation is cooperative. Both ``send`` and ``receive`` honour
``asyncio.CancelledError``; callers wrap them in :func:`asyncio.wait_for`
to apply timeouts. The transport itself does not impose a timeout
because that is a policy decision the proxy server owns.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from argos_proxy.jsonrpc import Batch, Message


class TransportError(Exception):
    """Base class for transport-layer faults.

    Distinct from :class:`argos_proxy.jsonrpc.JsonRpcProtocolError`
    because a transport fault is recoverable (reconnect, retry) while
    a protocol error is a permanent contract violation."""


class ClosedTransportError(TransportError):
    """Raised when send/receive is invoked on a closed transport."""


class Transport(ABC):
    """Bidirectional, message-oriented async transport."""

    @abstractmethod
    async def send(self, message: Message | Batch) -> None:
        """Send a single message or batch. Blocks until queued."""

    @abstractmethod
    async def receive(self) -> Message | Batch:
        """Receive the next message; blocks until one arrives.

        Raises :class:`ClosedTransportError` when the peer has closed
        the channel and no buffered data remains."""

    @abstractmethod
    async def close(self) -> None:
        """Idempotently release the transport's resources."""

    @property
    @abstractmethod
    def is_closed(self) -> bool:
        """True once :meth:`close` has been called or the peer hung up."""

    async def __aenter__(self) -> Transport:
        return self

    async def __aexit__(self, *_exc: object) -> None:
        await self.close()
