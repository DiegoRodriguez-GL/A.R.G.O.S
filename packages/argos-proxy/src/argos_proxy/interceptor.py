"""Interceptor: the seam where ARGOS observes (and optionally rewrites)
JSON-RPC traffic.

Intercepting is read-mostly. The default :class:`PassThroughInterceptor`
forwards every message untouched and returns no findings; downstream
detectors (Phase 3) plug in by extending :class:`ProxyInterceptor` and
overriding ``on_request_in`` / ``on_response_out``.

Three observation hooks exist:

- :meth:`ProxyInterceptor.on_request_in`: client -> upstream.
- :meth:`ProxyInterceptor.on_response_out`: upstream -> client.
- :meth:`ProxyInterceptor.on_notification`: fire-and-forget messages
  in either direction.

A hook may:

- Return ``None`` -> the original message is forwarded unchanged.
- Return a new :class:`Message` -> that replacement is forwarded.
- Raise :class:`argos_proxy.JsonRpcError` -> the proxy answers the
  client with that error and does NOT forward to upstream. Used by
  policy detectors (e.g. "block tool/call to a tool outside the
  declared scope").

The hook also receives an :class:`InterceptContext` carrying request
correlation info, OTel span handles (Phase 4) and the SQLite forensics
record builder (Phase 4). The context is opaque to the interceptor
implementer; downstream layers attach their own private state to it.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Final

from argos_proxy.jsonrpc import (
    Batch,
    Message,
    Notification,
    Request,
    Response,
)


@dataclass(frozen=True)
class InterceptContext:
    """Per-request correlation envelope passed through every hook.

    ``correlation_id`` uniquely identifies the (request, response) pair
    in the forensics store; ``client_request_id`` is the JSON-RPC ``id``
    the *client* sent, which we forward upstream verbatim. The two are
    distinct because batches multiplex many client ids onto one
    correlation envelope.
    """

    correlation_id: str
    received_at: float
    client_request_id: object = None
    extra: dict[str, Any] = field(default_factory=dict)


class ProxyInterceptor:
    """Base class for runtime detectors. Default impl is pass-through."""

    async def on_request_in(
        self,
        request: Request,
        ctx: InterceptContext,
    ) -> Request | None:
        """Inspect a request flowing client -> upstream.

        Returning ``None`` forwards the original. Returning a new
        :class:`Request` substitutes it. Raising
        :class:`argos_proxy.JsonRpcError` short-circuits with an error
        response back to the client without contacting upstream.
        """
        return None

    async def on_response_out(
        self,
        response: Response,
        ctx: InterceptContext,
    ) -> Response | None:
        """Inspect a response flowing upstream -> client."""
        return None

    async def on_notification(
        self,
        notification: Notification,
        ctx: InterceptContext,
        *,
        from_client: bool,
    ) -> Notification | None:
        """Inspect a notification (one-way message)."""
        return None

    async def on_batch(
        self,
        batch: Batch,
        ctx: InterceptContext,
    ) -> Batch | None:
        """Inspect a whole batch as a unit. Default: no-op.

        Most detectors care about individual messages and will route
        the batch through ``on_request_in`` / ``on_notification``;
        override this when the policy is batch-wide (e.g. "no batch
        may exceed N requests")."""
        return None


class PassThroughInterceptor(ProxyInterceptor):
    """Default: forward everything unchanged. Useful for benchmarks
    where we want the transport overhead alone, with no detectors."""


class ChainInterceptor(ProxyInterceptor):
    """Compose multiple interceptors. Hooks fire in declaration order;
    the first one to return a non-None replacement wins; the first one
    to raise propagates."""

    __slots__ = ("_chain",)

    def __init__(self, *interceptors: ProxyInterceptor) -> None:
        self._chain: tuple[ProxyInterceptor, ...] = tuple(interceptors)

    async def on_request_in(
        self,
        request: Request,
        ctx: InterceptContext,
    ) -> Request | None:
        current = request
        for inner in self._chain:
            replacement = await inner.on_request_in(current, ctx)
            if replacement is not None:
                current = replacement
        return current if current is not request else None

    async def on_response_out(
        self,
        response: Response,
        ctx: InterceptContext,
    ) -> Response | None:
        current = response
        for inner in self._chain:
            replacement = await inner.on_response_out(current, ctx)
            if replacement is not None:
                current = replacement
        return current if current is not response else None

    async def on_notification(
        self,
        notification: Notification,
        ctx: InterceptContext,
        *,
        from_client: bool,
    ) -> Notification | None:
        current = notification
        for inner in self._chain:
            replacement = await inner.on_notification(current, ctx, from_client=from_client)
            if replacement is not None:
                current = replacement
        return current if current is not notification else None


_CORRELATION_PREFIX: Final[str] = "argos-corr-"


def new_correlation_id() -> str:
    """Generate a fresh correlation id. UUID4-based, prefixed for grep."""
    return _CORRELATION_PREFIX + uuid.uuid4().hex[:12]


def new_context(client_request_id: object = None, **extra: Any) -> InterceptContext:
    """Convenience builder used by tests and the Phase 5 CLI."""
    return InterceptContext(
        correlation_id=new_correlation_id(),
        received_at=time.monotonic(),
        client_request_id=client_request_id,
        extra=dict(extra),
    )


# Re-exported so callers don't have to know whether Message is a
# Pydantic model or a Union; useful for type-narrowing.
__all__ = [
    "ChainInterceptor",
    "InterceptContext",
    "Message",
    "PassThroughInterceptor",
    "ProxyInterceptor",
    "new_context",
    "new_correlation_id",
]
