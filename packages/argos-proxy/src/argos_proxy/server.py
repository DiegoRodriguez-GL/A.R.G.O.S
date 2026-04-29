"""ARGOS audit proxy server: a transparent JSON-RPC 2.0 / MCP relay.

The :class:`ProxyServer` connects two transports -- ``client`` (the
downstream consumer) and ``upstream`` (the real MCP server) -- and
ferries every message between them through an :class:`ProxyInterceptor`.

Transparency property: in the default configuration with a
:class:`PassThroughInterceptor`, what the upstream sees is byte-faithful
to what the client sent (modulo a normalised ``jsonrpc: "2.0"`` field).
This property is asserted by ``test_server_transparent_roundtrip``.

Concurrency model:

- One asyncio task pumps ``client -> upstream`` (forward direction).
- One asyncio task pumps ``upstream -> client`` (reverse direction).
- A run-loop awaits both with :func:`asyncio.gather` and stops the
  whole proxy when either task exits (peer hung up, transport error).

Cancellation: stopping the proxy cancels both pumps and closes both
transports. Pending messages are dropped; the JSON-RPC spec is
explicit that requests with no response are valid (they're treated as
"this call timed out, server side").
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable
from contextlib import suppress
from typing import TYPE_CHECKING, Any

from argos_proxy.interceptor import (
    InterceptContext,
    PassThroughInterceptor,
    ProxyInterceptor,
    new_correlation_id,
)
from argos_proxy.jsonrpc import (
    Batch,
    ErrorObject,
    JsonRpcError,
    Notification,
    Request,
    Response,
)
from argos_proxy.transport import ClosedTransportError, Transport

if TYPE_CHECKING:
    from logging import Logger


_log: Logger = logging.getLogger("argos.proxy")


class ProxyServer:
    """Transparent JSON-RPC 2.0 proxy with pluggable interception.

    Lifecycle:

    1. ``server = ProxyServer(client, upstream, interceptor=...)``
    2. ``await server.run()`` -- pumps both directions until either
       transport closes.
    3. ``await server.stop()`` -- idempotent shutdown.
    """

    __slots__ = (
        "_client",
        "_interceptor",
        "_running",
        "_stopped",
        "_tasks",
        "_upstream",
    )

    def __init__(
        self,
        client: Transport,
        upstream: Transport,
        *,
        interceptor: ProxyInterceptor | None = None,
    ) -> None:
        self._client = client
        self._upstream = upstream
        self._interceptor = interceptor or PassThroughInterceptor()
        self._tasks: list[asyncio.Task[None]] = []
        self._running = False
        self._stopped = asyncio.Event()

    async def run(self) -> None:
        """Block pumping in both directions until either side closes."""
        if self._running:
            msg = "ProxyServer already running"
            raise RuntimeError(msg)
        self._running = True
        forward = asyncio.create_task(self._pump_forward(), name="argos.proxy.forward")
        reverse = asyncio.create_task(self._pump_reverse(), name="argos.proxy.reverse")
        self._tasks = [forward, reverse]
        try:
            done, pending = await asyncio.wait(
                self._tasks,
                return_when=asyncio.FIRST_COMPLETED,
            )
            # Surface the first task's exception (if any) so callers
            # can react to fatal transport faults; cancel the other
            # pump so it does not block the event loop forever.
            for task in pending:
                task.cancel()
            for task in pending:
                with suppress(asyncio.CancelledError):
                    await task
            for task in done:
                exc = task.exception()
                if exc is not None and not isinstance(exc, ClosedTransportError):
                    raise exc
        finally:
            self._running = False
            self._stopped.set()
            await self._close_transports()

    async def stop(self) -> None:
        """Cancel pumps and close both transports. Idempotent."""
        for task in self._tasks:
            task.cancel()
        for task in self._tasks:
            with suppress(asyncio.CancelledError):
                await task
        self._tasks.clear()
        await self._close_transports()
        self._stopped.set()

    async def wait_stopped(self) -> None:
        await self._stopped.wait()

    # ------------------------------------------------------------------
    # Pumps.
    # ------------------------------------------------------------------
    async def _pump_forward(self) -> None:
        """client -> [interceptor] -> upstream."""
        try:
            while True:
                msg = await self._client.receive()
                await self._handle_client_to_upstream(msg)
        except ClosedTransportError:
            return

    async def _pump_reverse(self) -> None:
        """upstream -> [interceptor] -> client."""
        try:
            while True:
                msg = await self._upstream.receive()
                await self._handle_upstream_to_client(msg)
        except ClosedTransportError:
            return

    # ------------------------------------------------------------------
    # Per-message routing.
    # ------------------------------------------------------------------
    async def _handle_client_to_upstream(
        self, msg: Request | Response | Notification | Batch
    ) -> None:
        if isinstance(msg, Batch):
            ctx = self._new_ctx(client_request_id=None)
            replacement_batch = await self._safe_call(
                self._interceptor.on_batch,
                msg,
                ctx,
            )
            outgoing = replacement_batch if replacement_batch is not None else msg
            await self._upstream.send(outgoing)
            return
        if isinstance(msg, Request):
            ctx = self._new_ctx(client_request_id=msg.id)
            try:
                replacement = await self._interceptor.on_request_in(msg, ctx)
            except JsonRpcError as err:
                # Detector vetoed the request; respond to the client
                # with the structured error and do NOT forward upstream.
                resp = Response(
                    error=ErrorObject(**err.to_object()),
                    id=msg.id,
                )
                await self._client.send(resp)
                return
            except Exception:  # noqa: BLE001
                _log.exception("on_request_in raised; falling back to pass-through")
                replacement = None
            outgoing = replacement if replacement is not None else msg
            await self._upstream.send(outgoing)
            return
        if isinstance(msg, Notification):
            ctx = self._new_ctx()
            replacement = await self._safe_call(
                self._interceptor.on_notification,
                msg,
                ctx,
                from_client=True,
            )
            outgoing = replacement if replacement is not None else msg
            await self._upstream.send(outgoing)
            return
        # A Response from the client makes no sense in JSON-RPC; the
        # spec only allows responses upstream -> client. Drop with a
        # log entry; do NOT raise (we don't want one malformed client
        # message to take down the proxy).
        _log.warning("dropping unexpected response from client side")

    async def _handle_upstream_to_client(
        self, msg: Request | Response | Notification | Batch
    ) -> None:
        if isinstance(msg, Batch):
            ctx = self._new_ctx()
            replacement_batch = await self._safe_call(
                self._interceptor.on_batch,
                msg,
                ctx,
            )
            outgoing = replacement_batch if replacement_batch is not None else msg
            await self._client.send(outgoing)
            return
        if isinstance(msg, Response):
            ctx = self._new_ctx(client_request_id=msg.id)
            try:
                replacement = await self._interceptor.on_response_out(msg, ctx)
            except JsonRpcError as err:
                replacement = Response(
                    error=ErrorObject(**err.to_object()),
                    id=msg.id,
                )
            except Exception:  # noqa: BLE001
                _log.exception("on_response_out raised; falling back to pass-through")
                replacement = None
            outgoing = replacement if replacement is not None else msg
            await self._client.send(outgoing)
            return
        if isinstance(msg, Notification):
            ctx = self._new_ctx()
            replacement = await self._safe_call(
                self._interceptor.on_notification,
                msg,
                ctx,
                from_client=False,
            )
            outgoing = replacement if replacement is not None else msg
            await self._client.send(outgoing)
            return
        # An MCP server can sometimes send Requests upstream -> client
        # (sampling, elicitation). Forward them transparently.
        if isinstance(msg, Request):
            await self._client.send(msg)

    # ------------------------------------------------------------------
    # Helpers.
    # ------------------------------------------------------------------
    @staticmethod
    def _new_ctx(client_request_id: object = None) -> InterceptContext:
        import time  # noqa: PLC0415 - small, hot helper

        return InterceptContext(
            correlation_id=new_correlation_id(),
            received_at=time.monotonic(),
            client_request_id=client_request_id,
        )

    async def _safe_call(
        self,
        fn: Callable[..., Awaitable[Any]],
        *args: Any,
        **kwargs: Any,
    ) -> Any:
        """Run a hook; if it raises an unexpected exception, log and
        treat as no-op so a buggy detector cannot crash the proxy."""
        try:
            return await fn(*args, **kwargs)
        except JsonRpcError:
            raise
        except Exception:  # noqa: BLE001
            _log.exception("interceptor hook raised; falling back to pass-through")
            return None

    async def _close_transports(self) -> None:
        for t in self._tasks:
            t.cancel()
        await self._client.close()
        await self._upstream.close()


__all__ = ["ProxyServer"]
