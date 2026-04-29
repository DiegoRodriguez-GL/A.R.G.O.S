"""End-to-end tests for :class:`ProxyServer` over the in-memory transport.

The proxy is built so the *only* observable behaviour with a
pass-through interceptor is "what the client sent, the upstream
sees -- byte-faithful". These tests pin that property and the
behaviour of every interceptor hook.
"""

from __future__ import annotations

import asyncio
from typing import Final

import pytest
from argos_proxy import (
    Batch,
    InMemoryTransport,
    InterceptContext,
    JsonRpcError,
    Notification,
    PassThroughInterceptor,
    ProxyInterceptor,
    ProxyServer,
    Request,
    Response,
    make_transport_pair,
)
from argos_proxy.jsonrpc import METHOD_NOT_FOUND

pytestmark = pytest.mark.asyncio

_TEST_TIMEOUT: Final[float] = 5.0


async def _wire(
    interceptor: ProxyInterceptor | None = None,
) -> tuple[asyncio.Task[None], _Wires]:
    """Set up a ProxyServer with two in-memory pairs and start the run task.

    The ``await asyncio.sleep(0)`` after task creation is mandatory: it
    yields control so the event loop schedules ``server.run()`` and
    flips ``_running`` to True before the test code returns. Without it,
    a test calling ``server.run()`` a second time would race with the
    first task's first-statement and deadlock.
    """
    client_side, proxy_in = make_transport_pair()
    proxy_out, upstream_side = make_transport_pair()
    server = ProxyServer(client=proxy_in, upstream=proxy_out, interceptor=interceptor)
    task = asyncio.create_task(server.run())
    await asyncio.sleep(0)
    return task, _Wires(server=server, client=client_side, upstream=upstream_side, task=task)


class _Wires:
    __slots__ = ("client", "server", "task", "upstream")

    def __init__(
        self,
        *,
        server: ProxyServer,
        client: InMemoryTransport,
        upstream: InMemoryTransport,
        task: asyncio.Task[None],
    ) -> None:
        self.server = server
        self.client = client
        self.upstream = upstream
        self.task = task

    async def close(self) -> None:
        await self.server.stop()
        await self.client.close()
        await self.upstream.close()
        with pytest.raises(BaseException):
            # Either CancelledError or no-op once stop is idempotent.
            await asyncio.wait_for(self.task, timeout=_TEST_TIMEOUT)


# ---------------------------------------------------------------------------
# Transparency.
# ---------------------------------------------------------------------------


async def test_request_flows_client_to_upstream_unchanged() -> None:
    _t, w = await _wire(PassThroughInterceptor())
    try:
        req = Request(method="tools/list", id=42)
        await w.client.send(req)
        received = await asyncio.wait_for(w.upstream.receive(), timeout=_TEST_TIMEOUT)
        assert received == req
    finally:
        await w.server.stop()


async def test_response_flows_upstream_to_client_unchanged() -> None:
    _t, w = await _wire(PassThroughInterceptor())
    try:
        await w.client.send(Request(method="tools/list", id=1))
        await asyncio.wait_for(w.upstream.receive(), timeout=_TEST_TIMEOUT)
        resp = Response(result={"tools": []}, id=1)
        await w.upstream.send(resp)
        received = await asyncio.wait_for(w.client.receive(), timeout=_TEST_TIMEOUT)
        assert received == resp
    finally:
        await w.server.stop()


async def test_notification_round_trips_in_both_directions() -> None:
    _t, w = await _wire(PassThroughInterceptor())
    try:
        n = Notification(method="tools/list/changed")
        await w.client.send(n)
        assert await asyncio.wait_for(w.upstream.receive(), timeout=_TEST_TIMEOUT) == n
        n2 = Notification(method="resources/list/changed")
        await w.upstream.send(n2)
        assert await asyncio.wait_for(w.client.receive(), timeout=_TEST_TIMEOUT) == n2
    finally:
        await w.server.stop()


async def test_batch_round_trips_unchanged() -> None:
    _t, w = await _wire(PassThroughInterceptor())
    try:
        batch = Batch(
            messages=(
                Request(method="a", id=1),
                Request(method="b", id=2),
                Notification(method="n"),
            )
        )
        await w.client.send(batch)
        received = await asyncio.wait_for(w.upstream.receive(), timeout=_TEST_TIMEOUT)
        assert received == batch
    finally:
        await w.server.stop()


# ---------------------------------------------------------------------------
# Interceptor hooks.
# ---------------------------------------------------------------------------


class _RecordingInterceptor(ProxyInterceptor):
    """Records every hook firing for assertion in the tests."""

    def __init__(self) -> None:
        self.requests: list[Request] = []
        self.responses: list[Response] = []
        self.notifications: list[tuple[Notification, bool]] = []

    async def on_request_in(self, request: Request, ctx: InterceptContext) -> None:
        self.requests.append(request)
        return

    async def on_response_out(self, response: Response, ctx: InterceptContext) -> None:
        self.responses.append(response)
        return

    async def on_notification(
        self,
        notification: Notification,
        ctx: InterceptContext,
        *,
        from_client: bool,
    ) -> None:
        self.notifications.append((notification, from_client))
        return


async def test_interceptor_observes_request_and_response() -> None:
    rec = _RecordingInterceptor()
    _t, w = await _wire(rec)
    try:
        req = Request(method="tools/call", id=1)
        await w.client.send(req)
        await asyncio.wait_for(w.upstream.receive(), timeout=_TEST_TIMEOUT)
        resp = Response(result=None, id=1)
        await w.upstream.send(resp)
        await asyncio.wait_for(w.client.receive(), timeout=_TEST_TIMEOUT)
        assert rec.requests == [req]
        assert rec.responses == [resp]
    finally:
        await w.server.stop()


async def test_interceptor_can_rewrite_request() -> None:
    """Replace ``method='tools/list'`` with ``method='tools/list/v2'``."""

    class Rewriter(ProxyInterceptor):
        async def on_request_in(
            self,
            request: Request,
            ctx: InterceptContext,
        ) -> Request | None:
            if request.method == "tools/list":
                return Request(method="tools/list/v2", params=request.params, id=request.id)
            return None

    _t, w = await _wire(Rewriter())
    try:
        await w.client.send(Request(method="tools/list", id=1))
        upstream_msg = await asyncio.wait_for(w.upstream.receive(), timeout=_TEST_TIMEOUT)
        assert isinstance(upstream_msg, Request)
        assert upstream_msg.method == "tools/list/v2"
    finally:
        await w.server.stop()


async def test_interceptor_can_short_circuit_with_jsonrpc_error() -> None:
    """A detector raising :class:`JsonRpcError` answers the client and
    does NOT forward the request upstream."""

    class Blocker(ProxyInterceptor):
        async def on_request_in(
            self,
            request: Request,
            ctx: InterceptContext,
        ) -> Request | None:
            if request.method == "dangerous":
                raise JsonRpcError(METHOD_NOT_FOUND, "blocked by ARGOS policy")
            return None

    _t, w = await _wire(Blocker())
    try:
        await w.client.send(Request(method="dangerous", id=99))
        # No request reaches upstream...
        with pytest.raises(asyncio.TimeoutError):
            await asyncio.wait_for(w.upstream.receive(), timeout=0.5)
        # ...and the client got a structured error.
        resp = await asyncio.wait_for(w.client.receive(), timeout=_TEST_TIMEOUT)
        assert isinstance(resp, Response)
        assert resp.is_error
        assert resp.error is not None
        assert resp.error.code == METHOD_NOT_FOUND
        assert "blocked" in resp.error.message
        assert resp.id == 99
    finally:
        await w.server.stop()


async def test_buggy_interceptor_does_not_crash_proxy() -> None:
    """If a hook raises an unexpected exception (not JsonRpcError), the
    proxy logs and falls back to pass-through. Critical: a faulty
    detector cannot bring the whole proxy down."""

    class Buggy(ProxyInterceptor):
        async def on_request_in(
            self,
            request: Request,
            ctx: InterceptContext,
        ) -> Request | None:
            raise RuntimeError("detector bug")

    _t, w = await _wire(Buggy())
    try:
        req = Request(method="m", id=1)
        await w.client.send(req)
        # Falls back to pass-through; upstream still gets the original.
        received = await asyncio.wait_for(w.upstream.receive(), timeout=_TEST_TIMEOUT)
        assert received == req
    finally:
        await w.server.stop()


# ---------------------------------------------------------------------------
# Lifecycle.
# ---------------------------------------------------------------------------


async def test_proxy_stops_when_client_disconnects() -> None:
    _t, w = await _wire()
    try:
        await w.client.close()
        await asyncio.wait_for(w.task, timeout=_TEST_TIMEOUT)
    finally:
        await w.upstream.close()


async def test_proxy_stops_when_upstream_disconnects() -> None:
    _t, w = await _wire()
    try:
        await w.upstream.close()
        await asyncio.wait_for(w.task, timeout=_TEST_TIMEOUT)
    finally:
        await w.client.close()


async def test_run_twice_raises() -> None:
    _t, w = await _wire()
    try:
        with pytest.raises(RuntimeError, match="already running"):
            await w.server.run()
    finally:
        await w.server.stop()


async def test_stop_is_idempotent() -> None:
    _t, w = await _wire()
    await w.server.stop()
    await w.server.stop()
    assert w.server is not None  # smoke: did not raise
