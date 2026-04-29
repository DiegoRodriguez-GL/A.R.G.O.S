"""Unit tests for :mod:`argos_proxy.interceptor`."""

from __future__ import annotations

from typing import ClassVar

import pytest
from argos_proxy import (
    ChainInterceptor,
    InterceptContext,
    Notification,
    PassThroughInterceptor,
    ProxyInterceptor,
    Request,
    Response,
)
from argos_proxy.interceptor import (
    new_context,
    new_correlation_id,
)

pytestmark = pytest.mark.asyncio


async def test_passthrough_returns_none_everywhere() -> None:
    p = PassThroughInterceptor()
    ctx = new_context()
    assert await p.on_request_in(Request(method="m", id=1), ctx) is None
    assert await p.on_response_out(Response(result=None, id=1), ctx) is None
    assert await p.on_notification(Notification(method="m"), ctx, from_client=True) is None


async def test_correlation_id_is_unique_and_prefixed() -> None:
    seen = {new_correlation_id() for _ in range(1000)}
    assert len(seen) == 1000
    assert all(s.startswith("argos-corr-") for s in seen)


async def test_chain_runs_in_declaration_order() -> None:
    order: list[str] = []

    class Tagger(ProxyInterceptor):
        tag: ClassVar[str] = ""

        async def on_request_in(
            self,
            request: Request,
            ctx: InterceptContext,
        ) -> Request | None:
            order.append(self.tag)
            return None

    class A(Tagger):
        tag: ClassVar[str] = "A"

    class B(Tagger):
        tag: ClassVar[str] = "B"

    chain = ChainInterceptor(A(), B())
    await chain.on_request_in(Request(method="m", id=1), new_context())
    assert order == ["A", "B"]


async def test_chain_replacement_propagates_through_remaining_links() -> None:
    """A replacement returned by an early link is what later links see."""
    seen: list[str] = []

    class Replacer(ProxyInterceptor):
        async def on_request_in(self, request, ctx):  # type: ignore[no-untyped-def]
            seen.append(request.method)
            return Request(method="rewritten", id=request.id)

    class Observer(ProxyInterceptor):
        async def on_request_in(self, request, ctx):  # type: ignore[no-untyped-def]
            seen.append(request.method)
            return

    chain = ChainInterceptor(Replacer(), Observer())
    out = await chain.on_request_in(Request(method="orig", id=1), new_context())
    assert out is not None
    assert out.method == "rewritten"
    assert seen == ["orig", "rewritten"]


async def test_chain_returns_none_when_no_replacement() -> None:
    """If no link rewrites, the chain returns None so the server forwards
    the original message unchanged."""
    chain = ChainInterceptor(PassThroughInterceptor(), PassThroughInterceptor())
    out = await chain.on_request_in(Request(method="m", id=1), new_context())
    assert out is None


async def test_intercept_context_is_frozen() -> None:
    ctx = new_context(client_request_id=1)
    with pytest.raises(Exception):  # dataclass(frozen=True) -> FrozenInstanceError
        ctx.correlation_id = "hijacked"  # type: ignore[misc]
