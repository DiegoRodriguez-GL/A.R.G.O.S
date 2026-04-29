"""In-memory transport pair tests.

The pair is the foundation for every server / interceptor test below.
Every property the higher layers rely on is verified here in isolation:

- Symmetric send/receive via :func:`make_transport_pair`.
- ``close()`` wakes the peer's pending ``receive`` with a
  :class:`ClosedTransportError`.
- ``send`` after ``close`` raises immediately, never blocks.
- Errors injected via ``inject_error`` surface on the peer.
"""

from __future__ import annotations

import asyncio

import pytest
from argos_proxy import (
    ClosedTransportError,
    Notification,
    Request,
    Response,
    TransportError,
    make_transport_pair,
)

pytestmark = pytest.mark.asyncio


async def test_pair_round_trips_request() -> None:
    a, b = make_transport_pair()
    req = Request(method="tools/list", id=1)
    await a.send(req)
    received = await b.receive()
    assert received == req


async def test_pair_round_trips_response_and_notification() -> None:
    a, b = make_transport_pair()
    resp = Response(result={"ok": True}, id=1)
    note = Notification(method="tools/list/changed")
    await a.send(resp)
    await a.send(note)
    assert await b.receive() == resp
    assert await b.receive() == note


async def test_close_wakes_pending_receive() -> None:
    a, b = make_transport_pair()
    receiver = asyncio.create_task(b.receive())
    await asyncio.sleep(0)  # let receiver park
    await a.close()
    with pytest.raises(ClosedTransportError):
        await receiver


async def test_send_after_close_fails_fast() -> None:
    a, _b = make_transport_pair()
    await a.close()
    with pytest.raises(ClosedTransportError):
        await a.send(Notification(method="m"))


async def test_close_is_idempotent() -> None:
    a, _b = make_transport_pair()
    await a.close()
    await a.close()  # must not raise
    assert a.is_closed


async def test_inject_error_surfaces_on_peer() -> None:
    a, b = make_transport_pair()
    await a.inject_error(TransportError("simulated"))
    with pytest.raises(TransportError, match="simulated"):
        await b.receive()


async def test_async_context_manager() -> None:
    a, _b = make_transport_pair()
    async with a:
        assert not a.is_closed
    assert a.is_closed


async def test_concurrent_sends_preserve_order() -> None:
    """Two concurrent senders into the same transport: ordering on the
    receiver side must match insertion order on the sender side."""
    a, b = make_transport_pair()
    payloads = [Request(method=f"m{i}", id=i) for i in range(50)]

    async def push() -> None:
        for p in payloads:
            await a.send(p)

    pusher = asyncio.create_task(push())
    received = []
    for _ in range(50):
        received.append(await b.receive())
    await pusher
    assert received == payloads
