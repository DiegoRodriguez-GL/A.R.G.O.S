"""Adversarial / stress tests for :class:`ProxyListener`.

These tests target the kind of failure modes a real deployment will see
under load: connection floods, slow-loris clients, abrupt resets,
malformed handshakes, upstream factory errors.

Each test is deliberately fast (sub-second on commodity hardware) so it
can run on every CI pass; the realistic scenarios are kept compact via
short timeouts and small concurrency caps.
"""

from __future__ import annotations

import asyncio
import json
import socket

import pytest
from argos_proxy import (
    ClosedTransportError,
    InMemoryUpstreamFactory,
    PassThroughInterceptor,
    ProxyListener,
    Request,
    Response,
    Transport,
    TransportError,
    UpstreamFactory,
)

pytestmark = [pytest.mark.asyncio]


# ---------------------------------------------------------------------------
# Helpers.
# ---------------------------------------------------------------------------


async def _drive_one_echo(factory: InMemoryUpstreamFactory, *, max_msgs: int = 200) -> None:
    """Cooperative echo: respond to every Request that arrives across
    every accepted upstream half. Cancels on cleanup."""
    served = 0
    handled_indices: set[int] = set()
    while served < max_msgs:
        await asyncio.sleep(0.005)
        for idx, peer in enumerate(list(factory.peer_transports)):
            if peer.is_closed:
                handled_indices.add(idx)
                continue
            try:
                msg = await asyncio.wait_for(peer.receive(), timeout=0.05)
            except (TimeoutError, ClosedTransportError):
                continue
            except Exception:  # noqa: BLE001
                continue
            if isinstance(msg, Request):
                try:
                    await peer.send(Response(result={"ok": True, "echo": msg.method}, id=msg.id))
                    served += 1
                except (ClosedTransportError, Exception):  # noqa: BLE001
                    handled_indices.add(idx)


# ---------------------------------------------------------------------------
# 1. Connection flooding.
# ---------------------------------------------------------------------------


class _SlowUpstreamFactory(UpstreamFactory):
    """Upstream that takes ``response_delay`` seconds to reply.

    Used by the connection-flooding test to keep sessions busy long
    enough that the concurrency cap is meaningful (otherwise fast
    sessions free their slot before the next client arrives)."""

    def __init__(self, response_delay: float = 0.5) -> None:
        self._inner = InMemoryUpstreamFactory()
        self._response_delay = response_delay
        self._task: asyncio.Task[None] | None = None

    async def __call__(self) -> Transport:
        return await self._inner()

    @property
    def peer_transports(self):  # type: ignore[no-untyped-def]
        return self._inner.peer_transports

    async def drive(self) -> None:
        served: set[int] = set()
        while True:
            await asyncio.sleep(0.005)
            for idx, peer in enumerate(list(self._inner.peer_transports)):
                if idx in served or peer.is_closed:
                    continue
                try:
                    msg = await asyncio.wait_for(peer.receive(), timeout=0.05)
                except (TimeoutError, ClosedTransportError):
                    continue
                except Exception:  # noqa: BLE001
                    served.add(idx)
                    continue
                if isinstance(msg, Request):
                    await asyncio.sleep(self._response_delay)
                    try:
                        await peer.send(Response(result={"ok": True}, id=msg.id))
                    except Exception:  # noqa: BLE001
                        pass
                    served.add(idx)


class TestConnectionFlooding:
    async def test_concurrent_cap_8_rejects_excess_with_busy_notices(self) -> None:
        """A burst of 20 simultaneous TCP opens against a listener with
        max_sessions=8 and a slow upstream must produce at most 8
        concurrent served sessions; the rest are busy-rejected.

        We measure ``listener.sessions.active_count`` at the peak of
        the burst -- it must never exceed 8."""
        factory = _SlowUpstreamFactory(response_delay=1.0)
        listener = ProxyListener(
            host="127.0.0.1",
            port=0,
            upstream_factory=factory,
            max_sessions=8,
        )
        await listener.start()
        drive_task = asyncio.create_task(factory.drive())
        try:
            host, port = listener.bound_address()  # type: ignore[misc]

            async def one_client(i: int) -> str:
                try:
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(host, port),
                        timeout=3.0,
                    )
                except Exception:  # noqa: BLE001 - any failure means no socket
                    return "open_failed"
                try:
                    payload = (
                        json.dumps({"jsonrpc": "2.0", "method": "ping", "id": i}) + "\n"
                    ).encode("utf-8")
                    writer.write(payload)
                    await writer.drain()
                    # Reading the first line: either a busy notice
                    # (immediate) or the slow upstream response.
                    line = await asyncio.wait_for(reader.readline(), timeout=5.0)
                    if not line:
                        return "empty"
                    msg = json.loads(line)
                    if msg.get("method") == "argos/notice":
                        return "busy"
                    return "served"  # noqa: TRY300
                except Exception:  # noqa: BLE001 - test classifies any error
                    return "error"
                finally:
                    try:
                        writer.close()
                        await asyncio.wait_for(writer.wait_closed(), timeout=1.0)
                    except Exception:  # noqa: BLE001
                        pass

            # Sample active_count just after the burst opens.
            async def sample_peak() -> int:
                peak = 0
                for _ in range(40):
                    peak = max(peak, listener.sessions.active_count)
                    await asyncio.sleep(0.01)
                return peak

            sampler = asyncio.create_task(sample_peak())
            results = await asyncio.gather(*(one_client(i) for i in range(20)))
            peak = await sampler
            busy = sum(1 for r in results if r == "busy")
            # Concurrent cap was honoured -- the listener never had
            # more than 8 sessions in flight.
            assert peak <= 8, f"peak active = {peak}, expected <= 8"
            # At least 12 (=20-8) clients had to be busy-rejected;
            # leave room for timing slack and accept >= 8.
            assert busy >= 8, f"busy={busy}, expected >= 8 with cap 8 and 20 clients"
            # Listener still alive.
            assert listener.is_running
        finally:
            drive_task.cancel()
            try:
                await drive_task
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass
            await listener.stop()


# ---------------------------------------------------------------------------
# 2. Slow-loris: client connects but never finishes a frame.
# ---------------------------------------------------------------------------


class TestSlowLoris:
    async def test_idle_timeout_closes_silent_client(self) -> None:
        """A client that connects but never sends anything must be
        kicked by the idle timeout. Set the timeout very short so the
        test is fast."""
        factory = InMemoryUpstreamFactory()
        listener = ProxyListener(
            host="127.0.0.1",
            port=0,
            upstream_factory=factory,
            session_idle_timeout=0.5,
            drain_timeout=0.5,
        )
        await listener.start()
        try:
            host, port = listener.bound_address()  # type: ignore[misc]
            reader, writer = await asyncio.open_connection(host, port)
            try:
                # Wait long enough for the listener to time out the session.
                # The listener should close the writer side.
                await asyncio.sleep(1.5)
                # Attempting to read after the timeout: peer closed -> EOF.
                line = await asyncio.wait_for(reader.read(), timeout=1.0)
                # Either empty (clean close) or whatever was buffered.
                # The crucial property is that the listener bookkeeping
                # is back to zero.
                _ = line
            finally:
                writer.close()
                try:
                    await writer.wait_closed()
                except (ConnectionResetError, BrokenPipeError):
                    pass
            # Active count must be 0.
            for _ in range(20):
                if listener.sessions.active_count == 0:
                    break
                await asyncio.sleep(0.05)
            assert listener.sessions.active_count == 0
        finally:
            await listener.stop()


# ---------------------------------------------------------------------------
# 3. Abrupt disconnect: client disappears mid-conversation.
# ---------------------------------------------------------------------------


class TestAbruptDisconnect:
    async def test_client_resets_after_request_does_not_break_listener(self) -> None:
        """RST after sending a request: the listener should clean up
        the session and remain operational for new clients."""
        factory = InMemoryUpstreamFactory()
        listener = ProxyListener(
            host="127.0.0.1",
            port=0,
            upstream_factory=factory,
            drain_timeout=1.0,
        )
        await listener.start()
        echo_task = asyncio.create_task(_drive_one_echo(factory))
        try:
            host, port = listener.bound_address()  # type: ignore[misc]
            # Open a raw socket so we can SO_LINGER + close to force RST.
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((host, port))
            sock.sendall(
                json.dumps({"jsonrpc": "2.0", "method": "ping", "id": 1}).encode("utf-8") + b"\n",
            )
            # Force RST by setting linger=0 and closing.
            try:
                sock.setsockopt(
                    socket.SOL_SOCKET,
                    socket.SO_LINGER,
                    b"\x01\x00\x00\x00\x00\x00\x00\x00",  # struct linger { l_onoff=1, l_linger=0 }
                )
            except OSError:
                # Some platforms reject; fall back to plain close.
                pass
            sock.close()
            # Allow the listener to detect and clean up.
            for _ in range(40):
                if listener.sessions.active_count == 0:
                    break
                await asyncio.sleep(0.05)
            assert listener.sessions.active_count == 0
            # New client still works.
            reader, writer = await asyncio.open_connection(host, port)
            writer.write(
                (json.dumps({"jsonrpc": "2.0", "method": "ping", "id": 2}) + "\n").encode("utf-8"),
            )
            await writer.drain()
            line = await asyncio.wait_for(reader.readline(), timeout=2.0)
            assert line, "fresh client got nothing after RST"
            writer.close()
            try:
                await writer.wait_closed()
            except (ConnectionResetError, BrokenPipeError):
                pass
        finally:
            echo_task.cancel()
            try:
                await echo_task
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass
            await listener.stop()


# ---------------------------------------------------------------------------
# 4. Malformed handshake.
# ---------------------------------------------------------------------------


class TestMalformedHandshake:
    async def test_garbage_bytes_close_session_without_crash(self) -> None:
        factory = InMemoryUpstreamFactory()
        listener = ProxyListener(
            host="127.0.0.1",
            port=0,
            upstream_factory=factory,
            session_idle_timeout=2.0,
            drain_timeout=1.0,
        )
        await listener.start()
        try:
            host, port = listener.bound_address()  # type: ignore[misc]
            reader, writer = await asyncio.open_connection(host, port)
            try:
                # Send pure garbage followed by a newline; parse_payload
                # raises JsonRpcProtocolError, which the proxy_server's
                # pump function should propagate through; the session
                # ends, transport closes.
                writer.write(b"\x00\x01\x02not-json\n")
                await writer.drain()
                # Read until EOF or empty.
                try:
                    await asyncio.wait_for(reader.read(), timeout=2.0)
                except TimeoutError:
                    pass
            finally:
                writer.close()
                try:
                    await writer.wait_closed()
                except (ConnectionResetError, BrokenPipeError):
                    pass
            # Listener must stay up.
            assert listener.is_running
        finally:
            await listener.stop()


# ---------------------------------------------------------------------------
# 5. Upstream factory failures.
# ---------------------------------------------------------------------------


class _FailingUpstreamFactory(UpstreamFactory):
    """Factory that always raises a TransportError. Used to verify the
    listener's error path."""

    async def __call__(self) -> Transport:
        msg = "upstream unavailable"
        raise TransportError(msg)


class _FlakyUpstreamFactory(UpstreamFactory):
    """First call raises, subsequent calls succeed via an inner
    InMemory factory. Models a transient upstream outage."""

    def __init__(self) -> None:
        self._inner = InMemoryUpstreamFactory()
        self._calls = 0

    async def __call__(self) -> Transport:
        self._calls += 1
        if self._calls == 1:
            msg = "transient outage"
            raise TransportError(msg)
        return await self._inner()

    @property
    def peer_transports(self):  # type: ignore[no-untyped-def]
        return self._inner.peer_transports


class TestUpstreamFailures:
    async def test_failing_factory_closes_session_without_killing_listener(self) -> None:
        listener = ProxyListener(
            host="127.0.0.1",
            port=0,
            upstream_factory=_FailingUpstreamFactory(),
            drain_timeout=1.0,
        )
        await listener.start()
        try:
            host, port = listener.bound_address()  # type: ignore[misc]
            reader, writer = await asyncio.open_connection(host, port)
            # The listener will close the connection because the
            # upstream factory failed. Read should EOF promptly.
            await asyncio.wait_for(reader.read(), timeout=2.0)
            writer.close()
            try:
                await writer.wait_closed()
            except (ConnectionResetError, BrokenPipeError):
                pass
            # Listener still up.
            assert listener.is_running
            # Sessions tracked but error noted.
            assert listener.sessions.total_started >= 1
        finally:
            await listener.stop()

    async def test_flaky_upstream_recovers_on_retry(self) -> None:
        """Two clients in series: first sees the outage and gets dropped,
        second succeeds. Pin the property that the listener does NOT
        cache the failure."""
        factory = _FlakyUpstreamFactory()
        listener = ProxyListener(
            host="127.0.0.1",
            port=0,
            upstream_factory=factory,
            drain_timeout=1.0,
        )
        await listener.start()
        echo_task = asyncio.create_task(_drive_one_echo(factory))  # type: ignore[arg-type]
        try:
            host, port = listener.bound_address()  # type: ignore[misc]
            # Client #1 (factory raises).
            r1, w1 = await asyncio.open_connection(host, port)
            await asyncio.wait_for(r1.read(), timeout=2.0)
            w1.close()
            try:
                await w1.wait_closed()
            except (ConnectionResetError, BrokenPipeError):
                pass
            # Client #2 (factory succeeds).
            r2, w2 = await asyncio.open_connection(host, port)
            try:
                w2.write(
                    (json.dumps({"jsonrpc": "2.0", "method": "ping", "id": 1}) + "\n").encode(
                        "utf-8"
                    ),
                )
                await w2.drain()
                line = await asyncio.wait_for(r2.readline(), timeout=3.0)
                assert line
                payload = json.loads(line)
                assert payload["id"] == 1
            finally:
                w2.close()
                try:
                    await w2.wait_closed()
                except (ConnectionResetError, BrokenPipeError):
                    pass
        finally:
            echo_task.cancel()
            try:
                await echo_task
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass
            await listener.stop()


# ---------------------------------------------------------------------------
# 6. Stop while many sessions are still active.
# ---------------------------------------------------------------------------


class TestShutdownStress:
    async def test_stop_with_5_active_sessions_drains_or_cancels(self) -> None:
        factory = InMemoryUpstreamFactory()
        listener = ProxyListener(
            host="127.0.0.1",
            port=0,
            upstream_factory=factory,
            max_sessions=10,
            drain_timeout=0.5,
        )
        await listener.start()
        try:
            host, port = listener.bound_address()  # type: ignore[misc]
            sockets: list[tuple[asyncio.StreamReader, asyncio.StreamWriter]] = []
            for _ in range(5):
                r, w = await asyncio.open_connection(host, port)
                sockets.append((r, w))
            for _ in range(40):
                if listener.sessions.active_count == 5:
                    break
                await asyncio.sleep(0.05)
            assert listener.sessions.active_count == 5
            # Stop the listener; should drain or cancel within a couple
            # of drain_timeout windows.
            await asyncio.wait_for(listener.stop(), timeout=5.0)
            assert listener.sessions.active_count == 0
            # Tear down client sockets.
            for _, w in sockets:
                w.close()
                try:
                    await w.wait_closed()
                except (ConnectionResetError, BrokenPipeError):
                    pass
        finally:
            # In case stop already ran, this is a no-op.
            await listener.stop()


# ---------------------------------------------------------------------------
# 7. Large message: stress the framer over a real socket.
# ---------------------------------------------------------------------------


class TestLargeMessage:
    async def test_64kb_payload_round_trips_through_real_tcp(self) -> None:
        factory = InMemoryUpstreamFactory()
        listener = ProxyListener(
            host="127.0.0.1",
            port=0,
            upstream_factory=factory,
        )
        await listener.start()

        async def upstream_pump() -> None:
            while True:
                await asyncio.sleep(0.005)
                for peer in list(factory.peer_transports):
                    try:
                        msg = await asyncio.wait_for(peer.receive(), timeout=0.05)
                    except (TimeoutError, ClosedTransportError):
                        continue
                    except Exception:  # noqa: BLE001
                        continue
                    if isinstance(msg, Request):
                        try:
                            await peer.send(
                                Response(
                                    result={"len": len(json.dumps(msg.params or {}))},
                                    id=msg.id,
                                ),
                            )
                        except Exception:  # noqa: BLE001
                            pass

        echo_task = asyncio.create_task(upstream_pump())
        try:
            host, port = listener.bound_address()  # type: ignore[misc]
            big_blob = "x" * (64 * 1024)
            reader, writer = await asyncio.open_connection(host, port)
            try:
                payload = (
                    json.dumps(
                        {
                            "jsonrpc": "2.0",
                            "method": "stress",
                            "params": {"blob": big_blob},
                            "id": 1,
                        },
                    ).encode("utf-8")
                    + b"\n"
                )
                writer.write(payload)
                await writer.drain()
                line = await asyncio.wait_for(reader.readline(), timeout=10.0)
                response = json.loads(line)
                assert response["id"] == 1
                # Round-tripped length matches what we sent (the dict
                # repr has a few constant-overhead bytes).
                assert response["result"]["len"] >= 64 * 1024
            finally:
                writer.close()
                try:
                    await writer.wait_closed()
                except (ConnectionResetError, BrokenPipeError):
                    pass
        finally:
            echo_task.cancel()
            try:
                await echo_task
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass
            await listener.stop()


# ---------------------------------------------------------------------------
# 8. Sequential session reuse: detector chain isolation persists across
#    sessions on the same listener.
# ---------------------------------------------------------------------------


class TestInterceptorSharing:
    async def test_shared_passthrough_interceptor_reused_across_sessions(self) -> None:
        factory = InMemoryUpstreamFactory()
        shared = PassThroughInterceptor()
        listener = ProxyListener(
            host="127.0.0.1",
            port=0,
            upstream_factory=factory,
            interceptor=shared,
        )
        await listener.start()
        echo_task = asyncio.create_task(_drive_one_echo(factory))
        try:
            host, port = listener.bound_address()  # type: ignore[misc]
            for i in range(3):
                reader, writer = await asyncio.open_connection(host, port)
                writer.write(
                    (json.dumps({"jsonrpc": "2.0", "method": "ping", "id": i}) + "\n").encode(
                        "utf-8"
                    ),
                )
                await writer.drain()
                await asyncio.wait_for(reader.readline(), timeout=3.0)
                writer.close()
                try:
                    await writer.wait_closed()
                except (ConnectionResetError, BrokenPipeError):
                    pass
            assert listener.sessions.total_started == 3
        finally:
            echo_task.cancel()
            try:
                await echo_task
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass
            await listener.stop()
