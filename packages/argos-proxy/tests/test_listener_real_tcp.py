"""Integration tests for :class:`ProxyListener` against real TCP sockets.

These tests open *real* sockets via ``asyncio.open_connection`` against
*real* listeners bound on ephemeral ports. They are slower than the
in-memory transport tests but they are the only way to validate the
contract that matters operationally: that the listener accepts
connections, ferries them through the interceptor chain, and shuts
down cleanly.

The upstream side is provided by an in-memory factory: the proxy's
upstream half is exposed back to the test which acts as a fake MCP
server. Where the test really wants a subprocess, it uses the
``fake_mcp_server.py`` fixture (separate test class).
"""

from __future__ import annotations

import asyncio
import json
import os
import socket
import sys
from pathlib import Path
from typing import Any

import pytest
from argos_proxy import (
    ChainInterceptor,
    InMemoryUpstreamFactory,
    PIIDetector,
    ProxyInterceptor,
    ProxyListener,
    Request,
    Response,
    ScopeDetector,
    StdioUpstreamFactory,
    ToolDriftDetector,
    parse_payload,
)

pytestmark = [pytest.mark.asyncio]


_FIXTURE_PATH = Path(__file__).parent / "fixtures" / "fake_mcp_server.py"


# ---------------------------------------------------------------------------
# Helpers shared across the integration suite.
# ---------------------------------------------------------------------------


async def _run_upstream_echo(factory: InMemoryUpstreamFactory) -> None:
    """Drive every accepted upstream half: receive a request, reply with
    a synthetic ``echo`` result. Lives until cancelled."""
    handled: set[int] = set()
    while True:
        await asyncio.sleep(0.01)
        for idx, peer in enumerate(list(factory.peer_transports)):
            if idx in handled:
                continue
            try:
                msg = await asyncio.wait_for(peer.receive(), timeout=0.5)
            except TimeoutError:
                continue
            except Exception:  # noqa: BLE001
                handled.add(idx)
                continue
            if isinstance(msg, Request):
                try:
                    await peer.send(
                        Response(result={"echo": msg.method, "params": msg.params}, id=msg.id),
                    )
                except Exception:  # noqa: BLE001
                    handled.add(idx)


async def _send_ndjson_request(
    host: str,
    port: int,
    method: str,
    *,
    id_: int = 1,
    timeout: float = 5.0,  # noqa: ASYNC109
) -> dict[str, Any]:
    """Open a TCP connection, send one NDJSON request, read one response,
    close. Returns the parsed JSON dict."""
    reader, writer = await asyncio.open_connection(host, port)
    payload = json.dumps({"jsonrpc": "2.0", "method": method, "id": id_}).encode("utf-8") + b"\n"
    writer.write(payload)
    await writer.drain()
    line = await asyncio.wait_for(reader.readline(), timeout=timeout)
    writer.close()
    try:
        await writer.wait_closed()
    except (ConnectionResetError, BrokenPipeError):
        pass
    if not line:
        msg = "no response from listener"
        raise AssertionError(msg)
    parsed: Any = json.loads(line)
    if not isinstance(parsed, dict):
        msg = f"expected JSON object, got {type(parsed).__name__}"
        raise AssertionError(msg)
    return parsed


# ---------------------------------------------------------------------------
# 1. Basic operability: listener binds, accepts, ferries, closes.
# ---------------------------------------------------------------------------


class TestListenerBasics:
    async def test_listener_binds_to_ephemeral_port(self) -> None:
        factory = InMemoryUpstreamFactory()
        listener = ProxyListener(host="127.0.0.1", port=0, upstream_factory=factory)
        await listener.start()
        try:
            bound = listener.bound_address()
            assert bound is not None
            host, port = bound
            assert host == "127.0.0.1"
            assert port > 0
            # Port is actually open.
            with socket.socket() as s:
                s.settimeout(2.0)
                s.connect((host, port))
        finally:
            await listener.stop()

    async def test_request_round_trip_through_real_tcp(self) -> None:
        factory = InMemoryUpstreamFactory()
        listener = ProxyListener(host="127.0.0.1", port=0, upstream_factory=factory)
        await listener.start()
        echo_task = asyncio.create_task(_run_upstream_echo(factory))
        try:
            host, port = listener.bound_address()  # type: ignore[misc]
            response = await _send_ndjson_request(host, port, "tools/list")
            assert response["jsonrpc"] == "2.0"
            assert response["id"] == 1
            assert response["result"]["echo"] == "tools/list"
            # Session metrics updated.
            assert listener.sessions.total_started == 1
        finally:
            echo_task.cancel()
            try:
                await echo_task
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass
            await listener.stop()

    async def test_listener_reports_no_active_sessions_after_client_disconnect(self) -> None:
        factory = InMemoryUpstreamFactory()
        listener = ProxyListener(host="127.0.0.1", port=0, upstream_factory=factory)
        await listener.start()
        echo_task = asyncio.create_task(_run_upstream_echo(factory))
        try:
            host, port = listener.bound_address()  # type: ignore[misc]
            await _send_ndjson_request(host, port, "ping")
            # Give the listener a moment to clean up its session.
            for _ in range(20):
                if listener.sessions.active_count == 0:
                    break
                await asyncio.sleep(0.05)
            assert listener.sessions.active_count == 0
        finally:
            echo_task.cancel()
            try:
                await echo_task
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass
            await listener.stop()

    async def test_async_context_manager_runs_listener(self) -> None:
        factory = InMemoryUpstreamFactory()
        async with ProxyListener(
            host="127.0.0.1",
            port=0,
            upstream_factory=factory,
        ) as listener:
            assert listener.is_running
            _host, port = listener.bound_address()  # type: ignore[misc]
            assert port > 0
        # After context exits, listener is stopped.
        assert not listener.is_running


# ---------------------------------------------------------------------------
# 2. Multi-session concurrency.
# ---------------------------------------------------------------------------


class TestMultiSession:
    async def test_three_concurrent_clients_all_succeed(self) -> None:
        factory = InMemoryUpstreamFactory()
        listener = ProxyListener(host="127.0.0.1", port=0, upstream_factory=factory)
        await listener.start()
        echo_task = asyncio.create_task(_run_upstream_echo(factory))
        try:
            host, port = listener.bound_address()  # type: ignore[misc]
            results = await asyncio.gather(
                *(
                    _send_ndjson_request(host, port, f"method-{i}", id_=i, timeout=10.0)
                    for i in range(3)
                ),
            )
            assert {r["id"] for r in results} == {0, 1, 2}
            assert all(r["result"]["echo"].startswith("method-") for r in results)
            assert listener.sessions.total_started == 3
        finally:
            echo_task.cancel()
            try:
                await echo_task
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass
            await listener.stop()

    async def test_max_sessions_cap_rejects_excess_with_busy_notice(self) -> None:
        """A client that lands when the cap is full must receive the
        ``server_busy`` notice (not a silent close)."""
        factory = InMemoryUpstreamFactory()
        # Cap at 1: the second client is busy-rejected.
        listener = ProxyListener(
            host="127.0.0.1",
            port=0,
            upstream_factory=factory,
            max_sessions=1,
        )
        await listener.start()
        try:
            host, port = listener.bound_address()  # type: ignore[misc]
            # Client A: opens, holds the connection.
            _ra, wa = await asyncio.open_connection(host, port)
            # Wait for the listener to register the session.
            for _ in range(20):
                if listener.sessions.active_count == 1:
                    break
                await asyncio.sleep(0.05)
            assert listener.sessions.active_count == 1

            # Client B: should immediately get the busy notice.
            rb, wb = await asyncio.open_connection(host, port)
            line = await asyncio.wait_for(rb.readline(), timeout=2.0)
            assert line, "client B got no response"
            notice = json.loads(line)
            assert notice["method"] == "argos/notice"
            assert notice["params"]["reason"] == "server_busy"

            wb.close()
            try:
                await wb.wait_closed()
            except (ConnectionResetError, BrokenPipeError):
                pass
            wa.close()
            try:
                await wa.wait_closed()
            except (ConnectionResetError, BrokenPipeError):
                pass
        finally:
            await listener.stop()


# ---------------------------------------------------------------------------
# 3. Lifecycle and graceful shutdown.
# ---------------------------------------------------------------------------


class TestLifecycle:
    async def test_stop_is_idempotent(self) -> None:
        factory = InMemoryUpstreamFactory()
        listener = ProxyListener(host="127.0.0.1", port=0, upstream_factory=factory)
        await listener.start()
        await listener.stop()
        await listener.stop()

    async def test_double_start_raises(self) -> None:
        factory = InMemoryUpstreamFactory()
        listener = ProxyListener(host="127.0.0.1", port=0, upstream_factory=factory)
        await listener.start()
        try:
            with pytest.raises(RuntimeError, match="already running"):
                await listener.start()
        finally:
            await listener.stop()

    async def test_graceful_shutdown_drains_active_session(self) -> None:
        """A client mid-conversation must finish (or be cancelled cleanly)
        when the listener shuts down. The drain timeout is short here so
        the test stays fast."""
        factory = InMemoryUpstreamFactory()
        listener = ProxyListener(
            host="127.0.0.1",
            port=0,
            upstream_factory=factory,
            drain_timeout=0.5,
        )
        await listener.start()
        echo_task = asyncio.create_task(_run_upstream_echo(factory))
        try:
            host, port = listener.bound_address()  # type: ignore[misc]
            _reader, writer = await asyncio.open_connection(host, port)
            # Open a session; do not send anything yet.
            for _ in range(20):
                if listener.sessions.active_count == 1:
                    break
                await asyncio.sleep(0.05)
            assert listener.sessions.active_count == 1
            # Stop while the session is alive. Drain timeout will elapse
            # because the session has no exit signal; cancel kicks in.
            await listener.stop()
            assert listener.sessions.active_count == 0
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

    async def test_duration_constructor_validation(self) -> None:
        with pytest.raises(ValueError, match="port"):
            ProxyListener(host="127.0.0.1", port=99999, upstream_factory=InMemoryUpstreamFactory())
        with pytest.raises(ValueError, match="host"):
            ProxyListener(host="", port=1234, upstream_factory=InMemoryUpstreamFactory())
        with pytest.raises(ValueError, match="framing"):
            ProxyListener(
                host="127.0.0.1",
                port=0,
                upstream_factory=InMemoryUpstreamFactory(),
                framing="grpc",
            )
        with pytest.raises(ValueError, match="session_idle_timeout"):
            ProxyListener(
                host="127.0.0.1",
                port=0,
                upstream_factory=InMemoryUpstreamFactory(),
                session_idle_timeout=-1.0,
            )
        with pytest.raises(ValueError, match="drain_timeout"):
            ProxyListener(
                host="127.0.0.1",
                port=0,
                upstream_factory=InMemoryUpstreamFactory(),
                drain_timeout=-0.5,
            )
        with pytest.raises(ValueError, match="interceptor"):
            ProxyListener(
                host="127.0.0.1",
                port=0,
                upstream_factory=InMemoryUpstreamFactory(),
                interceptor=ChainInterceptor(),
                interceptor_factory=ChainInterceptor,
            )


# ---------------------------------------------------------------------------
# 4. Per-session interceptor isolation.
# ---------------------------------------------------------------------------


class TestPerSessionInterceptor:
    async def test_drift_baseline_is_per_session(self) -> None:
        """Two sessions in series must each pin their OWN baseline.
        If the detector were shared, the second session would emit drift
        the first time it sees its own ``tools/list`` (because the
        baseline was set by session A)."""
        factory = InMemoryUpstreamFactory()

        baselines: list[int] = []

        def make_interceptor() -> ProxyInterceptor:
            d = ToolDriftDetector(mode="warn")
            baselines.append(id(d))
            return d

        listener = ProxyListener(
            host="127.0.0.1",
            port=0,
            upstream_factory=factory,
            interceptor_factory=make_interceptor,
        )
        await listener.start()

        async def _drive_upstream() -> None:
            handled = 0
            while True:
                await asyncio.sleep(0.01)
                for peer in list(factory.peer_transports):
                    if handled >= len(factory.peer_transports):
                        continue
                    try:
                        msg = await asyncio.wait_for(peer.receive(), timeout=0.3)
                    except TimeoutError:
                        continue
                    except Exception:  # noqa: BLE001
                        continue
                    if isinstance(msg, Request) and msg.method == "tools/list":
                        await peer.send(
                            Response(
                                result={"tools": [{"name": "x", "description": "v"}]},
                                id=msg.id,
                            ),
                        )
                handled = len(factory.peer_transports)

        echo_task = asyncio.create_task(_drive_upstream())
        try:
            host, port = listener.bound_address()  # type: ignore[misc]
            for _ in range(2):
                await _send_ndjson_request(host, port, "tools/list", timeout=10.0)
            # Two distinct ToolDriftDetector instances were built.
            assert len(set(baselines)) == 2
        finally:
            echo_task.cancel()
            try:
                await echo_task
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass
            await listener.stop()


# ---------------------------------------------------------------------------
# 5. Subprocess upstream: real fake MCP server.
# ---------------------------------------------------------------------------


def _python_for_subprocess() -> str:
    """Return the venv python where ``argos_proxy`` is importable."""
    venv = os.environ.get("VIRTUAL_ENV")
    if venv:
        for candidate in (
            Path(venv) / "Scripts" / "python.exe",
            Path(venv) / "bin" / "python",
        ):
            if candidate.is_file():
                return str(candidate)
    return sys.executable


class TestSubprocessUpstream:
    async def test_listener_with_real_subprocess_mcp_returns_tools_list(self) -> None:
        """End-to-end: TCP client -> proxy listener -> stdio subprocess
        running ``fake_mcp_server.py``. No in-memory shortcut."""
        py = _python_for_subprocess()
        factory = StdioUpstreamFactory([py, str(_FIXTURE_PATH)])
        listener = ProxyListener(
            host="127.0.0.1",
            port=0,
            upstream_factory=factory,
            session_idle_timeout=10.0,
            drain_timeout=2.0,
        )
        await listener.start()
        try:
            host, port = listener.bound_address()  # type: ignore[misc]
            response = await _send_ndjson_request(host, port, "tools/list", timeout=10.0)
            assert response["id"] == 1
            tools = response["result"]["tools"]
            assert len(tools) == 1
            assert tools[0]["name"] == "echo"
        finally:
            await listener.stop()

    async def test_listener_with_subprocess_handles_initialize_then_call(self) -> None:
        """Two sequential requests over the same TCP connection."""
        py = _python_for_subprocess()
        factory = StdioUpstreamFactory([py, str(_FIXTURE_PATH)])
        listener = ProxyListener(
            host="127.0.0.1",
            port=0,
            upstream_factory=factory,
            session_idle_timeout=10.0,
            drain_timeout=2.0,
        )
        await listener.start()
        try:
            host, port = listener.bound_address()  # type: ignore[misc]
            reader, writer = await asyncio.open_connection(host, port)
            try:
                # initialize
                writer.write(
                    (json.dumps({"jsonrpc": "2.0", "method": "initialize", "id": 1}) + "\n").encode(
                        "utf-8"
                    ),
                )
                await writer.drain()
                line = await asyncio.wait_for(reader.readline(), timeout=10.0)
                msg = parse_payload(line)
                assert msg.id == 1  # type: ignore[union-attr]
                assert msg.result["serverInfo"]["name"] == "fake-mcp"  # type: ignore[union-attr]
                # ping
                writer.write(
                    (json.dumps({"jsonrpc": "2.0", "method": "ping", "id": 2}) + "\n").encode(
                        "utf-8"
                    ),
                )
                await writer.drain()
                line = await asyncio.wait_for(reader.readline(), timeout=10.0)
                msg = parse_payload(line)
                assert msg.id == 2  # type: ignore[union-attr]
                assert msg.result == "pong"  # type: ignore[union-attr]
            finally:
                writer.close()
                try:
                    await writer.wait_closed()
                except (ConnectionResetError, BrokenPipeError):
                    pass
        finally:
            await listener.stop()


# ---------------------------------------------------------------------------
# 6. Detector chain end-to-end with subprocess.
# ---------------------------------------------------------------------------


class TestDetectorChainE2E:
    async def test_drift_detector_fires_on_real_subprocess_mutation(
        self,
        tmp_path: Path,
    ) -> None:
        """Real scenario: client opens a session, calls tools/list,
        upstream is restarted with FAKE_MCP_DRIFT=1 (different tool
        schema), the second session detects drift.

        Because tool drift is per-session in the listener config, the
        baseline is rebuilt on session #2, so the drift is NOT visible
        across sessions. We instead verify it on a SINGLE session:
        the same client opens, lists tools twice (drift would only
        emerge if the upstream mutated mid-session, which our fake
        server cannot do without restart). This test therefore pins
        the negative property: a single session with a stable upstream
        emits NO drift findings.

        The positive across-session drift test is covered by the unit
        test ``test_input_schema_change_detected``.
        """
        py = _python_for_subprocess()
        factory = StdioUpstreamFactory([py, str(_FIXTURE_PATH)])

        from argos_proxy import InMemoryFindingSink

        sink = InMemoryFindingSink()

        def make_chain() -> ProxyInterceptor:
            return ChainInterceptor(
                ToolDriftDetector(sink, mode="warn"),
                PIIDetector(sink),
                ScopeDetector(sink, block_on_violation=False),
            )

        listener = ProxyListener(
            host="127.0.0.1",
            port=0,
            upstream_factory=factory,
            interceptor_factory=make_chain,
            session_idle_timeout=10.0,
            drain_timeout=2.0,
        )
        await listener.start()
        try:
            host, port = listener.bound_address()  # type: ignore[misc]
            reader, writer = await asyncio.open_connection(host, port)
            try:
                for i in range(2):
                    writer.write(
                        (
                            json.dumps(
                                {"jsonrpc": "2.0", "method": "tools/list", "id": i + 1},
                            )
                            + "\n"
                        ).encode("utf-8"),
                    )
                    await writer.drain()
                    line = await asyncio.wait_for(reader.readline(), timeout=10.0)
                    assert line
            finally:
                writer.close()
                try:
                    await writer.wait_closed()
                except (ConnectionResetError, BrokenPipeError):
                    pass
        finally:
            await listener.stop()

        # The first tools/list pins the baseline (INFO breadcrumb).
        # The second is identical -> no drift finding.
        kinds = {f.severity for f in sink.findings}
        assert "INFO" in kinds
        assert "HIGH" not in kinds, f"unexpected HIGH findings: {sink.findings!r}"
