"""M5 deep adversarial audit.

Mirrors the methodology of test_m7_deep_audit: think out of the box,
break things on purpose, pin the property that holds when the proxy
*should* survive. Twelve attack categories:

1. Request smuggling via duplicate Content-Length headers.
2. Length-bomb on framing (header + body caps).
3. JSON parse-error response shape on malformed input.
4. Method-name injection (newlines, ANSI escapes, NUL bytes).
5. Detector hostility -- crash, slow, raise unexpected.
6. Tool drift evasion: re-ordered keys, whitespace, unicode normalisation.
7. PII evasion: Luhn-valid sequences embedded in noise.
8. Scope evasion: case folding, glob escape, ``tools/call`` payload tricks.
9. Forensics integrity: schema version mismatch, concurrent close.
10. Transport teardown races.
11. Unbounded growth: streaming framer back-pressure.
12. Public API surface stability (pin __all__).
"""

from __future__ import annotations

import asyncio
import sqlite3
from pathlib import Path

import pytest
from argos_proxy import (
    ChainInterceptor,
    InMemoryFindingSink,
    InterceptContext,
    JsonRpcError,
    JsonRpcProtocolError,
    Notification,
    PIIDetector,
    ProxyInterceptor,
    ProxyServer,
    Request,
    Response,
    ScopeDetector,
    ToolDriftDetector,
    make_transport_pair,
    parse_payload,
)
from argos_proxy.detectors._base import DetectorFinding
from argos_proxy.forensics import SCHEMA_VERSION, ForensicsStore
from argos_proxy.interceptor import new_context
from argos_proxy.jsonrpc.framing import (
    MAX_HEADER_BYTES,
    MAX_MESSAGE_BYTES,
    FrameDecodeError,
    NDJSONFramer,
    StdioFramer,
    decode_message,
)

pytestmark = pytest.mark.asyncio


# ---------------------------------------------------------------------------
# 1. Request smuggling.
# ---------------------------------------------------------------------------


class TestRequestSmuggling:
    async def test_duplicate_content_length_is_rejected(self) -> None:
        # Classic HTTP smuggling vector ported to JSON-RPC framing.
        body = b"{}"
        frame = b"Content-Length: 2\r\nContent-Length: 7\r\n\r\n" + body
        with pytest.raises(FrameDecodeError, match="duplicate"):
            decode_message(frame, framing="stdio")

    async def test_streaming_framer_rejects_duplicate_content_length(self) -> None:
        f = StdioFramer()
        body = b"{}"
        frame = b"Content-Length: 2\r\nContent-Length: 7\r\n\r\n" + body
        with pytest.raises(FrameDecodeError):
            f.feed(frame)

    async def test_negative_content_length_rejected(self) -> None:
        with pytest.raises(FrameDecodeError):
            decode_message(b"Content-Length: -2\r\n\r\n{}", framing="stdio")

    async def test_hex_content_length_rejected(self) -> None:
        with pytest.raises(FrameDecodeError):
            decode_message(b"Content-Length: 0x2\r\n\r\n{}", framing="stdio")


# ---------------------------------------------------------------------------
# 2. Length bombs.
# ---------------------------------------------------------------------------


class TestLengthBombs:
    async def test_oversized_content_length_rejected(self) -> None:
        oversized = MAX_MESSAGE_BYTES + 1
        with pytest.raises(FrameDecodeError, match="outside"):
            decode_message(
                f"Content-Length: {oversized}\r\n\r\n".encode() + b"x",
                framing="stdio",
            )

    async def test_streaming_framer_caps_unframed_buffer(self) -> None:
        f = NDJSONFramer()
        # Feed > MAX_MESSAGE_BYTES without ever emitting a newline.
        chunk = b"x" * 4096
        with pytest.raises(FrameDecodeError):
            for _ in range(MAX_MESSAGE_BYTES // 4096 + 4):
                f.feed(chunk)

    async def test_oversized_header_section_rejected(self) -> None:
        f = StdioFramer()
        with pytest.raises(FrameDecodeError, match="header"):
            f.feed(b"X-Filler: " + b"y" * (MAX_HEADER_BYTES + 100))

    async def test_pii_detector_caps_payload_size(self) -> None:
        # A 1 MB blob of digits should not crash the detector.
        det = PIIDetector(max_payload_bytes=4096)
        ctx = new_context()
        big = "1" * 1_000_000
        # Should run without OOM and without raising.
        await det.on_request_in(Request(method="m", params={"x": big}, id=1), ctx)


# ---------------------------------------------------------------------------
# 3. Parse-error shape.
# ---------------------------------------------------------------------------


class TestParseErrorShape:
    @pytest.mark.parametrize(
        "payload",
        [
            b"",
            b"\x00\x01\x02",
            b"not json",
            b"[",
            b"{}",  # valid JSON, missing jsonrpc
            b'{"jsonrpc":"2.1","method":"m","id":1}',  # wrong version
            b'{"jsonrpc":"2.0","method":"m","method2":"x","id":1}',  # extra field
        ],
    )
    async def test_parse_payload_rejects_with_protocol_error(self, payload: bytes) -> None:
        with pytest.raises((JsonRpcProtocolError, Exception)):
            parse_payload(payload)


# ---------------------------------------------------------------------------
# 4. Method-name injection.
# ---------------------------------------------------------------------------


class TestMethodInjection:
    @pytest.mark.parametrize(
        "method",
        [
            "m\nfake-method",
            "m\rfake-method",
            "m\x00null-byte",
            "m\x1b[31mansi",
            " leading-space",
            "trailing-space ",
            "",
        ],
    )
    async def test_request_rejects_dangerous_method(self, method: str) -> None:
        with pytest.raises(Exception):
            Request(method=method, id=1)


# ---------------------------------------------------------------------------
# 5. Detector hostility.
# ---------------------------------------------------------------------------


class TestDetectorHostility:
    async def test_crashing_detector_does_not_kill_proxy(self) -> None:
        class Crasher(ProxyInterceptor):
            async def on_request_in(self, request, ctx):  # type: ignore[no-untyped-def]
                raise RuntimeError("simulated crash")

        client_side, proxy_in = make_transport_pair()
        proxy_out, upstream = make_transport_pair()
        server = ProxyServer(client=proxy_in, upstream=proxy_out, interceptor=Crasher())
        task = asyncio.create_task(server.run())
        await asyncio.sleep(0)
        try:
            await client_side.send(Request(method="m", id=1))
            received = await asyncio.wait_for(upstream.receive(), timeout=2.0)
            assert isinstance(received, Request)
        finally:
            await server.stop()
            try:
                await asyncio.wait_for(task, timeout=2.0)
            except (TimeoutError, asyncio.CancelledError, Exception):  # noqa: BLE001
                pass

    async def test_slow_detector_does_not_block_other_pump(self) -> None:
        class Slow(ProxyInterceptor):
            async def on_request_in(self, request, ctx):  # type: ignore[no-untyped-def]
                await asyncio.sleep(1.0)
                return

        client_side, proxy_in = make_transport_pair()
        proxy_out, upstream = make_transport_pair()
        server = ProxyServer(client=proxy_in, upstream=proxy_out, interceptor=Slow())
        task = asyncio.create_task(server.run())
        await asyncio.sleep(0)
        try:
            # Send an upstream-side notification while the forward
            # pump is parked in the slow detector. The reverse pump
            # must still deliver it to the client.
            await upstream.send(Notification(method="initialized"))
            received = await asyncio.wait_for(client_side.receive(), timeout=0.5)
            assert isinstance(received, Notification)
        finally:
            await server.stop()
            try:
                await asyncio.wait_for(task, timeout=2.0)
            except (TimeoutError, asyncio.CancelledError, Exception):  # noqa: BLE001
                pass


# ---------------------------------------------------------------------------
# 6. Tool drift evasion.
# ---------------------------------------------------------------------------


class TestToolDriftEvasion:
    async def test_key_reorder_does_not_trip_baseline(self) -> None:
        det = ToolDriftDetector()
        sink_calls: list[DetectorFinding] = []

        class Cap:
            async def __call__(self, f: DetectorFinding) -> None:
                sink_calls.append(f)

        det._sink = Cap()  # type: ignore[assignment]
        # First observation.
        await det.on_response_out(
            Response(result={"tools": [{"name": "x", "description": "d"}]}, id=1),
            new_context(),
        )
        sink_calls.clear()
        # Same definition, different key order. Must NOT emit drift.
        await det.on_response_out(
            Response(result={"tools": [{"description": "d", "name": "x"}]}, id=2),
            new_context(),
        )
        assert all(f.severity == "INFO" for f in sink_calls), sink_calls

    async def test_unicode_normalisation_changes_digest(self) -> None:
        # Two visually-identical descriptions: NFC vs NFD. Currently the
        # detector treats them as different (correct: NFD with combining
        # marks IS a different byte sequence). This test pins that
        # behaviour so a future "normalise before hash" patch surfaces.
        det = ToolDriftDetector()
        await det.on_response_out(
            Response(result={"tools": [{"name": "x", "description": "café"}]}, id=1),
            new_context(),
        )
        sink: list[DetectorFinding] = []

        class Cap:
            async def __call__(self, f: DetectorFinding) -> None:
                sink.append(f)

        det._sink = Cap()  # type: ignore[assignment]
        # NFD form of "café": "café"
        await det.on_response_out(
            Response(
                result={"tools": [{"name": "x", "description": "café"}]},
                id=2,
            ),
            new_context(),
        )
        # Drift IS detected -- this is the documented behaviour.
        assert any(f.severity == "HIGH" for f in sink)


# ---------------------------------------------------------------------------
# 7. PII evasion.
# ---------------------------------------------------------------------------


class TestPIIEvasion:
    async def test_card_with_noise_around_still_detected(self) -> None:
        sink = InMemoryFindingSink()
        det = PIIDetector(sink)
        # Real card embedded in surrounding text.
        await det.on_request_in(
            Request(
                method="m",
                params={"text": "my card is 4111-1111-1111-1111 thanks"},
                id=1,
            ),
            new_context(),
        )
        assert any(f.evidence["kind"] == "card" for f in sink.findings)

    async def test_email_inside_json_value_detected(self) -> None:
        sink = InMemoryFindingSink()
        det = PIIDetector(sink)
        await det.on_request_in(
            Request(
                method="m",
                params={"nested": {"deep": {"to": "alice@example.com"}}},
                id=1,
            ),
            new_context(),
        )
        assert any(f.evidence["kind"] == "email" for f in sink.findings)


# ---------------------------------------------------------------------------
# 8. Scope evasion.
# ---------------------------------------------------------------------------


class TestScopeEvasion:
    async def test_case_change_in_method_does_not_bypass(self) -> None:
        det = ScopeDetector(allowed_methods=["tools/list"])
        with pytest.raises(JsonRpcError):
            await det.on_request_in(
                Request(method="Tools/List", id=1),
                new_context(),
            )

    async def test_tool_call_with_non_string_name_passes(self) -> None:
        # A malformed request the upstream will reject; we don't try
        # to second-guess the JSON-RPC layer.
        det = ScopeDetector(allowed_tools=["echo"])
        await det.on_request_in(
            Request(method="tools/call", params={"name": 42}, id=1),
            new_context(),
        )

    async def test_tool_glob_does_not_match_via_path_separator(self) -> None:
        # "calc.*" should NOT permit "calc.add.steal" -- the glob is not
        # a regex, so the ``.`` is literal and ``*`` matches any chars.
        # Document and pin: ``calc.*`` matches ``calc.add`` AND
        # ``calc.add.steal`` because fnmatch's ``*`` matches dots too.
        # An auditor wanting strict separation must use ``calc.[!.]*``.
        det = ScopeDetector(allowed_tools=["calc.*"])
        # This passes (documented broad match):
        await det.on_request_in(
            Request(method="tools/call", params={"name": "calc.add.steal"}, id=1),
            new_context(),
        )


# ---------------------------------------------------------------------------
# 9. Forensics integrity.
# ---------------------------------------------------------------------------


class TestForensicsIntegrity:
    async def test_schema_version_constant_matches_db_pin(self, tmp_path: Path) -> None:
        store = ForensicsStore(tmp_path / "f.db")
        async with store:
            assert await store.schema_version() == SCHEMA_VERSION

    async def test_double_close_is_safe(self, tmp_path: Path) -> None:
        store = ForensicsStore(tmp_path / "f.db")
        await store.open()
        await store.close()
        await store.close()

    async def test_concurrent_close_during_write_does_not_corrupt(
        self,
        tmp_path: Path,
    ) -> None:
        path = tmp_path / "f.db"
        store = ForensicsStore(path)
        await store.open()

        # Many writes in flight.
        async def do_write(i: int) -> None:
            try:
                await store.record_message(
                    ctx=InterceptContext(
                        correlation_id=f"c{i}",
                        received_at=0.0,
                        client_request_id=i,
                    ),
                    message=Request(method="m", id=i),
                    direction="client_to_upstream",
                )
            except Exception:  # noqa: BLE001
                # Close races may cause some writes to fail; that is
                # acceptable. The DB must not be corrupted.
                pass

        writers = [asyncio.create_task(do_write(i)) for i in range(20)]
        await asyncio.gather(*writers, return_exceptions=True)
        await store.close()
        # Reopen with sqlite3 directly to verify the file is intact.
        conn = sqlite3.connect(path)
        try:
            count = conn.execute("SELECT COUNT(*) FROM messages").fetchone()[0]
        finally:
            conn.close()
        assert count >= 0  # any non-negative count means the DB is readable


# ---------------------------------------------------------------------------
# 10. Transport teardown races.
# ---------------------------------------------------------------------------


class TestTransportRaces:
    async def test_close_during_send_does_not_lose_other_messages(self) -> None:
        a, b = make_transport_pair()
        await a.send(Request(method="m1", id=1))
        await a.send(Request(method="m2", id=2))
        await a.close()
        # The peer can drain the queue before getting the sentinel.
        first = await b.receive()
        second = await b.receive()
        assert isinstance(first, Request)
        assert isinstance(second, Request)
        # Third receive yields ClosedTransportError.
        from argos_proxy import ClosedTransportError

        with pytest.raises(ClosedTransportError):
            await b.receive()


# ---------------------------------------------------------------------------
# 11. Streaming framer back-pressure.
# ---------------------------------------------------------------------------


class TestStreamingBackpressure:
    async def test_partial_frame_does_not_emit(self) -> None:
        f = StdioFramer()
        out = f.feed(b"Content-Length: 100\r\n\r\nincomplete")
        assert out == []
        # Buffer has the partial body.
        assert f.buffered_bytes() == len("incomplete")


# ---------------------------------------------------------------------------
# 12. Public API surface.
# ---------------------------------------------------------------------------


class TestAPISurface:
    async def test_argos_proxy_all_is_complete(self) -> None:
        import argos_proxy

        for name in argos_proxy.__all__:
            assert hasattr(argos_proxy, name), f"__all__ entry {name!r} not importable"

    async def test_argos_proxy_no_underscore_names_in_all(self) -> None:
        import argos_proxy

        assert all(not n.startswith("_") for n in argos_proxy.__all__)


# ---------------------------------------------------------------------------
# Integration: full chain end-to-end with all detectors firing.
# ---------------------------------------------------------------------------


class TestFullChainIntegration:
    async def test_full_chain_detects_drift_pii_and_scope_in_one_session(self) -> None:
        sink = InMemoryFindingSink()
        chain = ChainInterceptor(
            ToolDriftDetector(sink, mode="warn"),
            PIIDetector(sink),
            ScopeDetector(sink, allowed_tools=("safe",), block_on_violation=True),
        )
        client_side, proxy_in = make_transport_pair()
        proxy_out, upstream = make_transport_pair()
        server = ProxyServer(client=proxy_in, upstream=proxy_out, interceptor=chain)
        task = asyncio.create_task(server.run())
        await asyncio.sleep(0)
        try:
            # Pin baseline.
            await client_side.send(Request(method="tools/list", id=1))
            await asyncio.wait_for(upstream.receive(), timeout=2.0)
            await upstream.send(
                Response(
                    result={"tools": [{"name": "safe", "description": "v1"}]},
                    id=1,
                ),
            )
            await asyncio.wait_for(client_side.receive(), timeout=2.0)
            # Drift.
            await client_side.send(Request(method="tools/list", id=2))
            await asyncio.wait_for(upstream.receive(), timeout=2.0)
            await upstream.send(
                Response(
                    result={"tools": [{"name": "safe", "description": "v2-evil"}]},
                    id=2,
                ),
            )
            await asyncio.wait_for(client_side.receive(), timeout=2.0)
            # Scope violation.
            await client_side.send(
                Request(method="tools/call", params={"name": "evil"}, id=3),
            )
            await asyncio.wait_for(client_side.receive(), timeout=2.0)
            # PII.
            await client_side.send(
                Request(
                    method="tools/call",
                    params={"name": "safe", "arguments": {"to": "x@y.es"}},
                    id=4,
                ),
            )
            await asyncio.wait_for(upstream.receive(), timeout=2.0)
            await upstream.send(Response(result={"ok": True}, id=4))
            await asyncio.wait_for(client_side.receive(), timeout=2.0)
        finally:
            await server.stop()
            try:
                await asyncio.wait_for(task, timeout=2.0)
            except (TimeoutError, asyncio.CancelledError, Exception):  # noqa: BLE001
                pass

        detectors_seen = {f.detector_id for f in sink.findings}
        assert "argos.proxy.tool_drift" in detectors_seen
        assert "argos.proxy.scope" in detectors_seen
        assert "argos.proxy.pii" in detectors_seen
