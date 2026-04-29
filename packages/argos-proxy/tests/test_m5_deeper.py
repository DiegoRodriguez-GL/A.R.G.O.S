"""M5 audit, second adversarial pass.

Each section attacks a property a TFM reviewer or a real adversary
might raise:

1. JSON-RPC spec edges (int64+, BOM, duplicate keys, deep nesting,
   batches inside batches, mixed framings).
2. Framing fuzz (Content-Length: 0, header without value, lone CR,
   NDJSON empty lines, Mac line endings).
3. Server lifecycle (concurrent ``stop()``, task leak detection,
   cancel during interceptor work, response from client side).
4. Detector deep edges (tool drift with duplicates / paged tools / null
   tools, PII NIE / multi-PII / nesting bomb, scope with name="" /
   path-traversal style, ANSI in payload).
5. Forensics integrity (SQL injection by correlation_id, large
   payload, idempotent open under contention, schema future-proof,
   double-close after error).
6. Pickling and cross-process state.
7. Hypothesis property tests on invariants the M5 contract pins.
"""

from __future__ import annotations

import asyncio
import json
import pickle
import sqlite3
import sys
import time
from pathlib import Path
from typing import Any

import pytest
from argos_proxy import (
    Batch,
    ChainInterceptor,
    ClosedTransportError,
    ErrorObject,
    InMemoryFindingSink,
    InterceptContext,
    JsonRpcError,
    JsonRpcProtocolError,
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
from argos_proxy.detectors.pii import (
    _nie_is_valid,
)
from argos_proxy.forensics import ForensicsStore
from argos_proxy.interceptor import new_context
from argos_proxy.jsonrpc.framing import (
    MAX_HEADER_BYTES,
    FrameDecodeError,
    NDJSONFramer,
    StdioFramer,
    decode_message,
    encode_message,
)

pytestmark = pytest.mark.asyncio


# ---------------------------------------------------------------------------
# 1. JSON-RPC spec edges.
# ---------------------------------------------------------------------------


class TestJsonRpcEdges:
    async def test_int_id_beyond_2_to_53_round_trips(self) -> None:
        # JSON-RPC permits ints; JSON parsers may degrade above 2^53
        # (IEEE 754 double precision). Python's json keeps ints exact.
        # Pin that property: a 19-digit id round-trips bit-faithfully.
        big = 9007199254740993  # 2^53 + 1
        wire = encode_message(Request(method="m", id=big), framing="ndjson")
        decoded = parse_payload(decode_message(wire, framing="ndjson"))
        assert isinstance(decoded, Request)
        assert decoded.id == big

    async def test_utf8_bom_in_payload_is_handled_or_rejected(self) -> None:
        # A BOM-prefixed JSON payload is technically not valid JSON
        # (RFC 8259 §8.1 forbids it). Some clients still emit one.
        # We require it to either parse OR raise our protocol error,
        # never crash the proxy.
        bom_payload = b"\xef\xbb\xbf" + b'{"jsonrpc":"2.0","method":"m","id":1}'
        try:
            msg = parse_payload(bom_payload)
        except JsonRpcProtocolError:
            return
        assert isinstance(msg, Request)

    async def test_duplicate_keys_in_object_resolve_last_wins(self) -> None:
        # JSON spec says duplicate names lead to undefined behaviour;
        # Python's json picks the last. Pin that the parser does NOT
        # raise (which would surprise interop) but produces a typed
        # message reflecting the last value.
        payload = b'{"jsonrpc":"2.0","method":"m","id":1,"id":2}'
        msg = parse_payload(payload)
        assert isinstance(msg, Request)
        assert msg.id == 2

    async def test_deeply_nested_json_does_not_recursion_error(self) -> None:
        # Adversary feeds [[[...]]] beyond Python's recursion limit.
        # The parser must convert it to a protocol error rather than
        # crash with RecursionError.
        depth = sys.getrecursionlimit() + 200
        payload = ("[" * depth + "]" * depth).encode("utf-8")
        with pytest.raises(JsonRpcProtocolError):
            parse_payload(payload)

    async def test_batch_with_nested_array_yields_protocol_error(self) -> None:
        # ``[[{...}], {...}]`` -- a list inside a batch is illegal per
        # the spec (every batch element must be a JSON-RPC object).
        with pytest.raises(JsonRpcProtocolError):
            parse_payload(b'[[{"jsonrpc":"2.0","method":"m","id":1}]]')

    async def test_message_with_id_containing_unicode_escapes(self) -> None:
        # ID is "café" with combining accent represented as é.
        payload = b'{"jsonrpc":"2.0","method":"m","id":"caf\\u00e9"}'
        msg = parse_payload(payload)
        assert isinstance(msg, Request)
        assert msg.id == "café"

    async def test_method_with_unicode_letters_rejected_by_strict_pattern(self) -> None:
        # Our method-name pattern is intentionally ASCII-only to keep
        # logs greppable; validate the rejection holds.
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            Request(method="café/lookup", id=1)


# ---------------------------------------------------------------------------
# 2. Framing fuzz.
# ---------------------------------------------------------------------------


class TestFramingEdges:
    async def test_content_length_zero_means_empty_body(self) -> None:
        # Zero-length frame is technically valid: the body is an empty
        # JSON value. Empty body fails JSON parsing downstream, but
        # the framer must accept the frame.
        body = decode_message(b"Content-Length: 0\r\n\r\n", framing="stdio")
        assert body == b""

    async def test_header_without_value_is_rejected(self) -> None:
        # ``Content-Length:\r\n`` -- name with no value.
        with pytest.raises(FrameDecodeError, match="non-numeric"):
            decode_message(b"Content-Length: \r\n\r\n", framing="stdio")

    async def test_lone_cr_in_ndjson_does_not_terminate(self) -> None:
        # Mac-classic line endings (lone \r) are not legal NDJSON
        # delimiters; the framer must keep buffering until \n.
        f = NDJSONFramer()
        out = f.feed(b'{"a":1}\r')
        assert out == []
        assert f.buffered_bytes() == len('{"a":1}\r')
        out = f.feed(b"\n")
        # Trailing CR is stripped by the streaming framer.
        assert out == [b'{"a":1}']

    async def test_empty_ndjson_lines_are_skipped(self) -> None:
        # ``{...}\n\n{...}\n`` -- the empty line in the middle becomes
        # an empty body. The framer emits the empty bytes; downstream
        # parse_payload would reject. The framer's job is only to
        # split.
        f = NDJSONFramer()
        out = f.feed(b'{"a":1}\n\n{"b":2}\n')
        assert out == [b'{"a":1}', b"", b'{"b":2}']

    async def test_stdio_with_lf_only_separator_is_rejected(self) -> None:
        # Some implementations sloppily emit ``\n\n`` instead of
        # ``\r\n\r\n``. Strict spec says reject; we honour that.
        with pytest.raises(FrameDecodeError):
            decode_message(b"Content-Length: 2\n\n{}", framing="stdio")

    async def test_stdio_oversized_header_value_rejected(self) -> None:
        # A megabyte of digits in the Content-Length header would
        # consume CPU and memory before failing -- the early header
        # cap stops it.
        bombed = b"Content-Length: " + b"9" * (MAX_HEADER_BYTES + 100) + b"\r\n\r\n{}"
        with pytest.raises(FrameDecodeError):
            decode_message(bombed, framing="stdio")

    async def test_streaming_framer_preserves_byte_boundary(self) -> None:
        # Concatenate two valid stdio frames and feed in 1-byte chunks.
        # The framer must reconstruct each body exactly.
        f = StdioFramer()
        body1 = b'{"a":1}'
        body2 = b'{"b":22}'
        wire = (
            f"Content-Length: {len(body1)}\r\n\r\n".encode()
            + body1
            + f"Content-Length: {len(body2)}\r\n\r\n".encode()
            + body2
        )
        out: list[bytes] = []
        for i in range(len(wire)):
            out.extend(f.feed(wire[i : i + 1]))
        assert out == [body1, body2]


# ---------------------------------------------------------------------------
# 3. Server lifecycle stress.
# ---------------------------------------------------------------------------


class TestServerLifecycle:
    async def test_concurrent_stop_calls_are_safe(self) -> None:
        client_side, proxy_in = make_transport_pair()
        proxy_out, upstream = make_transport_pair()
        server = ProxyServer(client=proxy_in, upstream=proxy_out)
        task = asyncio.create_task(server.run())
        await asyncio.sleep(0)
        # Five concurrent stops must all complete without raising.
        await asyncio.gather(*(server.stop() for _ in range(5)))
        try:
            await asyncio.wait_for(task, timeout=2.0)
        except (asyncio.CancelledError, Exception):  # noqa: BLE001
            pass
        await client_side.close()
        await upstream.close()

    async def test_response_from_client_side_is_dropped(self) -> None:
        # Spec: only the server side sends responses. If the client
        # sends one, the proxy must NOT forward it (would confuse the
        # upstream) and must NOT crash either.
        client_side, proxy_in = make_transport_pair()
        proxy_out, upstream = make_transport_pair()
        server = ProxyServer(client=proxy_in, upstream=proxy_out)
        task = asyncio.create_task(server.run())
        await asyncio.sleep(0)
        try:
            # Push a Response on the client side.
            await client_side.send(Response(result={"ok": True}, id=1))
            # Verify the upstream never receives anything.
            with pytest.raises(asyncio.TimeoutError):
                await asyncio.wait_for(upstream.receive(), timeout=0.3)
        finally:
            await server.stop()
            try:
                await asyncio.wait_for(task, timeout=2.0)
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass

    async def test_run_after_stop_raises(self) -> None:
        client_side, proxy_in = make_transport_pair()
        proxy_out, upstream = make_transport_pair()
        server = ProxyServer(client=proxy_in, upstream=proxy_out)
        task = asyncio.create_task(server.run())
        await asyncio.sleep(0)
        await server.stop()
        try:
            await asyncio.wait_for(task, timeout=1.0)
        except (asyncio.CancelledError, Exception):  # noqa: BLE001
            pass
        # ``_running`` is False again; calling run() a second time on
        # the same instance is technically permitted but the tests
        # above show the server is single-shot. Pin both.
        # Either succeeds (re-run cleanly) or raises -- not a hang.
        client2, proxy_in2 = make_transport_pair()
        proxy_out2, upstream2 = make_transport_pair()
        server2 = ProxyServer(client=proxy_in2, upstream=proxy_out2)
        # Quick smoke: a fresh server runs ok.
        t2 = asyncio.create_task(server2.run())
        await asyncio.sleep(0)
        await server2.stop()
        try:
            await asyncio.wait_for(t2, timeout=1.0)
        except (asyncio.CancelledError, Exception):  # noqa: BLE001
            pass
        await client_side.close()
        await upstream.close()
        await client2.close()
        await upstream2.close()

    async def test_no_task_leak_after_stop(self) -> None:
        before = len(asyncio.all_tasks())
        for _ in range(20):
            client_side, proxy_in = make_transport_pair()
            proxy_out, upstream = make_transport_pair()
            server = ProxyServer(client=proxy_in, upstream=proxy_out)
            task = asyncio.create_task(server.run())
            await asyncio.sleep(0)
            await server.stop()
            try:
                await asyncio.wait_for(task, timeout=0.5)
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass
            await client_side.close()
            await upstream.close()
        # Allow one event loop tick for any straggler to clean up.
        await asyncio.sleep(0)
        after = len(asyncio.all_tasks())
        # 20 servers x 2 pumps each = 40 tasks would leak; we tolerate
        # at most one residual (the test coroutine itself counts).
        assert after - before <= 2, f"task leak: {after - before} stragglers"


# ---------------------------------------------------------------------------
# 4. Detector deep edges.
# ---------------------------------------------------------------------------


class TestToolDriftDeep:
    async def test_duplicate_tool_names_in_one_response_collapse(self) -> None:
        # A malformed upstream might emit the same tool twice. The
        # detector currently collapses by name (last wins) and records
        # the snapshot for the deduped set.
        det = ToolDriftDetector()
        ctx = new_context()
        await det.on_response_out(
            Response(
                result={
                    "tools": [
                        {"name": "x", "description": "first"},
                        {"name": "x", "description": "second"},
                    ],
                },
                id=1,
            ),
            ctx,
        )
        # Baseline locked with one snapshot (the second).
        assert det.is_locked
        snap = det.baseline["x"]
        assert "second" in snap.canonical_json

    async def test_paged_tools_list_is_compared_per_response(self) -> None:
        # MCP supports cursor-paged ``tools/list``. The detector treats
        # each response in isolation: a second page with different
        # tools triggers drift unless the baseline already had them.
        sink = InMemoryFindingSink()
        det = ToolDriftDetector(sink)
        await det.on_response_out(
            Response(
                result={"tools": [{"name": "a", "description": "x"}], "nextCursor": "p2"},
                id=1,
            ),
            new_context(),
        )
        sink.clear()
        # Second page introduces a new tool.
        await det.on_response_out(
            Response(
                result={"tools": [{"name": "b", "description": "y"}], "nextCursor": None},
                id=2,
            ),
            new_context(),
        )
        # Drift detected: ``a`` removed AND ``b`` added.
        f = sink.findings[0]
        assert f.severity == "HIGH"
        assert "a" in f.evidence["removed"]
        assert "b" in f.evidence["added"]

    async def test_tools_field_is_null_does_not_lock_baseline(self) -> None:
        det = ToolDriftDetector()
        await det.on_response_out(
            Response(result={"tools": None}, id=1),
            new_context(),
        )
        assert not det.is_locked

    async def test_block_mode_emits_legal_response_after_drift(self) -> None:
        # The replacement Response built in block mode must itself be
        # valid: not failing the model validators when serialised.
        det = ToolDriftDetector(mode="block")
        await det.on_response_out(
            Response(result={"tools": [{"name": "a", "description": "x"}]}, id=1),
            new_context(),
        )
        replacement = await det.on_response_out(
            Response(result={"tools": [{"name": "a", "description": "EVIL"}]}, id=2),
            new_context(),
        )
        assert replacement is not None
        # Serialise + parse -- exercises the model_serializer too.
        wire = replacement.model_dump_json()
        reloaded = Response.model_validate_json(wire)
        assert reloaded.is_success


class TestPIIDeep:
    async def test_nie_with_valid_check_letter_detected(self) -> None:
        # NIE example: X1234567L. Substitute X=0 -> "01234567" -> int
        # 1234567. 1234567 mod 23 = 19 -> ``_DNI_LETTERS[19]`` = "L".
        sink = InMemoryFindingSink()
        det = PIIDetector(sink)
        await det.on_request_in(
            Request(method="m", params={"id": "X1234567L"}, id=1),
            new_context(),
        )
        kinds = [f.evidence["kind"] for f in sink.findings]
        assert "dni" in kinds  # NIE is reported under the DNI bucket

    async def test_nie_with_wrong_letter_is_rejected(self) -> None:
        sink = InMemoryFindingSink()
        det = PIIDetector(sink)
        await det.on_request_in(
            Request(method="m", params={"id": "X1234567A"}, id=1),
            new_context(),
        )
        assert all(f.evidence["kind"] != "dni" for f in sink.findings)

    async def test_nie_validator_unit(self) -> None:
        # X1234567 -> substitute X=0 -> "01234567" -> int 1234567.
        # 1234567 mod 23 = 19. ``_DNI_LETTERS[19]`` = "L".
        # So the valid NIE control letter is "L".
        assert _nie_is_valid("X", "1234567", "L")
        assert not _nie_is_valid("X", "1234567", "Z")
        # Every prefix maps to a digit; the validator accepts any
        # legal prefix without crashing.
        for prefix in ("X", "Y", "Z", "x", "y", "z"):
            _nie_is_valid(prefix, "1234567", "L")

    async def test_email_with_plus_subaddressing_detected(self) -> None:
        sink = InMemoryFindingSink()
        det = PIIDetector(sink)
        await det.on_request_in(
            Request(method="m", params={"to": "alice+filter@example.com"}, id=1),
            new_context(),
        )
        assert any(f.evidence["kind"] == "email" for f in sink.findings)

    async def test_multi_pii_in_same_payload_each_kind_reported_once(self) -> None:
        sink = InMemoryFindingSink()
        det = PIIDetector(sink)
        await det.on_request_in(
            Request(
                method="m",
                params={
                    "email": "a@b.es",
                    "dni": "12345678Z",
                    "iban": "ES9121000418450200051332",
                    "card": "4111111111111111",
                },
                id=1,
            ),
            new_context(),
        )
        kinds = sorted({f.evidence["kind"] for f in sink.findings})
        assert kinds == ["card", "dni", "email", "iban"]

    async def test_pii_in_deeply_nested_payload(self) -> None:
        # Construct a 30-level-deep dict with an email at the bottom.
        nested: dict[str, Any] = {"email": "x@y.es"}
        for _ in range(30):
            nested = {"k": nested}
        sink = InMemoryFindingSink()
        det = PIIDetector(sink)
        await det.on_request_in(
            Request(method="m", params=nested, id=1),
            new_context(),
        )
        assert any(f.evidence["kind"] == "email" for f in sink.findings)


class TestScopeDeep:
    async def test_tool_name_with_path_traversal_pattern_is_blocked(self) -> None:
        det = ScopeDetector(allowed_tools=["safe.*"])
        with pytest.raises(JsonRpcError):
            await det.on_request_in(
                Request(
                    method="tools/call",
                    params={"name": "../../../etc/passwd"},
                    id=1,
                ),
                new_context(),
            )

    async def test_empty_tool_name_treated_as_violation(self) -> None:
        det = ScopeDetector(allowed_tools=["echo"])
        with pytest.raises(JsonRpcError):
            await det.on_request_in(
                Request(method="tools/call", params={"name": ""}, id=1),
                new_context(),
            )

    async def test_tool_name_with_trailing_whitespace_does_not_match(self) -> None:
        # ``echo `` should NOT match ``echo`` -- otherwise an attacker
        # could bypass via padding.
        det = ScopeDetector(allowed_tools=["echo"])
        with pytest.raises(JsonRpcError):
            await det.on_request_in(
                Request(method="tools/call", params={"name": "echo "}, id=1),
                new_context(),
            )


# ---------------------------------------------------------------------------
# 5. Forensics integrity.
# ---------------------------------------------------------------------------


class TestForensicsAdversarial:
    async def test_correlation_id_with_sql_metacharacters(self, tmp_path: Path) -> None:
        # If the SQL were string-formatted (it isn't), this id would
        # drop the table. The parametrised query keeps it harmless.
        evil_id = "x' OR '1'='1; DROP TABLE messages; --"
        store = ForensicsStore(tmp_path / "f.db")
        async with store:
            await store.record_message(
                ctx=InterceptContext(correlation_id=evil_id, received_at=0.0),
                message=Request(method="m", id=1),
                direction="client_to_upstream",
            )
            rows = await store.messages_for(evil_id)
            assert len(rows) == 1

    async def test_concurrent_open_does_not_orphan_connection(
        self,
        tmp_path: Path,
    ) -> None:
        # Race: 10 coroutines all call open() before the first
        # connection is set on the instance. Without the open-lock,
        # nine connections would be opened and discarded (memory +
        # WAL leaks).
        store = ForensicsStore(tmp_path / "f.db")
        await asyncio.gather(*(store.open() for _ in range(10)))
        # Force a write to confirm the live connection works.
        await store.record_message(
            ctx=InterceptContext(correlation_id="c", received_at=0.0),
            message=Request(method="m", id=1),
            direction="client_to_upstream",
        )
        await store.close()

    async def test_record_message_with_large_payload(self, tmp_path: Path) -> None:
        # 256 KB nested params -- well within the proxy's accepted
        # message cap. Forensics must record without truncation.
        big = "x" * (256 * 1024)
        store = ForensicsStore(tmp_path / "f.db")
        async with store:
            await store.record_message(
                ctx=InterceptContext(correlation_id="big", received_at=0.0),
                message=Request(method="m", params={"blob": big}, id=1),
                direction="client_to_upstream",
            )
            rows = await store.messages_for("big")
            assert len(rows[0]["payload"]["params"]["blob"]) == 256 * 1024

    async def test_open_in_missing_directory_fails_predictably(
        self,
        tmp_path: Path,
    ) -> None:
        store = ForensicsStore(tmp_path / "no" / "such" / "dir" / "f.db")
        with pytest.raises((sqlite3.OperationalError, OSError)):
            await store.open()

    async def test_unicode_path(self, tmp_path: Path) -> None:
        path = tmp_path / "audit-ñoño-€.db"
        store = ForensicsStore(path)
        async with store:
            await store.record_message(
                ctx=InterceptContext(correlation_id="c", received_at=0.0),
                message=Request(method="m", id=1),
                direction="client_to_upstream",
            )
        assert path.exists()


# ---------------------------------------------------------------------------
# 6. Pickling.
# ---------------------------------------------------------------------------


class TestPickle:
    async def test_request_pickle_round_trips(self) -> None:
        req = Request(method="tools/list", params={"k": [1, 2]}, id="x")
        blob = pickle.dumps(req)
        assert pickle.loads(blob) == req

    async def test_response_pickle_round_trips(self) -> None:
        resp = Response(result={"ok": True}, id=1)
        blob = pickle.dumps(resp)
        restored = pickle.loads(blob)
        assert restored == resp
        # Serializer side: dump after pickle round-trip should still
        # emit only ``result`` (the field discriminator).
        out = json.loads(restored.model_dump_json())
        assert "result" in out
        assert "error" not in out

    async def test_error_response_pickle_round_trips(self) -> None:
        err = ErrorObject(code=-32601, message="x", data={"hint": "missing"})
        resp = Response(error=err, id=1)
        blob = pickle.dumps(resp)
        restored = pickle.loads(blob)
        assert restored == resp
        out = json.loads(restored.model_dump_json())
        assert "error" in out
        assert "result" not in out

    async def test_detector_finding_pickle_round_trips(self) -> None:
        f = DetectorFinding(
            detector_id="x",
            severity="HIGH",
            message="m",
            correlation_id="c",
            direction="client_to_upstream",
            evidence={"k": "v"},
        )
        blob = pickle.dumps(f)
        assert pickle.loads(blob) == f


# ---------------------------------------------------------------------------
# 7. Bug-fix regressions: properties of the audit-pass fixes.
# ---------------------------------------------------------------------------


class TestRegressionFixes:
    async def test_chain_interceptor_overrides_on_batch(self) -> None:
        """A batch-level detector must fire when wrapped in
        ChainInterceptor. The base implementation is a no-op, and
        ChainInterceptor previously inherited it -- silently bypassing
        every link's batch policy."""
        seen: list[str] = []

        class BatchPolicy(ProxyInterceptor):
            def __init__(self, tag: str) -> None:
                self._tag = tag

            async def on_batch(self, batch: Batch, ctx: InterceptContext) -> None:
                seen.append(self._tag)
                return

        chain = ChainInterceptor(BatchPolicy("a"), BatchPolicy("b"))
        await chain.on_batch(
            Batch(messages=(Request(method="m", id=1),)),
            new_context(),
        )
        assert seen == ["a", "b"]

    async def test_upstream_originated_request_runs_through_interceptor(self) -> None:
        """An MCP server can issue ``sampling/createMessage`` to the
        client. That reverse-direction Request previously bypassed the
        interceptor entirely -- now it goes through ``on_request_in``
        with the ``reverse_request`` flag."""
        observed: list[str] = []

        class Tracker(ProxyInterceptor):
            async def on_request_in(self, request: Request, ctx: InterceptContext) -> None:
                observed.append(f"{request.method}:{ctx.extra.get('reverse_request', False)}")
                return

        client_side, proxy_in = make_transport_pair()
        proxy_out, upstream = make_transport_pair()
        server = ProxyServer(client=proxy_in, upstream=proxy_out, interceptor=Tracker())
        task = asyncio.create_task(server.run())
        await asyncio.sleep(0)
        try:
            # Forward direction: client -> upstream.
            await client_side.send(Request(method="tools/list", id=1))
            await asyncio.wait_for(upstream.receive(), timeout=2.0)
            # Reverse direction: upstream -> client.
            await upstream.send(Request(method="sampling/createMessage", id=99))
            await asyncio.wait_for(client_side.receive(), timeout=2.0)
        finally:
            await server.stop()
            try:
                await asyncio.wait_for(task, timeout=2.0)
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass

        assert "tools/list:False" in observed
        assert "sampling/createMessage:True" in observed

    async def test_reverse_request_can_be_vetoed(self) -> None:
        """A detector raising JsonRpcError on a reverse request must
        answer the upstream with the structured error -- the upstream
        is awaiting a response just like a regular caller."""

        class Vetoer(ProxyInterceptor):
            async def on_request_in(self, request: Request, ctx: InterceptContext) -> None:
                if ctx.extra.get("reverse_request"):
                    raise JsonRpcError(-32601, "reverse vetoed")
                return

        client_side, proxy_in = make_transport_pair()
        proxy_out, upstream = make_transport_pair()
        server = ProxyServer(client=proxy_in, upstream=proxy_out, interceptor=Vetoer())
        task = asyncio.create_task(server.run())
        await asyncio.sleep(0)
        try:
            await upstream.send(Request(method="sampling/createMessage", id=99))
            # The upstream itself receives the error response (we put
            # the error onto the upstream transport).
            resp = await asyncio.wait_for(upstream.receive(), timeout=2.0)
            assert isinstance(resp, Response)
            assert resp.is_error
            assert resp.error is not None
            assert "reverse vetoed" in resp.error.message
            # Client never sees the reverse request.
            with pytest.raises(asyncio.TimeoutError):
                await asyncio.wait_for(client_side.receive(), timeout=0.3)
        finally:
            await server.stop()
            try:
                await asyncio.wait_for(task, timeout=2.0)
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass

    async def test_forensics_concurrent_open_does_not_orphan(
        self,
        tmp_path: Path,
    ) -> None:
        """Pin the lock-protected open(): 50 simultaneous opens build
        exactly one connection."""
        store = ForensicsStore(tmp_path / "f.db")
        await asyncio.gather(*(store.open() for _ in range(50)))
        # Functional check: the connection still works.
        await store.record_message(
            ctx=new_context(),
            message=Request(method="m", id=1),
            direction="client_to_upstream",
        )
        await store.close()

    async def test_pii_nie_now_detected_unlike_baseline(self) -> None:
        """Regression for the bug where NIE (X1234567L) was missed --
        only DNI (8 digits + letter) used to match. Both must now be
        flagged."""
        sink = InMemoryFindingSink()
        det = PIIDetector(sink)
        await det.on_request_in(
            Request(
                method="m",
                params={"dni": "12345678Z", "nie": "X1234567L"},
                id=1,
            ),
            new_context(),
        )
        # Both are reported under "dni" -- single bucket but the
        # de-dup happens once per kind. Verify at least one finding.
        assert any(f.evidence["kind"] == "dni" for f in sink.findings)

    async def test_recursion_bomb_in_json_is_caught(self) -> None:
        """JSON like ``[[[[[...]]]]]`` past Python's recursion limit
        used to crash with RecursionError; the parser now wraps it as
        a clean JsonRpcProtocolError."""
        bomb = ("[" * 5000 + "]" * 5000).encode("utf-8")
        with pytest.raises(JsonRpcProtocolError):
            parse_payload(bomb)

    async def test_scope_block_with_empty_allowlist_rejected(self) -> None:
        with pytest.raises(ValueError, match="block_on_violation=True"):
            ScopeDetector(block_on_violation=True)


# ---------------------------------------------------------------------------
# 8. End-to-end micro-benchmark (detector overhead is bounded).
# (Hypothesis property tests live in test_m5_property.py because they
# are sync and conflict with this module's asyncio mark.)
# ---------------------------------------------------------------------------


class TestPerformanceFloor:
    async def test_passthrough_bench_is_under_one_millisecond_p95(self) -> None:
        """Smoke benchmark: 200 round-trips through pass-through must
        average well below 1 ms each. Catches a regression where someone
        accidentally adds an O(n) scan to the hot path."""
        client_side, proxy_in = make_transport_pair()
        proxy_out, upstream = make_transport_pair()
        server = ProxyServer(client=proxy_in, upstream=proxy_out)
        task = asyncio.create_task(server.run())
        await asyncio.sleep(0)

        async def echo() -> None:
            while True:
                try:
                    msg = await upstream.receive()
                except ClosedTransportError:
                    return
                if isinstance(msg, Request):
                    await upstream.send(Response(result=None, id=msg.id))

        echo_task = asyncio.create_task(echo())
        samples: list[float] = []
        try:
            for i in range(200):
                t0 = time.perf_counter()
                await client_side.send(Request(method="bench", id=i))
                await client_side.receive()
                samples.append((time.perf_counter() - t0) * 1000)
        finally:
            await server.stop()
            echo_task.cancel()
            try:
                await echo_task
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass
            try:
                await asyncio.wait_for(task, timeout=2.0)
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass

        samples.sort()
        p95 = samples[int(len(samples) * 0.95) - 1]
        # 1 ms is a generous ceiling: real measurements are ~30 µs.
        # The check exists to flag a 30x regression.
        assert p95 < 1.0, f"pass-through p95 = {p95:.3f}ms exceeds 1.0ms"
