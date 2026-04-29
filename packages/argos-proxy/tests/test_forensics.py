"""Tests for :mod:`argos_proxy.forensics.sqlite`.

Covers:

- Open / close lifecycle, schema_version pin.
- WAL mode is actually enabled on the connection.
- Round-trip of messages and findings through the store.
- ``messages_for(correlation_id)`` returns chronological order.
- ``findings(detector_id=..., severity=...)`` filters correctly.
- Concurrent writes from multiple coroutines do not race.
"""

from __future__ import annotations

import asyncio
import sqlite3
from pathlib import Path

import pytest
from argos_proxy import (
    InterceptContext,
    Notification,
    Request,
    Response,
)
from argos_proxy.detectors import DetectorFinding
from argos_proxy.forensics import (
    SCHEMA_VERSION,
    ForensicsStore,
    SqliteForensicsSink,
)

pytestmark = pytest.mark.asyncio


def _ctx(corr: str = "argos-corr-test", req_id: object = None) -> InterceptContext:
    return InterceptContext(
        correlation_id=corr,
        received_at=0.0,
        client_request_id=req_id,
    )


# ---------------------------------------------------------------------------
# Lifecycle.
# ---------------------------------------------------------------------------


class TestLifecycle:
    async def test_schema_version_is_pinned_on_open(self, tmp_path: Path) -> None:
        store = ForensicsStore(tmp_path / "f.db")
        async with store:
            assert await store.schema_version() == SCHEMA_VERSION

    async def test_close_flushes_and_idempotent(self, tmp_path: Path) -> None:
        store = ForensicsStore(tmp_path / "f.db")
        await store.open()
        await store.record_message(
            ctx=_ctx(),
            message=Request(method="m", id=1),
            direction="client_to_upstream",
        )
        await store.close()
        await store.close()  # idempotent

    async def test_wal_mode_is_enabled(self, tmp_path: Path) -> None:
        path = tmp_path / "f.db"
        store = ForensicsStore(path)
        await store.open()
        try:
            # Open a side connection and verify WAL.
            conn = sqlite3.connect(path)
            mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
            conn.close()
            assert mode.lower() == "wal"
        finally:
            await store.close()


# ---------------------------------------------------------------------------
# Messages.
# ---------------------------------------------------------------------------


class TestMessages:
    async def test_record_request_round_trip(self, tmp_path: Path) -> None:
        store = ForensicsStore(tmp_path / "f.db")
        async with store:
            ctx = _ctx("c1", req_id=42)
            req = Request(method="tools/list", params={"k": "v"}, id=42)
            await store.record_message(ctx=ctx, message=req, direction="client_to_upstream")
            rows = await store.messages_for("c1")
        assert len(rows) == 1
        assert rows[0]["kind"] == "request"
        assert rows[0]["method"] == "tools/list"
        assert rows[0]["request_id"] == 42
        assert rows[0]["payload"]["method"] == "tools/list"

    async def test_record_response_round_trip(self, tmp_path: Path) -> None:
        store = ForensicsStore(tmp_path / "f.db")
        async with store:
            ctx = _ctx("c1", req_id=7)
            resp = Response(result={"ok": True}, id=7)
            await store.record_message(ctx=ctx, message=resp, direction="upstream_to_client")
            rows = await store.messages_for("c1")
        assert rows[0]["kind"] == "response"
        assert rows[0]["payload"]["result"] == {"ok": True}

    async def test_record_notification_round_trip(self, tmp_path: Path) -> None:
        store = ForensicsStore(tmp_path / "f.db")
        async with store:
            ctx = _ctx("c1")
            note = Notification(method="initialized")
            await store.record_message(ctx=ctx, message=note, direction="client_to_upstream")
            rows = await store.messages_for("c1")
        assert rows[0]["kind"] == "notification"
        assert rows[0]["method"] == "initialized"

    async def test_messages_returned_in_insertion_order(self, tmp_path: Path) -> None:
        store = ForensicsStore(tmp_path / "f.db")
        async with store:
            for i in range(5):
                await store.record_message(
                    ctx=_ctx("c", req_id=i),
                    message=Request(method=f"m{i}", id=i),
                    direction="client_to_upstream",
                )
            rows = await store.messages_for("c")
        assert [r["method"] for r in rows] == [f"m{i}" for i in range(5)]


# ---------------------------------------------------------------------------
# Findings.
# ---------------------------------------------------------------------------


class TestFindings:
    async def test_record_and_filter_findings(self, tmp_path: Path) -> None:
        store = ForensicsStore(tmp_path / "f.db")
        async with store:
            for sev in ("LOW", "HIGH", "HIGH"):
                await store.record_finding(
                    DetectorFinding(
                        detector_id="argos.proxy.test",
                        severity=sev,
                        message=f"test {sev}",
                        correlation_id="c",
                        direction="client_to_upstream",
                        evidence={"k": "v"},
                    ),
                )
            high = await store.findings(severity="HIGH")
            low = await store.findings(severity="LOW")
            test = await store.findings(detector_id="argos.proxy.test")
            unknown = await store.findings(detector_id="argos.proxy.nope")
        assert len(high) == 2
        assert len(low) == 1
        assert len(test) == 3
        assert len(unknown) == 0
        assert high[0]["evidence"] == {"k": "v"}

    async def test_sqlite_forensics_sink_adapter(self, tmp_path: Path) -> None:
        store = ForensicsStore(tmp_path / "f.db")
        async with store:
            sink = SqliteForensicsSink(store)
            await sink(
                DetectorFinding(
                    detector_id="argos.proxy.x",
                    severity="MEDIUM",
                    message="m",
                    correlation_id="c",
                    direction="client_to_upstream",
                ),
            )
            rows = await store.findings()
        assert rows[0]["detector_id"] == "argos.proxy.x"


# ---------------------------------------------------------------------------
# Concurrency.
# ---------------------------------------------------------------------------


class TestConcurrency:
    async def test_concurrent_writes_do_not_race(self, tmp_path: Path) -> None:
        store = ForensicsStore(tmp_path / "f.db")

        async def write(i: int) -> None:
            await store.record_message(
                ctx=_ctx(f"c{i}", req_id=i),
                message=Request(method=f"m{i}", id=i),
                direction="client_to_upstream",
            )

        async with store:
            await asyncio.gather(*(write(i) for i in range(50)))
            # Every correlation id has exactly one row.
            for i in range(50):
                rows = await store.messages_for(f"c{i}")
                assert len(rows) == 1
                assert rows[0]["request_id"] == i
