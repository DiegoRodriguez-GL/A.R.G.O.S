"""SQLite-backed forensics store.

Schema (v1):

- ``messages``: every Request, Response or Notification observed.
  Columns: ``id`` (auto), ``correlation_id``, ``direction``,
  ``method`` (nullable), ``request_id`` (json), ``payload`` (json),
  ``ts``.
- ``findings``: every :class:`DetectorFinding` emitted.
  Columns: ``id`` (auto), ``detector_id``, ``severity``,
  ``correlation_id``, ``direction``, ``method``, ``request_id`` (json),
  ``message``, ``evidence`` (json), ``ts``.
- ``meta``: a single-row table holding the ``schema_version`` so the
  CLI can refuse to read a database written by a future ARGOS.

WAL mode is enabled at open. Synchronous=NORMAL (the WAL pattern's
crash safety is sufficient for an audit log; FULL would halve write
throughput).
"""

from __future__ import annotations

import asyncio
import json
import sqlite3
import time
from pathlib import Path
from typing import Any, Final

from argos_proxy.detectors._base import DetectorFinding
from argos_proxy.interceptor import InterceptContext
from argos_proxy.jsonrpc import Notification, Request, Response

SCHEMA_VERSION: Final[int] = 1

_SCHEMA_SQL: Final[str] = """
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    correlation_id TEXT NOT NULL,
    direction TEXT NOT NULL,
    kind TEXT NOT NULL,
    method TEXT,
    request_id TEXT,
    payload TEXT NOT NULL,
    ts REAL NOT NULL
);

CREATE INDEX IF NOT EXISTS messages_corr ON messages(correlation_id);
CREATE INDEX IF NOT EXISTS messages_method ON messages(method);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    detector_id TEXT NOT NULL,
    severity TEXT NOT NULL,
    correlation_id TEXT NOT NULL,
    direction TEXT NOT NULL,
    method TEXT,
    request_id TEXT,
    message TEXT NOT NULL,
    evidence TEXT NOT NULL,
    ts REAL NOT NULL
);

CREATE INDEX IF NOT EXISTS findings_corr ON findings(correlation_id);
CREATE INDEX IF NOT EXISTS findings_detector ON findings(detector_id);
CREATE INDEX IF NOT EXISTS findings_severity ON findings(severity);
"""


class ForensicsStore:
    """Async-safe SQLite handle with WAL semantics.

    All writes go through ``self._lock`` so the proxy's concurrent
    pumps never collide. Reads can use a separate connection if the
    operator wants to inspect the database while the proxy is live;
    SQLite's WAL gives them a consistent snapshot.
    """

    __slots__ = ("_conn", "_lock", "_path")

    def __init__(self, path: Path) -> None:
        self._path = Path(path)
        self._conn: sqlite3.Connection | None = None
        self._lock = asyncio.Lock()

    async def open(self) -> None:
        if self._conn is not None:
            return
        # ``check_same_thread=False`` because asyncio runs on a single
        # OS thread but the connection traverses await boundaries; the
        # lock guarantees serialised access.
        self._conn = await asyncio.to_thread(self._open_sync)

    def _open_sync(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._path, check_same_thread=False)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.executescript(_SCHEMA_SQL)
        # Pin the schema version (idempotent).
        conn.execute(
            "INSERT INTO meta(key, value) VALUES('schema_version', ?) ON CONFLICT(key) DO NOTHING",
            (str(SCHEMA_VERSION),),
        )
        conn.commit()
        return conn

    async def close(self) -> None:
        if self._conn is None:
            return
        async with self._lock:
            await asyncio.to_thread(self._conn.commit)
            await asyncio.to_thread(self._conn.close)
            self._conn = None

    async def record_message(
        self,
        *,
        ctx: InterceptContext,
        message: Request | Response | Notification,
        direction: str,
    ) -> None:
        await self._ensure_open()
        method: str | None
        if isinstance(message, Request):
            kind = "request"
            method = message.method
        elif isinstance(message, Response):
            kind = "response"
            method = None
        else:
            # Notification (the Union is exhaustive, but mypy needs an
            # explicit branch for the elif chain to type-check).
            kind = "notification"
            method = message.method
        payload = message.model_dump_json()
        request_id = json.dumps(_normalise_id(ctx.client_request_id))
        ts = time.time()
        async with self._lock:
            assert self._conn is not None
            await asyncio.to_thread(
                self._conn.execute,
                "INSERT INTO messages(correlation_id, direction, kind, method, "
                "request_id, payload, ts) VALUES(?, ?, ?, ?, ?, ?, ?)",
                (ctx.correlation_id, direction, kind, method, request_id, payload, ts),
            )
            await asyncio.to_thread(self._conn.commit)

    async def record_finding(self, finding: DetectorFinding) -> None:
        await self._ensure_open()
        request_id = json.dumps(_normalise_id(finding.request_id))
        evidence = json.dumps(finding.evidence, ensure_ascii=False, separators=(",", ":"))
        async with self._lock:
            assert self._conn is not None
            await asyncio.to_thread(
                self._conn.execute,
                "INSERT INTO findings(detector_id, severity, correlation_id, "
                "direction, method, request_id, message, evidence, ts) "
                "VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    finding.detector_id,
                    finding.severity,
                    finding.correlation_id,
                    finding.direction,
                    finding.method,
                    request_id,
                    finding.message,
                    evidence,
                    finding.detected_at,
                ),
            )
            await asyncio.to_thread(self._conn.commit)

    async def messages_for(
        self,
        correlation_id: str,
    ) -> list[dict[str, Any]]:
        """Return every message stored under ``correlation_id``.

        Used by tests and by the ``argos proxy replay`` CLI command."""
        await self._ensure_open()
        async with self._lock:
            assert self._conn is not None
            conn = self._conn
            rows = await asyncio.to_thread(
                lambda: conn.execute(
                    "SELECT correlation_id, direction, kind, method, request_id, "
                    "payload, ts FROM messages WHERE correlation_id = ? ORDER BY id",
                    (correlation_id,),
                ).fetchall(),
            )
        return [
            {
                "correlation_id": r[0],
                "direction": r[1],
                "kind": r[2],
                "method": r[3],
                "request_id": json.loads(r[4]) if r[4] else None,
                "payload": json.loads(r[5]),
                "ts": r[6],
            }
            for r in rows
        ]

    async def findings(
        self,
        *,
        detector_id: str | None = None,
        severity: str | None = None,
    ) -> list[dict[str, Any]]:
        await self._ensure_open()
        clauses: list[str] = []
        params: list[Any] = []
        if detector_id is not None:
            clauses.append("detector_id = ?")
            params.append(detector_id)
        if severity is not None:
            clauses.append("severity = ?")
            params.append(severity)
        sql = (
            "SELECT detector_id, severity, correlation_id, direction, method, "
            "request_id, message, evidence, ts FROM findings"
        )
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY id"
        async with self._lock:
            assert self._conn is not None
            conn = self._conn
            rows = await asyncio.to_thread(
                lambda: conn.execute(sql, params).fetchall(),
            )
        return [
            {
                "detector_id": r[0],
                "severity": r[1],
                "correlation_id": r[2],
                "direction": r[3],
                "method": r[4],
                "request_id": json.loads(r[5]) if r[5] else None,
                "message": r[6],
                "evidence": json.loads(r[7]),
                "ts": r[8],
            }
            for r in rows
        ]

    async def schema_version(self) -> int:
        await self._ensure_open()
        async with self._lock:
            assert self._conn is not None
            conn = self._conn
            row = await asyncio.to_thread(
                lambda: conn.execute(
                    "SELECT value FROM meta WHERE key='schema_version'",
                ).fetchone(),
            )
        return int(row[0]) if row else 0

    async def _ensure_open(self) -> None:
        if self._conn is None:
            await self.open()

    async def __aenter__(self) -> ForensicsStore:
        await self.open()
        return self

    async def __aexit__(self, *_exc: object) -> None:
        await self.close()


class SqliteForensicsSink:
    """Adapter that fits :class:`ForensicsStore` into the
    :class:`FindingSink` protocol consumed by the detectors."""

    __slots__ = ("_store",)

    def __init__(self, store: ForensicsStore) -> None:
        self._store = store

    async def __call__(self, finding: DetectorFinding) -> None:
        await self._store.record_finding(finding)


# ---------------------------------------------------------------------------
# Helpers.
# ---------------------------------------------------------------------------


def _normalise_id(value: object) -> object:
    """Coerce a request id into a JSON-serialisable representation.

    Pydantic accepts None/str/int/float; that is already JSON-safe.
    Anything else (e.g. a stray bool) is rendered to string for
    storage."""
    if value is None or isinstance(value, (str, int, float)):
        return value
    return str(value)
