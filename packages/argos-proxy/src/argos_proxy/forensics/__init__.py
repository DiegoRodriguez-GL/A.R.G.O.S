"""Forensic persistence for the ARGOS audit proxy.

The forensics layer answers two operator questions:

1. **Replay:** "show me the exact request and response for correlation
   id ``argos-corr-abc...``."
2. **Audit:** "list every detector finding emitted in the last hour."

Both go through a single SQLite database with WAL mode enabled. The
schema is intentionally minimal -- raw payloads as JSON blobs, plus
indexed metadata columns. This is denormalised on purpose: a TFM
reviewer wants to grep the file with ``sqlite3``, not learn an ORM.

The database file is created lazily on first write. Closing the store
flushes the WAL. The store is async-safe via a single connection
lock; SQLite's own MVCC handles concurrent readers.
"""

from __future__ import annotations

from argos_proxy.forensics.sqlite import (
    SCHEMA_VERSION,
    ForensicsStore,
    SqliteForensicsSink,
)

__all__ = [
    "SCHEMA_VERSION",
    "ForensicsStore",
    "SqliteForensicsSink",
]
