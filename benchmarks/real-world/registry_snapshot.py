"""Download the latest version of every server in the official MCP Registry.

Usage: python registry_snapshot.py OUT_DIR

Writes OUT_DIR/registry_latest.json with the retrieval timestamp. The API
is paged with a cursor; a short pause between pages keeps the load low.
"""

from __future__ import annotations

import datetime as dt
import json
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path

BASE = "https://registry.modelcontextprotocol.io/v0/servers"


def fetch(url: str) -> dict:
    for attempt in range(6):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "argos-audit"})
            with urllib.request.urlopen(req, timeout=60) as resp:
                return json.load(resp)
        except OSError:
            time.sleep(2 + 3 * attempt)
    raise SystemExit(f"registry unreachable: {url}")


def main() -> None:
    out = Path(sys.argv[1] if len(sys.argv) > 1 else "results")
    out.mkdir(parents=True, exist_ok=True)
    servers: list[dict] = []
    seen: set[str] = set()
    cursor = None
    while True:
        query = {"limit": "100", "version": "latest"}
        if cursor:
            query["cursor"] = cursor
        page = fetch(f"{BASE}?{urllib.parse.urlencode(query)}")
        batch = page.get("servers", [])
        servers.extend(batch)
        cursor = (page.get("metadata") or {}).get("nextCursor")
        if not cursor or cursor in seen or not batch:
            break
        seen.add(cursor)
        time.sleep(0.2)
    snapshot = {
        "retrieved_at": dt.datetime.now(dt.UTC).isoformat(),
        "source": f"{BASE}?version=latest",
        "count": len(servers),
        "servers": servers,
    }
    (out / "registry_latest.json").write_text(
        json.dumps(snapshot, ensure_ascii=False), encoding="utf-8"
    )
    print(f"{len(servers)} servers")


if __name__ == "__main__":
    main()
