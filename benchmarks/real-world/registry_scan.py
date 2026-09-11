"""Campaign A: scan every registry entry with the ARGOS scanner.

Usage: python registry_scan.py OUT_DIR [TAG]

Reads OUT_DIR/registry_latest.json and writes OUT_DIR/findings[_TAG].jsonl
and OUT_DIR/scan_rows[_TAG].json. Each entry is written to disk exactly as
the registry API serves it (envelope included) and scanned through
``argos_scanner.engine.scan``, the same code path as ``argos scan``.
"""

from __future__ import annotations

import hashlib
import json
import sys
import tempfile
import time
import traceback
from pathlib import Path

from argos_scanner.engine import scan
from argos_scanner.parser import ParserError


def key(name: str | None) -> str:
    """Stable pseudonymous key for a server name."""
    return hashlib.sha256((name or "").encode("utf-8")).hexdigest()[:16]


def main() -> None:
    out = Path(sys.argv[1] if len(sys.argv) > 1 else "results")
    tag = f"_{sys.argv[2]}" if len(sys.argv) > 2 else ""
    snapshot = json.loads((out / "registry_latest.json").read_text(encoding="utf-8"))
    rows = []
    t0 = time.perf_counter()
    with (
        tempfile.TemporaryDirectory() as tmp,
        (out / f"findings{tag}.jsonl").open("w", encoding="utf-8") as sink,
    ):
        work = Path(tmp)
        for i, envelope in enumerate(snapshot["servers"]):
            doc = envelope.get("server") or {}
            meta = (envelope.get("_meta") or {}).get(
                "io.modelcontextprotocol.registry/official"
            ) or {}
            packages = [p for p in (doc.get("packages") or []) if isinstance(p, dict)]
            remotes = [r for r in (doc.get("remotes") or []) if isinstance(r, dict)]
            row = {
                "i": i,
                "key": key(doc.get("name")),
                "status": meta.get("status"),
                "packages": [p.get("registryType") for p in packages],
                "package_transports": [(p.get("transport") or {}).get("type") for p in packages],
                "remotes": [r.get("type") for r in remotes],
                "remote_urls": [r.get("url") for r in remotes],
                "error": None,
                "findings": 0,
            }
            path = work / f"{i:05d}.json"
            path.write_text(json.dumps(envelope, ensure_ascii=False), encoding="utf-8")
            t1 = time.perf_counter()
            try:
                result = scan(path)
            except ParserError as exc:
                row["error"] = f"parser: {exc}"[:400]
            except Exception as exc:
                row["error"] = f"crash: {type(exc).__name__}: {exc}"[:400]
                traceback.print_exc()
            else:
                row["findings"] = len(result.findings)
                for f in result.findings:
                    sink.write(
                        json.dumps(
                            {
                                "i": i,
                                "key": row["key"],
                                "status": meta.get("status"),
                                "rule": f.rule_id,
                                "severity": str(getattr(f.severity, "value", f.severity)),
                                "description": f.description[:600],
                            },
                            ensure_ascii=False,
                        )
                        + "\n"
                    )
            row["ms"] = round((time.perf_counter() - t1) * 1000, 3)
            rows.append(row)
            path.unlink()
    elapsed = time.perf_counter() - t0
    (out / f"scan_rows{tag}.json").write_text(
        json.dumps({"elapsed_s": elapsed, "retrieved_at": snapshot["retrieved_at"], "rows": rows}),
        encoding="utf-8",
    )
    print(f"{len(rows)} entries in {elapsed:.1f} s")


if __name__ == "__main__":
    main()
