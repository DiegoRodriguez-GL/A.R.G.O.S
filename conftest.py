"""Repo-root pytest bootstrap.

Makes every ``packages/*/src`` importable when running ``pytest`` from the
repo root before ``uv sync`` has been executed (useful for quick loops in
fresh checkouts and for CI stages that build but do not install).
"""

from __future__ import annotations

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent
for candidate in (_ROOT / "packages").glob("*/src"):
    src = str(candidate)
    if src not in sys.path:
        sys.path.insert(0, src)
