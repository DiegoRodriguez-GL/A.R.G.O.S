"""Generate CSS / Python / TypeScript artefacts from design-system/tokens.json.

Run:   uv run python scripts/build_tokens.py

Outputs (overwritten, never hand-edited):
    design-system/tokens.css   CSS custom properties
    design-system/tokens.py    Python constants (rich theme + matplotlib)
    design-system/tokens.ts    TypeScript constants (Astro landing)
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
DESIGN = ROOT / "design-system"
SRC = DESIGN / "tokens.json"
OUT_CSS = DESIGN / "tokens.css"
OUT_PY = DESIGN / "tokens.py"
OUT_TS = DESIGN / "tokens.ts"

HEADER = (
    "This file is generated from design-system/tokens.json. Do not edit by hand. "
    "Re-run `uv run python scripts/build_tokens.py` after any token change."
)


def _load() -> dict[str, Any]:
    if not SRC.exists():
        raise SystemExit(f"tokens.json not found at {SRC}")
    with SRC.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def _flatten(prefix: str, node: Any) -> list[tuple[str, str]]:
    """Walk the token tree; leaves are dicts with a non-dict ``value`` key."""
    pairs: list[tuple[str, str]] = []
    if isinstance(node, dict):
        if "value" in node and not isinstance(node["value"], dict):
            pairs.append((prefix, str(node["value"])))
            return pairs
        for key, child in node.items():
            if key.startswith("$") or key == "meta":
                continue
            segment = key.replace("_", "-")
            child_prefix = f"{prefix}-{segment}" if prefix else segment
            pairs.extend(_flatten(child_prefix, child))
    return pairs


def _emit_css(pairs: list[tuple[str, str]]) -> str:
    lines = ["/*", f" * {HEADER}", " */", ":root {"]
    lines.extend(f"  --argos-{name}: {value};" for name, value in pairs)
    lines.extend(["}", ""])
    return "\n".join(lines)


def _emit_py(pairs: list[tuple[str, str]]) -> str:
    lines = [
        '"""ARGOS design tokens as Python constants.',
        "",
        HEADER,
        '"""',
        "",
        "from __future__ import annotations",
        "",
        "from typing import Final",
        "",
    ]
    for name, value in pairs:
        ident = name.upper().replace("-", "_")
        lines.append(f'{ident}: Final[str] = "{value}"')
    lines.append("")
    return "\n".join(lines)


def _emit_ts(pairs: list[tuple[str, str]]) -> str:
    lines = ["/*", f" * {HEADER}", " */", "", "export const tokens = {"]
    for name, value in pairs:
        escaped = value.replace("\\", "\\\\").replace('"', '\\"')
        lines.append(f'  "{name}": "{escaped}",')
    lines.extend(["} as const;", "", "export type ArgosToken = keyof typeof tokens;", ""])
    return "\n".join(lines)


def main() -> int:
    data = _load()
    pairs: list[tuple[str, str]] = []
    for top in ("color", "typography", "spacing", "layout", "radius", "shadow", "motion"):
        if top in data:
            pairs.extend(_flatten(top, data[top]))

    if not pairs:
        print("no tokens emitted -- input is empty or malformed", file=sys.stderr)
        return 1

    OUT_CSS.write_text(_emit_css(pairs), encoding="utf-8", newline="\n")
    OUT_PY.write_text(_emit_py(pairs), encoding="utf-8", newline="\n")
    OUT_TS.write_text(_emit_ts(pairs), encoding="utf-8", newline="\n")

    print(f"wrote {len(pairs)} tokens -> {OUT_CSS.name}, {OUT_PY.name}, {OUT_TS.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
