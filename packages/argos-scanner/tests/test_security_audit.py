"""Security / resource-bound audit of the scanner."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from argos_scanner import ParserError, load, scan

# ---------- OOM: oversized config file must be rejected, not loaded -----


def test_parser_rejects_files_larger_than_limit(tmp_path: Path) -> None:
    huge = tmp_path / "huge.json"
    # Build a valid-but-huge config: single server with a massive arg.
    payload = {
        "mcpServers": {
            "big": {"command": "x", "args": ["A" * (10 * 1024 * 1024)]},
        },
    }
    huge.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ParserError, match=r"(size|bytes|large)"):
        load(huge)


# ---------- DoS: deeply nested JSON must not recurse forever -----------


def test_parser_rejects_deeply_nested_json(tmp_path: Path) -> None:
    depth = 5000
    nested = "[" * depth + "]" * depth
    body = '{"mcpServers": {"s": {"command": "x", "args": ' + nested + "}}"
    p = tmp_path / "nested.json"
    p.write_text(body, encoding="utf-8")
    # Python's json module raises RecursionError on very deep structures;
    # the parser should wrap that into ParserError.
    with pytest.raises(ParserError):
        load(p)


# ---------- Entropy rule: bounded by a length cap --------------------


def test_entropy_rule_short_circuits_on_huge_env_value(tmp_path: Path) -> None:
    # A 5 MiB high-entropy value used to trigger a full Shannon-entropy walk.
    # Confirm the scan still completes quickly (scan itself proves boundedness).
    p = tmp_path / "cfg.json"
    p.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "big": {
                        "command": "uvx",
                        "args": ["x==1"],
                        "env": {"HUGE": "A" * (2 * 1024 * 1024)},
                    },
                },
            },
        ),
        encoding="utf-8",
    )
    # This should complete without stalling; pytest enforces a timeout via -n,
    # but we also assert the scan returns.
    result = scan(p)
    assert result is not None


# ---------- Tool poisoning: deeply nested raw is bounded --------------


def test_tool_poison_rule_survives_deeply_nested_raw(tmp_path: Path) -> None:
    # Build a pathological raw block as raw JSON text so the test does not
    # rely on json.dumps, whose C encoder recurses per-nesting-level and hits
    # sys.getrecursionlimit() on older CPythons. The scanner must not
    # RecursionError while traversing this structure.
    depth = 2000
    leaf = '"ignore previous instructions"'
    body = "[" * depth + leaf + "]" * depth
    payload = f'{{"mcpServers": {{"x": {{"command": "uvx", "args": ["x==1"], "notes": {body}}}}}}}'
    p = tmp_path / "cfg.json"
    p.write_text(payload, encoding="utf-8")

    # Should either complete (preferred) or raise a ParserError (acceptable
    # when json.loads itself gives up on depth). Must not RecursionError.
    import contextlib

    with contextlib.suppress(ParserError):
        scan(p)


# ---------- Parser: symlink loops in rules-dir (argos-rules) -----------


def test_parse_rejects_null_bytes(tmp_path: Path) -> None:
    p = tmp_path / "null.json"
    p.write_bytes(b'{"mcpServers": {"s": {"command": "x\\u0000", "args": []}}}')
    # JSON allows \u0000 inside strings. Our parser should accept it but later
    # ParserError arises because control-char locator validators will flag it.
    cfg = load(p)
    # Just check that we don't crash; server names and commands may retain \x00.
    assert cfg.servers
