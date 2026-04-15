"""Design-system tokens: the generator must be deterministic and idempotent."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "scripts" / "build_tokens.py"
TOKENS_JSON = ROOT / "design-system" / "tokens.json"
OUT_CSS = ROOT / "design-system" / "tokens.css"
OUT_PY = ROOT / "design-system" / "tokens.py"
OUT_TS = ROOT / "design-system" / "tokens.ts"


def _run_generator() -> None:
    subprocess.run(
        [sys.executable, str(SCRIPT)],
        cwd=ROOT,
        check=True,
        capture_output=True,
    )


def test_tokens_json_is_valid_and_non_empty() -> None:
    data = json.loads(TOKENS_JSON.read_text(encoding="utf-8"))
    assert "meta" in data
    assert data["meta"]["version"]
    assert "color" in data


def test_generator_is_idempotent() -> None:
    _run_generator()
    css1 = OUT_CSS.read_bytes()
    py1 = OUT_PY.read_bytes()
    ts1 = OUT_TS.read_bytes()
    _run_generator()
    assert OUT_CSS.read_bytes() == css1
    assert OUT_PY.read_bytes() == py1
    assert OUT_TS.read_bytes() == ts1


def test_css_contains_every_severity_colour() -> None:
    _run_generator()
    css = OUT_CSS.read_text(encoding="utf-8")
    for level in ("critical", "high", "medium", "low", "info"):
        assert f"--argos-color-severity-{level}:" in css


def test_python_constants_are_valid_identifiers() -> None:
    _run_generator()
    py = OUT_PY.read_text(encoding="utf-8")
    for line in py.splitlines():
        if ": Final[str]" in line:
            ident = line.split(":", 1)[0].strip()
            assert ident.isidentifier(), f"not a valid Python identifier: {ident!r}"


def test_typescript_quotes_are_escaped() -> None:
    _run_generator()
    ts = OUT_TS.read_text(encoding="utf-8")
    # The sans fontstack contains an escaped `\"Segoe UI\"`; ensure it survives.
    assert '\\"Segoe UI\\"' in ts
    # And no raw unescaped inner quote.
    assert '"Segoe UI"' not in ts.replace('\\"Segoe UI\\"', "")


def test_generator_errors_on_missing_input(tmp_path: Path) -> None:
    # Load the script as a module and swap its SRC constant to a missing path
    # via vars(mod); mypy cannot see the attrs of a dynamically-loaded module
    # so we use the module __dict__ as an escape hatch.
    import importlib.util

    spec = importlib.util.spec_from_file_location("build_tokens", SCRIPT)
    assert spec is not None
    assert spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    namespace = vars(mod)
    original = namespace["SRC"]
    try:
        namespace["SRC"] = tmp_path / "missing.json"
        with pytest.raises(SystemExit):
            namespace["main"]()
    finally:
        namespace["SRC"] = original
