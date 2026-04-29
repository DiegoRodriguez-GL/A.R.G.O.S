"""Smoke tests for ``scripts/argos_self_audit.py``.

The dogfooding harness is a public artefact (committed in the
public ``scripts/`` directory) so it deserves a smoke test that
exercises the fast subset (skip eval + bench) and verifies the
report file lands at the expected path.

The slow steps -- ``argos eval`` and ``argos proxy bench`` -- are
already covered by their own dedicated tests; running them again
here would only add CI minutes.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[3]
_SCRIPT = _REPO_ROOT / "scripts" / "argos_self_audit.py"


def _python_with_argos_installed() -> str:
    venv = os.environ.get("VIRTUAL_ENV")
    if venv:
        for candidate in (
            Path(venv) / "Scripts" / "python.exe",
            Path(venv) / "bin" / "python",
        ):
            if candidate.is_file():
                return str(candidate)
    return sys.executable


def test_self_audit_script_exists_and_is_a_file() -> None:
    assert _SCRIPT.is_file(), f"missing: {_SCRIPT}"


def test_self_audit_help_exits_zero() -> None:
    py = _python_with_argos_installed()
    result = subprocess.run(
        [py, str(_SCRIPT), "--help"],
        capture_output=True,
        text=True,
        check=False,
        cwd=_REPO_ROOT,
    )
    assert result.returncode == 0
    assert "self-audit" in result.stdout.lower()


def test_self_audit_fast_path_writes_report(tmp_path: Path) -> None:
    """Skip the slow steps (eval + bench) and verify the harness still
    produces a usable report.

    Pinning the property: the orchestration / report rendering path is
    correct even when individual steps are skipped. A regression here
    would surface as a missing report, a crash, or a non-zero exit
    despite every selected step succeeding."""
    py = _python_with_argos_installed()
    out_dir = tmp_path / "audit"
    result = subprocess.run(
        [
            py,
            str(_SCRIPT),
            "--output",
            str(out_dir),
            "--skip-eval",
            "--skip-bench",
        ],
        capture_output=True,
        text=True,
        check=False,
        cwd=_REPO_ROOT,
    )
    assert result.returncode == 0, (
        f"self-audit failed: stdout={result.stdout!r} stderr={result.stderr!r}"
    )
    report = out_dir / "REPORT.md"
    assert report.is_file()
    text = report.read_text(encoding="utf-8")
    # Sanity-check the structural sections.
    assert "# ARGOS self-audit" in text
    assert "Run summary" in text
    assert "Static scanner findings" in text
    # The risky fixture is built to fire 20 findings; if the count
    # drifts, surface here.
    assert "Total findings: **20**" in text


@pytest.mark.parametrize(
    "artefact",
    ["status.txt", "rules.txt", "compliance.txt", "scan.jsonl"],
)
def test_self_audit_emits_each_artefact(tmp_path: Path, artefact: str) -> None:
    py = _python_with_argos_installed()
    out_dir = tmp_path / "audit"
    subprocess.run(
        [
            py,
            str(_SCRIPT),
            "--output",
            str(out_dir),
            "--skip-eval",
            "--skip-bench",
        ],
        capture_output=True,
        text=True,
        check=False,
        cwd=_REPO_ROOT,
    )
    assert (out_dir / artefact).is_file(), f"missing artefact: {artefact}"
