"""Tests for ``argos eval``: the M7 evaluation CLI verb.

Exercises the in-process Typer runner for fast tests, plus a real
subprocess invocation that pins the end-to-end contract: a clean
ARGOS install can run ``argos eval --output X.html --json Y.json``
and produce both a non-trivial HTML and a Pydantic-loadable JSON.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

from argos_cli.app import app
from argos_eval import EvalReport
from typer.testing import CliRunner

runner = CliRunner()
_REPO_ROOT = Path(__file__).resolve().parents[3]


def _python_with_argos_installed() -> str:
    """Return the path of a Python interpreter that has the workspace
    packages installed.

    Inside ``uv run pytest`` ``sys.executable`` can resolve to the
    *system* Python (uv keeps the actual environment in
    ``$VIRTUAL_ENV/Scripts/python.exe``). The subprocess tests below
    need the populated environment, so we prefer ``$VIRTUAL_ENV`` when
    set and fall back to ``sys.executable`` otherwise.
    """
    venv = os.environ.get("VIRTUAL_ENV")
    if venv:
        for candidate in (
            Path(venv, "Scripts", "python.exe"),
            Path(venv, "bin", "python"),
            Path(venv, "bin", "python3"),
        ):
            if candidate.is_file():
                return str(candidate)
    return sys.executable


# ---------------------------------------------------------------------------
# Top-level help mentions the new command.
# ---------------------------------------------------------------------------


def test_root_help_lists_eval_subcommand() -> None:
    r = runner.invoke(app, ["--help"])
    assert r.exit_code == 0
    combined = r.stdout + (r.stderr or "")
    assert "eval" in combined.lower()


def test_eval_help_describes_module_7() -> None:
    r = runner.invoke(app, ["eval", "--help"])
    assert r.exit_code == 0
    combined = r.stdout + (r.stderr or "")
    assert "evaluation" in combined.lower()


# ---------------------------------------------------------------------------
# In-process: run a tiny suite via probe filter.
# ---------------------------------------------------------------------------


def test_eval_writes_html_for_filtered_run(tmp_path: Path) -> None:
    out = tmp_path / "eval.html"
    # ASI02-* keeps the suite small (2 probes x 6 agents = 12 trials).
    r = runner.invoke(
        app,
        [
            "eval",
            "--probes",
            "ASI02-*",
            "--output",
            str(out),
            "--quiet",
        ],
    )
    assert r.exit_code == 0, r.stderr
    assert out.is_file()
    text = out.read_text(encoding="utf-8")
    assert text.startswith("<!doctype html>"), text[:100]
    assert "Empirical Evaluation" in text


def test_eval_writes_json_when_requested(tmp_path: Path) -> None:
    out_html = tmp_path / "eval.html"
    out_json = tmp_path / "eval.json"
    r = runner.invoke(
        app,
        [
            "eval",
            "--probes",
            "ASI02-*",
            "--output",
            str(out_html),
            "--json",
            str(out_json),
            "--quiet",
        ],
    )
    assert r.exit_code == 0, r.stderr
    assert out_json.is_file()
    # Round-trip: the JSON must reload as an EvalReport.
    rebuilt = EvalReport.model_validate_json(out_json.read_text(encoding="utf-8"))
    assert rebuilt.cases  # at least one case


def test_eval_rejects_unknown_agent_filter(tmp_path: Path) -> None:
    r = runner.invoke(
        app,
        [
            "eval",
            "--agents",
            "definitely-no-such-agent",
            "--output",
            str(tmp_path / "noop.html"),
            "--quiet",
        ],
    )
    assert r.exit_code == 2
    combined = r.stdout + (r.stderr or "")
    assert "no lab agents" in combined.lower()


def test_eval_rejects_unknown_probe_filter(tmp_path: Path) -> None:
    r = runner.invoke(
        app,
        [
            "eval",
            "--probes",
            "ZZZ99-NEVER-MATCHES",
            "--output",
            str(tmp_path / "noop.html"),
            "--quiet",
        ],
    )
    assert r.exit_code == 2
    combined = r.stdout + (r.stderr or "")
    assert "no probes" in combined.lower()


def test_eval_rejects_missing_ground_truth_file(tmp_path: Path) -> None:
    r = runner.invoke(
        app,
        [
            "eval",
            "--ground-truth",
            str(tmp_path / "nope.yaml"),
            "--output",
            str(tmp_path / "noop.html"),
            "--quiet",
        ],
    )
    assert r.exit_code == 2


def test_eval_clean_run_returns_zero(tmp_path: Path) -> None:
    """The canonical lab is FP=FN=0; the command must exit 0."""
    out = tmp_path / "eval.html"
    r = runner.invoke(app, ["eval", "--output", str(out), "--quiet"])
    assert r.exit_code == 0, r.stderr


# ---------------------------------------------------------------------------
# JSON dump must be reproducible: two runs yield identical content
# modulo timestamps. We test the deterministic fields only.
# ---------------------------------------------------------------------------


def test_eval_json_is_reproducible_across_runs(tmp_path: Path) -> None:
    a_json = tmp_path / "a.json"
    b_json = tmp_path / "b.json"
    for path in (a_json, b_json):
        r = runner.invoke(
            app,
            [
                "eval",
                "--probes",
                "ASI02-*",
                "--output",
                str(tmp_path / "out.html"),
                "--json",
                str(path),
                "--seed",
                "0",
                "--quiet",
            ],
        )
        assert r.exit_code == 0, r.stderr

    a = json.loads(a_json.read_text(encoding="utf-8"))
    b = json.loads(b_json.read_text(encoding="utf-8"))

    # Strip volatile fields (timestamps, durations) before comparing.
    def _strip(payload: dict[str, object]) -> dict[str, object]:
        payload = dict(payload)
        for vol in ("started_at", "finished_at"):
            payload.pop(vol, None)
        cases = payload.get("cases", [])
        if isinstance(cases, list):
            payload["cases"] = [{k: v for k, v in c.items() if k != "duration_ms"} for c in cases]
        return payload

    assert _strip(a) == _strip(b)


# ---------------------------------------------------------------------------
# End-to-end via subprocess.
# ---------------------------------------------------------------------------


def test_eval_subprocess_round_trip(tmp_path: Path) -> None:
    """Invoke the CLI through ``python -m argos_cli`` and assert both
    artefacts (HTML + JSON) are produced and well-formed."""
    out_html = tmp_path / "e.html"
    out_json = tmp_path / "e.json"
    proc = subprocess.run(
        [
            _python_with_argos_installed(),
            "-m",
            "argos_cli",
            "eval",
            "--probes",
            "ASI02-*",
            "--output",
            str(out_html),
            "--json",
            str(out_json),
            "--quiet",
        ],
        cwd=str(_REPO_ROOT),
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, f"stderr={proc.stderr}\nstdout={proc.stdout}"
    assert out_html.is_file()
    assert out_json.is_file()
    rebuilt = EvalReport.model_validate_json(out_json.read_text(encoding="utf-8"))
    assert rebuilt.cases
