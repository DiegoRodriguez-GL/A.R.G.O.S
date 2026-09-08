"""CLI-level controls from THREAT_MODEL.md: T3 (plugins), T4 (manifest),
T6 (report redaction) and T7 (proxy bind policy)."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
from argos_cli.app import app
from argos_cli.commands import compliance as compliance_cmd
from argos_cli.commands.proxy import _is_loopback
from argos_core import Evidence, Finding, Severity, Target, TargetKind
from argos_core.compliance.manifest import VerificationResult
from typer.testing import CliRunner

_ANSI = re.compile(chr(27) + "[[][0-9;]*m")


def _plain(text: str) -> str:
    """Strip terminal colour codes so option names survive rich styling."""
    return _ANSI.sub("", text)


runner = CliRunner()

_AWS = "AKIAIOSFODNN7EXAMPLE"


# ---------- T7: proxy bind policy ---------------------------------------


@pytest.mark.parametrize(
    ("host", "expected"),
    [
        ("127.0.0.1", True),
        ("127.0.0.2", True),
        ("localhost", True),
        ("LOCALHOST", True),
        ("::1", True),
        ("[::1]", True),
        ("0.0.0.0", False),
        ("::", False),
        ("10.0.0.5", False),
        ("192.168.1.10", False),
        ("example.internal", False),
        ("", False),
    ],
)
def test_is_loopback(host: str, expected: bool) -> None:
    assert _is_loopback(host) is expected


def test_proxy_run_refuses_non_loopback_bind_without_flag(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        [
            "proxy",
            "run",
            "--listen",
            "0.0.0.0:0",
            "--upstream",
            "stdio:python -c pass",
            "--forensics-db",
            str(tmp_path / "f.sqlite3"),
        ],
    )
    assert result.exit_code == 2
    combined = result.stdout + (result.stderr or "")
    assert "--allow-external" in _plain(combined)
    assert not (tmp_path / "f.sqlite3").exists()


def test_proxy_run_prints_identity_line_on_loopback(tmp_path: Path) -> None:
    db = tmp_path / "f.sqlite3"
    result = runner.invoke(
        app,
        [
            "proxy",
            "run",
            "--listen",
            "127.0.0.1:0",
            "--upstream",
            "stdio:python -c pass",
            "--forensics-db",
            str(db),
            "--duration",
            "0.3",
            "--no-otel",
        ],
    )
    assert result.exit_code == 0, result.stdout
    identity_lines = [
        line for line in result.stdout.splitlines() if '"event":"argos.proxy.identity"' in line
    ]
    assert len(identity_lines) == 1
    record = json.loads(identity_lines[0])
    assert record["pid"] > 0
    assert record["listen"].startswith("127.0.0.1:")
    assert record["upstream"].startswith("stdio:")
    assert record["forensics_db"] == str(db)
    assert "started_at" in record


# ---------- T4: compliance manifest -------------------------------------


def test_compliance_verify_passes_on_shipped_data() -> None:
    result = runner.invoke(app, ["compliance", "verify"])
    assert result.exit_code == 0, result.stdout
    assert "verified" in result.stdout
    assert "owasp_asi.yaml" in result.stdout


def test_compliance_verify_fails_on_drift(monkeypatch: pytest.MonkeyPatch) -> None:
    drifted = VerificationResult(
        manifest_present=True,
        checked=("owasp_asi.yaml",),
        mismatched=("mapping.yaml",),
        missing=("iso_42001.yaml",),
        unlisted=("extra.yaml",),
    )
    monkeypatch.setattr(compliance_cmd, "verify_manifest", lambda: drifted)
    result = runner.invoke(app, ["compliance", "verify"])
    assert result.exit_code == 1
    combined = result.stdout + (result.stderr or "")
    assert "mapping.yaml" in combined
    assert "iso_42001.yaml" in combined
    assert "extra.yaml" in combined


def test_build_manifest_script_check_mode_is_clean() -> None:
    import subprocess
    import sys

    repo = Path(__file__).resolve().parents[3]
    proc = subprocess.run(
        [sys.executable, str(repo / "scripts" / "build_compliance_manifest.py"), "--check"],
        capture_output=True,
        text=True,
        check=False,
        cwd=repo,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr


# ---------- T6: report redaction ----------------------------------------


def _jsonl_with_secret(path: Path) -> None:
    finding = Finding(
        rule_id="MCP-SEC-SECRET-PATTERN",
        title="Hardcoded AWS key",
        description=f"Found {_AWS} in env.",
        severity=Severity.CRITICAL,
        target=Target(kind=TargetKind.MCP_CONFIG, locator="/tmp/agent.json"),
        evidence=(Evidence(kind="raw", summary="env dump", blob=f"AWS_ACCESS_KEY_ID={_AWS}"),),
        compliance_refs=("owasp_asi:ASI03",),
        producer="argos-scanner",
    )
    path.write_text(finding.model_dump_json() + "\n" + finding.model_dump_json() + "\n")


def test_report_redacts_by_default(tmp_path: Path) -> None:
    src = tmp_path / "findings.jsonl"
    _jsonl_with_secret(src)
    out = tmp_path / "r.html"
    result = runner.invoke(app, ["report", str(src), "-o", str(out)])
    assert result.exit_code == 0, result.stdout
    html = out.read_text(encoding="utf-8")
    assert _AWS not in html
    assert "[REDACTED:AWS_ACCESS_KEY]" in html


def test_report_no_redact_requires_confirmation(tmp_path: Path) -> None:
    src = tmp_path / "findings.jsonl"
    _jsonl_with_secret(src)
    out = tmp_path / "r.html"
    result = runner.invoke(app, ["report", str(src), "-o", str(out), "--no-redact"], input="n\n")
    assert result.exit_code == 1
    assert not out.exists()


def test_report_no_redact_with_yes_writes_raw_evidence(tmp_path: Path) -> None:
    src = tmp_path / "findings.jsonl"
    _jsonl_with_secret(src)
    out = tmp_path / "r.html"
    result = runner.invoke(app, ["report", str(src), "-o", str(out), "--no-redact", "--yes"])
    assert result.exit_code == 0, result.stdout
    assert _AWS in out.read_text(encoding="utf-8")
    combined = result.stdout + (result.stderr or "")
    assert "without redaction" in combined


# ---------- T3: plugin inventory ----------------------------------------


def test_status_reports_plugin_inventory() -> None:
    result = runner.invoke(app, ["status"])
    assert result.exit_code == 0
    assert "Plugins" in result.stdout
