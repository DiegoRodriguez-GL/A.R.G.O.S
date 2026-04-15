"""Integration tests for `argos status`, `argos rules` and `argos compliance`."""

from __future__ import annotations

from argos_cli.app import app
from typer.testing import CliRunner

runner = CliRunner()


# ---------- status ----------------------------------------------------


def test_status_exits_zero_and_mentions_core_numbers() -> None:
    r = runner.invoke(app, ["status"])
    assert r.exit_code == 0
    combined = r.stdout + (r.stderr or "")
    assert "ARGOS" in combined
    assert "Scanner rules" in combined
    assert "Compliance frameworks" in combined


# ---------- rules -----------------------------------------------------


def test_rules_list_contains_every_rule() -> None:
    r = runner.invoke(app, ["rules", "list"])
    assert r.exit_code == 0
    # Sanity: at least the fingerprint rules appear.
    for expected in (
        "MCP-SEC-SECRET-PATTERN",
        "MCP-SEC-DOCKER-PRIVILEGED",
        "MCP-SEC-TLS-PLAINTEXT",
    ):
        assert expected in r.stdout


def test_rules_list_severity_filter_narrows_output() -> None:
    r = runner.invoke(app, ["rules", "list", "-s", "critical"])
    assert r.exit_code == 0
    # HIGH-only rule should not appear in a critical-only listing.
    assert "MCP-SEC-SECRET-ENTROPY" not in r.stdout


def test_rules_list_match_filter() -> None:
    r = runner.invoke(app, ["rules", "list", "-m", "MCP-SEC-DOCKER-*"])
    assert r.exit_code == 0
    assert "DOCKER-PRIVILEGED" in r.stdout
    assert "SECRET-PATTERN" not in r.stdout


def test_rules_list_framework_filter() -> None:
    r = runner.invoke(app, ["rules", "list", "-f", "iso_42001"])
    assert r.exit_code == 0
    # All of our rules cite ISO 42001 in their compliance_refs, so at least one
    # rule must appear.
    assert "MCP-SEC-" in r.stdout


def test_rules_list_no_match_exits_nonzero() -> None:
    r = runner.invoke(app, ["rules", "list", "-m", "NOPE-*"])
    assert r.exit_code == 1


def test_rules_show_known_rule() -> None:
    r = runner.invoke(app, ["rules", "show", "MCP-SEC-SECRET-PATTERN"])
    assert r.exit_code == 0
    combined = r.stdout + (r.stderr or "")
    assert "MCP-SEC-SECRET-PATTERN" in combined
    assert "Remediation" in combined
    assert "owasp_asi" in combined


def test_rules_show_unknown_rule_exits_nonzero() -> None:
    r = runner.invoke(app, ["rules", "show", "NO-SUCH-RULE"])
    assert r.exit_code == 1


# ---------- compliance ------------------------------------------------


def test_compliance_list_mentions_every_framework() -> None:
    r = runner.invoke(app, ["compliance", "list"])
    assert r.exit_code == 0
    for fw in ("owasp_asi", "csa_aicm", "eu_ai_act", "nist_ai_rmf", "iso_42001"):
        assert fw in r.stdout


def test_compliance_show_known_control() -> None:
    r = runner.invoke(app, ["compliance", "show", "owasp_asi:ASI01"])
    assert r.exit_code == 0
    assert "Memory Poisoning" in r.stdout


def test_compliance_show_unknown_control_exits_nonzero() -> None:
    r = runner.invoke(app, ["compliance", "show", "nonexistent:X"])
    assert r.exit_code == 1


def test_compliance_map_prints_targets_and_rationale() -> None:
    r = runner.invoke(app, ["compliance", "map", "owasp_asi:ASI01"])
    assert r.exit_code == 0
    assert "mitigates" in r.stdout
    assert "csa_aicm" in r.stdout


def test_compliance_map_unknown_control_exits_nonzero() -> None:
    r = runner.invoke(app, ["compliance", "map", "nonexistent:X"])
    assert r.exit_code == 1
