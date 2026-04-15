"""End-to-end tests for the scanner engine over real fixtures."""

from __future__ import annotations

from pathlib import Path

from argos_core import Severity
from argos_scanner import all_rules, scan

FIXTURES = Path(__file__).parent / "fixtures"


def test_clean_config_produces_no_findings() -> None:
    result = scan(FIXTURES / "clean.claude_desktop.json")
    assert result.findings == ()
    assert result.max_severity() is None
    assert result.duration_seconds >= 0.0


def test_risky_config_triggers_multiple_rules() -> None:
    result = scan(FIXTURES / "risky.claude_desktop.json")
    assert len(result.findings) >= 10
    triggered = {f.rule_id for f in result.findings}
    expected_subset = {
        "MCP-SEC-SECRET-PATTERN",
        "MCP-SEC-TLS-PLAINTEXT",
        "MCP-SEC-SHELL-PIPE",
        "MCP-SEC-FS-ROOT",
        "MCP-SEC-DOCKER-PRIVILEGED",
        "MCP-SEC-DOCKER-HOST-MOUNT",
        "MCP-SEC-DOCKER-HOST-NET",
        "MCP-SEC-SUPPLY-NPX-AUTO",
        "MCP-SEC-TOOL-POISON",
        "MCP-SEC-ENV-SENSITIVE-KEY",
    }
    missing = expected_subset - triggered
    assert not missing, f"rules that should have fired but did not: {missing}"


def test_every_finding_has_compliance_refs() -> None:
    result = scan(FIXTURES / "risky.claude_desktop.json")
    for finding in result.findings:
        assert finding.compliance_refs, f"rule {finding.rule_id} has no compliance_refs"
        for ref in finding.compliance_refs:
            assert ":" in ref, f"ref {ref!r} is not a qualified id"


def test_every_finding_has_evidence() -> None:
    result = scan(FIXTURES / "risky.claude_desktop.json")
    for finding in result.findings:
        assert finding.evidence, f"rule {finding.rule_id} emitted a finding without evidence"


def test_severity_floor_drops_low_findings() -> None:
    all_result = scan(FIXTURES / "risky.claude_desktop.json")
    high_only = scan(FIXTURES / "risky.claude_desktop.json", severity_floor=Severity.HIGH)
    assert len(high_only.findings) <= len(all_result.findings)
    for f in high_only.findings:
        assert f.severity >= Severity.HIGH


def test_rule_glob_narrows_selection() -> None:
    only_docker = scan(
        FIXTURES / "risky.claude_desktop.json",
        rules=["MCP-SEC-DOCKER-*"],
    )
    for f in only_docker.findings:
        assert f.rule_id.startswith("MCP-SEC-DOCKER-")


def test_at_least_fifteen_rules_registered() -> None:
    # OE2 contract: the built-in set contains at least 15 rules.
    assert len(all_rules()) >= 15


def test_mcp_spec_dialect_scans_cleanly() -> None:
    result = scan(FIXTURES / "mcp_spec.json")
    assert result.findings == ()


def test_findings_are_frozen() -> None:
    import pytest
    from pydantic import ValidationError

    result = scan(FIXTURES / "risky.claude_desktop.json")
    finding = result.findings[0]
    with pytest.raises(ValidationError):
        finding.severity = Severity.LOW
