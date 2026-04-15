"""Smoke tests for the top-level model surface."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from argos_core import Evidence, Finding, ScanResult, Severity, Target
from argos_core.models.target import TargetKind
from pydantic import ValidationError


def _target() -> Target:
    return Target(kind=TargetKind.MCP_CONFIG, locator="examples/agent.mcp.json")


def _finding(severity: Severity = Severity.HIGH) -> Finding:
    return Finding(
        rule_id="ASI01-01",
        title="Goal hijack via tool output",
        description="Tool description contains instructions that override the system prompt.",
        severity=severity,
        target=_target(),
        producer="argos-scanner",
        evidence=(
            Evidence(
                kind="source-range",
                summary="Instructions injected in description",
                path="agent.mcp.json",
                line_start=12,
                line_end=14,
            ),
        ),
    )


def test_finding_has_stable_id_shape() -> None:
    finding = _finding()
    assert finding.id.startswith("ARGOS-")
    assert len(finding.id) == len("ARGOS-") + 12


def test_finding_is_frozen() -> None:
    finding = _finding()
    with pytest.raises(ValidationError):
        finding.severity = Severity.LOW


def test_finding_rejects_unknown_fields() -> None:
    with pytest.raises(ValidationError):
        Finding(
            rule_id="ASI01-01",
            title="t",
            description="d",
            severity=Severity.HIGH,
            target=_target(),
            producer="argos-scanner",
            undeclared_field="nope",  # type: ignore[call-arg]
        )


def test_finding_rule_id_regex_can_be_enforced() -> None:
    f = _finding().model_copy(update={"rule_id": "lowercase-bad"})
    with pytest.raises(ValueError, match="canonical form"):
        f.validate_rule_id()


def test_scan_result_aggregates_severities() -> None:
    now = datetime.now(UTC)
    result = ScanResult(
        target=_target(),
        producer="argos-scanner@0.0.1",
        started_at=now,
        finished_at=now + timedelta(seconds=1),
        findings=(
            _finding(Severity.HIGH),
            _finding(Severity.LOW),
            _finding(Severity.CRITICAL),
        ),
    )
    counts = result.count_by_severity()
    assert counts[Severity.CRITICAL] == 1
    assert counts[Severity.HIGH] == 1
    assert counts[Severity.LOW] == 1
    assert counts[Severity.MEDIUM] == 0
    assert result.max_severity() == Severity.CRITICAL
    assert result.duration_seconds == pytest.approx(1.0)


def test_empty_scan_result_has_no_max_severity() -> None:
    result = ScanResult.empty(target=_target(), producer="argos-scanner@0.0.1")
    assert result.max_severity() is None
    assert result.findings == ()
