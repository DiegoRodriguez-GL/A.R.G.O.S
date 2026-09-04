"""Reporter redaction (THREAT_MODEL.md T6): secrets never reach the HTML by default."""

from __future__ import annotations

from datetime import UTC, datetime

from argos_core import Evidence, Finding, ScanResult, Severity, Target, TargetKind
from argos_reporter import redact_finding, redact_result, render_html

_AWS = "AKIAIOSFODNN7EXAMPLE"
_EMAIL = "ana.perez@example.com"
_GH = "ghp_abcdefghijklmnopqrstuvwxyz0123456789ABCD"


def _finding() -> Finding:
    return Finding(
        rule_id="MCP-SEC-SECRET-PATTERN",
        title=f"Hardcoded key {_AWS}",
        description=f"Config leaks {_AWS} to {_EMAIL}.",
        severity=Severity.CRITICAL,
        target=Target(kind=TargetKind.MCP_CONFIG, locator="/tmp/agent.json"),
        evidence=(
            Evidence(
                kind="request-response",
                summary=f"summary mentions {_EMAIL}",
                request=f"Authorization: Bearer {_GH}",
                response=f"AWS_ACCESS_KEY_ID={_AWS}",
            ),
            Evidence(kind="raw", summary="raw blob", blob=f"blob {_GH}"),
        ),
        compliance_refs=("owasp_asi:ASI03", "eu_ai_act:ART-15"),
        remediation=f"Rotate {_AWS} now.",
        producer="argos-scanner",
    )


def _result() -> ScanResult:
    now = datetime.now(UTC)
    return ScanResult(
        target=Target(kind=TargetKind.MCP_CONFIG, locator="/tmp/agent.json"),
        producer="argos-scanner",
        started_at=now,
        finished_at=now,
        findings=(_finding(),),
    )


def test_render_html_redacts_every_free_text_field_by_default() -> None:
    html = render_html(_result())
    for secret in (_AWS, _EMAIL, _GH):
        assert secret not in html
    assert "[REDACTED:AWS_ACCESS_KEY]" in html
    assert "[REDACTED:EMAIL]" in html
    assert "[REDACTED:GITHUB_TOKEN]" in html


def test_render_html_keeps_secrets_only_when_explicitly_disabled() -> None:
    html = render_html(_result(), redact_evidence=False)
    assert _AWS in html
    assert _EMAIL in html


def test_redact_finding_leaves_structural_fields_untouched() -> None:
    original = _finding()
    masked = redact_finding(original)
    assert masked.id == original.id
    assert masked.rule_id == original.rule_id
    assert masked.severity == original.severity
    assert masked.compliance_refs == original.compliance_refs
    assert masked.target == original.target
    assert masked.evidence[0].kind == "request-response"
    assert masked.evidence[1].kind == "raw"
    assert _AWS not in masked.title
    assert masked.remediation is not None
    assert _AWS not in masked.remediation
    assert masked.evidence[1].blob == "blob [REDACTED:GITHUB_TOKEN]"


def test_redact_result_is_pure() -> None:
    result = _result()
    masked = redact_result(result)
    assert _AWS in result.findings[0].title  # original untouched
    assert _AWS not in masked.findings[0].title
    assert masked.run_id == result.run_id


def test_redaction_keeps_render_deterministic() -> None:
    result = _result()
    assert render_html(result) == render_html(result)
