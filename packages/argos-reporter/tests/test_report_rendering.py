"""Tests for the ``render_html`` reporter surface.

Covers:
- Structural invariants: every rendered report carries a cover, a
  severity stats grid, a compliance matrix and the methodology
  appendix.
- CSP: the strict policy inherited from ``base.html.j2`` survives into
  the rendered document; no external asset references leak in.
- Severity classes: every severity present in the findings is rendered
  with the canonical ``sev-<level>`` class the CSS expects.
- Empty runs: a ScanResult with zero findings renders the safe banner,
  not a broken table.
- Round-trip: renders for the same ScanResult are byte-identical (the
  report must be reproducible for diffing).
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from argos_core import Evidence, Finding, ScanResult, Severity, Target, TargetKind
from argos_reporter import render_html


def _target() -> Target:
    return Target(kind=TargetKind.AGENT_HTTP, locator="https://demo.argos.local/chat")


def _ev() -> Evidence:
    return Evidence(
        kind="request-response",
        summary="demo",
        request="hello",
        response="world",
    )


def _finding(sev: Severity, rule: str = "ASI06-INTENT-TOOLDESC") -> Finding:
    return Finding(
        rule_id=rule,
        title="Sample finding",
        description="A sample finding used in reporter tests.",
        severity=sev,
        target=_target(),
        evidence=(_ev(),),
        compliance_refs=(
            "owasp_asi:ASI06",
            "owasp_asi:ASI06-01",
            "nist_ai_rmf:MS-2.6",
            "eu_ai_act:ART-15",
            "csa_aicm:AIS-04",
        ),
        remediation="Apply defence in depth.",
        producer="argos-redteam",
    )


def _result(*findings: Finding) -> ScanResult:
    now = datetime.now(UTC)
    return ScanResult(
        target=_target(),
        producer="argos-redteam",
        started_at=now,
        finished_at=now,
        findings=findings,
    )


# ---------------------------------------------------------------------------
# Structural
# ---------------------------------------------------------------------------


def test_rendered_report_has_cover_and_all_sections() -> None:
    html = render_html(_result(_finding(Severity.CRITICAL)))
    # Cover + each numbered section must be present.
    for needle in (
        'class="cover"',
        'id="overview"',
        'id="summary"',
        'id="compliance"',
        'id="findings-index"',
        'id="findings-detail"',
        'id="methodology"',
    ):
        assert needle in html, f"missing {needle} in rendered report"


def test_report_cover_carries_target_locator() -> None:
    html = render_html(_result(_finding(Severity.HIGH)))
    assert "demo.argos.local/chat" in html


def test_report_includes_stats_grid_for_each_severity() -> None:
    html = render_html(
        _result(
            _finding(Severity.HIGH),
            _finding(Severity.LOW, rule="ASI10-HITL-RAPID-FIRE"),
        ),
    )
    # Every severity label shows up in the stats grid, even when zero.
    for level in ("sev-critical", "sev-high", "sev-medium", "sev-low", "sev-info"):
        assert f"stat-card {level}" in html


def test_report_emits_finding_cards_with_severity_class() -> None:
    html = render_html(_result(_finding(Severity.CRITICAL, rule="ASI02-TOOL-ARG-SMUGGLE")))
    assert "finding-sev-badge sev-critical" in html
    assert "ASI02-TOOL-ARG-SMUGGLE" in html


# ---------------------------------------------------------------------------
# CSP / safety
# ---------------------------------------------------------------------------


def test_rendered_report_has_strict_csp() -> None:
    html = render_html(_result(_finding(Severity.CRITICAL)))
    assert "default-src 'none'" in html
    assert "frame-ancestors 'none'" in html
    assert "form-action 'none'" in html


def test_rendered_report_does_not_reference_external_assets() -> None:
    """The report must be offline-safe: no <link>, <script src>, or
    remote image / stylesheet references. We do allow XML namespace
    URIs (like the SVG xmlns) and URLs that appear as part of finding
    content; only actual resource fetches matter."""
    html = render_html(_result(_finding(Severity.CRITICAL)))
    assert "<link" not in html
    assert "<script" not in html
    # The only forms of resource reference we care about: src="...",
    # href="...", and CSS url(...). None should point off-site.
    for needle in ('src="http', "src='http", 'href="http', "href='http", "url(http"):
        assert needle not in html, f"external resource reference found: {needle}"


def test_rendered_report_escapes_user_controlled_strings() -> None:
    """A crafted finding title with ``<script>`` must end up escaped."""
    tricky = Finding(
        rule_id="DEMO-INJECT",
        title="<b>Bold</b>",
        description="<script>alert(1)</script>",
        severity=Severity.HIGH,
        target=_target(),
        evidence=(_ev(),),
        producer="argos-test",
    )
    html = render_html(_result(tricky))
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html


# ---------------------------------------------------------------------------
# Empty run
# ---------------------------------------------------------------------------


def test_empty_result_renders_safe_banner() -> None:
    html = render_html(_result())
    assert "safe-banner" in html
    assert "No se han detectado hallazgos" in html


# ---------------------------------------------------------------------------
# Determinism / round-trip
# ---------------------------------------------------------------------------


def test_same_result_renders_identically_twice() -> None:
    """Reports must be reproducible: given the same ScanResult, the
    output bytes are identical. Diffing two runs is how an auditor
    confirms nothing changed between scans."""
    r = _result(
        _finding(Severity.CRITICAL, rule="ASI06-INTENT-TOOLDESC"),
        _finding(Severity.MEDIUM, rule="ASI10-HITL-RAPID-FIRE"),
    )
    a = render_html(r)
    b = render_html(r)
    assert a == b


def test_compliance_matrix_fires_hit_on_cited_framework() -> None:
    html = render_html(_result(_finding(Severity.HIGH)))
    # The finding cites nist_ai_rmf, eu_ai_act, csa_aicm; each column
    # should show a ``cov-hit`` cell for ASI06.
    assert "cov-hit" in html


def test_methodology_appendix_mentions_taxonomy() -> None:
    html = render_html(_result(_finding(Severity.HIGH)))
    assert "Agentic AI" in html
    assert "Threats and Mitigations" in html


# ---------------------------------------------------------------------------
# Language control
# ---------------------------------------------------------------------------


def test_report_defaults_to_spanish_lang() -> None:
    html = render_html(_result(_finding(Severity.HIGH)))
    assert 'lang="es"' in html


@pytest.mark.parametrize("sev", list(Severity))
def test_report_handles_every_severity_level(sev: Severity) -> None:
    html = render_html(_result(_finding(sev)))
    assert f"sev-{sev.value}" in html
