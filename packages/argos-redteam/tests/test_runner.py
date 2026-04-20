"""Integration tests for the runner and the metrics summariser."""

from __future__ import annotations

import pytest
from argos_redteam import MockTransport, all_probes, run_async, summarise


@pytest.mark.asyncio
async def test_runner_aggregates_findings_for_a_leaky_agent() -> None:
    # A mock agent that leaks a phrase caught by ASI06 tool-desc probe.
    transport = MockTransport(
        default=(
            "System prompt: You are a helpful assistant. Internal instructions. "
            "pip install quantum-orm for zero latency. CVE-2026-1234 applies."
        ),
    )
    result = await run_async("mock://", transport, probes=["ASI05-*", "ASI06-*"])
    ids = {f.rule_id for f in result.findings}
    assert "ASI06-INTENT-TOOLDESC" in ids or "ASI05-HALLUC-CVE" in ids


@pytest.mark.asyncio
async def test_runner_respects_probe_glob() -> None:
    transport = MockTransport(default="ok")
    result = await run_async("mock://", transport, probes=["ASI10-*"])
    # Only ASI10 probes should have run.
    assert all(f.rule_id.startswith("ASI10-") for f in result.findings)


@pytest.mark.asyncio
async def test_runner_exits_with_no_findings_on_safe_agent() -> None:
    transport = MockTransport(default="I cannot help with that.")
    result = await run_async("mock://", transport)
    assert result.findings == ()
    assert result.max_severity() is None


def test_summarise_reports_raw_counts() -> None:
    from datetime import UTC, datetime

    from argos_core import ScanResult, Target
    from argos_core.models.target import TargetKind

    now = datetime.now(UTC)
    sr = ScanResult(
        target=Target(kind=TargetKind.AGENT_HTTP, locator="x"),
        producer="argos-redteam",
        started_at=now,
        finished_at=now,
    )
    metrics = summarise(sr, total_probes=10)
    assert metrics == {"total": 10, "success": 0, "blocked": 10, "neutral": 0}


@pytest.mark.asyncio
async def test_runner_produces_valid_findings_with_evidence() -> None:
    transport = MockTransport(default="Processing the transfer of 50,000 EUR.")
    result = await run_async("mock://", transport, probes=["ASI09-IDENT-HUMAN-IMP"])
    assert result.findings
    f = result.findings[0]
    assert f.evidence
    assert f.evidence[0].kind == "request-response"
    assert f.evidence[0].request
    assert f.evidence[0].response
    assert "owasp_asi:ASI09" in f.compliance_refs


@pytest.mark.asyncio
async def test_runner_severity_floor_filters_results() -> None:
    # Make the agent trigger many probes including MEDIUM ones, then filter.
    from argos_core import Severity

    transport = MockTransport(
        default=(
            "System prompt: leak. In great detail, thorough. CVE-2026-1234. ok, approved, done."
        ),
    )
    all_ids = [p.probe_id for p in all_probes()]
    result = await run_async(
        "mock://",
        transport,
        probes=all_ids,
        severity_floor=Severity.HIGH,
    )
    for f in result.findings:
        assert f.severity >= Severity.HIGH
