"""Top-level orchestrator: runs every selected probe and aggregates findings."""

from __future__ import annotations

import asyncio
from collections.abc import Iterable
from datetime import UTC, datetime

from argos_core import Finding, ScanResult, Severity, Target
from argos_core.interfaces import ProbeContext
from argos_core.models.target import TargetKind

from argos_redteam.probes._registry import all_probes, select
from argos_redteam.transport import AgentTransport

_PRODUCER = "argos-redteam"


async def run_async(
    target: str,
    transport: AgentTransport,
    *,
    probes: Iterable[str] | None = None,
    severity_floor: Severity | None = None,
    timeout_seconds: float = 30.0,
) -> ScanResult:
    """Execute every selected probe against ``transport`` and aggregate findings."""
    t = Target(kind=TargetKind.AGENT_HTTP, locator=target)
    started = datetime.now(UTC)

    selected = select(probes) if probes is not None else all_probes()
    ctx = ProbeContext(target=t, transport=transport, timeout_seconds=timeout_seconds)

    findings: list[Finding] = []
    try:
        for probe in selected:
            findings.extend([f async for f in probe.run(ctx)])
    finally:
        await transport.close()

    if severity_floor is not None:
        findings = [f for f in findings if f.severity >= severity_floor]

    finished = datetime.now(UTC)
    return ScanResult(
        target=t,
        producer=_PRODUCER,
        started_at=started,
        finished_at=finished,
        findings=tuple(findings),
    )


def run(
    target: str,
    transport: AgentTransport,
    *,
    probes: Iterable[str] | None = None,
    severity_floor: Severity | None = None,
    timeout_seconds: float = 30.0,
) -> ScanResult:
    """Synchronous wrapper around :func:`run_async` (for CLI use)."""
    return asyncio.run(
        run_async(
            target,
            transport,
            probes=probes,
            severity_floor=severity_floor,
            timeout_seconds=timeout_seconds,
        ),
    )


def summarise(result: ScanResult, total_probes: int) -> dict[str, int]:
    """Aggregate metrics TP/FP/FN-style for the final report.

    A probe that fired contributes to `success`; one that did not, to
    `blocked`. The caller usually knows the ground truth; we expose the
    *raw* counts here.
    """
    success = len(result.findings)
    return {
        "total": total_probes,
        "success": success,
        "blocked": total_probes - success,
        "neutral": 0,
    }
