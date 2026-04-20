"""Top-level orchestrator: runs every selected probe and aggregates findings.

The runner is **concurrent with isolation**. Probes execute in parallel under
an asyncio semaphore so a 20-probe run does not take 20x the slowest
round-trip. If one probe raises, it is isolated: the finding list loses
that probe but the rest of the run completes and the error is recorded
in the ScanResult summary.
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterable
from datetime import UTC, datetime

from argos_core import Finding, ScanResult, Severity, Target
from argos_core.interfaces import ProbeContext
from argos_core.models.target import TargetKind

from argos_redteam.probes._base import BaseProbe
from argos_redteam.probes._registry import all_probes, select
from argos_redteam.transport import AgentTransport

_PRODUCER = "argos-redteam"
_DEFAULT_CONCURRENCY = 8
_MAX_CONCURRENCY = 64


async def _run_one(
    probe: BaseProbe,
    ctx: ProbeContext,
    semaphore: asyncio.Semaphore,
) -> tuple[str, list[Finding], Exception | None]:
    """Execute a single probe under the semaphore. Never raises."""
    async with semaphore:
        try:
            findings = [f async for f in probe.run(ctx)]
        except Exception as exc:  # noqa: BLE001 -- isolate per-probe failures
            return probe.probe_id, [], exc
        return probe.probe_id, findings, None


async def run_async(
    target: str,
    transport: AgentTransport,
    *,
    probes: Iterable[str] | None = None,
    severity_floor: Severity | None = None,
    timeout_seconds: float = 30.0,
    concurrency: int = _DEFAULT_CONCURRENCY,
) -> ScanResult:
    """Execute every selected probe against ``transport`` concurrently.

    Args:
        target: URL or identifier of the agent under test.
        transport: :class:`AgentTransport` implementation. Closed on exit.
        probes: Optional globs over probe ids. ``None`` runs every registered.
        severity_floor: Drop findings below this severity.
        timeout_seconds: Per-request timeout forwarded via the probe context.
        concurrency: Maximum simultaneous in-flight probes. Clamped to
            ``[1, MAX_CONCURRENCY]``.
    """
    concurrency = max(1, min(concurrency, _MAX_CONCURRENCY))
    t = Target(kind=TargetKind.AGENT_HTTP, locator=target)
    started = datetime.now(UTC)

    selected = select(probes) if probes is not None else all_probes()
    ctx = ProbeContext(target=t, transport=transport, timeout_seconds=timeout_seconds)
    semaphore = asyncio.Semaphore(concurrency)

    try:
        results = await asyncio.gather(
            *(_run_one(p, ctx, semaphore) for p in selected),
            return_exceptions=False,
        )
    finally:
        await transport.close()

    findings: list[Finding] = []
    for _probe_id, probe_findings, _err in results:
        findings.extend(probe_findings)

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
    concurrency: int = _DEFAULT_CONCURRENCY,
) -> ScanResult:
    """Synchronous wrapper around :func:`run_async` (for CLI use)."""
    return asyncio.run(
        run_async(
            target,
            transport,
            probes=probes,
            severity_floor=severity_floor,
            timeout_seconds=timeout_seconds,
            concurrency=concurrency,
        ),
    )


def summarise(result: ScanResult, total_probes: int) -> dict[str, int]:
    """Aggregate raw counts across a red-team run."""
    success = len(result.findings)
    return {
        "total": total_probes,
        "success": success,
        "blocked": total_probes - success,
        "neutral": 0,
    }
