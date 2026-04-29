"""Suite runner: evaluate a list of probes against a list of lab agents
according to a ground truth.

The runner is responsible for **measuring** ARGOS, not for **describing**
it. It executes every (agent, probe) pair, captures whether the probe
fired, classifies the outcome against the ground truth and returns a
single :class:`argos_eval.EvalReport` that downstream phases (CLI,
HTML reporter, dissertation) consume.

Design properties:

- **Concurrency with isolation.** Pairs run under an asyncio semaphore
  so a 120-pair suite does not pay 120x the slowest probe. A pair that
  raises is captured as ``EvalCase.error`` rather than killing the
  run.
- **Deterministic output.** The order in which pairs finish is
  non-deterministic when concurrency > 1, but the final ``EvalReport``
  sorts cases by ``(agent_id, probe_id)``, so two runs against the
  same lab produce the same JSON to the byte.
- **Per-pair timeout.** Each probe inherits the timeout set on the
  context; a hung agent does not stall the whole suite.
"""

from __future__ import annotations

import asyncio
import re
import time
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta

from argos_core import Target
from argos_core.interfaces import ProbeContext
from argos_core.models.target import TargetKind
from argos_redteam.probes._base import BaseProbe

from argos_eval.ground_truth import GroundTruth
from argos_eval.lab._base import LabAgent
from argos_eval.report import EvalCase, EvalReport, Outcome

DEFAULT_CONCURRENCY = 8
MAX_CONCURRENCY = 64
DEFAULT_TIMEOUT_SECONDS = 30.0

_ASI_HEAD_RE = re.compile(r"^(ASI\d{2})\b")


def _asi_category_of(probe_id: str) -> str | None:
    """Best-effort ASI category extraction from the probe id."""
    match = _ASI_HEAD_RE.match(probe_id)
    return match.group(1) if match else None


async def _run_pair(
    agent: LabAgent,
    probe: BaseProbe,
    ground_truth: GroundTruth,
    timeout_seconds: float,
    semaphore: asyncio.Semaphore,
) -> EvalCase:
    """Execute a single (agent, probe) trial under the semaphore.

    Never raises: a probe that throws is captured as the case's
    ``error`` field so the surrounding ``gather`` does not abort.
    """
    async with semaphore:
        ctx = ProbeContext(
            target=Target(
                kind=TargetKind.AGENT_HTTP,
                locator=f"lab://{agent.agent_id}",
            ),
            transport=agent,
            timeout_seconds=timeout_seconds,
        )
        predicted = Outcome.BLOCK
        error: str | None = None
        started = time.perf_counter()
        try:
            async for _finding in probe.run(ctx):
                predicted = Outcome.FIRE
                # One finding is enough to classify; consuming the rest
                # would just waste time and (for HTTP transports) money.
                break
        except Exception as exc:  # noqa: BLE001 -- we deliberately catch every error
            # Bound the captured text: a runaway exception with a huge
            # repr would otherwise inflate the report.
            error = f"{type(exc).__name__}: {exc!s}"[:1900]
        duration_ms = (time.perf_counter() - started) * 1000.0

        return EvalCase(
            agent_id=agent.agent_id,
            probe_id=probe.probe_id,
            expected=ground_truth.expected_for(agent.agent_id, probe.probe_id),
            predicted=predicted,
            asi_category=_asi_category_of(probe.probe_id),
            error=error,
            duration_ms=duration_ms,
        )


async def run_suite_async(
    agents: Sequence[LabAgent],
    probes: Sequence[BaseProbe],
    ground_truth: GroundTruth,
    *,
    concurrency: int = DEFAULT_CONCURRENCY,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    seed: int | None = 0,
) -> EvalReport:
    """Run every (agent, probe) pair and return a single EvalReport.

    Args:
        agents: lab agents to evaluate. Order does not affect the
            output (cases are sorted before serialisation).
        probes: probes to run against each agent.
        ground_truth: maps each pair to its expected outcome. Cells
            not listed default to BLOCK (no fire expected).
        concurrency: maximum simultaneous in-flight pairs. Clamped to
            ``[1, MAX_CONCURRENCY]``.
        timeout_seconds: per-probe timeout forwarded via the context.
        seed: recorded on the resulting report for reproducibility
            metadata; the runner itself is deterministic so the seed
            is informational at this layer.
    """
    if not agents:
        msg = "run_suite_async: at least one agent is required"
        raise ValueError(msg)
    if not probes:
        msg = "run_suite_async: at least one probe is required"
        raise ValueError(msg)

    concurrency = max(1, min(concurrency, MAX_CONCURRENCY))

    started_at = datetime.now(UTC)
    semaphore = asyncio.Semaphore(concurrency)

    tasks = [
        _run_pair(agent, probe, ground_truth, timeout_seconds, semaphore)
        for agent in agents
        for probe in probes
    ]
    cases = await asyncio.gather(*tasks)

    # Stable order: by agent_id, then probe_id. Concurrency is allowed
    # to interleave execution but the report must be byte-stable.
    cases_sorted = tuple(sorted(cases, key=lambda c: (c.agent_id, c.probe_id)))

    # ``finished_at`` is guaranteed to be >= ``started_at`` because
    # ``datetime.now`` is monotonic across calls in the same process,
    # but on extremely fast paths the two timestamps can collapse to
    # the same microsecond. Bump the second one by 1 microsecond when
    # that happens so EvalReport's validator does not reject the run.
    finished_at = datetime.now(UTC)
    if finished_at <= started_at:
        finished_at = started_at + timedelta(microseconds=1)

    return EvalReport(
        started_at=started_at,
        finished_at=finished_at,
        cases=cases_sorted,
        catalogue_version=ground_truth.catalogue_version,
        seed=seed,
    )


def run_suite(
    agents: Sequence[LabAgent],
    probes: Sequence[BaseProbe],
    ground_truth: GroundTruth,
    *,
    concurrency: int = DEFAULT_CONCURRENCY,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    seed: int | None = 0,
) -> EvalReport:
    """Synchronous wrapper around :func:`run_suite_async`."""
    return asyncio.run(
        run_suite_async(
            agents,
            probes,
            ground_truth,
            concurrency=concurrency,
            timeout_seconds=timeout_seconds,
            seed=seed,
        ),
    )
