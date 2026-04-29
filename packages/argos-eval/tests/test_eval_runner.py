"""Tests for the suite runner.

Three things matter at this layer:

- **Coverage** every (agent, probe) pair produces exactly one
  ``EvalCase`` regardless of concurrency.
- **Reproducibility** two runs against the same lab produce
  byte-identical case lists (modulo timestamps).
- **Isolation** a probe that raises does not abort the run; its
  failure is captured in ``EvalCase.error`` so the metrics pipeline
  can score it separately.
"""

from __future__ import annotations

import asyncio
from typing import ClassVar

import pytest
from argos_core import Severity
from argos_eval import (
    DEFAULT_CONCURRENCY,
    MAX_CONCURRENCY,
    EvalReport,
    GroundTruth,
    Outcome,
    all_agents,
    default_ground_truth,
    run_suite,
    run_suite_async,
)
from argos_eval.lab._base import LabAgent
from argos_redteam import all_probes
from argos_redteam.probes._base import BaseProbe
from argos_redteam.probes._registry import _REGISTRY

# ---------------------------------------------------------------------------
# Coverage: 1 case per pair, in canonical order.
# ---------------------------------------------------------------------------


def test_run_suite_produces_one_case_per_pair() -> None:
    agents = list(all_agents())
    probes = list(all_probes())
    gt = default_ground_truth()
    report = run_suite(agents, probes, gt)
    assert len(report.cases) == len(agents) * len(probes)


def test_run_suite_orders_cases_by_agent_id_then_probe_id() -> None:
    agents = list(all_agents())
    probes = list(all_probes())[:3]
    report = run_suite(agents, probes, default_ground_truth())
    keys = [(c.agent_id, c.probe_id) for c in report.cases]
    assert keys == sorted(keys), "cases must be sorted for byte-stable reports"


def test_run_suite_rejects_empty_inputs() -> None:
    agents = list(all_agents())
    probes = list(all_probes())[:1]
    gt = GroundTruth()
    with pytest.raises(ValueError, match=r"at least one agent"):
        run_suite([], probes, gt)
    with pytest.raises(ValueError, match=r"at least one probe"):
        run_suite(agents, [], gt)


# ---------------------------------------------------------------------------
# Reproducibility: byte-stable across runs.
# ---------------------------------------------------------------------------


def _fingerprint(report: EvalReport) -> tuple[tuple[str, str, str, str, str], ...]:
    """Project a report to its (agent, probe, expected, predicted, error)
    tuple list. Excludes timestamps and duration, which legitimately
    drift across runs."""
    return tuple(
        (c.agent_id, c.probe_id, c.expected.value, c.predicted.value, c.error or "")
        for c in report.cases
    )


def test_run_suite_is_byte_stable_across_runs() -> None:
    agents = list(all_agents())
    probes = list(all_probes())
    gt = default_ground_truth()
    a = run_suite(agents, probes, gt, seed=7)
    b = run_suite(agents, probes, gt, seed=7)
    assert _fingerprint(a) == _fingerprint(b)


def test_seed_value_is_recorded_on_report() -> None:
    report = run_suite(
        list(all_agents()),
        list(all_probes())[:1],
        default_ground_truth(),
        seed=42,
    )
    assert report.seed == 42


# ---------------------------------------------------------------------------
# Isolation: a misbehaving probe is caught, run continues.
# ---------------------------------------------------------------------------


class _ExplodingProbe(BaseProbe):
    """Probe that raises before any detector runs; used to verify the
    runner captures the exception in ``EvalCase.error``."""

    probe_id = "ASI99-EXPLODE-EVAL"
    title = "explodes on purpose during eval"
    description = "x"
    remediation = "x"
    severity = Severity.HIGH
    asi_category = "ASI99"
    compliance_refs = ("owasp_asi:ASI99",)

    def build_seed(self):  # type: ignore[no-untyped-def]
        msg = "intentional eval-time failure"
        raise RuntimeError(msg)

    def detector(self):  # type: ignore[no-untyped-def]
        from argos_redteam.detectors import StringMatchDetector

        return StringMatchDetector(("never",))


def test_probe_exception_is_captured_in_case_error_field() -> None:
    """A probe that raises must produce a case with ``error != None``,
    not abort the suite."""
    agents = list(all_agents())[:1]
    exploder = _ExplodingProbe()
    _REGISTRY[exploder.probe_id] = exploder
    try:
        report = asyncio.run(
            run_suite_async(
                agents=agents,
                probes=[exploder],
                ground_truth=GroundTruth(),
            ),
        )
    finally:
        _REGISTRY.pop(exploder.probe_id, None)

    assert len(report.cases) == 1
    case = report.cases[0]
    assert case.error is not None
    assert "RuntimeError" in case.error
    # Errored cases land in no cell of the confusion matrix:
    assert not case.is_true_positive
    assert not case.is_true_negative
    assert not case.is_false_positive
    assert not case.is_false_negative


# ---------------------------------------------------------------------------
# Per-pair classification matches the ground truth lookup.
# ---------------------------------------------------------------------------


def test_each_case_has_expected_set_from_ground_truth() -> None:
    """Spot-check: a vulnerable agent on a probe in its surface
    should have ``expected = FIRE``; everything else ``expected = BLOCK``."""
    agents = list(all_agents())
    probes = list(all_probes())
    gt = default_ground_truth()
    fire_set = {(a, p) for a, p in gt.fire_cells}

    report = run_suite(agents, probes, gt)
    for case in report.cases:
        if (case.agent_id, case.probe_id) in fire_set:
            assert case.expected is Outcome.FIRE
        else:
            assert case.expected is Outcome.BLOCK


# ---------------------------------------------------------------------------
# Concurrency: clamped to [1, MAX_CONCURRENCY].
# ---------------------------------------------------------------------------


def test_concurrency_is_clamped_low() -> None:
    report = run_suite(
        list(all_agents())[:1],
        list(all_probes())[:1],
        default_ground_truth(),
        concurrency=0,  # clamped to 1
    )
    assert len(report.cases) == 1


def test_concurrency_is_clamped_high() -> None:
    report = run_suite(
        list(all_agents())[:1],
        list(all_probes())[:1],
        default_ground_truth(),
        concurrency=10_000,  # clamped to MAX_CONCURRENCY
    )
    assert len(report.cases) == 1


def test_default_concurrency_is_documented() -> None:
    assert DEFAULT_CONCURRENCY >= 1
    assert MAX_CONCURRENCY >= DEFAULT_CONCURRENCY


# ---------------------------------------------------------------------------
# Duration is captured per-pair.
# ---------------------------------------------------------------------------


def test_each_case_has_non_negative_duration_ms() -> None:
    report = run_suite(
        list(all_agents())[:1],
        list(all_probes())[:3],
        default_ground_truth(),
    )
    for case in report.cases:
        assert case.duration_ms >= 0.0
        assert case.duration_ms < 60_000.0  # 60 s sanity floor for the lab


# ---------------------------------------------------------------------------
# Sync wrapper: run_suite() vs run_suite_async() agree.
# ---------------------------------------------------------------------------


def test_sync_and_async_runners_agree_on_structure() -> None:
    agents = list(all_agents())[:2]
    probes = list(all_probes())[:3]
    gt = default_ground_truth()

    sync_report = run_suite(agents, probes, gt)
    async_report = asyncio.run(run_suite_async(agents, probes, gt))

    assert _fingerprint(sync_report) == _fingerprint(async_report)


# ---------------------------------------------------------------------------
# Lab agent timeout: a hanging transport is cut off cleanly.
# ---------------------------------------------------------------------------


class _HangingAgent(LabAgent):
    agent_id: ClassVar[str] = "lab.test.hanging"
    is_vulnerable: ClassVar[bool] = False
    vulnerability_surface: ClassVar[tuple[str, ...]] = ("ASI01-MEM-SINGLE-INJECT",)

    def _script(self) -> list[tuple[str, str]]:
        return []

    async def send(self, transcript):  # type: ignore[no-untyped-def]  # noqa: ARG002
        await asyncio.sleep(30)
        from argos_redteam.models import Message, Role

        return Message(role=Role.ASSISTANT, content="too late")


def test_per_pair_timeout_is_enforced() -> None:
    agents = [_HangingAgent()]
    probes = [next(p for p in all_probes() if p.probe_id == "ASI01-MEM-SINGLE-INJECT")]
    report = run_suite(agents, probes, GroundTruth(), timeout_seconds=0.2)
    # The hanging probe must yield a case (not hang the suite); the
    # case should be either errored or BLOCK (no fire was possible).
    assert len(report.cases) == 1
    case = report.cases[0]
    assert case.predicted is Outcome.BLOCK
