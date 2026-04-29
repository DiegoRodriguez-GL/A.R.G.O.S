"""End-to-end evaluation: 6 lab agents x 20 probes against the canonical
ground truth.

This is the **construct-validity property** of the lab benchmark: under
the lab agents implemented in Phase 2 and the probes shipped today, a
ground-truth-aware suite must produce a 100% diagonal confusion matrix
(precision = recall = F1 = MCC = 1.0). Any off-diagonal cell after this
test passes is a real defect either in a probe or in a lab agent and
should be a regression flag.

It is the academic foundation Phase 5 cites: "the framework correctly
classifies every case in the controlled benchmark, so the metrics
reported on stochastic LLM endpoints in the transferability annex
inherit the reliability proven here."
"""

from __future__ import annotations

from argos_eval import (
    all_agents,
    default_ground_truth,
    f1_score,
    matthews_correlation,
    precision,
    recall,
    run_suite,
)
from argos_redteam import all_probes


def test_full_suite_produces_perfect_diagonal_matrix() -> None:
    agents = list(all_agents())
    probes = list(all_probes())
    gt = default_ground_truth()

    report = run_suite(agents, probes, gt)

    cm = report.confusion_matrix()
    # Every (vulnerable, in-surface) pair in the ground truth is one
    # TP; every other pair is a TN. No FP or FN.
    assert cm.fp == 0, f"unexpected false positives: {cm}"
    assert cm.fn == 0, f"unexpected false negatives: {cm}"
    assert cm.tp == gt.total_fire_cells()
    assert cm.tn == len(agents) * len(probes) - cm.tp


def test_full_suite_reaches_perfect_metrics() -> None:
    report = run_suite(list(all_agents()), list(all_probes()), default_ground_truth())
    cm = report.confusion_matrix()
    assert precision(cm) == 1.0
    assert recall(cm) == 1.0
    assert f1_score(cm) == 1.0
    assert matthews_correlation(cm) == 1.0


def test_full_suite_reports_zero_errors() -> None:
    """Every (agent, probe) pair must complete without raising. Any
    captured error here would imply a bug in either the lab agent's
    transport, the probe's strategy, or the runner's exception
    isolation; all three are unacceptable at this point."""
    report = run_suite(list(all_agents()), list(all_probes()), default_ground_truth())
    assert report.errored == ()


def test_full_suite_per_category_breakdown_is_diagonal() -> None:
    """Per-ASI confusion matrices must each individually be diagonal
    (no FP / FN within any category). This is what Phase 5 reports
    as 'consistent across categories'."""
    report = run_suite(list(all_agents()), list(all_probes()), default_ground_truth())
    by_cat = report.by_category()
    assert by_cat, "expected at least one category bucket"
    for code, cm in by_cat.items():
        assert cm.fp == 0, f"{code}: false positives = {cm.fp}"
        assert cm.fn == 0, f"{code}: false negatives = {cm.fn}"


def test_full_suite_per_agent_breakdown_is_diagonal() -> None:
    report = run_suite(list(all_agents()), list(all_probes()), default_ground_truth())
    by_agent = report.by_agent()
    for agent_id, cm in by_agent.items():
        assert cm.fp == 0, f"{agent_id}: false positives = {cm.fp}"
        assert cm.fn == 0, f"{agent_id}: false negatives = {cm.fn}"
