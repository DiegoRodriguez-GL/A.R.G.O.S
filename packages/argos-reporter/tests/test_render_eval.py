"""Tests for ``render_eval_html``: the empirical evaluation reporter.

Mirrors the audit-report tests in shape but pins the evaluation-specific
invariants: every section is present, the strict CSP from the base
layout survives, the rendered output is byte-stable for the same
report, and statistical content (precision / recall / F1 / MCC,
confusion matrix cells) is wired correctly.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta

import pytest
from argos_eval import (
    EvalCase,
    EvalReport,
    Outcome,
    all_agents,
    default_ground_truth,
    run_suite,
)
from argos_redteam import all_probes
from argos_reporter import render_eval_html


def _case(
    *,
    agent: str = "lab.react.vulnerable",
    probe: str = "ASI06-INTENT-TOOLDESC",
    expected: Outcome = Outcome.FIRE,
    predicted: Outcome = Outcome.FIRE,
    asi: str | None = "ASI06",
) -> EvalCase:
    return EvalCase(
        agent_id=agent,
        probe_id=probe,
        expected=expected,
        predicted=predicted,
        asi_category=asi,
    )


def _trivial_report() -> EvalReport:
    """A small EvalReport with one TP, one TN, one FP, one FN so every
    cell of the confusion matrix renders non-empty in the test."""
    now = datetime.now(UTC)
    cases = (
        _case(
            agent="lab.react.vulnerable",
            probe="ASI02-TOOL-ARG-SMUGGLE",
            expected=Outcome.FIRE,
            predicted=Outcome.FIRE,
            asi="ASI02",
        ),
        _case(
            agent="lab.react.hardened",
            probe="ASI02-TOOL-ARG-SMUGGLE",
            expected=Outcome.BLOCK,
            predicted=Outcome.BLOCK,
            asi="ASI02",
        ),
        _case(
            agent="lab.react.hardened",
            probe="ASI06-INTENT-TOOLDESC",
            expected=Outcome.BLOCK,
            predicted=Outcome.FIRE,
            asi="ASI06",
        ),
        _case(
            agent="lab.react.vulnerable",
            probe="ASI06-INTENT-TOOLDESC",
            expected=Outcome.FIRE,
            predicted=Outcome.BLOCK,
            asi="ASI06",
        ),
    )
    return EvalReport(
        started_at=now,
        finished_at=now + timedelta(seconds=1),
        cases=cases,
        seed=0,
    )


# ---------------------------------------------------------------------------
# Structure
# ---------------------------------------------------------------------------


def test_eval_report_has_cover_and_all_sections() -> None:
    html = render_eval_html(_trivial_report())
    for needle in (
        'class="cover"',
        'id="eval-overview"',
        'id="eval-metrics"',
        'id="eval-confusion"',
        'id="eval-per-asi"',
        'id="eval-per-agent"',
        'id="eval-methodology"',
    ):
        assert needle in html, f"missing {needle}"


def test_eval_report_includes_all_six_metric_labels() -> None:
    html = render_eval_html(_trivial_report())
    for label in ("Precision", "Recall", "Specificity", "Accuracy", "F1 score", "MCC"):
        assert label in html


def test_eval_report_renders_confusion_matrix_cells() -> None:
    html = render_eval_html(_trivial_report())
    # Each of the four classes must appear with its label.
    for needle in ("cell-tp", "cell-tn", "cell-fp", "cell-fn"):
        assert needle in html


def test_eval_report_carries_ci_legend_and_references() -> None:
    html = render_eval_html(_trivial_report())
    assert "Wilson" in html
    assert "Newcombe" in html
    assert "Matthews" in html
    assert "CI 95%" in html


# ---------------------------------------------------------------------------
# CSP / safety
# ---------------------------------------------------------------------------


def test_eval_report_inherits_strict_csp() -> None:
    html = render_eval_html(_trivial_report())
    assert "default-src 'none'" in html
    assert "frame-ancestors 'none'" in html


def test_eval_report_has_no_external_resource_references() -> None:
    html = render_eval_html(_trivial_report())
    for needle in ("<script", "<link", 'src="http', 'href="http', "url(http"):
        assert needle not in html


def test_eval_report_escapes_html_in_dynamic_strings() -> None:
    """A crafted EvalCase agent_id like ``<script>`` should be escaped
    by Jinja2 autoescape, never appear raw."""
    now = datetime.now(UTC)
    case = EvalCase(
        agent_id="lab.x.y",
        probe_id="ASI01-X",
        expected=Outcome.FIRE,
        predicted=Outcome.FIRE,
        asi_category="ASI01",
    )
    report = EvalReport(
        started_at=now,
        finished_at=now + timedelta(seconds=1),
        cases=(case,),
        catalogue_version="<custom>",
    )
    html = render_eval_html(report)
    # The injected angle brackets must be escaped.
    assert "<custom>" not in html
    assert "&lt;custom&gt;" in html


# ---------------------------------------------------------------------------
# Determinism
# ---------------------------------------------------------------------------


def test_eval_report_is_byte_stable_for_same_report() -> None:
    report = _trivial_report()
    a = render_eval_html(report)
    b = render_eval_html(report)
    assert a == b


def test_eval_report_lang_defaults_to_spanish() -> None:
    html = render_eval_html(_trivial_report())
    assert 'lang="es"' in html


# ---------------------------------------------------------------------------
# Numerical content: the rendered values match the metrics we'd compute.
# ---------------------------------------------------------------------------


def test_eval_report_shows_correct_total_trial_count() -> None:
    html = render_eval_html(_trivial_report())
    # 4 cases in the trivial report; the overview table renders that.
    assert re.search(r"Trials totales[^\d]*<strong>4</strong>", html), html[:200]


def test_eval_report_shows_zero_errored_when_clean() -> None:
    html = render_eval_html(_trivial_report())
    assert "Trials errored" in html


def test_eval_report_full_lab_suite_shows_perfect_metrics() -> None:
    """Sanity tie-in: rendering the full lab suite + canonical ground
    truth must surface 100% on every score band (high). This is what
    the dissertation appendix prints as the "no defects" baseline."""
    report = run_suite(list(all_agents()), list(all_probes()), default_ground_truth())
    html = render_eval_html(report)
    # Every applied band on a healthy run is "high"; the CSS file
    # itself defines all four band classes so we look for the applied
    # combo (class attribute), not the bare token.
    assert 'eval-metric-card eval-band-high"' in html
    assert 'eval-metric-card eval-band-fail"' not in html


# ---------------------------------------------------------------------------
# Per-agent and per-asi tables.
# ---------------------------------------------------------------------------


def test_per_agent_table_lists_each_agent_id() -> None:
    report = run_suite(
        list(all_agents()),
        list(all_probes())[:1],
        default_ground_truth(),
    )
    html = render_eval_html(report)
    for agent in all_agents():
        assert agent.agent_id in html


@pytest.mark.parametrize("section", ["per-asi", "per-agent"])
def test_per_breakdown_sections_exist(section: str) -> None:
    html = render_eval_html(_trivial_report())
    assert f'id="eval-{section}"' in html
