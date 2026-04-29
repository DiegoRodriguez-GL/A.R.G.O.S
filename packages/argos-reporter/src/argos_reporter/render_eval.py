"""Render an :class:`argos_eval.EvalReport` into a self-contained
HTML evaluation report.

The output is a sibling to the audit report produced by
:func:`render_html`; it shares the design system (dark cover header,
emerald accent, severity-tinted cards) but presents a different kind
of payload: the scientific summary of the empirical run rather than a
list of findings.

Sections in order:

1. Cover with target = "ARGOS evaluation suite", run metadata.
2. Overview: trial counts, duration, errored cases.
3. Global metrics: precision, recall, F1, accuracy, MCC, each with a
   95% Wilson confidence interval (Wilson 1927).
4. Confusion matrix as a 2x2 visual grid.
5. Per-ASI breakdown with per-category metrics.
6. Per-agent breakdown.
7. Methodology appendix: cited references and validity discussion.

The function is deterministic: passing the same EvalReport produces
byte-identical HTML, which means a TFM appendix that pins the report
hash gets a meaningful integrity check for free.
"""

from __future__ import annotations

from typing import Final

from argos_eval import (
    ConfusionMatrix,
    EvalReport,
    accuracy,
    f1_score,
    matthews_correlation,
    precision,
    recall,
    specificity,
    wilson_interval,
)

from argos_reporter.html import build_env

_CONFIDENCE: Final[float] = 0.95


def _format_pct(x: float) -> str:
    """Render a float in [0, 1] as a percentage string with two decimals."""
    return f"{100.0 * x:.2f}"


def _format_signed(x: float) -> str:
    """Render MCC (range [-1, 1]) with three decimals; signs are
    informative because a negative MCC means anti-correlation."""
    return f"{x:+.3f}"


def _wilson_pct(numerator: int, denominator: int) -> tuple[str, str]:
    """Return ``(low, high)`` of the Wilson CI rendered as percentages."""
    low, high = wilson_interval(numerator, denominator, confidence=_CONFIDENCE)
    return (_format_pct(low), _format_pct(high))


def _metric_row(
    label: str,
    *,
    point_value: float,
    numerator: int,
    denominator: int,
    has_ci: bool = True,
    score_band: str = "high",
) -> dict[str, object]:
    """Pack a metric for a row in the metrics table."""
    point_str = _format_pct(point_value)
    if has_ci and denominator > 0:
        low, high = _wilson_pct(numerator, denominator)
        ci_str = f"{low}% - {high}%"
    else:
        ci_str = "n/a"
    return {
        "label": label,
        "point": point_str,
        "ci": ci_str,
        "band": score_band,
    }


def _band_for(score: float) -> str:
    """Map a score in [0, 1] to a CSS band class."""
    if score >= 0.90:
        return "high"
    if score >= 0.70:
        return "med"
    if score >= 0.50:
        return "low"
    return "fail"


def _build_metrics(cm: ConfusionMatrix) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    p = precision(cm)
    r = recall(cm)
    a = accuracy(cm)
    f = f1_score(cm)
    sp = specificity(cm)
    mcc = matthews_correlation(cm)

    rows.append(
        _metric_row(
            "Precision",
            point_value=p,
            numerator=cm.tp,
            denominator=cm.predicted_positive,
            score_band=_band_for(p),
        ),
    )
    rows.append(
        _metric_row(
            "Recall",
            point_value=r,
            numerator=cm.tp,
            denominator=cm.actual_positive,
            score_band=_band_for(r),
        ),
    )
    rows.append(
        _metric_row(
            "Specificity",
            point_value=sp,
            numerator=cm.tn,
            denominator=cm.actual_negative,
            score_band=_band_for(sp),
        ),
    )
    rows.append(
        _metric_row(
            "Accuracy",
            point_value=a,
            numerator=cm.tp + cm.tn,
            denominator=cm.total,
            score_band=_band_for(a),
        ),
    )
    # F1 is not a single proportion; we report the point value without
    # a Wilson CI (the dissertation may add a bootstrap CI in an annex).
    rows.append(
        {
            "label": "F1 score",
            "point": _format_pct(f),
            "ci": "(harmonic mean)",
            "band": _band_for(f),
        },
    )
    # MCC is in [-1, +1]; report with sign.
    rows.append(
        {
            "label": "MCC",
            "point": _format_signed(mcc),
            "ci": "(Matthews 1975)",
            "band": _band_for(max(0.0, mcc)),
        },
    )
    return rows


def _breakdown_rows(
    items: dict[str, ConfusionMatrix],
) -> list[dict[str, object]]:
    """Build per-category / per-agent rows ordered by key."""
    out: list[dict[str, object]] = []
    for key, cm in sorted(items.items()):
        p = precision(cm)
        r = recall(cm)
        f = f1_score(cm)
        out.append(
            {
                "label": key,
                "total": cm.total,
                "tp": cm.tp,
                "fp": cm.fp,
                "tn": cm.tn,
                "fn": cm.fn,
                "precision": _format_pct(p),
                "recall": _format_pct(r),
                "f1": _format_pct(f),
                "f1_band": _band_for(f),
            },
        )
    return out


def render_eval_html(
    report: EvalReport,
    *,
    generator_version: str = "0.0.1",
) -> str:
    """Render ``report`` as a single self-contained HTML document."""
    env = build_env()
    template = env.get_template("eval_report.html.j2")

    cm = report.confusion_matrix()
    return template.render(
        report_title="Empirical Evaluation",
        report_subtitle="ARGOS lab benchmark, OWASP ASI coverage",
        target_kind="Evaluation suite",
        target_locator="argos-eval/lab",
        producer="argos-eval",
        methodology_version=report.catalogue_version,
        started_at=report.started_at,
        finished_at=report.finished_at,
        duration_seconds=report.duration_seconds,
        generated_at=report.finished_at,
        generated_at_human=report.finished_at.strftime("%d %B %Y"),
        run_id=None,
        seed=report.seed,
        # Suite-level numbers.
        total_cases=len(report.cases),
        errored_cases=len(report.errored),
        confusion=cm,
        confusion_total=cm.total,
        # Metrics table.
        metric_rows=_build_metrics(cm),
        # Breakdowns.
        per_asi_rows=_breakdown_rows(report.by_category()),
        per_agent_rows=_breakdown_rows(report.by_agent()),
        # Confidence level used in CI columns.
        confidence_pct=int(_CONFIDENCE * 100),
        generator_version=generator_version,
        lang="es",
    )
