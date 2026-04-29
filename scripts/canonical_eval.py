"""Reproducible canonical evaluation runner.

Run:
    uv run python scripts/canonical_eval.py
    uv run python scripts/canonical_eval.py --output report.html --json report.json

Identical to invoking ``argos eval`` with default parameters (full
catalogue, default ground truth, seed 0). Provided as a stand-alone
script so a TFM reviewer or a CI job can pin the canonical output
without depending on the CLI being on PATH.

The script exits 0 when the run is clean (FP = FN = 0), 1 otherwise.
"""

from __future__ import annotations

import argparse
from datetime import UTC, datetime
from pathlib import Path

from argos_eval import (
    EvalReport,
    accuracy,
    all_agents,
    default_ground_truth,
    f1_score,
    matthews_correlation,
    precision,
    recall,
    run_suite,
    specificity,
    wilson_interval,
)
from argos_redteam import all_probes
from argos_reporter import render_eval_html


def _format_pct(x: float) -> str:
    return f"{100.0 * x:.2f}%"


def _print_table(report: EvalReport) -> None:
    cm = report.confusion_matrix()
    rows: list[tuple[str, str]] = [
        ("Started", report.started_at.isoformat(timespec="seconds")),
        ("Finished", report.finished_at.isoformat(timespec="seconds")),
        ("Duration (s)", f"{report.duration_seconds:.2f}"),
        ("Trials", str(len(report.cases))),
        ("Errored", str(len(report.errored))),
        ("TP", str(cm.tp)),
        ("FP", str(cm.fp)),
        ("TN", str(cm.tn)),
        ("FN", str(cm.fn)),
        ("Precision", _format_pct(precision(cm))),
        ("Recall", _format_pct(recall(cm))),
        ("Specificity", _format_pct(specificity(cm))),
        ("Accuracy", _format_pct(accuracy(cm))),
        ("F1", _format_pct(f1_score(cm))),
        ("MCC", f"{matthews_correlation(cm):+.4f}"),
    ]
    p_low, p_high = wilson_interval(cm.tp, cm.predicted_positive)
    r_low, r_high = wilson_interval(cm.tp, cm.actual_positive)
    rows.append(("Precision CI95", f"[{_format_pct(p_low)}, {_format_pct(p_high)}]"))
    rows.append(("Recall CI95", f"[{_format_pct(r_low)}, {_format_pct(r_high)}]"))

    label_w = max(len(k) for k, _ in rows)
    print("=" * 60)
    print("ARGOS canonical empirical evaluation")
    print(f"generated_at: {datetime.now(UTC).isoformat(timespec='seconds')}")
    print("-" * 60)
    for label, value in rows:
        print(f"{label.ljust(label_w)}  {value}")
    print("=" * 60)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run the ARGOS canonical empirical evaluation.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Optional HTML report output path.",
    )
    parser.add_argument(
        "--json",
        type=Path,
        default=None,
        help="Optional JSON dump path for the raw EvalReport.",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=0,
        help="Recorded on the report for reproducibility metadata.",
    )
    args = parser.parse_args()

    report = run_suite(
        list(all_agents()),
        list(all_probes()),
        default_ground_truth(),
        seed=args.seed,
    )

    if args.output is not None:
        args.output.write_text(render_eval_html(report), encoding="utf-8")
    if args.json is not None:
        args.json.write_text(report.model_dump_json(indent=2), encoding="utf-8")

    _print_table(report)

    cm = report.confusion_matrix()
    return 0 if (cm.fp == 0 and cm.fn == 0) else 1


if __name__ == "__main__":
    raise SystemExit(main())
