"""ARGOS empirical evaluation framework.

Phase 1 of Module 7 (OE6). Pure stats: confusion matrices, point
metrics, confidence intervals and the data types that downstream
phases (lab agents, suite runner, CLI) build on.
"""

from __future__ import annotations

from argos_eval.intervals import (
    DEFAULT_BOOTSTRAP_SAMPLES,
    DEFAULT_CONFIDENCE,
    bootstrap_ci,
    wilson_interval,
)
from argos_eval.metrics import (
    ConfusionMatrix,
    accuracy,
    aggregate_by,
    f1_score,
    macro_average,
    matthews_correlation,
    precision,
    recall,
    specificity,
)
from argos_eval.report import EvalCase, EvalReport, Outcome

__all__ = [
    "DEFAULT_BOOTSTRAP_SAMPLES",
    "DEFAULT_CONFIDENCE",
    "ConfusionMatrix",
    "EvalCase",
    "EvalReport",
    "Outcome",
    "accuracy",
    "aggregate_by",
    "bootstrap_ci",
    "f1_score",
    "macro_average",
    "matthews_correlation",
    "precision",
    "recall",
    "specificity",
    "wilson_interval",
]

__version__ = "0.0.1"
