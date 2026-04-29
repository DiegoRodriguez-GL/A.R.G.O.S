"""ARGOS empirical evaluation framework.

Phase 1 of Module 7 (OE6). Pure stats: confusion matrices, point
metrics, confidence intervals and the data types that downstream
phases (lab agents, suite runner, CLI) build on.
"""

from __future__ import annotations

from argos_eval.ground_truth import (
    GroundTruth,
    default_ground_truth,
    default_ground_truth_path,
)
from argos_eval.intervals import (
    DEFAULT_BOOTSTRAP_SAMPLES,
    DEFAULT_CONFIDENCE,
    bootstrap_ci,
    wilson_interval,
)
from argos_eval.lab import (
    ALL_AGENT_CLASSES,
    LabAgent,
    LangGraphHardened,
    LangGraphVulnerable,
    MemoryHardened,
    MemoryVulnerable,
    ReActHardened,
    ReActVulnerable,
    all_agents,
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
from argos_eval.report import (
    ClassificationChange,
    EvalCase,
    EvalReport,
    EvalReportDiff,
    Outcome,
)
from argos_eval.runner import (
    DEFAULT_CONCURRENCY,
    DEFAULT_TIMEOUT_SECONDS,
    MAX_CONCURRENCY,
    run_suite,
    run_suite_async,
)

__all__ = [
    "ALL_AGENT_CLASSES",
    "DEFAULT_BOOTSTRAP_SAMPLES",
    "DEFAULT_CONCURRENCY",
    "DEFAULT_CONFIDENCE",
    "DEFAULT_TIMEOUT_SECONDS",
    "MAX_CONCURRENCY",
    "ClassificationChange",
    "ConfusionMatrix",
    "EvalCase",
    "EvalReport",
    "EvalReportDiff",
    "GroundTruth",
    "LabAgent",
    "LangGraphHardened",
    "LangGraphVulnerable",
    "MemoryHardened",
    "MemoryVulnerable",
    "Outcome",
    "ReActHardened",
    "ReActVulnerable",
    "accuracy",
    "aggregate_by",
    "all_agents",
    "bootstrap_ci",
    "default_ground_truth",
    "default_ground_truth_path",
    "f1_score",
    "macro_average",
    "matthews_correlation",
    "precision",
    "recall",
    "run_suite",
    "run_suite_async",
    "specificity",
    "wilson_interval",
]

__version__ = "0.0.1"
