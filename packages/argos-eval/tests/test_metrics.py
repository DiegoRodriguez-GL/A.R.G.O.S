"""Unit tests for the confusion matrix and the five point metrics.

These are the line-level tests; algebraic invariants live in the
companion :mod:`test_metrics_property` module under Hypothesis.
"""

from __future__ import annotations

import math

import pytest
from argos_eval import ConfusionMatrix
from argos_eval.metrics import (
    accuracy,
    aggregate_by,
    f1_score,
    macro_average,
    matthews_correlation,
    precision,
    recall,
    specificity,
)
from pydantic import ValidationError

# ---------------------------------------------------------------------------
# ConfusionMatrix construction.
# ---------------------------------------------------------------------------


def test_confusion_matrix_defaults_to_zero() -> None:
    cm = ConfusionMatrix()
    assert cm.tp == cm.fp == cm.tn == cm.fn == 0
    assert cm.total == 0


def test_confusion_matrix_rejects_negative_counts() -> None:
    with pytest.raises(ValidationError):
        ConfusionMatrix(tp=-1)


def test_confusion_matrix_rejects_unknown_field() -> None:
    with pytest.raises(ValidationError):
        ConfusionMatrix.model_validate({"tp": 1, "ufo": 99})


def test_confusion_matrix_is_frozen() -> None:
    cm = ConfusionMatrix(tp=1)
    with pytest.raises(ValidationError):
        cm.tp = 99


def test_confusion_matrix_addition_sums_componentwise() -> None:
    a = ConfusionMatrix(tp=1, fp=2, tn=3, fn=4)
    b = ConfusionMatrix(tp=10, fp=20, tn=30, fn=40)
    c = a + b
    assert c.tp == 11
    assert c.fp == 22
    assert c.tn == 33
    assert c.fn == 44


def test_confusion_matrix_addition_rejects_wrong_type() -> None:
    cm = ConfusionMatrix(tp=1)
    with pytest.raises(TypeError):
        _ = cm + 42


def test_confusion_matrix_marginals_match_arithmetic() -> None:
    cm = ConfusionMatrix(tp=5, fp=2, tn=10, fn=3)
    assert cm.predicted_positive == 7
    assert cm.predicted_negative == 13
    assert cm.actual_positive == 8
    assert cm.actual_negative == 12
    assert cm.total == 20


# ---------------------------------------------------------------------------
# Point metrics: known values + degenerate cases.
# ---------------------------------------------------------------------------


def test_perfect_classifier_metrics_are_one() -> None:
    cm = ConfusionMatrix(tp=10, fp=0, tn=10, fn=0)
    assert precision(cm) == 1.0
    assert recall(cm) == 1.0
    assert f1_score(cm) == 1.0
    assert accuracy(cm) == 1.0
    assert matthews_correlation(cm) == 1.0


def test_inverse_classifier_has_mcc_minus_one() -> None:
    """Predict everything backwards: TP=0, FP=10, TN=0, FN=10 (we said
    fire on every clean target and stayed silent on every real attack)."""
    cm = ConfusionMatrix(tp=0, fp=10, tn=0, fn=10)
    assert matthews_correlation(cm) == -1.0


def test_random_classifier_has_mcc_near_zero() -> None:
    """Random guesses on a balanced dataset yield TP=TN=FP=FN, which
    MCC reports as 0 (by construction the numerator is zero)."""
    cm = ConfusionMatrix(tp=5, fp=5, tn=5, fn=5)
    assert matthews_correlation(cm) == 0.0


def test_precision_zero_division_returns_zero() -> None:
    """No positive predictions means no TP and no FP: precision is
    undefined; ARGOS's convention is to return 0.0 (matching sklearn)."""
    cm = ConfusionMatrix(tp=0, fp=0, tn=10, fn=5)
    assert precision(cm) == 0.0


def test_recall_zero_division_returns_zero() -> None:
    cm = ConfusionMatrix(tp=0, fp=2, tn=10, fn=0)
    assert recall(cm) == 0.0


def test_f1_zero_when_both_terms_zero() -> None:
    cm = ConfusionMatrix(tp=0, fp=2, tn=0, fn=0)
    assert f1_score(cm) == 0.0


def test_accuracy_zero_for_empty_matrix() -> None:
    assert accuracy(ConfusionMatrix()) == 0.0


def test_mcc_returns_zero_when_one_class_is_absent() -> None:
    """Marginal collapse: no actual positives at all. MCC is undefined;
    sklearn convention is 0.0, which we follow."""
    cm = ConfusionMatrix(tp=0, fp=0, tn=20, fn=0)
    assert matthews_correlation(cm) == 0.0


def test_specificity_known_value() -> None:
    cm = ConfusionMatrix(tp=0, fp=4, tn=16, fn=0)
    # TN / (TN + FP) = 16 / 20 = 0.8
    assert math.isclose(specificity(cm), 0.8)


# ---------------------------------------------------------------------------
# Aggregation helpers.
# ---------------------------------------------------------------------------


def test_aggregate_by_groups_and_sums() -> None:
    items = [
        ("ASI01", ConfusionMatrix(tp=1, fp=2, tn=3, fn=4)),
        ("ASI02", ConfusionMatrix(tp=10, fp=20, tn=30, fn=40)),
        ("ASI01", ConfusionMatrix(tp=100, fp=200, tn=300, fn=400)),
    ]
    out = aggregate_by(items)
    assert out["ASI01"] == ConfusionMatrix(tp=101, fp=202, tn=303, fn=404)
    assert out["ASI02"] == ConfusionMatrix(tp=10, fp=20, tn=30, fn=40)


def test_aggregate_by_preserves_first_seen_order() -> None:
    items = [
        ("ASI03", ConfusionMatrix(tp=1)),
        ("ASI01", ConfusionMatrix(tp=2)),
        ("ASI02", ConfusionMatrix(tp=3)),
    ]
    assert list(aggregate_by(items).keys()) == ["ASI03", "ASI01", "ASI02"]


def test_macro_average_equal_weights_each_matrix() -> None:
    cms = [
        ConfusionMatrix(tp=10, fp=0, tn=0, fn=0),  # precision = 1.0
        ConfusionMatrix(tp=0, fp=10, tn=0, fn=0),  # precision = 0.0
    ]
    # Equal weight: (1.0 + 0.0) / 2 = 0.5.
    assert macro_average(cms, precision) == 0.5


def test_macro_average_empty_input_returns_zero() -> None:
    assert macro_average([], precision) == 0.0
