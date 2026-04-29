"""Confusion matrix and the five binary-classification metrics ARGOS
uses to score a probe catalogue against a ground truth.

Conventions
-----------
A "positive" prediction means the probe **fired** (it claims it
detected the attacker behaviour). A "negative" prediction means the
probe **blocked / declined** (it found no evidence). The expected
column comes from a ground-truth declaration written by the auditor.

So:
- TP  fire / fire   probe fired and we expected it to (correct detection).
- TN  block / block  probe stayed silent and we expected it to (correct refusal).
- FP  fire / block   probe fired on a clean target (false alarm).
- FN  block / fire   probe missed a real attack (false negative).

Edge cases
----------
Every metric returns a finite ``float`` in a known range:

- precision, recall, F1, accuracy in [0.0, 1.0]
- MCC in [-1.0, 1.0]

When a denominator is zero the convention is to return ``0.0`` rather
than raising. Two reasons: (a) downstream aggregation does not have to
special-case empty cells, and (b) the rationale is academically
defensible (see scikit-learn's ``zero_division`` default).

References
----------
- Matthews, B. W. (1975). *Comparison of the predicted and observed
  secondary structure of T4 phage lysozyme.* Biochimica et Biophysica
  Acta 405. (MCC.)
- van Rijsbergen, C. J. (1979). *Information Retrieval.* (F-measure.)
- Powers, D. M. W. (2011). *Evaluation: From precision, recall and
  F-measure to ROC, informedness, markedness and correlation.*
"""

from __future__ import annotations

import math
from collections.abc import Callable, Iterable
from typing import Final

from pydantic import BaseModel, ConfigDict, Field, model_validator

# Largest count we accept in a single matrix cell. The metrics formulae
# operate on (tp + fp) etc. as Python ints (unbounded), but very large
# values in MCC's denominator can lose precision once we square them.
# A defensive cap keeps the floats in the well-conditioned regime.
_MAX_COUNT: Final[int] = 2**52


class ConfusionMatrix(BaseModel):
    """Frozen 2x2 confusion matrix. All cells are non-negative ints.

    Two matrices add component-wise via :meth:`__add__`, which makes
    aggregation across categories or runs a one-liner.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    tp: int = Field(default=0, ge=0, le=_MAX_COUNT, description="True positives.")
    fp: int = Field(default=0, ge=0, le=_MAX_COUNT, description="False positives.")
    tn: int = Field(default=0, ge=0, le=_MAX_COUNT, description="True negatives.")
    fn: int = Field(default=0, ge=0, le=_MAX_COUNT, description="False negatives.")

    @model_validator(mode="after")
    def _bounded_total(self) -> ConfusionMatrix:
        if self.total > _MAX_COUNT:
            msg = f"confusion matrix total {self.total} exceeds {_MAX_COUNT}"
            raise ValueError(msg)
        return self

    # ------------------------------------------------------------------
    # Derived counts (no allocations; Python ints are exact).
    # ------------------------------------------------------------------
    @property
    def total(self) -> int:
        return self.tp + self.fp + self.tn + self.fn

    @property
    def predicted_positive(self) -> int:
        return self.tp + self.fp

    @property
    def predicted_negative(self) -> int:
        return self.tn + self.fn

    @property
    def actual_positive(self) -> int:
        return self.tp + self.fn

    @property
    def actual_negative(self) -> int:
        return self.tn + self.fp

    # ------------------------------------------------------------------
    # Aggregation. Two matrices add component-wise.
    # ------------------------------------------------------------------
    def __add__(self, other: object) -> ConfusionMatrix:
        if not isinstance(other, ConfusionMatrix):
            return NotImplemented
        return ConfusionMatrix(
            tp=self.tp + other.tp,
            fp=self.fp + other.fp,
            tn=self.tn + other.tn,
            fn=self.fn + other.fn,
        )


# ---------------------------------------------------------------------------
# Metric functions.
# ---------------------------------------------------------------------------


def precision(cm: ConfusionMatrix) -> float:
    """Precision (positive predictive value): TP / (TP + FP).

    Returns ``0.0`` when no positive predictions were made.
    """
    denom = cm.predicted_positive
    if denom == 0:
        return 0.0
    return cm.tp / denom


def recall(cm: ConfusionMatrix) -> float:
    """Recall (sensitivity, true-positive rate): TP / (TP + FN).

    Returns ``0.0`` when there are no actual positives in the sample.
    """
    denom = cm.actual_positive
    if denom == 0:
        return 0.0
    return cm.tp / denom


def specificity(cm: ConfusionMatrix) -> float:
    """Specificity (true-negative rate): TN / (TN + FP).

    Reported as auxiliary; not part of the five canonical metrics but
    useful when discussing false-alarm rates.
    """
    denom = cm.actual_negative
    if denom == 0:
        return 0.0
    return cm.tn / denom


def f1_score(cm: ConfusionMatrix) -> float:
    """F1 score: harmonic mean of precision and recall.

    Returns ``0.0`` when both precision and recall are zero (the
    harmonic mean is undefined there). Equivalent to scikit-learn's
    ``f1_score(..., zero_division=0)``.
    """
    p = precision(cm)
    r = recall(cm)
    if p == 0.0 and r == 0.0:
        return 0.0
    return 2.0 * p * r / (p + r)


def accuracy(cm: ConfusionMatrix) -> float:
    """Accuracy: (TP + TN) / total.

    Returns ``0.0`` on an empty matrix to match the rest of the API.
    Note: accuracy is misleading on imbalanced data; reach for MCC or
    F1 when the positive class is rare.
    """
    if cm.total == 0:
        return 0.0
    return (cm.tp + cm.tn) / cm.total


def matthews_correlation(cm: ConfusionMatrix) -> float:
    """Matthews Correlation Coefficient (Matthews 1975).

    Returns a value in ``[-1.0, +1.0]``:
    +1 perfect prediction, 0 no better than random, -1 inverse prediction.

    MCC is the recommended summary statistic for imbalanced binary
    classification, because unlike F1 or accuracy it accounts for all
    four cells of the confusion matrix at once. See Chicco and Jurman
    (2020), *The advantages of the Matthews correlation coefficient
    (MCC) over F1 score and accuracy in binary classification*.

    The denominator is set to ``1`` whenever any of the four marginal
    sums is zero (a "degenerate" matrix in which one class is absent
    from either the predictions or the labels). The numerator is then
    also zero, so the function returns ``0.0`` -- the convention used
    in scikit-learn.
    """
    tp, fp, tn, fn = cm.tp, cm.fp, cm.tn, cm.fn
    numerator = (tp * tn) - (fp * fn)
    a = tp + fp
    b = tp + fn
    c = tn + fp
    d = tn + fn
    if a == 0 or b == 0 or c == 0 or d == 0:
        return 0.0
    # All marginals positive: the denominator is well-defined and the
    # square root operates on a positive product.
    denom = math.sqrt(a * b * c * d)
    if denom == 0.0 or not math.isfinite(denom):
        return 0.0
    value = numerator / denom
    # Clamp residual floating-point drift; MCC is mathematically in
    # [-1, 1] but rounding can land at +1.0000000000002 etc.
    return max(-1.0, min(1.0, value))


# ---------------------------------------------------------------------------
# Aggregation helpers.
# ---------------------------------------------------------------------------


def aggregate_by(
    items: Iterable[tuple[str, ConfusionMatrix]],
) -> dict[str, ConfusionMatrix]:
    """Group matrices by key and sum component-wise.

    The order of keys in the returned dict mirrors first-seen order in
    ``items`` (Python 3.7+ dict insertion order), so a caller who
    pre-sorts gets a deterministic output.
    """
    out: dict[str, ConfusionMatrix] = {}
    for key, cm in items:
        out[key] = out[key] + cm if key in out else cm
    return out


def macro_average(
    cms: Iterable[ConfusionMatrix],
    metric: Callable[[ConfusionMatrix], float],
) -> float:
    """Macro-average ``metric`` across multiple matrices.

    Macro means equal weight per matrix regardless of size: this is the
    right summary when you care about the worst-served category, not
    the most common one (e.g. "is ARGOS uniformly competent across all
    ten ASI categories?").

    Empty input returns ``0.0``.
    """
    values = [metric(cm) for cm in cms]
    if not values:
        return 0.0
    return sum(values) / len(values)
