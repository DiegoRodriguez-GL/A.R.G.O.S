"""Tests for Wilson and bootstrap confidence intervals.

Two layers:

- Closed-form: Wilson's formula gives a deterministic result for any
  ``(successes, n, confidence)`` triple. We compare against published
  reference values (Newcombe 1998 Table 1 and the calculator at
  https://wise1.cgu.edu/wise/portfolio/binomialprop.asp) plus
  algebraic invariants (interval contains the point estimate; interval
  shrinks as n grows).
- Empirical: bootstrap_ci should converge to the underlying truth as
  the resample count grows. We verify that on data with a known mean.
"""

from __future__ import annotations

import math
import statistics

import pytest
from argos_eval import bootstrap_ci, wilson_interval
from hypothesis import given, settings
from hypothesis import strategies as st

# ---------------------------------------------------------------------------
# Wilson interval: closed-form sanity vs published values.
# ---------------------------------------------------------------------------


def test_wilson_interval_returns_uniform_when_n_zero() -> None:
    """Zero trials means no information; we return the trivial [0, 1]
    rather than raising or returning NaN."""
    assert wilson_interval(0, 0) == (0.0, 1.0)


def test_wilson_interval_full_success() -> None:
    """81 successes out of 81: the interval should hug 1.0 from below."""
    low, high = wilson_interval(81, 81, confidence=0.95)
    # Newcombe 1998 reports (0.9550, 1.0000) for 81/81 at 95%; we
    # tolerate a small absolute difference due to the z-score
    # numerical precision.
    assert math.isclose(low, 0.9550, abs_tol=5e-3)
    assert high == 1.0


def test_wilson_interval_zero_successes() -> None:
    low, high = wilson_interval(0, 30, confidence=0.95)
    assert low == 0.0
    # Newcombe 1998 reports ~0.1142 for 0/30; check loose bound.
    assert 0.10 < high < 0.13


def test_wilson_interval_known_value_15_of_50() -> None:
    """15 hits out of 50 trials at 95% confidence is one of the
    classic worked examples; Wilson's formula gives roughly
    (0.190, 0.434)."""
    low, high = wilson_interval(15, 50, confidence=0.95)
    assert math.isclose(low, 0.190, abs_tol=5e-3)
    assert math.isclose(high, 0.434, abs_tol=5e-3)


@given(
    successes=st.integers(min_value=0, max_value=200),
    n=st.integers(min_value=1, max_value=200),
)
def test_wilson_interval_contains_point_estimate(successes: int, n: int) -> None:
    """The classical guarantee: the Wilson interval brackets the
    sample proportion."""
    if successes > n:
        return  # Hypothesis can produce the impossible pair; skip.
    low, high = wilson_interval(successes, n)
    p_hat = successes / n
    assert low <= p_hat <= high


@given(
    successes=st.integers(min_value=0, max_value=100),
    n=st.integers(min_value=1, max_value=100),
)
def test_wilson_interval_is_inside_unit_interval(successes: int, n: int) -> None:
    if successes > n:
        return
    low, high = wilson_interval(successes, n)
    assert 0.0 <= low <= high <= 1.0


def test_wilson_interval_width_decreases_with_more_data() -> None:
    """Same point proportion, more samples: tighter interval."""
    small = wilson_interval(1, 10)
    big = wilson_interval(100, 1000)
    assert (big[1] - big[0]) < (small[1] - small[0])


def test_wilson_interval_rejects_invalid_inputs() -> None:
    with pytest.raises(ValueError, match="successes"):
        wilson_interval(-1, 10)
    with pytest.raises(ValueError, match="n"):
        wilson_interval(5, -1)
    with pytest.raises(ValueError, match="cannot exceed"):
        wilson_interval(15, 10)
    with pytest.raises(ValueError, match="confidence"):
        wilson_interval(5, 10, confidence=0.0)
    with pytest.raises(ValueError, match="confidence"):
        wilson_interval(5, 10, confidence=1.0)


def test_wilson_interval_higher_confidence_is_wider() -> None:
    a_low, a_high = wilson_interval(50, 100, confidence=0.90)
    b_low, b_high = wilson_interval(50, 100, confidence=0.99)
    assert (b_high - b_low) > (a_high - a_low)


# ---------------------------------------------------------------------------
# Bootstrap CI: empirical convergence + degenerate cases.
# ---------------------------------------------------------------------------


def test_bootstrap_ci_constant_data_has_zero_width() -> None:
    """Resampling from a constant series cannot change the mean; the
    bootstrap interval collapses to the point value."""
    data = [0.5] * 100
    low, high = bootstrap_ci(data, statistics.mean, samples=500)
    assert low == 0.5
    assert high == 0.5


def test_bootstrap_ci_brackets_true_mean_on_uniform_data() -> None:
    """Synthetic uniform-on-[0,1] data: with enough samples the 95%
    bootstrap CI for the mean should bracket 0.5 most of the time.
    We use a fixed seed so the test is deterministic."""
    import random as _r

    rng = _r.Random(42)
    data = [rng.random() for _ in range(500)]
    low, high = bootstrap_ci(data, statistics.mean, samples=2000, seed=7)
    assert low < 0.5 < high


def test_bootstrap_ci_is_deterministic_for_a_given_seed() -> None:
    data = [1.0, 2.0, 3.0, 4.0, 5.0]
    a = bootstrap_ci(data, statistics.mean, samples=500, seed=1)
    b = bootstrap_ci(data, statistics.mean, samples=500, seed=1)
    assert a == b


def test_bootstrap_ci_seed_change_changes_result() -> None:
    """Sanity: different seeds usually produce different intervals."""
    data = [1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0]
    a = bootstrap_ci(data, statistics.mean, samples=500, seed=1)
    b = bootstrap_ci(data, statistics.mean, samples=500, seed=2)
    assert a != b


def test_bootstrap_ci_rejects_empty_sample() -> None:
    with pytest.raises(ValueError, match="non-empty"):
        bootstrap_ci([], statistics.mean)


def test_bootstrap_ci_rejects_too_few_samples() -> None:
    with pytest.raises(ValueError, match="floor"):
        bootstrap_ci([1.0, 2.0], statistics.mean, samples=10)


def test_bootstrap_ci_rejects_invalid_confidence() -> None:
    with pytest.raises(ValueError, match="confidence"):
        bootstrap_ci([1.0], statistics.mean, samples=500, confidence=2.0)


def test_bootstrap_ci_higher_confidence_is_wider() -> None:
    import random as _r

    rng = _r.Random(0)
    data = [rng.gauss(0, 1) for _ in range(200)]
    a_low, a_high = bootstrap_ci(data, statistics.mean, samples=1000, seed=0, confidence=0.80)
    b_low, b_high = bootstrap_ci(data, statistics.mean, samples=1000, seed=0, confidence=0.99)
    assert (b_high - b_low) > (a_high - a_low)


@given(
    values=st.lists(
        st.floats(min_value=-10.0, max_value=10.0, allow_nan=False, allow_infinity=False),
        min_size=10,
        max_size=200,
    ),
)
@settings(max_examples=20, deadline=None)
def test_bootstrap_ci_brackets_point_estimate_for_mean(values: list[float]) -> None:
    """The percentile bootstrap CI for the mean must contain the
    sample mean (the centre of the resample distribution)."""
    sample_mean = statistics.mean(values)
    low, high = bootstrap_ci(values, statistics.mean, samples=500, seed=0)
    # The bootstrap distribution centres on the sample mean; with 500
    # resamples and a typical 95% interval we expect the sample mean
    # to fall comfortably inside.
    assert low <= sample_mean <= high
