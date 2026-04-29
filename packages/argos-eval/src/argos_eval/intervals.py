"""Confidence intervals: Wilson score (closed-form) and bootstrap.

When you report a metric like "precision = 0.83" without a confidence
interval, you imply you measured it perfectly. With small samples, the
real precision could be anywhere from 0.6 to 0.95. The TFM dissertation
must report uncertainty alongside the point estimate; this module
gives the two CIs everyone expects in a benchmark paper.

Two methods are exposed:

- :func:`wilson_interval` is closed-form, O(1), and produces a much
  better approximation than the textbook normal interval for small
  ``n`` or proportions near 0/1. Use this for any metric that is a
  proportion (precision, recall, accuracy).

- :func:`bootstrap_ci` resamples a list of values with replacement and
  computes the requested statistic on each resample. Use it when the
  statistic is *not* a simple proportion (e.g. F1 averaged across
  categories), or when the i.i.d. assumption is dubious and you want
  empirical evidence.

Both functions are deterministic in the bootstrap case once a seed is
fixed; Wilson is deterministic by construction.

References
----------
- Wilson, E. B. (1927). *Probable Inference, the Law of Succession,
  and Statistical Inference.* JASA 22(158), 209-212.
- Newcombe, R. G. (1998). *Two-sided confidence intervals for the
  single proportion: comparison of seven methods.* Statistics in
  Medicine 17, 857-872.
- Efron, B. (1979). *Bootstrap methods: another look at the
  jackknife.* Annals of Statistics 7(1), 1-26.
- Efron, B. and Tibshirani, R. (1993). *An Introduction to the
  Bootstrap.* Chapman & Hall.
"""

from __future__ import annotations

import math
import random
from collections.abc import Callable, Sequence
from statistics import NormalDist
from typing import Final

# Reasonable defaults: 95% confidence and 2000 bootstrap resamples.
# The 2000 figure follows Efron & Tibshirani's recommendation for
# percentile CIs (200 is the floor; 1000-2000 is the practical
# standard; > 2000 buys little extra precision for proportion-like
# statistics).
DEFAULT_CONFIDENCE: Final[float] = 0.95
DEFAULT_BOOTSTRAP_SAMPLES: Final[int] = 2000


def _z_score(confidence: float) -> float:
    """Two-sided z-score for the given confidence level.

    ``confidence`` must be in (0, 1) exclusive. ``NormalDist`` from the
    standard library gives us the inverse CDF without a SciPy dep.
    """
    if not 0.0 < confidence < 1.0:
        msg = f"confidence must lie in (0, 1); got {confidence!r}"
        raise ValueError(msg)
    return NormalDist().inv_cdf((1.0 + confidence) / 2.0)


def wilson_interval(
    successes: int,
    n: int,
    *,
    confidence: float = DEFAULT_CONFIDENCE,
) -> tuple[float, float]:
    """Wilson score interval for a binomial proportion.

    Parameters
    ----------
    successes
        Number of successes (must be 0 <= successes <= n).
    n
        Total number of trials.
    confidence
        Two-sided confidence level, e.g. 0.95.

    Returns
    -------
    (low, high) as floats clamped to [0.0, 1.0].

    Notes
    -----
    The interval is **always** in [0, 1] (a property the normal
    approximation can violate for extreme proportions). When ``n`` is
    zero we conventionally return ``(0.0, 1.0)`` to signal "no
    information"; this matches the behaviour of most stats packages
    and is more honest than raising.
    """
    if successes < 0:
        msg = f"successes must be non-negative; got {successes}"
        raise ValueError(msg)
    if n < 0:
        msg = f"n must be non-negative; got {n}"
        raise ValueError(msg)
    if successes > n:
        msg = f"successes ({successes}) cannot exceed n ({n})"
        raise ValueError(msg)
    if n == 0:
        return (0.0, 1.0)

    z = _z_score(confidence)
    z2 = z * z
    p_hat = successes / n
    denom = 1.0 + z2 / n
    centre = (p_hat + z2 / (2.0 * n)) / denom
    margin = z * math.sqrt((p_hat * (1.0 - p_hat) + z2 / (4.0 * n)) / n) / denom
    low = max(0.0, centre - margin)
    high = min(1.0, centre + margin)
    # Snap to the unit endpoints when all trials succeeded or none did.
    # Floating-point rounding can leave the boundary at 0.9999...9 even
    # though every successful trial means p_hat = 1.0 must lie inside
    # the interval; the same applies symmetrically at zero.
    if successes == n:
        high = 1.0
    if successes == 0:
        low = 0.0
    # Defensive clamp: the interval must always contain the point
    # estimate, regardless of any residual numerical drift.
    low = min(low, p_hat)
    high = max(high, p_hat)
    return (low, high)


def bootstrap_ci(
    values: Sequence[float],
    statistic: Callable[[Sequence[float]], float],
    *,
    samples: int = DEFAULT_BOOTSTRAP_SAMPLES,
    confidence: float = DEFAULT_CONFIDENCE,
    seed: int | None = 0,
) -> tuple[float, float]:
    """Percentile bootstrap confidence interval for an arbitrary statistic.

    Parameters
    ----------
    values
        Sample to resample from. Order is irrelevant. Must be non-empty.
    statistic
        Callable that maps a resampled sequence to a float (e.g.
        ``statistics.mean``, ``functools.partial(numpy.percentile, q=50)``,
        a closure that builds a confusion matrix and returns its F1).
    samples
        Number of bootstrap resamples to draw. ``DEFAULT_BOOTSTRAP_SAMPLES``
        is the textbook recommendation; 200 is the floor below which the
        percentile CI is too noisy to be reliable.
    confidence
        Two-sided confidence level, e.g. 0.95.
    seed
        PRNG seed for reproducibility. ``None`` uses ``os.urandom`` (not
        reproducible) which we intentionally avoid by defaulting to 0;
        any explicit seed makes the function fully deterministic.

    Returns
    -------
    (low, high) percentiles of the bootstrap distribution.
    """
    if not values:
        msg = "bootstrap_ci requires a non-empty sample"
        raise ValueError(msg)
    if samples < 200:
        msg = f"samples={samples} is below the {200}-resample floor for percentile CIs"
        raise ValueError(msg)
    if not 0.0 < confidence < 1.0:
        msg = f"confidence must lie in (0, 1); got {confidence!r}"
        raise ValueError(msg)

    # ``random.Random`` is a non-cryptographic PRNG, which is exactly
    # what bootstrap requires (deterministic given a seed; no security
    # boundary involved). Bandit / ruff S311 is therefore a false
    # positive in this context.
    rng = random.Random(seed)  # noqa: S311
    pool = list(values)
    n = len(pool)
    estimates: list[float] = []
    # ``rng.choices`` is the canonical way to sample with replacement;
    # it is also the documented hot path in CPython for this case.
    for _ in range(samples):
        resample = rng.choices(pool, k=n)
        estimates.append(statistic(resample))
    estimates.sort()

    alpha = (1.0 - confidence) / 2.0
    low_idx = math.floor(alpha * samples)
    high_idx = math.ceil((1.0 - alpha) * samples) - 1
    # Clamp into the valid index range to defend against rounding when
    # ``samples`` is the smallest accepted value.
    low_idx = max(0, min(low_idx, samples - 1))
    high_idx = max(0, min(high_idx, samples - 1))
    return (estimates[low_idx], estimates[high_idx])
