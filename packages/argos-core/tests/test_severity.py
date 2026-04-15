"""Ordering and serialisation guarantees on :class:`argos_core.Severity`."""

from __future__ import annotations

from itertools import pairwise

import pytest
from argos_core import Severity


def test_ordering_is_total() -> None:
    ordered = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
    for lo, hi in pairwise(ordered):
        assert lo < hi
        assert lo <= hi
        assert hi > lo
        assert hi >= lo
        assert lo != hi


def test_ordering_allows_filtering() -> None:
    severities = [Severity.LOW, Severity.HIGH, Severity.INFO, Severity.CRITICAL]
    at_least_high = sorted(s for s in severities if s >= Severity.HIGH)
    assert at_least_high == [Severity.HIGH, Severity.CRITICAL]


def test_serialises_to_string() -> None:
    assert Severity.CRITICAL.value == "critical"


def test_max_returns_highest() -> None:
    assert max(Severity) == Severity.CRITICAL
    assert min(Severity) == Severity.INFO


def test_comparison_with_non_severity_raises_type_error() -> None:
    with pytest.raises(TypeError):
        _ = Severity.HIGH < "critical"
    with pytest.raises(TypeError):
        _ = Severity.HIGH > 3
    with pytest.raises(TypeError):
        _ = Severity.HIGH <= None
    with pytest.raises(TypeError):
        _ = Severity.HIGH >= "anything"
