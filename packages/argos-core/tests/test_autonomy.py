"""Bounds and monotonicity for the CBRA scoring formula."""

from __future__ import annotations

from itertools import pairwise

import pytest
from argos_core import AutonomyLevel, cbra_score


@pytest.mark.parametrize("level", list(AutonomyLevel))
def test_cbra_is_bounded_unit_interval(level: AutonomyLevel) -> None:
    score = cbra_score(autonomy=level, exposure=1.0, blast_radius=1.0, reversibility=0.0)
    assert 0.0 <= score <= 1.0


def test_cbra_monotonic_in_autonomy() -> None:
    common = {"exposure": 0.8, "blast_radius": 0.7, "reversibility": 0.2}
    scores = [cbra_score(autonomy=lv, **common) for lv in AutonomyLevel]
    for lo, hi in pairwise(scores):
        assert lo <= hi


def test_cbra_rejects_out_of_range() -> None:
    with pytest.raises(ValueError, match=r"exposure=.* must be within"):
        cbra_score(
            autonomy=AutonomyLevel.L3_AUTONOMOUS,
            exposure=1.5,
            blast_radius=0.5,
            reversibility=0.5,
        )


def test_autonomy_level_label_is_human_readable() -> None:
    assert "L3" in AutonomyLevel.L3_AUTONOMOUS.label
    assert "Autonomous" in AutonomyLevel.L3_AUTONOMOUS.label
