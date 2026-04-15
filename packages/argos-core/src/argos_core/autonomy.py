"""Autonomy taxonomy (CSA L0-L5) and Capability-Based Risk Attribution score."""

from __future__ import annotations

from enum import IntEnum


class AutonomyLevel(IntEnum):
    """CSA Agentic AI capability levels."""

    L0_ASSISTIVE = 0
    L1_SUPERVISED = 1
    L2_SEMI_AUTONOMOUS = 2
    L3_AUTONOMOUS = 3
    L4_GOAL_DIRECTED = 4
    L5_FULLY_AUTONOMOUS = 5

    @property
    def label(self) -> str:
        return {
            AutonomyLevel.L0_ASSISTIVE: "L0 -- Assistive",
            AutonomyLevel.L1_SUPERVISED: "L1 -- Supervised",
            AutonomyLevel.L2_SEMI_AUTONOMOUS: "L2 -- Semi-autonomous",
            AutonomyLevel.L3_AUTONOMOUS: "L3 -- Autonomous",
            AutonomyLevel.L4_GOAL_DIRECTED: "L4 -- Goal-directed",
            AutonomyLevel.L5_FULLY_AUTONOMOUS: "L5 -- Fully autonomous",
        }[self]


# Empirical weights per autonomy level. Rationale and calibration live in
# docs-internal/RFCs/0002-cbra.md (to be written in Module 1).
_LEVEL_W: dict[AutonomyLevel, float] = {
    AutonomyLevel.L0_ASSISTIVE: 0.10,
    AutonomyLevel.L1_SUPERVISED: 0.25,
    AutonomyLevel.L2_SEMI_AUTONOMOUS: 0.50,
    AutonomyLevel.L3_AUTONOMOUS: 0.75,
    AutonomyLevel.L4_GOAL_DIRECTED: 0.90,
    AutonomyLevel.L5_FULLY_AUTONOMOUS: 1.00,
}


def cbra_score(
    *,
    autonomy: AutonomyLevel,
    exposure: float,
    blast_radius: float,
    reversibility: float,
) -> float:
    """Return a ranking score in [0, 1] combining autonomy weight, exposure,
    blast radius and reversibility. Higher == more risk.

    Raises:
        ValueError: if ``exposure``, ``blast_radius`` or ``reversibility`` are
            outside [0, 1].
    """
    for name, val in (
        ("exposure", exposure),
        ("blast_radius", blast_radius),
        ("reversibility", reversibility),
    ):
        if not 0.0 <= val <= 1.0:
            raise ValueError(f"{name}={val!r} must be within [0, 1]")

    w = _LEVEL_W[autonomy]
    raw = w * (0.5 * exposure + 0.5 * blast_radius) * (1.0 - 0.5 * reversibility)
    return max(0.0, min(1.0, raw))
