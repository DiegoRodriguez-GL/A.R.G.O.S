"""ARGOS core: shared models, interfaces, autonomy taxonomy and telemetry."""

from __future__ import annotations

from argos_core.autonomy import AutonomyLevel, cbra_score
from argos_core.models import (
    Evidence,
    Finding,
    ScanResult,
    Severity,
    Target,
)

__all__ = [
    "AutonomyLevel",
    "Evidence",
    "Finding",
    "ScanResult",
    "Severity",
    "Target",
    "cbra_score",
]

__version__ = "0.0.1"
