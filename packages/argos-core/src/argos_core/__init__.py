"""ARGOS core: shared models, interfaces, autonomy taxonomy and telemetry."""

from __future__ import annotations

from argos_core.autonomy import AutonomyLevel, cbra_score
from argos_core.interfaces import (
    Detection,
    IDetector,
    IPlugin,
    IProbe,
    IReporter,
    IScanner,
    PluginMetadata,
    ProbeContext,
)
from argos_core.models import (
    Evidence,
    Finding,
    FindingId,
    ScanResult,
    Severity,
    Target,
    TargetKind,
)

__all__ = [
    "AutonomyLevel",
    "Detection",
    "Evidence",
    "Finding",
    "FindingId",
    "IDetector",
    "IPlugin",
    "IProbe",
    "IReporter",
    "IScanner",
    "PluginMetadata",
    "ProbeContext",
    "ScanResult",
    "Severity",
    "Target",
    "TargetKind",
    "cbra_score",
]

__version__ = "0.0.1"
