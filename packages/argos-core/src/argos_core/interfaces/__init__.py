"""Abstract contracts implemented by every ARGOS producer."""

from __future__ import annotations

from argos_core.interfaces.detector import Detection, IDetector
from argos_core.interfaces.plugin import IPlugin, PluginMetadata
from argos_core.interfaces.probe import IProbe, ProbeContext
from argos_core.interfaces.reporter import IReporter
from argos_core.interfaces.scanner import IScanner

__all__ = [
    "Detection",
    "IDetector",
    "IPlugin",
    "IProbe",
    "IReporter",
    "IScanner",
    "PluginMetadata",
    "ProbeContext",
]
