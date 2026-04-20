"""Base class for red-team detectors."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass

from argos_core import Severity


@dataclass(frozen=True)
class Detection:
    """Verdict emitted by a detector against a piece of agent output."""

    matched: bool
    severity: Severity
    rationale: str
    confidence: float = 1.0


class BaseDetector(ABC):
    """Classifies a single string payload as matching an attack pattern."""

    @abstractmethod
    def detect(self, payload: str) -> Detection: ...
