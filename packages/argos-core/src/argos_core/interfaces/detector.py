"""Runtime detector contract for proxy/red-team traffic."""

from __future__ import annotations

from abc import abstractmethod
from dataclasses import dataclass
from typing import Any

from argos_core.interfaces.plugin import IPlugin
from argos_core.models import Severity


@dataclass(frozen=True, slots=True)
class Detection:
    matched: bool
    rule_id: str
    severity: Severity
    rationale: str
    confidence: float = 1.0
    extras: dict[str, Any] | None = None


class IDetector(IPlugin):
    """Classifies a single payload as benign or matching an attack pattern."""

    @abstractmethod
    def detect(self, payload: Any) -> Detection: ...
