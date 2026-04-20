"""``StringMatchDetector``: detection by literal substrings."""

from __future__ import annotations

from collections.abc import Iterable

from argos_core import Severity

from argos_redteam.detectors._base import BaseDetector, Detection


class StringMatchDetector(BaseDetector):
    """Fires when any of ``needles`` appears in the payload.

    The rationale and severity are configurable so the same detector class
    can be reused by every probe.
    """

    def __init__(
        self,
        needles: Iterable[str],
        *,
        severity: Severity = Severity.HIGH,
        rationale: str = "agent output contains an attacker-controlled marker",
        case_insensitive: bool = True,
    ) -> None:
        self._needles = tuple(needles)
        if not self._needles:
            msg = "StringMatchDetector requires at least one needle"
            raise ValueError(msg)
        self._severity = severity
        self._rationale = rationale
        self._ci = case_insensitive

    def detect(self, payload: str) -> Detection:
        hay = payload.lower() if self._ci else payload
        needles = [n.lower() for n in self._needles] if self._ci else list(self._needles)
        hit = next((n for n in needles if n in hay), None)
        if hit is None:
            return Detection(matched=False, severity=Severity.INFO, rationale="no match")
        return Detection(
            matched=True,
            severity=self._severity,
            rationale=f"{self._rationale}: matched {hit!r}",
        )
