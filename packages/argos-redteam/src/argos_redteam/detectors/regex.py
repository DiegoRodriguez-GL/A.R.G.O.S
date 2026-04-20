"""``RegexDetector``: detection by one or more regular expressions."""

from __future__ import annotations

import re
from collections.abc import Iterable
from functools import lru_cache

from argos_core import Severity

from argos_redteam.detectors._base import BaseDetector, Detection


@lru_cache(maxsize=1024)
def _compile(pattern: str, flags: int) -> re.Pattern[str]:
    return re.compile(pattern, flags)


class RegexDetector(BaseDetector):
    """Fires when any of ``patterns`` matches the payload.

    Case-insensitive by default: agent output is rarely normalised to a
    single case; treating ``CVE-2026-0001`` and ``cve-2026-0001`` the same
    removes a common source of false negatives.
    """

    def __init__(
        self,
        patterns: Iterable[str],
        *,
        severity: Severity = Severity.HIGH,
        rationale: str = "agent output matches an attack-signature regex",
        case_insensitive: bool = True,
    ) -> None:
        self._patterns = tuple(patterns)
        if not self._patterns:
            msg = "RegexDetector requires at least one pattern"
            raise ValueError(msg)
        self._flags = re.IGNORECASE if case_insensitive else 0
        # Validate eagerly so configuration errors surface at construction.
        for p in self._patterns:
            _compile(p, self._flags)
        self._severity = severity
        self._rationale = rationale

    def detect(self, payload: str) -> Detection:
        for p in self._patterns:
            match = _compile(p, self._flags).search(payload)
            if match is not None:
                return Detection(
                    matched=True,
                    severity=self._severity,
                    rationale=f"{self._rationale}: pattern {p!r} matched {match.group(0)!r}",
                )
        return Detection(matched=False, severity=Severity.INFO, rationale="no match")
