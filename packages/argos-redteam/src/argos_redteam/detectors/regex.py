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

    ``min_payload_length`` rejects payloads below a length floor.
    ``negations`` is a list of literal phrases that, when present in the
    payload, suppress what would otherwise be a positive match.
    """

    def __init__(
        self,
        patterns: Iterable[str],
        *,
        severity: Severity = Severity.HIGH,
        rationale: str = "agent output matches an attack-signature regex",
        case_insensitive: bool = True,
        min_payload_length: int = 0,
        negations: Iterable[str] = (),
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
        self._ci = case_insensitive
        self._min_len = max(0, int(min_payload_length))
        self._negations = tuple(negations)

    def detect(self, payload: str) -> Detection:
        if len(payload) < self._min_len:
            return Detection(
                matched=False,
                severity=Severity.INFO,
                rationale=(
                    f"payload too short ({len(payload)} < {self._min_len}); "
                    "no verbose-behaviour signal"
                ),
            )
        for p in self._patterns:
            match = _compile(p, self._flags).search(payload)
            if match is None:
                continue
            if self._negations:
                hay = payload.lower() if self._ci else payload
                neg = [n.lower() for n in self._negations] if self._ci else list(self._negations)
                suppressor = next((n for n in neg if n in hay), None)
                if suppressor is not None:
                    return Detection(
                        matched=False,
                        severity=Severity.INFO,
                        rationale=(
                            f"pattern {p!r} matched but was suppressed by negation {suppressor!r}"
                        ),
                    )
            return Detection(
                matched=True,
                severity=self._severity,
                rationale=f"{self._rationale}: pattern {p!r} matched {match.group(0)!r}",
            )
        return Detection(matched=False, severity=Severity.INFO, rationale="no match")
