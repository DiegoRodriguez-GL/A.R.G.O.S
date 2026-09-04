"""Credential redaction for red-team evidence.

The implementation lives in :mod:`argos_core.redaction` so the HTML
reporter (THREAT_MODEL.md T6) and the red-team runner share one
pattern set. This module keeps the historical import path.
"""

from __future__ import annotations

from argos_core.redaction import CREDENTIAL_PATTERNS, redact

# Historical alias kept for callers that extended the pattern table.
_PATTERNS = CREDENTIAL_PATTERNS

__all__ = ["CREDENTIAL_PATTERNS", "redact"]
