"""Compliance data access surface.

Five framework YAMLs ship under ``data/``:

- OWASP Agentic Security Initiative (``owasp_asi``) -- hub of the mapping graph
- Cloud Security Alliance AI Control Matrix (``csa_aicm``)
- EU AI Act (``eu_ai_act``)
- NIST AI Risk Management Framework (``nist_ai_rmf``)
- ISO/IEC 42001 (``iso_42001``)

Plus ``mapping.yaml`` with N:M cross-framework relationships and
``MANIFEST.sha256``, the integrity manifest every load is checked against
(THREAT_MODEL.md T4).
"""

from __future__ import annotations

from argos_core.compliance.loader import load_controls
from argos_core.compliance.manifest import (
    MANIFEST_FILENAME,
    ComplianceIntegrityWarning,
    VerificationResult,
    verify_manifest,
)
from argos_core.compliance.models import (
    Confidence,
    Control,
    ControlIndex,
    FrameworkData,
    FrameworkId,
    FrameworkMeta,
    Mapping,
    MappingEntry,
    MappingMeta,
    Relationship,
)

__all__ = [
    "MANIFEST_FILENAME",
    "ComplianceIntegrityWarning",
    "Confidence",
    "Control",
    "ControlIndex",
    "FrameworkData",
    "FrameworkId",
    "FrameworkMeta",
    "Mapping",
    "MappingEntry",
    "MappingMeta",
    "Relationship",
    "VerificationResult",
    "load_controls",
    "verify_manifest",
]
