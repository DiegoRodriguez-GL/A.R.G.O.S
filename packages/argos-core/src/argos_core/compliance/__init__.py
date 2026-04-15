"""Compliance data access surface.

Five framework YAMLs ship under ``data/``:

- OWASP Agentic Security Initiative (``owasp_asi``) -- hub of the mapping graph
- Cloud Security Alliance AI Control Matrix (``csa_aicm``)
- EU AI Act (``eu_ai_act``)
- NIST AI Risk Management Framework (``nist_ai_rmf``)
- ISO/IEC 42001 (``iso_42001``)

Plus ``mapping.yaml`` with N:M cross-framework relationships.
"""

from __future__ import annotations

from argos_core.compliance.loader import load_controls
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
    "load_controls",
]
