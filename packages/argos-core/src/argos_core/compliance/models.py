"""Compliance models: controls, frameworks and cross-framework mappings.

All public types are frozen Pydantic models. A ``Control`` belongs to exactly
one framework; cross-framework links live in :class:`Mapping`.
"""

from __future__ import annotations

import re
from datetime import date
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

Relationship = Literal["mitigates", "implements", "requires", "related"]
Confidence = Literal["high", "medium", "low"]
FrameworkId = Literal[
    "owasp_asi",
    "csa_aicm",
    "eu_ai_act",
    "nist_ai_rmf",
    "iso_42001",
]

_QID_RE = re.compile(r"^[a-z0-9_]+:[A-Za-z0-9][A-Za-z0-9_\-\.]*$")


class Control(BaseModel):
    """A single normative control inside one framework."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str = Field(..., min_length=1, max_length=64)
    framework: FrameworkId
    title: str = Field(..., min_length=1, max_length=200)
    text: str = Field(
        ..., min_length=1, description="Faithful summary; see source_url for normative text."
    )
    parent_id: str | None = Field(
        default=None, description="Parent control id within the same framework."
    )
    section: str | None = Field(default=None, description="Source section, e.g. 'Annex A.6'.")
    source_url: str | None = Field(default=None, description="Link to the authoritative document.")
    tags: tuple[str, ...] = Field(default_factory=tuple)
    references: tuple[str, ...] = Field(default_factory=tuple)

    @property
    def qid(self) -> str:
        """Qualified id across frameworks, e.g. ``owasp_asi:ASI01``."""
        return f"{self.framework}:{self.id}"


class FrameworkMeta(BaseModel):
    """Metadata describing one framework file."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: FrameworkId
    name: str = Field(..., min_length=1, max_length=200)
    version: str = Field(..., min_length=1, max_length=64)
    updated: date
    source_url: str = Field(..., min_length=1)
    description: str = Field(..., min_length=1)
    license: str | None = Field(
        default=None, description="License of the source text (summaries are ARGOS)."
    )
    notes: str | None = None


class FrameworkData(BaseModel):
    """Top-level schema of each framework YAML file."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    meta: FrameworkMeta
    controls: tuple[Control, ...] = Field(..., min_length=1)

    @field_validator("controls")
    @classmethod
    def _unique_ids(cls, v: tuple[Control, ...]) -> tuple[Control, ...]:
        seen: set[str] = set()
        for c in v:
            if c.id in seen:
                raise ValueError(f"duplicate control id within framework: {c.id}")
            seen.add(c.id)
        return v


class MappingEntry(BaseModel):
    """A single cross-framework link.

    ``source`` is a qualified control id (``framework:control_id``). ``targets``
    is a non-empty tuple of qualified ids in *other* frameworks. ``relationship``
    captures semantics; ``rationale`` is the auditable justification.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    source: str = Field(..., pattern=_QID_RE.pattern)
    targets: tuple[str, ...] = Field(..., min_length=1)
    relationship: Relationship
    rationale: str = Field(..., min_length=1, max_length=800)
    confidence: Confidence = "high"

    @field_validator("targets")
    @classmethod
    def _validate_targets(cls, v: tuple[str, ...]) -> tuple[str, ...]:
        for qid in v:
            if not _QID_RE.match(qid):
                raise ValueError(f"invalid qualified id in targets: {qid!r}")
        if len(set(v)) != len(v):
            raise ValueError("duplicate target ids")
        return v


class MappingMeta(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: str = Field(..., min_length=1)
    updated: date
    hub: FrameworkId = Field(..., description="Framework that anchors the mapping graph.")
    description: str = Field(..., min_length=1)


class Mapping(BaseModel):
    """Top-level schema of mapping.yaml."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    meta: MappingMeta
    entries: tuple[MappingEntry, ...] = Field(..., min_length=1)


class ControlIndex(BaseModel):
    """Queryable view over every loaded control."""

    model_config = ConfigDict(extra="forbid", frozen=True, arbitrary_types_allowed=True)

    frameworks: tuple[FrameworkMeta, ...] = Field(default_factory=tuple)
    controls: tuple[Control, ...] = Field(default_factory=tuple)
    mapping: Mapping | None = None

    def by_qid(self, qid: str) -> Control | None:
        for c in self.controls:
            if c.qid == qid:
                return c
        return None

    def by_id(self, control_id: str) -> Control | None:
        """Backwards-compatible lookup by bare id (first match wins)."""
        for c in self.controls:
            if c.id == control_id:
                return c
        return None

    def by_framework(self, framework: str) -> tuple[Control, ...]:
        return tuple(c for c in self.controls if c.framework == framework)

    def mappings_for(self, qid: str) -> tuple[MappingEntry, ...]:
        """Return every mapping entry where ``qid`` is either source or target."""
        if self.mapping is None:
            return ()
        return tuple(e for e in self.mapping.entries if e.source == qid or qid in e.targets)
