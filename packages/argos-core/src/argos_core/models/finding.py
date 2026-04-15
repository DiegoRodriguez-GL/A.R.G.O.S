"""Finding: atomic detection unit exchanged across the ARGOS pipeline."""

from __future__ import annotations

import re
import uuid
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints

from argos_core.models.evidence import Evidence
from argos_core.models.severity import Severity
from argos_core.models.target import Target

FindingId = Annotated[str, StringConstraints(pattern=r"^ARGOS-[0-9A-F]{12}$")]

_RULE_ID_RE = re.compile(r"^[A-Z0-9][A-Z0-9_\-\.]{1,63}$")


def _new_finding_id() -> str:
    return "ARGOS-" + uuid.uuid4().hex[:12].upper()


class Finding(BaseModel):
    """A single detected risk with enough context for triage."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: FindingId = Field(default_factory=_new_finding_id)
    rule_id: str = Field(
        ...,
        min_length=1,
        max_length=128,
        description="Rule identifier, e.g. 'ASI01-01'.",
    )
    title: str = Field(..., min_length=1, max_length=160)
    description: str = Field(..., min_length=1)
    severity: Severity
    target: Target
    evidence: tuple[Evidence, ...] = Field(default_factory=tuple)

    # N:M cross-reference to compliance controls, e.g. "OWASP-ASI01".
    compliance_refs: tuple[str, ...] = Field(default_factory=tuple)
    remediation: str | None = None
    producer: str = Field(
        ...,
        min_length=1,
        max_length=128,
        description="Package name that emitted the finding.",
    )
    schema_version: Literal[1] = 1

    def validate_rule_id(self) -> None:
        """Raise ValueError when rule_id is not canonical. Opt-in by callers."""
        if not _RULE_ID_RE.match(self.rule_id):
            raise ValueError(f"rule_id {self.rule_id!r} is not in canonical form")
