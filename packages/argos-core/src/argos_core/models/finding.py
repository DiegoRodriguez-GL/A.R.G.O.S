"""Finding: atomic detection unit exchanged across the ARGOS pipeline."""

from __future__ import annotations

import re
import uuid
from typing import Annotated, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    ValidationInfo,
    field_validator,
)

from argos_core.models.evidence import Evidence
from argos_core.models.severity import Severity
from argos_core.models.target import Target

FindingId = Annotated[str, StringConstraints(pattern=r"^ARGOS-[0-9A-F]{12}$")]

_RULE_ID_RE = re.compile(r"^[A-Z0-9][A-Z0-9_\-\.]{1,63}$")


def _new_finding_id() -> str:
    return "ARGOS-" + uuid.uuid4().hex[:12].upper()


# Whitespace control characters that are legitimate in prose
# (newline, carriage return, tab). Everything else below 0x20 plus 0x7F
# (DEL) and the explicit ANSI escape lead 0x1B is a log-injection /
# terminal-repaint vector that has no business in a finding field.
_SAFE_CONTROL_CHARS = frozenset("\t\n\r")


def _reject_ansi_escape(value: str, *, field_name: str) -> str:
    """Control characters forged into rendered findings let a rule
    author (or an attacker who can reflect strings into a rule) repaint
    a terminal log or CI pipeline output in misleading colours. Reject
    them at the model boundary so downstream renderers can assume the
    text is display-safe. Tabs, newlines and carriage returns are
    preserved: they are legitimate in prose."""
    for ch in value:
        code = ord(ch)
        if ch in _SAFE_CONTROL_CHARS:
            continue
        if code == 0x1B or code < 0x20 or code == 0x7F:
            msg = (
                f"{field_name} contains ANSI escape / control character "
                f"(U+{code:04X}); refused to protect terminal renderers"
            )
            raise ValueError(msg)
    return value


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

    @field_validator("title", "description", "rule_id")
    @classmethod
    def _reject_control_chars(cls, v: str, info: ValidationInfo) -> str:
        return _reject_ansi_escape(v, field_name=info.field_name or "field")

    def validate_rule_id(self) -> None:
        """Raise ValueError when rule_id is not canonical. Opt-in by callers."""
        if not _RULE_ID_RE.match(self.rule_id):
            raise ValueError(f"rule_id {self.rule_id!r} is not in canonical form")
