"""Aggregate run envelope consumed by reporters and downstream tooling."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from argos_core.models.finding import Finding
from argos_core.models.severity import Severity
from argos_core.models.target import Target


class ScanResult(BaseModel):
    """Envelope for a full audit run."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    target: Target
    producer: str = Field(..., min_length=1, description="name@version of the emitting tool.")
    started_at: datetime
    finished_at: datetime
    findings: tuple[Finding, ...] = Field(default_factory=tuple)
    methodology_version: str = Field(default="argos-1.0")
    run_id: str | None = None
    schema_version: Literal[1] = 1

    @model_validator(mode="after")
    def _finished_not_before_started(self) -> ScanResult:
        if self.finished_at < self.started_at:
            msg = "finished_at must not precede started_at"
            raise ValueError(msg)
        return self

    @classmethod
    def empty(cls, target: Target, producer: str) -> ScanResult:
        now = datetime.now(UTC)
        return cls(target=target, producer=producer, started_at=now, finished_at=now)

    def count_by_severity(self) -> dict[Severity, int]:
        counts: dict[Severity, int] = dict.fromkeys(Severity, 0)
        for finding in self.findings:
            counts[finding.severity] += 1
        return counts

    def max_severity(self) -> Severity | None:
        if not self.findings:
            return None
        return max(f.severity for f in self.findings)

    @property
    def duration_seconds(self) -> float:
        return (self.finished_at - self.started_at).total_seconds()
