"""Evidence attached to a Finding. Every detection must carry at least one."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class Evidence(BaseModel):
    """Self-contained artefact supporting a detection.

    Four flavours: ``source-range`` (file + lines), ``request-response``
    (captured by proxy/red-team), ``trace`` (OpenTelemetry id), ``raw`` (blob).
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: Literal["source-range", "request-response", "trace", "raw"]
    summary: str = Field(..., min_length=1, max_length=512)

    path: str | None = None
    line_start: int | None = Field(default=None, ge=1)
    line_end: int | None = Field(default=None, ge=1)

    request: str | None = None
    response: str | None = None

    trace_id: str | None = None
    span_id: str | None = None

    blob: str | None = None
