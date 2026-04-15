"""Evidence attached to a Finding. Every detection must carry at least one."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class Evidence(BaseModel):
    """Self-contained artefact supporting a detection.

    Four flavours, each with required fields:

    - ``source-range``: requires ``path`` (line_start/line_end optional)
    - ``request-response``: requires ``request`` and ``response``
    - ``trace``: requires ``trace_id``
    - ``raw``: requires ``blob``
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

    @model_validator(mode="after")
    def _kind_has_required_fields(self) -> Evidence:
        if self.kind == "source-range" and not self.path:
            msg = "evidence of kind 'source-range' requires a path"
            raise ValueError(msg)
        if self.kind == "request-response" and not (self.request and self.response):
            msg = "evidence of kind 'request-response' requires both request and response"
            raise ValueError(msg)
        if self.kind == "trace" and not self.trace_id:
            msg = "evidence of kind 'trace' requires a trace_id"
            raise ValueError(msg)
        if self.kind == "raw" and not self.blob:
            msg = "evidence of kind 'raw' requires a blob"
            raise ValueError(msg)
        if (
            self.line_end is not None
            and self.line_start is not None
            and self.line_end < self.line_start
        ):
            msg = "line_end must not precede line_start"
            raise ValueError(msg)
        return self
