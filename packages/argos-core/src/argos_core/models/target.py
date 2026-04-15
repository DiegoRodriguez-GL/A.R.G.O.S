"""Audit target descriptor."""

from __future__ import annotations

from enum import Enum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


class TargetKind(Enum):
    MCP_CONFIG = "mcp-config"
    MCP_SERVER = "mcp-server"
    AGENT_HTTP = "agent-http"
    AGENT_LANGGRAPH = "agent-langgraph"
    FILESYSTEM = "filesystem"


_MAX_LOCATOR_LENGTH = 4096


class Target(BaseModel):
    """What is being audited and where it lives."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: TargetKind
    locator: str = Field(
        ...,
        min_length=1,
        max_length=_MAX_LOCATOR_LENGTH,
        description="File path, URL or identifier per kind.",
    )
    label: str | None = None
    tags: tuple[str, ...] = Field(default_factory=tuple)
    schema_version: Literal[1] = 1

    @field_validator("locator")
    @classmethod
    def _reject_control_chars(cls, v: str) -> str:
        # Control characters (including \x00, CR, LF, ESC) smuggle terminal
        # escapes into reports and log lines. Reject them at the boundary.
        if any(ord(c) < 0x20 or ord(c) == 0x7F for c in v):
            msg = "locator contains control characters"
            raise ValueError(msg)
        return v
