"""Audit target descriptor."""

from __future__ import annotations

from enum import Enum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class TargetKind(Enum):
    MCP_CONFIG = "mcp-config"
    MCP_SERVER = "mcp-server"
    AGENT_HTTP = "agent-http"
    AGENT_LANGGRAPH = "agent-langgraph"
    FILESYSTEM = "filesystem"


class Target(BaseModel):
    """What is being audited and where it lives."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: TargetKind
    locator: str = Field(..., min_length=1, description="File path, URL or identifier per kind.")
    label: str | None = None
    tags: tuple[str, ...] = Field(default_factory=tuple)
    schema_version: Literal[1] = 1
