"""Typed representation of an MCP configuration.

ARGOS normalises every supported config dialect (``claude_desktop_config.json``,
``.vscode/mcp.json``, the draft ``mcp.json`` spec) to a single ``MCPConfig``
instance. Rules consume the normalised form exclusively.
"""

from __future__ import annotations

from enum import Enum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


class TransportKind(Enum):
    STDIO = "stdio"
    SSE = "sse"
    HTTP = "http"
    STREAMABLE_HTTP = "streamable-http"
    WEBSOCKET = "websocket"
    UNKNOWN = "unknown"


class MCPServer(BaseModel):
    """One entry under the config's ``mcpServers``/``servers`` mapping."""

    model_config = ConfigDict(extra="allow", frozen=True)

    name: str = Field(..., min_length=1, max_length=128)
    transport: TransportKind = TransportKind.STDIO

    # stdio / local process
    command: str | None = None
    args: tuple[str, ...] = Field(default_factory=tuple)
    env: dict[str, str] = Field(default_factory=dict)
    cwd: str | None = None

    # remote
    url: str | None = None
    headers: dict[str, str] = Field(default_factory=dict)

    # Raw fragment preserved so rules can inspect vendor-specific extensions
    # without losing fidelity.
    raw: dict[str, Any] = Field(default_factory=dict)

    @field_validator("name")
    @classmethod
    def _reject_control_chars(cls, v: str) -> str:
        if any(ord(c) < 0x20 for c in v):
            msg = f"server name {v!r} contains control characters"
            raise ValueError(msg)
        return v

    @property
    def is_remote(self) -> bool:
        return (
            self.transport
            in {
                TransportKind.SSE,
                TransportKind.HTTP,
                TransportKind.STREAMABLE_HTTP,
                TransportKind.WEBSOCKET,
            }
            or self.url is not None
        )

    @property
    def argv(self) -> tuple[str, ...]:
        """Full argv as it would be passed to ``exec``: ``(command, *args)``."""
        if not self.command:
            return ()
        return (self.command, *self.args)


class MCPConfig(BaseModel):
    """Normalised representation of an MCP configuration file."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    path: Path
    dialect: str = Field(..., description="Source dialect, e.g. 'claude-desktop' or 'mcp-spec'.")
    servers: tuple[MCPServer, ...] = Field(default_factory=tuple)
    raw: dict[str, Any] = Field(default_factory=dict)

    @field_validator("servers")
    @classmethod
    def _names_unique(cls, v: tuple[MCPServer, ...]) -> tuple[MCPServer, ...]:
        seen: set[str] = set()
        for s in v:
            if s.name in seen:
                msg = f"duplicate server name: {s.name!r}"
                raise ValueError(msg)
            seen.add(s.name)
        return v
