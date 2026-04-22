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

# Unicode codepoints that change visual rendering without showing a glyph.
# They let an attacker construct a locator that looks like one thing in a
# report and resolves as another at runtime (classic IDN / bidi homograph
# class of tricks). We reject them at the model boundary because they are
# never legitimate in a URL or filesystem path.
_BIDI_OVERRIDES = frozenset(
    "\u202a\u202b\u202c\u202d\u202e"  # LRE, RLE, PDF, LRO, RLO
    "\u2066\u2067\u2068\u2069",  # LRI, RLI, FSI, PDI
)
_ZERO_WIDTH = frozenset(
    "\u200b\u200c\u200d\u200e\u200f"  # ZWSP, ZWNJ, ZWJ, LRM, RLM
    "\u2060\ufeff",  # word joiner, ZWNBSP / BOM
)


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
        # Bidirectional override and zero-width format characters are a
        # separate class of risk: they produce a URL the eye reads as
        # example.com/foo but the browser / OS resolves as something
        # else. Reject them unconditionally.
        for ch in v:
            if ch in _BIDI_OVERRIDES:
                msg = (
                    f"locator contains unicode bidi override "
                    f"(U+{ord(ch):04X}); refusing to accept a string "
                    "that does not render visibly"
                )
                raise ValueError(msg)
            if ch in _ZERO_WIDTH:
                msg = (
                    f"locator contains unicode zero-width / format char "
                    f"(U+{ord(ch):04X}); refusing to accept a string "
                    "that does not render visibly"
                )
                raise ValueError(msg)
        return v
