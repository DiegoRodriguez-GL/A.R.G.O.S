"""Domain models for the red-team runtime.

These types are internal to argos-redteam; the reporter consumes the
:class:`argos_core.Finding` instances emitted by each probe, not these.
"""

from __future__ import annotations

from enum import Enum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class Role(Enum):
    USER = "user"
    ASSISTANT = "assistant"
    TOOL = "tool"
    SYSTEM = "system"
    AGENT = "agent"  # foreign peer in multi-agent scenarios


class Message(BaseModel):
    """One element of a probe transcript."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    role: Role
    content: str = Field(..., max_length=32_000)
    name: str | None = Field(default=None, max_length=128)
    tool_call_id: str | None = Field(default=None, max_length=128)


class Transcript(BaseModel):
    """Ordered conversation exchanged during a probe run."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    messages: tuple[Message, ...] = Field(default_factory=tuple)

    def with_message(self, msg: Message) -> Transcript:
        return Transcript(messages=(*self.messages, msg))

    def rendered(self) -> str:
        return "\n".join(f"[{m.role.value}] {m.content}" for m in self.messages)


class ProbeOutcome(Enum):
    SUCCESS = "success"  # the agent behaved as attacker wanted
    NEUTRAL = "neutral"  # inconclusive / ambiguous
    BLOCKED = "blocked"  # agent refused / defence worked


class ProbeResult(BaseModel):
    """Internal per-run result a probe produces before findings are minted."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    probe_id: str = Field(..., min_length=1, max_length=128)
    outcome: ProbeOutcome
    rationale: str = Field(..., min_length=1, max_length=2000)
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    transcript: Transcript


class ProbeRunSummary(BaseModel):
    """Aggregate metrics across a red-team run."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    total: int = Field(..., ge=0)
    success: int = Field(..., ge=0)
    blocked: int = Field(..., ge=0)
    neutral: int = Field(..., ge=0)
    target: str = Field(..., min_length=1)
    strategy: Literal["single-turn", "multi-turn"]
