"""Red-team probe contract."""

from __future__ import annotations

from abc import abstractmethod
from collections.abc import AsyncIterable
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from argos_core.interfaces.plugin import IPlugin
from argos_core.models import Finding, Target


class ProbeContext(BaseModel):
    """Execution context handed to every probe invocation."""

    model_config = ConfigDict(extra="allow", frozen=True, arbitrary_types_allowed=True)

    target: Target
    timeout_seconds: float = Field(default=30.0, gt=0)
    transport: Any = Field(
        default=None,
        description="Caller-provided transport handle (httpx client, MCP stub, ...).",
    )


class IProbe(IPlugin):
    """Async generator probe. Multi-turn attacks yield findings progressively.

    Implementations are **async generators**: they use ``async def`` with
    ``yield`` rather than returning an awaitable. Python's type-checker
    treats such functions as returning an ``AsyncIterable`` directly.
    """

    @abstractmethod
    def run(self, ctx: ProbeContext) -> AsyncIterable[Finding]: ...
