"""Root plugin contract. Discovery happens via importlib entry points."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class PluginMetadata(BaseModel):
    """Descriptive metadata returned by every plugin."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str = Field(..., min_length=1, max_length=64)
    version: str = Field(..., pattern=r"^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$")
    kind: Literal["scanner-rule", "probe", "proxy-detector", "reporter", "rule-matcher"]
    description: str = Field(..., min_length=1, max_length=512)
    author: str | None = None
    homepage: str | None = None
    owasp_asi: tuple[str, ...] = Field(default_factory=tuple)
    mitre_atlas: tuple[str, ...] = Field(default_factory=tuple)


class IPlugin(ABC):
    @abstractmethod
    def metadata(self) -> PluginMetadata: ...
