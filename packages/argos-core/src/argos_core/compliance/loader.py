"""Compliance YAML loader. Tolerant of missing files during M0."""

from __future__ import annotations

from functools import lru_cache
from importlib import resources
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field


class Control(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str = Field(..., min_length=1)
    framework: str = Field(..., min_length=1)
    title: str = Field(..., min_length=1)
    text: str = Field(..., min_length=1)
    tags: tuple[str, ...] = Field(default_factory=tuple)


class ControlIndex(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, arbitrary_types_allowed=True)

    controls: tuple[Control, ...] = Field(default_factory=tuple)

    def by_id(self, control_id: str) -> Control | None:
        for c in self.controls:
            if c.id == control_id:
                return c
        return None

    def by_framework(self, framework: str) -> tuple[Control, ...]:
        return tuple(c for c in self.controls if c.framework == framework)


_KNOWN_FRAMEWORKS: tuple[str, ...] = (
    "owasp_asi",
    "csa_aicm",
    "eu_ai_act",
    "nist_ai_rmf",
    "iso_42001",
)


@lru_cache(maxsize=1)
def load_controls() -> ControlIndex:
    """Aggregate bundled compliance YAML files into a single index."""
    controls: list[Control] = []
    data_root = resources.files("argos_core.compliance") / "data"
    for framework in _KNOWN_FRAMEWORKS:
        resource = data_root / f"{framework}.yaml"
        if not resource.is_file():
            continue
        raw: Any = yaml.safe_load(resource.read_text(encoding="utf-8"))
        if not isinstance(raw, list):
            raise ValueError(f"{framework}.yaml must be a YAML list of controls")
        for entry in raw:
            controls.append(Control(framework=framework, **entry))
    return ControlIndex(controls=tuple(controls))
