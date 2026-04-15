"""Configuration loader. Precedence: env > ./argos.yaml > platform config > defaults."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field


class Config(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    no_color: bool = Field(default=False)
    otel_endpoint: str | None = Field(default=None)
    plugin_paths: tuple[Path, ...] = Field(default_factory=tuple)


def _platform_config_path() -> Path:
    if os.name == "nt":
        base = Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming"))
    else:
        base = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
    return base / "argos" / "argos.yaml"


def _load_file(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(raw, dict):
        raise TypeError(f"{path} must contain a YAML mapping at the root")
    return raw


def load_config() -> Config:
    """Assemble the effective Config for the current process."""
    merged: dict[str, Any] = {}
    for path in (_platform_config_path(), Path.cwd() / "argos.yaml"):
        merged.update(_load_file(path))

    if os.environ.get("ARGOS_NO_COLOR") or os.environ.get("NO_COLOR"):
        merged["no_color"] = True
    if endpoint := os.environ.get("ARGOS_OTEL_ENDPOINT"):
        merged["otel_endpoint"] = endpoint

    return Config.model_validate(merged)
