"""Shared ``rich`` console. Respects NO_COLOR and ARGOS_NO_COLOR."""

from __future__ import annotations

import os
from functools import lru_cache

from rich.console import Console
from rich.theme import Theme

_ARGOS_THEME = Theme(
    {
        "argos.brand": "bold #059669",
        "argos.accent": "#10b981",
        "argos.muted": "#6b7280",
        "argos.ok": "#047857",
        "argos.info": "#1e40af",
        "argos.warn": "#a16207",
        "argos.danger": "bold #991b1b",
        "argos.critical": "bold reverse #991b1b",
        "argos.path": "#374151",
        "argos.code": "bold #111827 on #f3f4f6",
    },
)


def _color_system() -> str | None:
    if os.environ.get("NO_COLOR") or os.environ.get("ARGOS_NO_COLOR"):
        return None
    return "auto"


@lru_cache(maxsize=1)
def get_console() -> Console:
    return Console(
        theme=_ARGOS_THEME,
        color_system=_color_system(),  # type: ignore[arg-type]
        highlight=False,
        emoji=False,
        markup=True,
        soft_wrap=False,
    )


@lru_cache(maxsize=1)
def get_err_console() -> Console:
    return Console(
        theme=_ARGOS_THEME,
        color_system=_color_system(),  # type: ignore[arg-type]
        stderr=True,
        highlight=False,
        emoji=False,
        markup=True,
    )
