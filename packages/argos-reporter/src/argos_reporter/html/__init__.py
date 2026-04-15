"""HTML reporter surface. Jinja2 env is built lazily with autoescape + StrictUndefined."""

from __future__ import annotations

from functools import lru_cache
from importlib import resources
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, StrictUndefined, select_autoescape


@lru_cache(maxsize=1)
def templates_path() -> Path:
    return Path(str(resources.files("argos_reporter").joinpath("html", "templates")))


@lru_cache(maxsize=1)
def static_path() -> Path:
    return Path(str(resources.files("argos_reporter").joinpath("html", "static")))


def build_env() -> Environment:
    """Jinja2 env with autoescape (xss-safe) and StrictUndefined (loud bugs)."""
    return Environment(
        loader=FileSystemLoader(str(templates_path())),
        autoescape=select_autoescape(enabled_extensions=("html", "j2"), default_for_string=True),
        undefined=StrictUndefined,
        trim_blocks=True,
        lstrip_blocks=True,
        keep_trailing_newline=True,
    )


__all__ = ["build_env", "static_path", "templates_path"]
