"""Shared helper for sub-commands whose implementation lands in later modules."""

from __future__ import annotations

import typer

from argos_cli.console import get_err_console

NOT_IMPLEMENTED_EXIT = 2


def not_implemented(name: str, module: str) -> None:
    """Print a consistent 'planned' notice and exit with code 2."""
    get_err_console().print(
        f"[argos.warn]argos {name}[/] is not implemented yet. "
        f"Planned for {module}; see docs-internal/PLAN.md.",
    )
    raise typer.Exit(code=NOT_IMPLEMENTED_EXIT)
