"""``argos scan`` -- static audit of MCP configurations (implemented in M2)."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer

from argos_cli.console import get_err_console

app = typer.Typer(help="Statically scan MCP configurations against ARGOS rules.")

_NOT_IMPLEMENTED_EXIT = 2


@app.callback(invoke_without_command=True)
def run(
    target: Annotated[
        Path | None,
        typer.Argument(
            exists=False,
            file_okay=True,
            dir_okay=True,
            readable=True,
            resolve_path=True,
            help="Path to an MCP configuration file or directory.",
        ),
    ] = None,
    rules: Annotated[
        str | None,
        typer.Option("--rules", "-r", help="Glob of rule identifiers to include."),
    ] = None,
    severity: Annotated[
        str | None,
        typer.Option("--severity", "-s", help="Minimum severity (info|low|medium|high|critical)."),
    ] = None,
) -> None:
    _ = (target, rules, severity)
    get_err_console().print(
        "[argos.warn]argos scan[/] is not implemented yet. Planned for Module 2; "
        "see docs-internal/PLAN.md.",
    )
    raise typer.Exit(code=_NOT_IMPLEMENTED_EXIT)
