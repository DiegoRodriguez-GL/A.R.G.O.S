"""``argos redteam`` -- probe an agent endpoint (implemented in M4)."""

from __future__ import annotations

from typing import Annotated

import typer

from argos_cli.console import get_err_console

app = typer.Typer(help="Run ARGOS red-teaming probes against a target.")

_NOT_IMPLEMENTED_EXIT = 2


@app.callback(invoke_without_command=True)
def run(
    target: Annotated[
        str | None,
        typer.Option("--target", "-t", help="Target endpoint URL or connector id."),
    ] = None,
    probes: Annotated[
        str | None,
        typer.Option("--probes", "-p", help="Glob of probe ids (e.g. 'asi01-*')."),
    ] = None,
) -> None:
    _ = (target, probes)
    get_err_console().print(
        "[argos.warn]argos redteam[/] is not implemented yet. Planned for Module 4; "
        "see docs-internal/PLAN.md.",
    )
    raise typer.Exit(code=_NOT_IMPLEMENTED_EXIT)
