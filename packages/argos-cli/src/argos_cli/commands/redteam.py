"""``argos redteam``: probe an agent endpoint (implemented in M4)."""

from __future__ import annotations

from typing import Annotated

import typer

from argos_cli.commands._placeholder import not_implemented

app = typer.Typer(help="Run ARGOS red-teaming probes against a target.")


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
    not_implemented("redteam", "Module 4")
