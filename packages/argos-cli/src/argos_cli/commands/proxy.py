"""``argos proxy`` -- transparent MCP audit proxy (implemented in M5)."""

from __future__ import annotations

from typing import Annotated

import typer

from argos_cli.console import get_err_console

app = typer.Typer(help="Run the ARGOS MCP audit proxy.")

_NOT_IMPLEMENTED_EXIT = 2


@app.callback(invoke_without_command=True)
def run(
    listen: Annotated[
        str | None,
        typer.Option("--listen", help="host:port to bind."),
    ] = None,
    upstream: Annotated[
        str | None,
        typer.Option("--upstream", help="Upstream MCP server URL."),
    ] = None,
) -> None:
    _ = (listen, upstream)
    get_err_console().print(
        "[argos.warn]argos proxy[/] is not implemented yet. Planned for Module 5; "
        "see docs-internal/PLAN.md.",
    )
    raise typer.Exit(code=_NOT_IMPLEMENTED_EXIT)
