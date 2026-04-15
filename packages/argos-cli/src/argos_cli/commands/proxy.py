"""``argos proxy``: transparent MCP audit proxy (implemented in M5)."""

from __future__ import annotations

from typing import Annotated

import typer

from argos_cli.commands._placeholder import not_implemented

app = typer.Typer(help="Run the ARGOS MCP audit proxy.")


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
    not_implemented("proxy", "Module 5")
