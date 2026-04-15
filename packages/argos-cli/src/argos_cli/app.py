"""Typer application root. Sub-commands live in argos_cli.commands.*"""

from __future__ import annotations

from typing import Annotated

import typer
from rich.panel import Panel
from rich.text import Text

from argos_cli import __version__
from argos_cli.commands import proxy, redteam, report, scan
from argos_cli.console import get_console

app = typer.Typer(
    name="argos",
    help=(
        "ARGOS -- Agent Risk Governance and Operational Security. "
        "Static scanner, red-teaming suite, audit proxy and reporting engine "
        "for MCP-based agentic systems."
    ),
    rich_markup_mode="rich",
    no_args_is_help=True,
    add_completion=True,
    pretty_exceptions_show_locals=False,
)

app.add_typer(scan.app, name="scan")
app.add_typer(redteam.app, name="redteam")
app.add_typer(proxy.app, name="proxy")
app.add_typer(report.app, name="report")


def _banner() -> Panel:
    title = Text("ARGOS", style="argos.brand")
    subtitle = Text(" Agent Risk Governance and Operational Security", style="argos.muted")
    version = Text(f"  v{__version__}", style="argos.accent")
    return Panel(
        Text.assemble(title, subtitle, version),
        border_style="argos.accent",
        padding=(0, 2),
        expand=False,
    )


def _version_callback(value: bool) -> None:
    if not value:
        return
    get_console().print(f"argos {__version__}", style="argos.brand")
    raise typer.Exit()


def _banner_callback(value: bool) -> None:
    if not value:
        return
    get_console().print(_banner())
    raise typer.Exit()


@app.callback()
def _main(
    version: Annotated[
        bool,
        typer.Option(
            "--version",
            "-V",
            help="Print the ARGOS version and exit.",
            callback=_version_callback,
            is_eager=True,
        ),
    ] = False,
    banner: Annotated[
        bool,
        typer.Option(
            "--banner",
            help="Print the ARGOS banner and exit.",
            callback=_banner_callback,
            is_eager=True,
            hidden=True,
        ),
    ] = False,
) -> None:
    _ = (version, banner)  # consumed by eager callbacks
