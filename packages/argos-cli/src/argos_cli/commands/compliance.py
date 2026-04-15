"""``argos compliance``: introspect the cross-framework mapping graph."""

from __future__ import annotations

from typing import Annotated

import typer
from argos_core.compliance import load_controls
from rich import box
from rich.panel import Panel
from rich.table import Table

from argos_cli.console import get_console, get_err_console

app = typer.Typer(
    help="Inspect the compliance frameworks and the cross-framework mapping graph.",
    no_args_is_help=True,
)


@app.command("list")
def list_frameworks() -> None:
    """List every loaded framework with its control count and metadata."""
    idx = load_controls()
    console = get_console()

    table = Table(show_header=True, header_style="bold", box=box.MINIMAL_HEAVY_HEAD, expand=True)
    table.add_column("Framework", no_wrap=True)
    table.add_column("Name")
    table.add_column("Version", no_wrap=True, style="argos.muted")
    table.add_column("Updated", no_wrap=True, style="argos.muted")
    table.add_column("Controls", no_wrap=True, justify="right")
    for meta in idx.frameworks:
        count = len(idx.by_framework(meta.id))
        table.add_row(
            meta.id,
            meta.name,
            meta.version,
            str(meta.updated),
            str(count),
        )
    console.print(table)

    mapping_entries = len(idx.mapping.entries) if idx.mapping else 0
    console.print(
        f"[argos.muted]{len(idx.controls)} controls total, {mapping_entries} mapping entries.[/]",
    )


@app.command("show")
def show_control(
    qid: Annotated[
        str,
        typer.Argument(
            help="Qualified control id, e.g. owasp_asi:ASI01 or iso_42001:A.6.2.8.",
        ),
    ],
) -> None:
    """Show the full text of a single control."""
    idx = load_controls()
    control = idx.by_qid(qid)
    if control is None:
        get_err_console().print(
            f"[argos.danger]unknown control:[/] {qid}\n"
            "Run `argos compliance list` to see loaded frameworks.",
        )
        raise typer.Exit(code=1)

    console = get_console()
    console.print(
        Panel(
            f"[bold]{control.qid}[/]  [argos.muted]{control.section or ''}[/]",
            border_style="argos.accent",
            expand=False,
        ),
    )
    console.print(f"[bold]Title[/]      {control.title}")
    console.print(f"[bold]Framework[/]  {control.framework}")
    if control.parent_id:
        console.print(f"[bold]Parent[/]     {control.parent_id}")
    if control.section:
        console.print(f"[bold]Section[/]    {control.section}")
    if control.tags:
        console.print(f"[bold]Tags[/]       {', '.join(control.tags)}")
    if control.source_url:
        console.print(f"[bold]Source[/]     [argos.muted]{control.source_url}[/]")
    console.print()
    console.print(control.text)


@app.command("map")
def map_control(
    qid: Annotated[
        str,
        typer.Argument(help="Qualified control id whose mappings to display."),
    ],
) -> None:
    """Show the cross-framework relationships touching this control."""
    idx = load_controls()
    if idx.by_qid(qid) is None:
        get_err_console().print(f"[argos.danger]unknown control:[/] {qid}")
        raise typer.Exit(code=1)

    entries = idx.mappings_for(qid)
    if not entries:
        get_console().print(f"[argos.muted]No mapping entries reference {qid}.[/]")
        raise typer.Exit(code=0)

    console = get_console()
    table = Table(show_header=True, header_style="bold", box=box.MINIMAL_HEAVY_HEAD, expand=True)
    table.add_column("Source", no_wrap=True)
    table.add_column("Relationship", no_wrap=True, style="argos.muted")
    table.add_column("Targets")
    table.add_column("Conf.", no_wrap=True, width=6, style="argos.muted")
    for e in entries:
        table.add_row(
            e.source,
            e.relationship,
            ", ".join(e.targets),
            e.confidence,
        )
    console.print(table)

    for e in entries:
        console.print(
            Panel(
                e.rationale,
                title=f"[bold]{e.source}[/] ({e.relationship}, conf={e.confidence})",
                border_style="argos.muted",
                expand=True,
            ),
        )
