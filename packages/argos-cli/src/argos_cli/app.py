"""Typer application root. Sub-commands live in ``argos_cli.commands.*``."""

from __future__ import annotations

from typing import Annotated

import typer
from rich.panel import Panel
from rich.text import Text

from argos_cli import __version__
from argos_cli.commands import compliance as compliance_cmds
from argos_cli.commands import rules as rules_cmds
from argos_cli.commands.demo import demo
from argos_cli.commands.doctor import doctor
from argos_cli.commands.eval import eval_
from argos_cli.commands.proxy import proxy_app
from argos_cli.commands.quickstart import quickstart
from argos_cli.commands.redteam import redteam
from argos_cli.commands.report import report
from argos_cli.commands.scan import scan
from argos_cli.commands.status import status
from argos_cli.console import get_console

app = typer.Typer(
    name="argos",
    help=(
        "ARGOS -- Agent Risk Governance and Operational Security.\n\n"
        "Try [bold]argos demo[/] for a 10-second guided tour, or "
        "[bold]argos quickstart[/] for a copy-paste cheat sheet of every "
        "common command.\n\n"
        "Static scanner, red-teaming suite, audit proxy and reporting engine "
        "for MCP-based agentic systems."
    ),
    rich_markup_mode="rich",
    no_args_is_help=True,
    add_completion=True,
    pretty_exceptions_show_locals=False,
)

# Onboarding commands -- top of the help so they appear first.
app.command(
    "demo",
    help="Run a 10-second guided tour of every ARGOS capability.",
)(demo)
app.command(
    "quickstart",
    help="Copy-paste cheat sheet of the most common workflows.",
)(quickstart)

# Single-verb commands. Each carries an epilog with copy-paste examples
# so ``argos <verb> --help`` always finishes with a working command.
app.command(
    "status",
    help="One-screen summary of the ARGOS install.",
    epilog=("[bold]Example[/]: [cyan]argos status[/] -- shows version, rules, frameworks loaded."),
)(status)
app.command(
    "doctor",
    help="Auto-detect and scan every known MCP config on this machine.",
    epilog=(
        "[bold]Examples[/]:\n"
        "  [cyan]argos doctor[/]              audit every detected config\n"
        "  [cyan]argos doctor --paths[/]      list paths only, no scanning"
    ),
)(doctor)
app.command(
    "scan",
    help="Statically scan an MCP configuration.",
    epilog=(
        "[bold]Examples[/]:\n"
        "  [cyan]argos scan path/to/config.json[/]\n"
        "  [cyan]argos scan config.json -f jsonl -o findings.jsonl[/]\n"
        "  [cyan]argos scan config.json -s high[/]    only HIGH+ findings"
    ),
)(scan)
app.command(
    "redteam",
    help="Run red-teaming probes (Module 4) against an agent endpoint.",
    epilog=(
        "[bold]Examples[/]:\n"
        "  [cyan]argos redteam -t http://localhost:11434/api/chat[/]\n"
        "  [cyan]argos redteam -t URL -p 'ASI06-*'[/]    filter by category"
    ),
)(redteam)
# proxy is grouped (run / bench), exposed via add_typer below.
app.command(
    "report",
    help="Render findings into HTML or JSONL (Module 6).",
    epilog=(
        "[bold]Examples[/]:\n"
        "  [cyan]argos report findings.jsonl -o report.html[/]\n"
        "  [cyan]argos report --demo[/]    sample report (no input needed)"
    ),
)(report)
app.command(
    "eval",
    help="Run the empirical evaluation suite (Module 7).",
    epilog=(
        "[bold]Examples[/]:\n"
        "  [cyan]argos eval[/]                              run the lab\n"
        "  [cyan]argos eval --json out.json --markdown out.md[/]"
    ),
)(eval_)

# Grouped commands.
app.add_typer(rules_cmds.app, name="rules")
app.add_typer(compliance_cmds.app, name="compliance")
app.add_typer(proxy_app, name="proxy")


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
