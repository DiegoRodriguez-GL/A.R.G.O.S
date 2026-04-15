"""``argos doctor``: auto-detect and scan every known MCP configuration."""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Annotated

import typer
from argos_core import Severity
from argos_scanner import ParserError
from argos_scanner import scan as run_scan
from rich import box
from rich.table import Table

from argos_cli.console import get_console

_SEVERITY_STYLE: dict[Severity, str] = {
    Severity.CRITICAL: "argos.critical",
    Severity.HIGH: "argos.danger",
    Severity.MEDIUM: "argos.warn",
    Severity.LOW: "argos.ok",
    Severity.INFO: "argos.info",
}


def _known_paths() -> list[tuple[str, Path]]:
    """Return ``(client-label, path)`` pairs for every MCP client we know.

    Covers every file path a reasonably popular MCP client will write on
    Windows, macOS and Linux, plus the project-local variants.
    """
    home = Path.home()
    cwd = Path.cwd()
    out: list[tuple[str, Path]] = []

    if os.name == "nt":
        appdata = Path(os.environ.get("APPDATA") or home / "AppData" / "Roaming")
        out.append(("Claude Desktop (user)", appdata / "Claude" / "claude_desktop_config.json"))
        out.append(("VS Code (user)", appdata / "Code" / "User" / "mcp.json"))
    elif sys.platform == "darwin":
        lib = home / "Library" / "Application Support"
        out.append(("Claude Desktop (user)", lib / "Claude" / "claude_desktop_config.json"))
        out.append(("VS Code (user)", lib / "Code" / "User" / "mcp.json"))
    else:
        xdg = Path(os.environ.get("XDG_CONFIG_HOME") or home / ".config")
        out.append(("Claude Desktop (user)", xdg / "Claude" / "claude_desktop_config.json"))
        out.append(("VS Code (user)", xdg / "Code" / "User" / "mcp.json"))

    out.extend(
        [
            ("Cursor (user)", home / ".cursor" / "mcp.json"),
            ("Windsurf (user)", home / ".codeium" / "windsurf" / "mcp_config.json"),
            ("Continue (user)", home / ".continue" / "config.json"),
            ("VS Code (project)", cwd / ".vscode" / "mcp.json"),
            ("Cursor (project)", cwd / ".cursor" / "mcp.json"),
            ("Windsurf (project)", cwd / ".windsurf" / "mcp_config.json"),
        ],
    )
    return out


def doctor(
    paths_only: Annotated[
        bool,
        typer.Option("--paths", help="Only print the paths we look at; do not scan."),
    ] = False,
) -> None:
    """Auto-detect and scan every known MCP configuration on this system."""
    console = get_console()
    candidates = _known_paths()

    if paths_only:
        table = Table(
            show_header=True,
            header_style="bold",
            box=box.MINIMAL_HEAVY_HEAD,
            expand=True,
        )
        table.add_column("Client", no_wrap=True)
        table.add_column("Path", overflow="fold")
        table.add_column("Exists", no_wrap=True)
        for label, p in candidates:
            exists = "[argos.ok]yes[/]" if p.is_file() else "[argos.muted]no[/]"
            table.add_row(label, str(p), exists)
        console.print(table)
        return

    found = [(label, p) for label, p in candidates if p.is_file()]
    if not found:
        console.print(
            "[argos.muted]No MCP configurations found in known locations.[/]\n"
            "Try [argos.code]argos doctor --paths[/] to see where we looked, or\n"
            "[argos.code]argos scan <path>[/] if your config lives somewhere else.",
        )
        raise typer.Exit(code=0)

    table = Table(show_header=True, header_style="bold", box=box.MINIMAL_HEAVY_HEAD, expand=True)
    table.add_column("Client", no_wrap=True)
    table.add_column("Path", overflow="fold")
    table.add_column("Findings", no_wrap=True, justify="right")
    table.add_column("Worst", no_wrap=True)

    worst_overall: Severity | None = None
    for label, p in found:
        try:
            result = run_scan(p)
        except ParserError:
            table.add_row(label, str(p), "-", "[argos.warn]parse error[/]")
            continue
        worst = result.max_severity()
        if worst is not None and (worst_overall is None or worst > worst_overall):
            worst_overall = worst
        worst_cell = "-" if worst is None else f"[{_SEVERITY_STYLE[worst]}]{worst.value.upper()}[/]"
        table.add_row(label, str(p), str(len(result.findings)), worst_cell)

    console.print(table)
    console.print(f"[argos.muted]{len(found)} configuration(s) scanned.[/]")
    console.print(
        "Run [argos.code]argos scan <path>[/] for per-finding detail.",
    )

    if worst_overall is not None and worst_overall >= Severity.HIGH:
        raise typer.Exit(code=1)
