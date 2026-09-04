"""``argos status``: one-screen summary of the running ARGOS install."""

from __future__ import annotations

import typer
from argos_core.compliance import load_controls
from argos_scanner import all_rules
from rich import box
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from argos_cli import __version__
from argos_cli.console import get_console
from argos_cli.plugins import discover


def status() -> None:
    """Print a compact summary: version, rules, compliance data, modules."""
    console = get_console()
    console.print(
        Panel(
            Text.assemble(
                ("ARGOS", "argos.brand"),
                " ",
                ("Agent Risk Governance and Operational Security", "argos.muted"),
                "  ",
                (f"v{__version__}", "argos.accent"),
            ),
            border_style="argos.accent",
            padding=(0, 2),
            expand=False,
        ),
    )

    idx = load_controls()
    rules = all_rules()
    mapping_entries = len(idx.mapping.entries) if idx.mapping else 0
    frameworks = ", ".join(m.id for m in idx.frameworks)

    rows = (
        ("Scanner rules", f"[argos.brand]{len(rules)}[/] loaded"),
        ("Compliance frameworks", f"[argos.brand]{len(idx.frameworks)}[/]  {frameworks}"),
        ("Controls indexed", f"[argos.brand]{len(idx.controls)}[/]"),
        ("Mapping entries", f"[argos.brand]{mapping_entries}[/]"),
        ("CLI version", f"v{__version__}"),
    )
    key_width = max(len(k) for k, _ in rows) + 2

    table = Table(show_header=False, box=box.MINIMAL, pad_edge=False, expand=False)
    table.add_column("k", style="argos.muted", no_wrap=True, width=key_width)
    table.add_column("v", overflow="fold")
    for key, val in rows:
        table.add_row(key, val)
    console.print(table)

    # THREAT_MODEL.md T3: every third-party plugin that can influence a
    # verdict is listed with the distribution that provides it, so an
    # auditor can see at a glance which packages were trusted.
    plugins = list(discover())
    console.print()
    if not plugins:
        console.print(
            "[argos.muted]Plugins: none discovered via entry points "
            "(only first-party rules, probes and detectors are active).[/]",
        )
    else:
        console.print(f"[bold]Plugins[/] ({len(plugins)} discovered via entry points):")
        ptable = Table(show_header=True, header_style="bold", box=box.MINIMAL, expand=False)
        ptable.add_column("Group", style="argos.muted", no_wrap=True)
        ptable.add_column("Name", no_wrap=True)
        ptable.add_column("Distribution", no_wrap=True)
        for plugin in plugins:
            dist = plugin.entry_point.dist
            provider = f"{dist.name}=={dist.version}" if dist is not None else "unknown"
            ptable.add_row(plugin.group, plugin.name, provider)
        console.print(ptable)

    console.print()
    console.print(
        Text.assemble(
            ("New here? Run ", "argos.muted"),
            ("argos demo", "argos.brand"),
            (" for a 10-second guided tour, or ", "argos.muted"),
            ("argos quickstart", "argos.brand"),
            (" for the cheat sheet.", "argos.muted"),
        ),
    )
    raise typer.Exit(code=0)
