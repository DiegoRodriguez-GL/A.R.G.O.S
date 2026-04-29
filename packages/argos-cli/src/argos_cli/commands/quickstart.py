"""``argos quickstart``: a copy-paste cheat sheet for new users.

Prints the smallest invocation for every capability, grouped by intent
(audit, evaluate, run-time observe). Designed so a user who runs
``argos quickstart`` once can clone the commands they need without
hunting through the per-command --help output.
"""

from __future__ import annotations

from rich import box
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from argos_cli import __version__
from argos_cli.console import get_console

_SECTIONS: tuple[tuple[str, str, tuple[tuple[str, str], ...]], ...] = (
    (
        "1. See ARGOS in action",
        "Run the full guided tour. Zero arguments, ~10 seconds.",
        (
            ("argos demo", "audit + eval + proxy bench + compliance, end-to-end"),
            ("argos status", "version, rules loaded, frameworks indexed"),
        ),
    ),
    (
        "2. Audit a static MCP config",
        "Scan a JSON / YAML configuration for known risk patterns.",
        (
            ("argos scan path/to/config.json", "scan one config file"),
            ("argos scan config.json -f jsonl -o findings.jsonl", "machine-readable output"),
            ("argos doctor", "auto-detect every MCP config on this machine and scan it"),
        ),
    ),
    (
        "3. Red-team an agent endpoint",
        "Send 20 probes (ASI01-ASI10) against a chat-style HTTP endpoint.",
        (
            ("argos redteam -t http://localhost:11434/api/chat", "minimal invocation"),
            ("argos redteam -t URL -p 'ASI06-*'", "filter probes by ASI category"),
        ),
    ),
    (
        "4. Run the empirical benchmark",
        "Execute the canonical 6-agent x 20-probe lab. Reproducible.",
        (
            ("argos eval", "run the suite, write argos-eval.html"),
            ("argos eval --json out.json --markdown out.md", "extra export formats"),
        ),
    ),
    (
        "5. Audit live MCP traffic via proxy",
        "TCP listener that ferries JSON-RPC between client and upstream.",
        (
            (
                "argos proxy run -u stdio:'python -m my_mcp_server'",
                "default listen 127.0.0.1:8765, all detectors on",
            ),
            (
                "argos proxy run -u stdio:'npx pkg' -l 127.0.0.1:9000",
                "custom port",
            ),
            (
                "argos proxy run -u tcp:127.0.0.1:9000 --duration 30",
                "TCP upstream, auto-stop after 30 s (CI smoke)",
            ),
            ("argos proxy bench", "latency benchmark; pins RNF-02 < 50 ms"),
        ),
    ),
    (
        "6. Render a report",
        "Convert findings into HTML with the compliance heatmap.",
        (
            ("argos report findings.jsonl -o report.html", "JSONL findings -> HTML"),
            ("argos report --demo", "render a sample report (no input needed)"),
        ),
    ),
    (
        "7. Inspect inventory and mappings",
        "What rules / frameworks / controls are indexed.",
        (
            ("argos rules list", "table of every loaded scanner rule"),
            ("argos compliance list", "frameworks + control counts"),
            ("argos compliance show owasp_asi:ASI01", "a single control detail"),
            ("argos compliance map owasp_asi:ASI01", "cross-framework links"),
        ),
    ),
)


def quickstart() -> None:
    """Print a one-screen cheat sheet of the most common ARGOS invocations."""
    console = get_console()
    console.print(
        Panel(
            Text.assemble(
                ("ARGOS quickstart", "argos.brand"),
                "  ",
                ("v" + __version__, "argos.accent"),
                "\n",
                ("copy-paste cheat sheet for the seven most common workflows", "argos.muted"),
            ),
            border_style="argos.accent",
            padding=(0, 2),
            expand=False,
        ),
    )
    console.print()
    for title, blurb, commands in _SECTIONS:
        console.print(f"[argos.brand]{title}[/]")
        console.print(f"[argos.muted]{blurb}[/]")
        table = Table(
            show_header=False,
            box=box.MINIMAL,
            pad_edge=False,
            expand=False,
        )
        table.add_column("cmd", style="argos.code", no_wrap=False, overflow="fold")
        table.add_column("explain", style="argos.muted", overflow="fold")
        for cmd, explain in commands:
            table.add_row(cmd, explain)
        console.print(table)
        console.print()
    console.print(
        Text.assemble(
            ("Tip: ", "argos.muted"),
            ("every command supports ", "argos.muted"),
            ("--help", "argos.code"),
            (" for the full option list.", "argos.muted"),
        ),
    )
