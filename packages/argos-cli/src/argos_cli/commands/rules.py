"""``argos rules``: introspect the registered scanner rule set."""

from __future__ import annotations

import fnmatch
from pathlib import Path
from typing import Annotated

import typer
from argos_core import Severity
from argos_rules import RuleError, load_rule_file, load_rules_dir
from argos_scanner import all_rules
from rich import box
from rich.panel import Panel
from rich.table import Table

from argos_cli.console import get_console, get_err_console

app = typer.Typer(help="Inspect the registered scanner rules.", no_args_is_help=True)

_SEVERITY_STYLE: dict[Severity, str] = {
    Severity.CRITICAL: "argos.critical",
    Severity.HIGH: "argos.danger",
    Severity.MEDIUM: "argos.warn",
    Severity.LOW: "argos.ok",
    Severity.INFO: "argos.info",
}


def _parse_severity(value: str | None) -> Severity | None:
    if value is None:
        return None
    try:
        return Severity(value.lower())
    except ValueError as exc:
        valid = ", ".join(s.value for s in Severity)
        msg = f"invalid severity {value!r}; expected one of {valid}"
        raise typer.BadParameter(msg) from exc


@app.command("list")
def list_rules(
    severity: Annotated[
        str | None,
        typer.Option("--severity", "-s", help="Filter by minimum severity."),
    ] = None,
    framework: Annotated[
        str | None,
        typer.Option(
            "--framework",
            "-f",
            help="Filter rules that reference this framework (owasp_asi, eu_ai_act, ...).",
        ),
    ] = None,
    match: Annotated[
        str | None,
        typer.Option("--match", "-m", help="Glob over rule ids (e.g. 'MCP-SEC-DOCKER-*')."),
    ] = None,
) -> None:
    """List every registered rule in a tabular view."""
    floor = _parse_severity(severity)
    rules = list(all_rules())
    if floor is not None:
        rules = [r for r in rules if r.severity >= floor]
    if framework is not None:
        rules = [
            r for r in rules if any(ref.startswith(f"{framework}:") for ref in r.compliance_refs)
        ]
    if match is not None:
        rules = [r for r in rules if fnmatch.fnmatch(r.rule_id, match)]

    rules.sort(key=lambda r: (-r.severity.rank, r.rule_id))

    console = get_console()
    if not rules:
        get_err_console().print("[argos.warn]no rules match those filters[/]")
        raise typer.Exit(code=1)

    table = Table(
        show_header=True,
        header_style="bold",
        box=box.MINIMAL_HEAVY_HEAD,
        expand=True,
    )
    table.add_column("Severity", no_wrap=True, width=10)
    table.add_column("Rule", no_wrap=True)
    table.add_column("Title")
    table.add_column("ASI", no_wrap=True, style="argos.muted")
    for rule in rules:
        asi_refs = ", ".join(
            ref.split(":", 1)[1] for ref in rule.compliance_refs if ref.startswith("owasp_asi:")
        )
        table.add_row(
            f"[{_SEVERITY_STYLE[rule.severity]}]{rule.severity.value.upper()}[/]",
            rule.rule_id,
            rule.title,
            asi_refs or "-",
        )
    console.print(table)
    console.print(f"[argos.muted]{len(rules)} rule(s) shown.[/]")


@app.command("validate")
def validate_rule_file(
    path: Annotated[
        Path,
        typer.Argument(
            exists=True,
            file_okay=True,
            dir_okay=True,
            readable=True,
            resolve_path=True,
            help="YAML rule file or directory of them.",
        ),
    ],
) -> None:
    """Validate a YAML rule document (or directory of them) against the DSL."""
    console = get_console()
    try:
        rules = load_rules_dir(path) if path.is_dir() else (load_rule_file(path),)
    except RuleError as exc:
        get_err_console().print(f"[argos.danger]invalid:[/] {exc}")
        raise typer.Exit(code=1) from exc

    for rule in rules:
        console.print(
            f"[argos.ok]ok[/]  {rule.id}  "
            f"[argos.muted]({rule.info.severity.value}, "
            f"{len(rule.matchers)} matcher(s), "
            f"{len(rule.info.compliance)} compliance ref(s))[/]",
        )
    console.print(f"[argos.muted]{len(rules)} rule(s) validated.[/]")


@app.command("show")
def show_rule(
    rule_id: Annotated[
        str,
        typer.Argument(help="Rule id to describe (e.g. MCP-SEC-DOCKER-PRIVILEGED)."),
    ],
) -> None:
    """Show the full description, remediation and compliance refs of a rule."""
    rule = next((r for r in all_rules() if r.rule_id == rule_id), None)
    if rule is None:
        get_err_console().print(
            f"[argos.danger]unknown rule id:[/] {rule_id}\n"
            "Run `argos rules list` to see every registered rule.",
        )
        raise typer.Exit(code=1)

    console = get_console()
    style = _SEVERITY_STYLE[rule.severity]
    header = (
        f"[bold]{rule.rule_id}[/]  "
        f"[{style}]{rule.severity.value.upper()}[/]  "
        f"[argos.muted]{', '.join(rule.tags) or '-'}[/]"
    )
    console.print(Panel(header, border_style=style, expand=False))

    console.print(f"[bold]Title[/]      {rule.title}")
    console.print(f"[bold]Description[/] {rule.description}")
    if rule.remediation:
        console.print(f"[bold]Remediation[/] {rule.remediation}")

    if rule.compliance_refs:
        t = Table(show_header=True, header_style="bold", box=box.MINIMAL, expand=False)
        t.add_column("Framework", no_wrap=True, style="argos.muted")
        t.add_column("Control id", no_wrap=True)
        for ref in rule.compliance_refs:
            fw, _, cid = ref.partition(":")
            t.add_row(fw, cid)
        console.print("[bold]Compliance refs[/]")
        console.print(t)
