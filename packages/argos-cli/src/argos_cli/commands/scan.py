"""``argos scan``: static audit of MCP configurations."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer
from argos_core import ScanResult, Severity
from argos_rules import RuleError
from argos_scanner import ParserError
from argos_scanner import scan as run_scan
from rich.table import Table

from argos_cli.console import get_console, get_err_console

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


def _exit_code_for(max_severity: Severity | None) -> int:
    if max_severity is None:
        return 0
    if max_severity >= Severity.HIGH:
        return 1
    return 0


def _render_table(result: ScanResult) -> None:
    console = get_console()
    console.print(
        f"[argos.brand]ARGOS scan[/]  target={result.target.locator}  "
        f"producer={result.producer}  findings={len(result.findings)}",
    )
    if not result.findings:
        console.print("[argos.ok]No findings.[/]")
        return

    table = Table(show_header=True, header_style="bold", expand=True)
    table.add_column("Severity", no_wrap=True, width=10)
    table.add_column("Rule", no_wrap=True)
    table.add_column("Title")
    for finding in sorted(result.findings, key=lambda f: -f.severity.rank):
        style = _SEVERITY_STYLE.get(finding.severity, "")
        table.add_row(
            f"[{style}]{finding.severity.value.upper()}[/]",
            finding.rule_id,
            finding.title,
        )
    console.print(table)


def _emit_jsonl(result: ScanResult, output_path: Path | None) -> None:
    lines = [finding.model_dump_json() for finding in result.findings]
    payload = "\n".join(lines) + ("\n" if lines else "")
    if output_path is None:
        get_console().out(payload, end="")
    else:
        output_path.write_text(payload, encoding="utf-8")


def scan(
    target: Annotated[
        Path,
        typer.Argument(
            exists=True,
            file_okay=True,
            dir_okay=False,
            readable=True,
            resolve_path=True,
            help="Path to an MCP configuration file.",
        ),
    ],
    rules: Annotated[
        list[str] | None,
        typer.Option(
            "--rules",
            "-r",
            help="Glob of rule ids to include (repeat or comma-separate).",
        ),
    ] = None,
    severity: Annotated[
        str | None,
        typer.Option("--severity", "-s", help="Minimum severity (info|low|medium|high|critical)."),
    ] = None,
    output_format: Annotated[
        str,
        typer.Option("--format", "-f", help="Output format: table (default) or jsonl."),
    ] = "table",
    output_path: Annotated[
        Path | None,
        typer.Option(
            "--output",
            "-o",
            help="Write JSONL findings to this path instead of stdout (--format jsonl).",
        ),
    ] = None,
    rules_dir: Annotated[
        Path | None,
        typer.Option(
            "--rules-dir",
            "-R",
            exists=True,
            file_okay=False,
            dir_okay=True,
            resolve_path=True,
            help="Directory of YAML rule files to apply on top of built-in rules.",
        ),
    ] = None,
) -> None:
    """Statically scan an MCP configuration file for known risk patterns."""
    severity_floor = _parse_severity(severity)
    if rules:
        rule_globs: tuple[str, ...] | None = tuple(
            p.strip() for spec in rules for p in spec.split(",") if p.strip()
        )
    else:
        rule_globs = None

    try:
        result = run_scan(
            target,
            rules=rule_globs,
            severity_floor=severity_floor,
            yaml_rules_dir=rules_dir,
        )
    except ParserError as exc:
        get_err_console().print(f"[argos.danger]parse error:[/] {exc}")
        raise typer.Exit(code=2) from exc
    except RuleError as exc:
        get_err_console().print(f"[argos.danger]rule error:[/] {exc}")
        raise typer.Exit(code=2) from exc

    if output_format == "jsonl":
        _emit_jsonl(result, output_path)
    elif output_format == "table":
        _render_table(result)
    else:
        msg = f"invalid --format {output_format!r}; expected 'table' or 'jsonl'"
        raise typer.BadParameter(msg)

    raise typer.Exit(code=_exit_code_for(result.max_severity()))
