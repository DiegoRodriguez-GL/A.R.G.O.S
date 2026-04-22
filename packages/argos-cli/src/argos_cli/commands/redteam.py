"""``argos redteam``: execute red-team probes against an agent endpoint."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer
from argos_core import ScanResult, Severity
from argos_redteam import HttpTransport, all_probes, run, select
from argos_redteam import summarise as _summarise
from rich import box
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


def _render_table(result: ScanResult, metrics: dict[str, int]) -> None:
    console = get_console()
    console.print(
        f"[argos.brand]ARGOS redteam[/]  target={result.target.locator}  "
        f"probes={metrics['total']}  success={metrics['success']}  blocked={metrics['blocked']}",
    )
    if not result.findings:
        console.print("[argos.ok]No successful probes. Agent behaved safely against this set.[/]")
        return

    table = Table(
        show_header=True,
        header_style="bold",
        box=box.MINIMAL_HEAVY_HEAD,
        expand=True,
    )
    table.add_column("Severity", no_wrap=True, width=10)
    table.add_column("Probe", no_wrap=True)
    table.add_column("Title")
    for finding in sorted(result.findings, key=lambda f: -f.severity.rank):
        style = _SEVERITY_STYLE[finding.severity]
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


def redteam(
    target: Annotated[
        str,
        typer.Option(
            "--target",
            "-t",
            help="Target agent endpoint URL (must accept chat-style POST).",
        ),
    ],
    probes: Annotated[
        list[str] | None,
        typer.Option(
            "--probes",
            "-p",
            help="Glob of probe ids (e.g. 'ASI06-*'). Repeat or comma-separate.",
        ),
    ] = None,
    severity: Annotated[
        str | None,
        typer.Option("--severity", "-s", help="Minimum severity to report."),
    ] = None,
    header: Annotated[
        list[str] | None,
        typer.Option(
            "--header",
            "-H",
            help="Additional HTTP header (Key: Value). Repeat for more.",
        ),
    ] = None,
    timeout_seconds: Annotated[
        float,
        typer.Option("--timeout", help="Per-request timeout in seconds."),
    ] = 30.0,
    max_requests: Annotated[
        int | None,
        typer.Option(
            "--max-requests",
            help=(
                "Denial-of-wallet cap: refuse to talk to the agent more than "
                "N times total (across probes + retries). Leave unset for no cap."
            ),
        ),
    ] = None,
    output_format: Annotated[
        str,
        typer.Option("--format", "-f", help="Output format: table or jsonl."),
    ] = "table",
    output_path: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Write JSONL findings to this path."),
    ] = None,
) -> None:
    """Launch red-teaming probes mapped to OWASP ASI01..ASI10 against a target."""
    headers: dict[str, str] = {}
    for h in header or ():
        if ":" not in h:
            raise typer.BadParameter(f"invalid header {h!r}; expected 'Key: Value'")
        k, _, v = h.partition(":")
        headers[k.strip()] = v.strip()

    probe_globs: tuple[str, ...] | None = None
    if probes:
        probe_globs = tuple(p.strip() for spec in probes for p in spec.split(",") if p.strip())

    transport = HttpTransport(
        endpoint=target,
        headers=headers,
        timeout_seconds=timeout_seconds,
        max_requests=max_requests,
    )

    try:
        result = run(
            target,
            transport,
            probes=probe_globs,
            severity_floor=_parse_severity(severity),
            timeout_seconds=timeout_seconds,
        )
    except Exception as exc:
        get_err_console().print(f"[argos.danger]redteam error:[/] {exc}")
        raise typer.Exit(code=2) from exc

    selected = select(probe_globs) if probe_globs is not None else all_probes()
    metrics = _summarise(result, total_probes=len(selected))

    if output_format == "jsonl":
        _emit_jsonl(result, output_path)
    elif output_format == "table":
        _render_table(result, metrics)
    else:
        raise typer.BadParameter(f"invalid --format {output_format!r}; expected 'table' or 'jsonl'")

    # Exit 0 if no successful probe; 1 if at least one success at HIGH+.
    worst = result.max_severity()
    if worst is not None and worst >= Severity.HIGH:
        raise typer.Exit(code=1)
    raise typer.Exit(code=0)
