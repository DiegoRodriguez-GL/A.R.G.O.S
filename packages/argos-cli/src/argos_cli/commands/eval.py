"""``argos eval``: run the empirical evaluation suite.

Executes every (lab agent, probe) pair in the ARGOS benchmark, scores
the results against the canonical ground truth and writes:

- An HTML report (default ``argos-eval.html``) with the confusion
  matrix, metrics with Wilson confidence intervals, per-ASI and
  per-agent breakdowns, and the methodology appendix.
- Optionally a JSON dump of the raw :class:`argos_eval.EvalReport`
  (``--json <path>``) for downstream analysis or for pinning a
  reproducible artefact in a TFM appendix.

The command is fully reproducible: no external network, no LLM
sampling, deterministic agents. Two invocations against the same
catalogue must produce byte-identical HTML and JSON outputs (modulo
clock-derived fields, which are fixed per run).
"""

from __future__ import annotations

import fnmatch
from pathlib import Path
from typing import Annotated

import typer
from argos_eval import (
    DEFAULT_CONCURRENCY,
    DEFAULT_TIMEOUT_SECONDS,
    EvalReport,
    GroundTruth,
    LabAgent,
    all_agents,
    default_ground_truth,
    f1_score,
    matthews_correlation,
    precision,
    recall,
    run_suite,
)
from argos_redteam import all_probes
from argos_redteam.probes._base import BaseProbe
from argos_reporter import render_eval_html
from rich.table import Table

from argos_cli.console import get_console, get_err_console


def _select_probes(globs: tuple[str, ...] | None) -> list[BaseProbe]:
    """Filter the probe catalogue by user-supplied globs (e.g. ``ASI06-*``)."""
    catalogue = list(all_probes())
    if not globs:
        return catalogue
    return [p for p in catalogue if any(fnmatch.fnmatch(p.probe_id, g) for g in globs)]


def _select_agents(filters: tuple[str, ...] | None) -> list[LabAgent]:
    """Filter lab agents by id substring match (case-insensitive)."""
    catalogue = list(all_agents())
    if not filters:
        return catalogue
    needles = tuple(f.lower() for f in filters)
    return [a for a in catalogue if any(n in a.agent_id.lower() for n in needles)]


def eval_(
    ground_truth_path: Annotated[
        Path | None,
        typer.Option(
            "--ground-truth",
            "-g",
            help="YAML ground-truth file. Default: the one shipped with argos-eval.",
            file_okay=True,
            dir_okay=False,
        ),
    ] = None,
    probes: Annotated[
        list[str] | None,
        typer.Option(
            "--probes",
            "-p",
            help="Glob over probe ids to include (e.g. 'ASI06-*'). Repeat or comma-separate.",
        ),
    ] = None,
    agents: Annotated[
        list[str] | None,
        typer.Option(
            "--agents",
            "-a",
            help="Substring filter over agent ids (e.g. 'react'). Repeatable.",
        ),
    ] = None,
    output_path: Annotated[
        Path,
        typer.Option(
            "--output",
            "-o",
            help="Output HTML report.",
            file_okay=True,
            dir_okay=False,
            writable=True,
        ),
    ] = Path("argos-eval.html"),
    json_path: Annotated[
        Path | None,
        typer.Option(
            "--json",
            "-j",
            help="Optional path for a JSON dump of the raw EvalReport.",
            file_okay=True,
            dir_okay=False,
            writable=True,
        ),
    ] = None,
    concurrency: Annotated[
        int,
        typer.Option(
            "--concurrency",
            "-c",
            help=f"Maximum concurrent (agent, probe) pairs. Default {DEFAULT_CONCURRENCY}.",
        ),
    ] = DEFAULT_CONCURRENCY,
    timeout_seconds: Annotated[
        float,
        typer.Option(
            "--timeout",
            help=f"Per-pair timeout in seconds. Default {DEFAULT_TIMEOUT_SECONDS}.",
        ),
    ] = DEFAULT_TIMEOUT_SECONDS,
    seed: Annotated[
        int,
        typer.Option(
            "--seed",
            help="Recorded on the report for reproducibility metadata.",
        ),
    ] = 0,
    quiet: Annotated[
        bool,
        typer.Option("--quiet", "-q", help="Suppress the summary table."),
    ] = False,
) -> None:
    """Run the lab benchmark and emit an HTML evaluation report."""
    err = get_err_console()

    # Resolve ground truth.
    if ground_truth_path is not None and not ground_truth_path.is_file():
        raise typer.BadParameter(f"{ground_truth_path} is not a file")
    try:
        gt = (
            default_ground_truth()
            if ground_truth_path is None
            else GroundTruth.from_yaml(ground_truth_path)
        )
    except Exception as exc:
        err.print(f"[argos.danger]ground truth error:[/] {exc}")
        raise typer.Exit(code=2) from exc

    # Resolve agent + probe selection.
    probe_globs: tuple[str, ...] | None = None
    if probes:
        probe_globs = tuple(p.strip() for spec in probes for p in spec.split(",") if p.strip())
    selected_probes = _select_probes(probe_globs)
    selected_agents = _select_agents(tuple(agents) if agents else None)

    if not selected_agents:
        err.print("[argos.danger]eval error:[/] no lab agents matched the filter.")
        raise typer.Exit(code=2)
    if not selected_probes:
        err.print("[argos.danger]eval error:[/] no probes matched the filter.")
        raise typer.Exit(code=2)

    # Validate the ground truth against the FULL catalogues, not the
    # selected slice: a YAML reference to ``ASI03-*`` is still a valid
    # cell when the user is only running ``ASI02-*`` -- the runner
    # simply skips it because no pair lands on that row. The selected
    # slice is what we actually execute; the validation is purely a
    # structural sanity check on the file.
    try:
        gt.validate_against(
            known_agents={a.agent_id for a in all_agents()},
            known_probes={p.probe_id for p in all_probes()},
        )
    except ValueError as exc:
        err.print(f"[argos.danger]ground truth mismatch:[/] {exc}")
        raise typer.Exit(code=2) from exc

    # Run the suite.
    try:
        report = run_suite(
            selected_agents,
            selected_probes,
            gt,
            concurrency=concurrency,
            timeout_seconds=timeout_seconds,
            seed=seed,
        )
    except Exception as exc:
        err.print(f"[argos.danger]suite execution failed:[/] {exc}")
        raise typer.Exit(code=2) from exc

    # Render the report.
    html = render_eval_html(report)
    output_path.write_text(html, encoding="utf-8")

    if json_path is not None:
        json_path.write_text(report.model_dump_json(indent=2), encoding="utf-8")

    if not quiet:
        _render_summary(report)

    cm = report.confusion_matrix()
    get_console().print(
        f"[argos.ok]eval written:[/] {output_path} "
        f"([argos.muted]{len(html):,} bytes; "
        f"{len(report.cases)} trials, {len(report.errored)} errored[/])",
    )

    # Exit code 0 when the lab is clean, 1 if any FP / FN appeared
    # (this hooks the command into CI: a regression flips the exit
    # code without flooding stderr).
    if cm.fp > 0 or cm.fn > 0:
        raise typer.Exit(code=1)


def _render_summary(report: EvalReport) -> None:
    """Print a compact rich summary table on stdout."""
    cm = report.confusion_matrix()
    table = Table(
        show_header=True,
        header_style="bold",
        title="ARGOS evaluation summary",
        title_style="argos.brand",
        expand=False,
    )
    table.add_column("Metric", no_wrap=True)
    table.add_column("Value", justify="right", no_wrap=True)
    table.add_row("trials", str(len(report.cases)))
    table.add_row("errored", str(len(report.errored)))
    table.add_row("TP", str(cm.tp))
    table.add_row("FP", str(cm.fp))
    table.add_row("TN", str(cm.tn))
    table.add_row("FN", str(cm.fn))
    table.add_row("precision", f"{precision(cm):.4f}")
    table.add_row("recall", f"{recall(cm):.4f}")
    table.add_row("F1", f"{f1_score(cm):.4f}")
    table.add_row("MCC", f"{matthews_correlation(cm):+.4f}")
    get_console().print(table)
