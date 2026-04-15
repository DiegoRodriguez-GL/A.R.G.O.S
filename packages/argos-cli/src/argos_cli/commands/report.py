"""``argos report``: produce HTML / JSONL reports (implemented in M6)."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer

from argos_cli.commands._placeholder import not_implemented


def report(
    input_path: Annotated[
        Path | None,
        typer.Option("--input", "-i", help="Path to a JSONL findings file."),
    ] = None,
    output_path: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Output path for the rendered report."),
    ] = None,
    fmt: Annotated[
        str | None,
        typer.Option("--format", "-f", help="Output format: html or jsonl."),
    ] = None,
) -> None:
    """Render ARGOS findings into HTML or JSONL."""
    _ = (input_path, output_path, fmt)
    not_implemented("report", "Module 6")
