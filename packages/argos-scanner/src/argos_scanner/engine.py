"""Scanner engine: orchestrates rule execution over an MCP config."""

from __future__ import annotations

from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path

from argos_core import Finding, ScanResult, Severity, Target
from argos_core.models.target import TargetKind

from argos_scanner.parser import load as load_config
from argos_scanner.registry import all_rules, select
from argos_scanner.rules._base import BaseRule

_PRODUCER = "argos-scanner"


def scan(
    path: Path,
    *,
    rules: Iterable[str] | None = None,
    severity_floor: Severity | None = None,
) -> ScanResult:
    """Scan a single MCP configuration file and return a :class:`ScanResult`.

    Args:
        path: Path to the configuration file.
        rules: Optional glob patterns over rule ids (``MCP-SEC-*``). ``None``
            runs every registered rule.
        severity_floor: Drop findings below this severity. ``None`` keeps all.
    """
    target = Target(kind=TargetKind.MCP_CONFIG, locator=str(path))
    started = datetime.now(UTC)
    config = load_config(path)

    selected: tuple[BaseRule, ...] = select(rules) if rules is not None else all_rules()

    findings: list[Finding] = []
    for rule in selected:
        findings.extend(rule.scan(target=target, artefact=config))

    if severity_floor is not None:
        findings = [f for f in findings if f.severity >= severity_floor]

    finished = datetime.now(UTC)
    return ScanResult(
        target=target,
        producer=_PRODUCER,
        started_at=started,
        finished_at=finished,
        findings=tuple(findings),
    )
