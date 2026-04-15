"""Scanner engine: orchestrates built-in rules and optional YAML rules."""

from __future__ import annotations

from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path

from argos_core import Finding, ScanResult, Severity, Target
from argos_core.models.target import TargetKind
from argos_rules import evaluate_all as evaluate_yaml_rules
from argos_rules import load_rules_dir

from argos_scanner.parser import load as load_config
from argos_scanner.registry import all_rules, select
from argos_scanner.rules._base import BaseRule

_PRODUCER = "argos-scanner"


def scan(
    path: Path,
    *,
    rules: Iterable[str] | None = None,
    severity_floor: Severity | None = None,
    yaml_rules_dir: Path | None = None,
) -> ScanResult:
    """Scan a single MCP configuration file and return a :class:`ScanResult`.

    Args:
        path: Path to the configuration file.
        rules: Optional glob patterns over built-in rule ids. ``None`` runs
            every registered rule.
        severity_floor: Drop findings below this severity. ``None`` keeps all.
        yaml_rules_dir: Optional directory of YAML rule files (argos-rules DSL)
            to apply in addition to the built-in rules.
    """
    target = Target(kind=TargetKind.MCP_CONFIG, locator=str(path))
    started = datetime.now(UTC)
    config = load_config(path)

    selected: tuple[BaseRule, ...] = select(rules) if rules is not None else all_rules()

    findings: list[Finding] = []
    for rule in selected:
        findings.extend(rule.scan(target=target, artefact=config))

    if yaml_rules_dir is not None:
        yaml_rules = load_rules_dir(yaml_rules_dir)
        findings.extend(evaluate_yaml_rules(yaml_rules, config))

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
