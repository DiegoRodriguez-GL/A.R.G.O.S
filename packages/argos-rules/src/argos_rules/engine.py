"""Evaluate :class:`Rule` documents against an MCP configuration.

The output is a tuple of :class:`argos_core.Finding` identical in shape to
what the built-in scanner produces, so the reporter and compliance matrix
treat YAML-authored findings as first-class citizens.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import TYPE_CHECKING

from argos_core import Evidence, Finding, Target

from argos_rules.extractors import run_extractor
from argos_rules.matchers import evaluate_matcher
from argos_rules.models import Rule
from argos_rules.selectors import explain, select

if TYPE_CHECKING:  # pragma: no cover
    from argos_scanner.models import MCPConfig


_PRODUCER = "argos-rules"


def _evaluate_server(rule: Rule, config: MCPConfig, server_index: int) -> Finding | None:
    server = config.servers[server_index]

    # Each matcher's verdict.
    matcher_fires: list[bool] = []
    matched_parts: list[tuple[str, list[str]]] = []
    for m in rule.matchers:
        parts = select(config, server, m.part)
        fired = evaluate_matcher(m, parts)
        matcher_fires.append(fired)
        if fired:
            matched_parts.append((m.part, parts))

    combined = all(matcher_fires) if rule.matchers_condition == "and" else any(matcher_fires)
    if not combined:
        return None

    # Extract concrete evidence snippets, if any extractors are declared.
    captured: list[str] = []
    for ex in rule.extractors:
        parts = select(config, server, ex.part)
        captured.extend(run_extractor(ex, parts))

    evidence: tuple[Evidence, ...] = (
        Evidence(
            kind="source-range",
            summary=(
                f"{server.name}: "
                + explain([f"{part}={explain(hits)}" for part, hits in matched_parts])
            ),
            path=str(config.path),
            blob="\n".join(captured) if captured else None,
        ),
    )

    target = Target(kind="mcp-config", locator=str(config.path))  # type: ignore[arg-type]
    return Finding(
        rule_id=rule.id,
        title=rule.info.name,
        description=rule.info.description or rule.info.name,
        severity=rule.info.severity,
        target=target,
        evidence=evidence,
        compliance_refs=rule.info.compliance,
        remediation=rule.info.remediation,
        producer=_PRODUCER,
    )


def evaluate(rule: Rule, config: MCPConfig) -> tuple[Finding, ...]:
    """Apply ``rule`` to every server in ``config``. Yields 0..N findings."""
    findings: list[Finding] = []
    for idx in range(len(config.servers)):
        finding = _evaluate_server(rule, config, idx)
        if finding is not None:
            findings.append(finding)
    return tuple(findings)


def evaluate_all(rules: Iterable[Rule], config: MCPConfig) -> tuple[Finding, ...]:
    """Apply every rule to the config and collect all findings."""
    findings: list[Finding] = []
    for rule in rules:
        findings.extend(evaluate(rule, config))
    return tuple(findings)
