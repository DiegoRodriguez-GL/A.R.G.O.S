"""Render a :class:`argos_core.ScanResult` into a self-contained HTML
report that follows the ARGOS design system.

The output is a single HTML file: no external CSS, no external fonts,
no external scripts. It is safe to email, archive, print to PDF via
Gotenberg or a browser, and open offline. Content-Security-Policy is
``default-src 'none'`` with only ``style-src 'unsafe-inline'`` for the
inlined ``<style>`` block, inherited from ``base.html.j2``.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime
from typing import Final

from argos_core import Finding, ScanResult, Severity

from argos_reporter.html import build_env

_SEVERITY_LABELS: Final[dict[Severity, str]] = {
    Severity.CRITICAL: "Criticas",
    Severity.HIGH: "Altas",
    Severity.MEDIUM: "Medias",
    Severity.LOW: "Bajas",
    Severity.INFO: "Info",
}

_SEVERITY_DISPLAY_ORDER: Final[tuple[Severity, ...]] = (
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
)

_FRAMEWORKS: Final[tuple[dict[str, str], ...]] = (
    {"key": "nist_ai_rmf", "label": "NIST AI RMF"},
    {"key": "eu_ai_act", "label": "EU AI Act"},
    {"key": "csa_aicm", "label": "CSA AICM"},
    {"key": "iso_42001", "label": "ISO/IEC 42001"},
)

_ASI_TITLES: Final[dict[str, str]] = {
    "ASI01": "Memory Poisoning",
    "ASI02": "Tool Misuse",
    "ASI03": "Privilege Compromise",
    "ASI04": "Resource Overload",
    "ASI05": "Cascading Hallucination",
    "ASI06": "Intent Breaking",
    "ASI07": "Deceptive Behaviour",
    "ASI08": "Repudiation",
    "ASI09": "Identity Spoofing",
    "ASI10": "HITL Overwhelm",
}


def _severity_key(sev: Severity) -> str:
    """CSS class suffix used by the templates (``sev-critical`` etc.)."""
    return sev.value


def _format_date_human(dt: datetime) -> str:
    """Locale-neutral date for the cover page (``23 April 2026``)."""
    # Using the default English locale keeps renders deterministic across
    # platforms (the TFM demo must read the same in any machine).
    return dt.strftime("%d %B %Y")


def _asi_category_of(finding: Finding) -> str | None:
    """Extract the ASI top-level code from the rule id.

    The red-team catalogue uses ``ASI##-DETAIL-SLUG`` and the scanner
    catalogue uses ``MCP-SEC-*`` plus a cross-reference in
    ``compliance_refs``. We look at the compliance refs first; when an
    ``owasp_asi:ASI##`` reference is present we take its top-level code.
    """
    for ref in finding.compliance_refs:
        if not ref.startswith("owasp_asi:"):
            continue
        code = ref.split(":", 1)[1]
        # Top-level is always the first ``ASI##`` token.
        head = code.split("-", 1)[0]
        if head.startswith("ASI") and len(head) == 5:
            return head
    # Fallback: parse the rule_id head.
    head = finding.rule_id.split("-", 1)[0]
    if head.startswith("ASI") and len(head) == 5:
        return head
    return None


def _build_category_rows(findings: tuple[Finding, ...]) -> list[dict[str, object]]:
    bucket: dict[str, dict[Severity, int]] = defaultdict(
        lambda: dict.fromkeys(Severity, 0),
    )
    for f in findings:
        code = _asi_category_of(f) or "OTHER"
        bucket[code][f.severity] += 1
    rows: list[dict[str, object]] = []
    # Emit rows in canonical ASI order + OTHER at the end when present.
    for code in [*_ASI_TITLES, "OTHER"]:
        counts = bucket.get(code)
        if not counts or sum(counts.values()) == 0:
            continue
        title = _ASI_TITLES.get(code, "Other / unmapped")
        rows.append(
            {
                "label": f"{code} {title}",
                "total": sum(counts.values()),
                "by_severity": {s.value: counts[s] for s in Severity},
            },
        )
    return rows


def _build_compliance_matrix(findings: tuple[Finding, ...]) -> list[dict[str, object]]:
    """For each ASI row and each framework column, collect the set of
    control codes that fired through any finding cited under that
    combination. Cell state is ``hit`` when at least one control was
    cited, ``miss`` otherwise. (Partial is reserved for a future
    similarity pass; the current engine emits only full hits.)"""
    seen: dict[str, dict[str, set[str]]] = {
        code: {fw["key"]: set() for fw in _FRAMEWORKS} for code in _ASI_TITLES
    }
    for f in findings:
        asi = _asi_category_of(f)
        if asi is None or asi not in seen:
            continue
        for ref in f.compliance_refs:
            if ":" not in ref:
                continue
            framework, control = ref.split(":", 1)
            if framework in seen[asi]:
                seen[asi][framework].add(control)

    rows: list[dict[str, object]] = []
    for asi in _ASI_TITLES:
        cells: list[dict[str, object]] = []
        for fw in _FRAMEWORKS:
            controls = sorted(seen[asi][fw["key"]])
            cells.append(
                {
                    "state": "hit" if controls else "miss",
                    "controls": controls,
                },
            )
        rows.append({"asi": asi, "label": _ASI_TITLES[asi], "cells": cells})
    return rows


def _infer_target_kind_label(result: ScanResult) -> str:
    mapping = {
        "mcp-config": "MCP configuration",
        "mcp-server": "MCP server",
        "agent-http": "Agent HTTP endpoint",
        "agent-langgraph": "LangGraph agent",
        "filesystem": "Filesystem",
    }
    return mapping.get(result.target.kind.value, result.target.kind.value)


def _infer_title(result: ScanResult) -> tuple[str, str | None]:
    """Choose a sensible title / subtitle from the result metadata.

    Red-team runs are titled differently from scanner runs so a reviewer
    can tell them apart at a glance, without needing to read the body.
    """
    if result.producer.startswith("argos-redteam"):
        return ("Agent Security Audit", "OWASP ASI red-team run")
    if result.producer.startswith("argos-scanner"):
        return ("MCP Configuration Audit", "Static analysis")
    return ("ARGOS Audit Report", None)


def render_html(
    result: ScanResult,
    *,
    generator_version: str = "0.0.1",
) -> str:
    """Render ``result`` as a single self-contained HTML document."""
    env = build_env()
    template = env.get_template("report.html.j2")

    severity_counts = result.count_by_severity()
    worst = result.max_severity()
    severity_order = [
        (_SEVERITY_LABELS[s], _severity_key(s), severity_counts.get(s, 0))
        for s in _SEVERITY_DISPLAY_ORDER
    ]
    findings_sorted = tuple(
        sorted(result.findings, key=lambda f: (-f.severity.rank, f.rule_id, f.id)),
    )
    report_title, report_subtitle = _infer_title(result)

    toc_entries = [
        {"num": "1.", "title": "Resumen de la auditoria"},
        {"num": "2.", "title": "Resumen ejecutivo"},
        {"num": "3.", "title": "Matriz de compliance cruzada"},
        {"num": "4.", "title": "Indice de hallazgos"},
        {"num": "5.", "title": "Detalle de hallazgos"},
        {"num": "6.", "title": "Apendice metodologico"},
    ]

    return template.render(
        report_title=report_title,
        report_subtitle=report_subtitle,
        target_kind=_infer_target_kind_label(result),
        target_locator=result.target.locator,
        producer=result.producer,
        methodology_version=result.methodology_version,
        started_at=result.started_at,
        finished_at=result.finished_at,
        duration_seconds=result.duration_seconds,
        generated_at=result.finished_at,
        generated_at_human=_format_date_human(result.finished_at),
        run_id=result.run_id,
        finding_total=len(result.findings),
        severity_order=severity_order,
        worst_severity=(worst.value.upper() if worst else None),
        category_rows=_build_category_rows(result.findings),
        no_findings=not result.findings,
        frameworks=list(_FRAMEWORKS),
        matrix_rows=_build_compliance_matrix(result.findings),
        findings=findings_sorted,
        severity_key=_severity_key,
        toc_entries=toc_entries,
        generator_version=generator_version,
        lang="es",
    )
