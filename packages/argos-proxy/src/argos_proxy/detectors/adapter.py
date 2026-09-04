"""Translate proxy :class:`DetectorFinding` rows into :class:`argos_core.Finding`.

The proxy keeps its own lightweight finding shape on the hot path
(correlation id, direction, JSON-RPC request id) because the wire
contract differs from the static pipeline. When an operator wants a
unified report -- ``argos report`` over proxy and callback captures --
the rows are lifted into the shared model here.

Each detector maps to one OWASP ASI category (February 2025 T1-T10
numbering, see ``docs/asi-taxonomy-crossref.md``); the remaining
cross-framework references are resolved from the M1 mapping graph so
the adapter never hard-codes CSA / EU / NIST / ISO ids that could drift
from the data files.
"""

from __future__ import annotations

from typing import Final

from argos_core import Evidence, Finding, Severity, Target, TargetKind
from argos_core.compliance import load_controls

from argos_proxy.detectors._base import DetectorFinding

#: detector_id -> (rule id prefix, ASI top-level control, title)
_DETECTOR_PROFILE: Final[dict[str, tuple[str, str, str]]] = {
    # Tool rug-pull: the canonical ASI02 Tool Misuse pattern.
    "argos.proxy.tool_drift": ("PROXY-TOOL-DRIFT", "owasp_asi:ASI02", "Tool definition drift"),
    # Personal data crossing the tool boundary is exfiltration through
    # tools (ASI02) rather than a model-level leak.
    "argos.proxy.pii": ("PROXY-PII-EXPOSURE", "owasp_asi:ASI02", "Personal data in MCP traffic"),
    # Calling a tool outside the declared scope is privilege compromise.
    "argos.proxy.scope": ("PROXY-SCOPE-VIOLATION", "owasp_asi:ASI03", "Out-of-scope tool call"),
}

_SEVERITY: Final[dict[str, Severity]] = {
    "INFO": Severity.INFO,
    "LOW": Severity.LOW,
    "MEDIUM": Severity.MEDIUM,
    "HIGH": Severity.HIGH,
    "CRITICAL": Severity.CRITICAL,
}


def compliance_refs_for(detector_id: str) -> tuple[str, ...]:
    """ASI control plus every cross-framework target the M1 graph maps it to."""
    profile = _DETECTOR_PROFILE.get(detector_id)
    if profile is None:
        return ()
    asi_qid = profile[1]
    index = load_controls()
    refs: list[str] = [asi_qid]
    for entry in index.mappings_for(asi_qid):
        if entry.source != asi_qid:
            continue
        for target in entry.targets:
            if target not in refs:
                refs.append(target)
    return tuple(refs)


def to_core_finding(
    finding: DetectorFinding,
    *,
    target: Target | None = None,
    producer: str = "argos-proxy",
) -> Finding:
    """Lift one proxy finding into the shared :class:`argos_core.Finding` model."""
    profile = _DETECTOR_PROFILE.get(finding.detector_id)
    if profile is None:
        rule_prefix = "PROXY-" + finding.detector_id.rsplit(".", 1)[-1].upper().replace("_", "-")
        title = finding.detector_id
    else:
        rule_prefix, _, title = profile
    evidence = Evidence(
        kind="trace",
        summary=finding.message,
        trace_id=finding.correlation_id,
        span_id=str(finding.request_id) if finding.request_id is not None else None,
        blob=repr(finding.evidence) if finding.evidence else None,
    )
    return Finding(
        rule_id=rule_prefix,
        title=title,
        description=(
            f"{finding.message} (direction={finding.direction}, "
            f"method={finding.method or 'n/a'}, correlation={finding.correlation_id})"
        ),
        severity=_SEVERITY[finding.severity],
        target=target
        or Target(kind=TargetKind.MCP_SERVER, locator=f"proxy:{finding.correlation_id}"),
        evidence=(evidence,),
        compliance_refs=compliance_refs_for(finding.detector_id),
        producer=producer,
    )


__all__ = ["compliance_refs_for", "to_core_finding"]
