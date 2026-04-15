"""Base class for built-in MCP scanner rules.

Rules are stateless. ``scan_server`` is the hot path; returning an empty tuple
means the server is clean for this rule. Rules that need to inspect the full
config (cross-server correlations) override ``scan_config`` instead.
"""

from __future__ import annotations

from abc import abstractmethod
from collections.abc import Iterable

from argos_core import Evidence, Finding, Severity, Target
from argos_core.interfaces import IScanner, PluginMetadata

from argos_scanner.models import MCPConfig, MCPServer

_PRODUCER = "argos-scanner"


class BaseRule(IScanner):
    """Common plumbing for ARGOS scanner rules."""

    rule_id: str
    title: str
    severity: Severity
    description: str
    remediation: str | None = None
    compliance_refs: tuple[str, ...] = ()
    tags: tuple[str, ...] = ()

    def metadata(self) -> PluginMetadata:
        owasp_asi = tuple(r for r in self.compliance_refs if r.startswith("owasp_asi:"))
        return PluginMetadata(
            name=self.rule_id,
            version="0.0.1",
            kind="scanner-rule",
            description=self.title,
            owasp_asi=owasp_asi,
        )

    # IScanner contract ---------------------------------------------------
    def scan(self, *, target: Target, artefact: object) -> Iterable[Finding]:
        if not isinstance(artefact, MCPConfig):
            return ()
        return self.scan_config(target=target, config=artefact)

    # Rule-specific overrides --------------------------------------------
    def scan_config(self, *, target: Target, config: MCPConfig) -> Iterable[Finding]:
        findings: list[Finding] = []
        for server in config.servers:
            findings.extend(self.scan_server(target=target, config=config, server=server))
        return findings

    @abstractmethod
    def scan_server(
        self,
        *,
        target: Target,
        config: MCPConfig,
        server: MCPServer,
    ) -> Iterable[Finding]: ...

    # Convenience builder -------------------------------------------------
    def build_finding(
        self,
        *,
        target: Target,
        title: str,
        description: str,
        evidence: tuple[Evidence, ...],
        severity: Severity | None = None,
    ) -> Finding:
        return Finding(
            rule_id=self.rule_id,
            title=title,
            description=description,
            severity=severity or self.severity,
            target=target,
            evidence=evidence,
            compliance_refs=self.compliance_refs,
            remediation=self.remediation,
            producer=_PRODUCER,
        )
