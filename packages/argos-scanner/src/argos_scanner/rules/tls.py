"""Detect remote MCP servers reached over plaintext HTTP."""

from __future__ import annotations

from collections.abc import Iterable
from urllib.parse import urlparse

from argos_core import Evidence, Finding, Severity, Target

from argos_scanner.models import MCPConfig, MCPServer
from argos_scanner.registry import register
from argos_scanner.rules._base import BaseRule

_LOOPBACK_HOSTS: frozenset[str] = frozenset({"localhost", "127.0.0.1", "::1"})


@register
class PlaintextRemoteTransportRule(BaseRule):
    rule_id = "MCP-SEC-TLS-PLAINTEXT"
    title = "Remote MCP server reached over plaintext HTTP"
    severity = Severity.HIGH
    description = (
        "The server is configured with an `http://` URL that resolves to a "
        "non-loopback host. Anyone on the path between the agent and the "
        "server can read prompts, tool arguments and responses, and inject "
        "messages into the stream."
    )
    remediation = "Switch to HTTPS (or SSE over HTTPS) and verify the server's certificate."
    compliance_refs = (
        "owasp_asi:ASI03",
        "owasp_asi:ASI09",
        "eu_ai_act:ART-15",
        "nist_ai_rmf:MS-2.6",
        "iso_42001:A.6.2.8",
        "csa_aicm:AIS-06",
    )
    tags = ("tls", "network")

    def scan_server(
        self,
        *,
        target: Target,
        config: MCPConfig,
        server: MCPServer,
    ) -> Iterable[Finding]:
        if not server.url:
            return ()
        parsed = urlparse(server.url)
        if parsed.scheme != "http":
            return ()
        host = (parsed.hostname or "").lower()
        if host in _LOOPBACK_HOSTS:
            return ()
        return (
            self.build_finding(
                target=target,
                title=self.title,
                description=(
                    f"Server '{server.name}' uses URL '{server.url}' over plaintext "
                    f"HTTP to non-loopback host '{host}'."
                ),
                evidence=(
                    Evidence(
                        kind="source-range",
                        summary=f"{server.name}.url={server.url}",
                        path=str(config.path),
                    ),
                ),
            ),
        )
