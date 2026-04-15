"""Detect filesystem-server configurations that grant broad access."""

from __future__ import annotations

from collections.abc import Iterable

from argos_core import Evidence, Finding, Severity, Target

from argos_scanner.models import MCPConfig, MCPServer
from argos_scanner.registry import register
from argos_scanner.rules._base import BaseRule

_DANGEROUS_ROOTS: frozenset[str] = frozenset(
    {
        "/",
        "/etc",
        "/usr",
        "/var",
        "/root",
        "/home",
        "/mnt",
        "/Users",
        "C:\\",
        "C:/",
        "C:\\Users",
        "$HOME",
        "~",
        "~/",
        "%USERPROFILE%",
        "%HOMEPATH%",
    },
)

_FILESYSTEM_SERVER_TOKENS: frozenset[str] = frozenset(
    {
        "@modelcontextprotocol/server-filesystem",
        "mcp-server-filesystem",
        "server-filesystem",
        "@mcp/server-filesystem",
    },
)


def _targets_filesystem_server(server: MCPServer) -> bool:
    haystack = " ".join(server.argv).lower()
    return any(tok in haystack for tok in _FILESYSTEM_SERVER_TOKENS)


@register
class FilesystemRootAccessRule(BaseRule):
    rule_id = "MCP-SEC-FS-ROOT"
    title = "Filesystem server granted top-level host path"
    severity = Severity.HIGH
    description = (
        "A `server-filesystem`-style entry exposes a top-level host directory "
        "(`/`, `$HOME`, `C:\\`, `/etc`, ...) to the agent. Any path traversal "
        "or prompt-injection bug now reads or writes the operator's entire "
        "workstation."
    )
    remediation = (
        "Scope the filesystem server to a project-specific directory and use "
        "read-only mounts where possible."
    )
    compliance_refs = (
        "owasp_asi:ASI03",
        "owasp_asi:ASI03-01",
        "eu_ai_act:ART-15",
        "nist_ai_rmf:MS-2.6",
        "iso_42001:A.7.5",
        "csa_aicm:IAM-01",
    )
    tags = ("filesystem", "scope")

    def scan_server(
        self,
        *,
        target: Target,
        config: MCPConfig,
        server: MCPServer,
    ) -> Iterable[Finding]:
        if not _targets_filesystem_server(server):
            return ()
        return tuple(
            self.build_finding(
                target=target,
                title=self.title,
                description=(
                    f"Server '{server.name}' grants the filesystem server access to '{arg}'."
                ),
                evidence=(
                    Evidence(
                        kind="source-range",
                        summary=f"{server.name} filesystem root: {arg}",
                        path=str(config.path),
                    ),
                ),
            )
            for arg in server.args
            if arg in _DANGEROUS_ROOTS or arg.rstrip("/") in _DANGEROUS_ROOTS
        )
