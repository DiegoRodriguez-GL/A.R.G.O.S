"""Detect dangerous shell patterns in server command lines."""

from __future__ import annotations

import re
from collections.abc import Iterable

from argos_core import Evidence, Finding, Severity, Target

from argos_scanner.models import MCPConfig, MCPServer
from argos_scanner.registry import register
from argos_scanner.rules._base import BaseRule

_PIPE_TO_SHELL = re.compile(
    r"\b(curl|wget|iwr|invoke-webrequest)\b.*\|\s*(bash|sh|zsh|pwsh|powershell)\b", re.IGNORECASE
)
_SHELL_INTERPRETERS: frozenset[str] = frozenset(
    {"bash", "sh", "zsh", "ksh", "dash", "pwsh", "powershell.exe", "cmd.exe"}
)
_DESTRUCTIVE = re.compile(
    r"(^|\s)("
    # rm -rf hitting root or a system directory (not /tmp, /opt/myapp, etc.)
    r"rm\s+-[rRfF]{1,2}\s+/(\s|$|etc\b|var\b|usr\b|bin\b|sbin\b|boot\b|"
    r"root\b|home\b|Users\b|lib\b|proc\b|sys\b|dev\b)"
    # chmod 777 on root or system dirs
    r"|chmod\s+-?R?\s*777\s+/(\s|$|etc\b|usr\b|bin\b|sbin\b|boot\b|root\b|home\b|opt\b|lib\b)"
    # mkfs on any filesystem type is always destructive
    r"|mkfs\.[A-Za-z0-9]+\b"
    # dd writing to a device node
    r"|dd\s+[^|&;]*\bof=/dev/"
    # fork bomb
    r"|:\(\)\s*\{\s*:\|:&\s*\}\s*;:"
    r")",
    re.IGNORECASE,
)
_EVAL_INTERP = re.compile(r"\beval\s*\(|\bexec\s*\(|`[^`]+`|\$\([^)]+\)")


def _joined(server: MCPServer) -> str:
    return " ".join(server.argv)


@register
class PipeToShellRule(BaseRule):
    rule_id = "MCP-SEC-SHELL-PIPE"
    title = "Command pipes untrusted output into a shell interpreter"
    severity = Severity.CRITICAL
    description = (
        "The server's command downloads content from the network and pipes it "
        "into a shell for execution (curl | sh). This gives the upstream "
        "total code-execution on the auditor's workstation every time the "
        "agent starts."
    )
    remediation = (
        "Install the server from a pinned package on a trusted registry, "
        "or include the script in the repository and review it."
    )
    compliance_refs = (
        "owasp_asi:ASI02",
        "owasp_asi:ASI09",
        "eu_ai_act:ART-15",
        "nist_ai_rmf:MS-2.6",
        "csa_aicm:DSP-02",
    )
    tags = ("shell", "rce")

    def scan_server(
        self,
        *,
        target: Target,
        config: MCPConfig,
        server: MCPServer,
    ) -> Iterable[Finding]:
        joined = _joined(server)
        if not _PIPE_TO_SHELL.search(joined):
            return ()
        return (
            self.build_finding(
                target=target,
                title=self.title,
                description=f"Server '{server.name}' command matches pipe-to-shell: {joined!r}",
                evidence=(
                    Evidence(
                        kind="source-range",
                        summary=f"{server.name} argv pipes to shell",
                        path=str(config.path),
                    ),
                ),
            ),
        )


@register
class ShellInterpreterCommandRule(BaseRule):
    rule_id = "MCP-SEC-SHELL-INTERPRETER"
    title = "Server command is a raw shell interpreter with inline script"
    severity = Severity.HIGH
    description = (
        "The server is launched as a shell interpreter (bash, sh, pwsh, ...) "
        "with an inline `-c` script. This pattern is indistinguishable from "
        "arbitrary code execution and defeats any pinning or provenance checks."
    )
    remediation = "Replace with a concrete executable or a versioned package."
    compliance_refs = (
        "owasp_asi:ASI02",
        "eu_ai_act:ART-15",
        "nist_ai_rmf:MS-2.6",
        "csa_aicm:AIS-06",
    )
    tags = ("shell", "rce")

    def scan_server(
        self,
        *,
        target: Target,
        config: MCPConfig,
        server: MCPServer,
    ) -> Iterable[Finding]:
        if not server.command:
            return ()
        if server.command.lower() not in _SHELL_INTERPRETERS:
            return ()
        if not any(a in {"-c", "/c"} for a in server.args):
            return ()
        return (
            self.build_finding(
                target=target,
                title=self.title,
                description=f"Server '{server.name}' uses {server.command} -c pattern.",
                evidence=(
                    Evidence(
                        kind="source-range",
                        summary=f"{server.name} argv={server.argv}",
                        path=str(config.path),
                    ),
                ),
            ),
        )


@register
class DestructiveCommandRule(BaseRule):
    rule_id = "MCP-SEC-SHELL-DESTRUCTIVE"
    title = "Server command contains a destructive shell pattern"
    severity = Severity.HIGH
    description = (
        "The server command contains a recognisable destructive pattern "
        "(rm -rf /, chmod 777 /, dd to a device, mkfs, ...). Even if harmless "
        "in context, these patterns should never ship in configuration files."
    )
    remediation = "Move dangerous maintenance scripts out of agent configuration entirely."
    compliance_refs = (
        "owasp_asi:ASI02",
        "nist_ai_rmf:MS-2.6",
        "iso_42001:A.6.2.6",
        "csa_aicm:AIS-06",
    )
    tags = ("shell", "destructive")

    def scan_server(
        self,
        *,
        target: Target,
        config: MCPConfig,
        server: MCPServer,
    ) -> Iterable[Finding]:
        joined = _joined(server)
        if not _DESTRUCTIVE.search(joined):
            return ()
        return (
            self.build_finding(
                target=target,
                title=self.title,
                description=(
                    f"Server '{server.name}' command matches a destructive pattern: {joined!r}"
                ),
                evidence=(
                    Evidence(
                        kind="source-range",
                        summary=f"{server.name} destructive pattern",
                        path=str(config.path),
                    ),
                ),
            ),
        )


@register
class ShellEvalInjectionRule(BaseRule):
    rule_id = "MCP-SEC-SHELL-EVAL"
    title = "Server command contains shell eval / command substitution"
    severity = Severity.MEDIUM
    description = (
        "The command uses eval, exec, backticks or $(...) substitution. "
        "These constructs evaluate arbitrary strings at launch time and "
        "turn any upstream input into code."
    )
    remediation = "Replace substitutions with static arguments."
    compliance_refs = (
        "owasp_asi:ASI02",
        "owasp_asi:ASI02-01",
        "csa_aicm:AIS-04",
    )
    tags = ("shell", "injection")

    def scan_server(
        self,
        *,
        target: Target,
        config: MCPConfig,
        server: MCPServer,
    ) -> Iterable[Finding]:
        joined = _joined(server)
        if not _EVAL_INTERP.search(joined):
            return ()
        return (
            self.build_finding(
                target=target,
                title=self.title,
                description=f"Server '{server.name}' argv contains eval/substitution: {joined!r}",
                evidence=(
                    Evidence(
                        kind="source-range",
                        summary=f"{server.name} eval substitution",
                        path=str(config.path),
                    ),
                ),
            ),
        )
