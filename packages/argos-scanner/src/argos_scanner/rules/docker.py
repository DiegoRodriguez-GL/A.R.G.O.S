"""Detect risky Docker flags in server command lines."""

from __future__ import annotations

import re
from collections.abc import Iterable

from argos_core import Evidence, Finding, Severity, Target

from argos_scanner.models import MCPConfig, MCPServer
from argos_scanner.registry import register
from argos_scanner.rules._base import BaseRule

_DOCKER_BINS: frozenset[str] = frozenset({"docker", "podman", "nerdctl"})
_HOST_MOUNT = re.compile(r"^(/|\$HOME|~|%USERPROFILE%|%HOMEPATH%)(:|/|$)")


def _is_docker(server: MCPServer) -> bool:
    return server.command is not None and server.command.lower() in _DOCKER_BINS


@register
class DockerPrivilegedRule(BaseRule):
    rule_id = "MCP-SEC-DOCKER-PRIVILEGED"
    title = "Docker server runs with --privileged"
    severity = Severity.CRITICAL
    description = (
        "The server invokes docker/podman with the `--privileged` flag. "
        "That grants the container full host capabilities, defeating the "
        "sandbox that justified running the server in a container at all."
    )
    remediation = "Drop --privileged and add only the capabilities the server actually needs."
    compliance_refs = (
        "owasp_asi:ASI03",
        "owasp_asi:ASI03-01",
        "eu_ai_act:ART-15",
        "nist_ai_rmf:MS-2.6",
        "iso_42001:A.6.2.6",
        "csa_aicm:IAM-01",
    )
    tags = ("docker", "sandbox")

    def scan_server(
        self,
        *,
        target: Target,
        config: MCPConfig,
        server: MCPServer,
    ) -> Iterable[Finding]:
        if not _is_docker(server):
            return ()
        privileged = any(a == "--privileged" or a.startswith("--privileged=") for a in server.args)
        if not privileged:
            return ()
        return (
            self.build_finding(
                target=target,
                title=self.title,
                description=f"Server '{server.name}' passes --privileged to {server.command}.",
                evidence=(
                    Evidence(
                        kind="source-range",
                        summary=f"{server.name} --privileged",
                        path=str(config.path),
                    ),
                ),
            ),
        )


@register
class DockerHostMountRule(BaseRule):
    rule_id = "MCP-SEC-DOCKER-HOST-MOUNT"
    title = "Docker server mounts the host filesystem at /"
    severity = Severity.CRITICAL
    description = (
        "The server mounts a top-level host path (`/`, `$HOME`, `%USERPROFILE%`) "
        "into the container. The agent now has read/write access to the "
        "operator's personal data and system files."
    )
    remediation = "Mount only the specific directory the server needs, read-only when possible."
    compliance_refs = (
        "owasp_asi:ASI03",
        "owasp_asi:ASI03-01",
        "eu_ai_act:ART-15",
        "nist_ai_rmf:MS-2.6",
        "iso_42001:A.7.5",
        "csa_aicm:IAM-01",
    )
    tags = ("docker", "sandbox")

    def scan_server(
        self,
        *,
        target: Target,
        config: MCPConfig,
        server: MCPServer,
    ) -> Iterable[Finding]:
        if not _is_docker(server):
            return ()
        findings: list[Finding] = []
        for i, arg in enumerate(server.args):
            if arg not in {"-v", "--volume", "--mount"}:
                continue
            if i + 1 >= len(server.args):
                continue
            spec = server.args[i + 1]
            # --mount uses "type=bind,source=/,..." syntax; -v uses "/:/container"
            src = spec.split(":", 1)[0] if arg in {"-v", "--volume"} else _mount_source(spec)
            if src and _HOST_MOUNT.match(src):
                findings.append(
                    self.build_finding(
                        target=target,
                        title=self.title,
                        description=f"Server '{server.name}' mounts '{src}' into the container.",
                        evidence=(
                            Evidence(
                                kind="source-range",
                                summary=f"{server.name} mount spec: {spec}",
                                path=str(config.path),
                            ),
                        ),
                    ),
                )
        return findings


def _mount_source(spec: str) -> str:
    for part in spec.split(","):
        k, _, v = part.partition("=")
        if k.strip() == "source":
            return v.strip()
    return ""


@register
class DockerHostNetworkRule(BaseRule):
    rule_id = "MCP-SEC-DOCKER-HOST-NET"
    title = "Docker server shares the host network"
    severity = Severity.HIGH
    description = (
        "`--network host` removes the network namespace boundary: the server "
        "can reach loopback services, bind privileged ports, and sniff local "
        "traffic. Equivalent to running without a sandbox."
    )
    remediation = "Use a dedicated bridge network or a port mapping."
    compliance_refs = (
        "owasp_asi:ASI03",
        "eu_ai_act:ART-15",
        "nist_ai_rmf:MS-2.6",
        "csa_aicm:IAM-01",
    )
    tags = ("docker", "network")

    def scan_server(
        self,
        *,
        target: Target,
        config: MCPConfig,
        server: MCPServer,
    ) -> Iterable[Finding]:
        if not _is_docker(server):
            return ()
        for i, arg in enumerate(server.args):
            if arg == "--network" and i + 1 < len(server.args) and server.args[i + 1] == "host":
                break
            if arg == "--network=host":
                break
        else:
            return ()
        return (
            self.build_finding(
                target=target,
                title=self.title,
                description=f"Server '{server.name}' uses --network host.",
                evidence=(
                    Evidence(
                        kind="source-range",
                        summary=f"{server.name} --network host",
                        path=str(config.path),
                    ),
                ),
            ),
        )
