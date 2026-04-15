"""Supply-chain hygiene: pinning and auto-install behaviours."""

from __future__ import annotations

import re
from collections.abc import Iterable

from argos_core import Evidence, Finding, Severity, Target

from argos_scanner.models import MCPConfig, MCPServer
from argos_scanner.registry import register
from argos_scanner.rules._base import BaseRule

_NPX_AUTO_FLAGS: frozenset[str] = frozenset({"-y", "--yes", "--auto"})
_UVX_AUTO_FLAGS: frozenset[str] = frozenset({"--from", "--with"})
_PACKAGE_PATTERN = re.compile(r"^(?!-)[A-Za-z0-9@/_\-\.]+")
_PINNED_SUFFIX = re.compile(r"(@|==|~=|>=|<=)[A-Za-z0-9][A-Za-z0-9\-_\.]*$")
_DOCKER_IMAGE_TAG = re.compile(r"^[A-Za-z0-9][A-Za-z0-9\-_.\/]*:[A-Za-z0-9][A-Za-z0-9\-_.]*$")
_DOCKER_IMAGE_DIGEST = re.compile(r"@sha256:[A-Fa-f0-9]{64}$")


def _first_non_flag(args: tuple[str, ...], start: int = 0) -> str | None:
    for i in range(start, len(args)):
        if not args[i].startswith("-"):
            return args[i]
    return None


@register
class NpxAutoInstallRule(BaseRule):
    rule_id = "MCP-SEC-SUPPLY-NPX-AUTO"
    title = "npx downloads and runs an unpinned package automatically"
    severity = Severity.HIGH
    description = (
        "The server uses `npx` with `-y`/`--yes` on a package that is not "
        "pinned to a version. Every launch re-resolves the latest version "
        "from the public registry, so an attacker who takes over the package "
        "reaches the agent on the next start."
    )
    remediation = (
        "Pin the package to a specific version (`package@1.2.3`) and prefer "
        "a dedicated registry mirror where available."
    )
    compliance_refs = (
        "owasp_asi:ASI09",
        "owasp_asi:ASI09-01",
        "eu_ai_act:ART-15",
        "nist_ai_rmf:GV-6",
        "nist_ai_rmf:MG-3",
        "iso_42001:A.10.3",
        "csa_aicm:DSP-02",
    )
    tags = ("supply-chain", "npm")

    def scan_server(
        self,
        *,
        target: Target,
        config: MCPConfig,
        server: MCPServer,
    ) -> Iterable[Finding]:
        if not server.command or server.command.lower() != "npx":
            return ()
        has_auto = any(a in _NPX_AUTO_FLAGS for a in server.args)
        package = _first_non_flag(server.args)
        if not (has_auto and package):
            return ()
        if _PINNED_SUFFIX.search(package) or "#" in package:
            return ()
        return (
            self.build_finding(
                target=target,
                title=self.title,
                description=(
                    f"Server '{server.name}' invokes `npx -y {package}`; package is unpinned."
                ),
                evidence=(
                    Evidence(
                        kind="source-range",
                        summary=f"{server.name} unpinned npx package: {package}",
                        path=str(config.path),
                    ),
                ),
            ),
        )


@register
class UvxAutoInstallRule(BaseRule):
    rule_id = "MCP-SEC-SUPPLY-UVX-AUTO"
    title = "uvx downloads and runs an unpinned Python package automatically"
    severity = Severity.HIGH
    description = (
        "The server uses `uvx` to launch an unpinned PyPI package. Launching "
        "re-resolves the package on every start and trusts whatever the "
        "registry serves."
    )
    remediation = "Pin the package (`uvx package==1.2.3`) and consider a local index mirror."
    compliance_refs = (
        "owasp_asi:ASI09",
        "owasp_asi:ASI09-01",
        "nist_ai_rmf:GV-6",
        "iso_42001:A.10.3",
        "csa_aicm:DSP-02",
    )
    tags = ("supply-chain", "pypi")

    def scan_server(
        self,
        *,
        target: Target,
        config: MCPConfig,
        server: MCPServer,
    ) -> Iterable[Finding]:
        if not server.command or server.command.lower() not in {"uvx", "pipx"}:
            return ()
        package = _first_non_flag(server.args)
        if not package:
            return ()
        if _PINNED_SUFFIX.search(package) or "==" in package:
            return ()
        return (
            self.build_finding(
                target=target,
                title=self.title,
                description=(
                    f"Server '{server.name}' runs `{server.command} {package}`; "
                    "package is unpinned."
                ),
                evidence=(
                    Evidence(
                        kind="source-range",
                        summary=f"{server.name} unpinned package: {package}",
                        path=str(config.path),
                    ),
                ),
            ),
        )


@register
class DockerUnpinnedImageRule(BaseRule):
    rule_id = "MCP-SEC-SUPPLY-DOCKER-TAG"
    title = "Docker image is not pinned by digest"
    severity = Severity.MEDIUM
    description = (
        "The server runs a Docker image identified by a mutable tag (or no "
        "tag at all). Container registries allow tags to be retargeted; a "
        "digest (`image@sha256:...`) is the only reproducible reference."
    )
    remediation = "Pin the image by digest and refresh deliberately."
    compliance_refs = (
        "owasp_asi:ASI09",
        "nist_ai_rmf:GV-6",
        "iso_42001:A.10.3",
        "csa_aicm:DSP-02",
    )
    tags = ("supply-chain", "docker")

    def scan_server(
        self,
        *,
        target: Target,
        config: MCPConfig,
        server: MCPServer,
    ) -> Iterable[Finding]:
        if not server.command or server.command.lower() not in {"docker", "podman", "nerdctl"}:
            return ()
        if not server.args or server.args[0] != "run":
            return ()
        image = None
        for a in server.args[1:]:
            if not a.startswith("-"):
                image = a
                break
        if image is None:
            return ()
        if _DOCKER_IMAGE_DIGEST.search(image):
            return ()
        return (
            self.build_finding(
                target=target,
                title=self.title,
                description=(
                    f"Server '{server.name}' uses Docker image '{image}' without a digest pin."
                ),
                evidence=(
                    Evidence(
                        kind="source-range",
                        summary=f"{server.name} unpinned image: {image}",
                        path=str(config.path),
                    ),
                ),
            ),
        )
