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


#: npx options that take a value. The value of ``--package``/``-p`` is the
#: package that gets installed; the first positional is only the binary.
_NPX_VALUE_FLAGS: frozenset[str] = frozenset(
    {
        "--package",
        "-p",
        "--cache",
        "--registry",
        "--userconfig",
        "--call",
        "-c",
        "--workspace",
        "-w",
    },
)
#: uvx options that take a value. ``--from`` names the package that gets
#: installed; ``--with`` adds dependencies and is not the package itself.
_UVX_VALUE_FLAGS: frozenset[str] = frozenset(
    {
        "--from",
        "--with",
        "--with-requirements",
        "--with-editable",
        "--python",
        "-p",
        "--index",
        "--index-url",
        "--extra-index-url",
        "--default-index",
        "--find-links",
        "-f",
        "--constraint",
        "-c",
        "--override",
        "--directory",
        "--cache-dir",
        "--config-file",
    },
)


def _first_non_flag(args: tuple[str, ...], start: int = 0) -> str | None:
    for i in range(start, len(args)):
        if not args[i].startswith("-"):
            return args[i]
    return None


def _split_launcher_args(
    args: tuple[str, ...],
    value_flags: frozenset[str],
) -> tuple[dict[str, list[str]], str | None]:
    """Walk launcher arguments the way the launcher does.

    Returns the options seen before the first positional (flag -> values,
    ``--flag=value`` and ``--flag value`` alike) and that positional.
    """
    options: dict[str, list[str]] = {}
    i = 0
    while i < len(args):
        arg = args[i]
        if not arg.startswith("-"):
            return options, arg
        name, eq, inline = arg.partition("=")
        if eq:
            options.setdefault(name, []).append(inline)
        elif name in value_flags and i + 1 < len(args):
            options.setdefault(name, []).append(args[i + 1])
            i += 1
        else:
            options.setdefault(name, [])
        i += 1
    return options, None


def _is_local_spec(spec: str) -> bool:
    return spec.startswith((".", "/", "~", "file:")) or "\\" in spec


def _npm_spec_pinned(spec: str) -> bool:
    return bool(_PINNED_SUFFIX.search(spec)) or "#" in spec or _is_local_spec(spec)


def _python_spec_pinned(spec: str) -> bool:
    return (
        "==" in spec
        or "@" in spec  # ``pkg@1.2.3`` and ``pkg @ git+...@ref``
        or bool(_PINNED_SUFFIX.search(spec))
        or _is_local_spec(spec)
    )


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
        options, first = _split_launcher_args(server.args, _NPX_VALUE_FLAGS)
        has_auto = any(flag in options for flag in _NPX_AUTO_FLAGS)
        # With --package/-p the installed package is named there and the
        # positional is only the binary to run from it.
        specs = [*options.get("--package", []), *options.get("-p", [])]
        if not specs and first:
            specs = [first]
        unpinned = [spec for spec in specs if not _npm_spec_pinned(spec)]
        if not (has_auto and unpinned):
            return ()
        package = unpinned[0]
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
        args = server.args
        if server.command.lower() == "pipx" and args[:1] == ("run",):
            args = args[1:]
        options, first = _split_launcher_args(args, _UVX_VALUE_FLAGS)
        # ``uvx --from pkg cmd`` installs ``pkg`` and runs its ``cmd``.
        from_specs = options.get("--from", [])
        package = from_specs[0] if from_specs else first
        if not package or _python_spec_pinned(package):
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
