"""Broad cloud/credential exposure checks beyond the secret patterns."""

from __future__ import annotations

from collections.abc import Iterable

from argos_core import Evidence, Finding, Severity, Target

from argos_scanner.models import MCPConfig, MCPServer
from argos_scanner.registry import register
from argos_scanner.rules._base import BaseRule

_SENSITIVE_ENV_PREFIXES: tuple[str, ...] = (
    "AWS_",
    "AZURE_",
    "GCP_",
    "GOOGLE_",
    "OPENAI_",
    "ANTHROPIC_",
    "HUGGINGFACE_",
    "HF_",
    "STRIPE_",
    "SLACK_",
    "GITHUB_",
    "GITLAB_",
)


@register
class SensitiveEnvExposureRule(BaseRule):
    rule_id = "MCP-SEC-ENV-SENSITIVE-KEY"
    title = "Server env declares a sensitive-looking key"
    severity = Severity.MEDIUM
    description = (
        "The server declares an env key matching a well-known sensitive "
        "prefix (AWS_, OPENAI_, GITHUB_, ...). Even if the value is empty "
        "or a placeholder today, the key will be populated at runtime and "
        "exposed to whatever process the server launches. Review whether "
        "the server actually needs that credential."
    )
    remediation = (
        "Remove the env declaration if the server does not require the "
        "credential, or scope the credential with a token that has the "
        "minimum necessary permissions."
    )
    compliance_refs = (
        "owasp_asi:ASI03",
        "owasp_asi:ASI03-01",
        "csa_aicm:IAM-01",
        "nist_ai_rmf:GV-6",
        "iso_42001:A.6.2.6",
    )
    tags = ("iam", "env")

    def scan_server(
        self,
        *,
        target: Target,
        config: MCPConfig,
        server: MCPServer,
    ) -> Iterable[Finding]:
        flagged = sorted(
            k for k in server.env if any(k.startswith(p) for p in _SENSITIVE_ENV_PREFIXES)
        )
        if not flagged:
            return ()
        return (
            self.build_finding(
                target=target,
                title=self.title,
                description=(
                    f"Server '{server.name}' declares sensitive env keys: {', '.join(flagged)}."
                ),
                evidence=(
                    Evidence(
                        kind="source-range",
                        summary=f"{server.name} sensitive env keys",
                        path=str(config.path),
                    ),
                ),
            ),
        )


@register
class RemoteHeaderBearerRule(BaseRule):
    rule_id = "MCP-SEC-REMOTE-BEARER-HARDCODED"
    title = "Remote server pins a bearer token in a header"
    severity = Severity.HIGH
    description = (
        "A remote server carries an `Authorization` header with a literal "
        "bearer token in the configuration. Token rotates every commit and "
        "is exposed to every reader of the repository."
    )
    remediation = "Reference the token via a placeholder resolved at runtime from a secret store."
    compliance_refs = (
        "owasp_asi:ASI03",
        "owasp_asi:ASI03-02",
        "eu_ai_act:ART-15",
        "csa_aicm:IAM-01",
    )
    tags = ("iam", "headers")

    def scan_server(
        self,
        *,
        target: Target,
        config: MCPConfig,
        server: MCPServer,
    ) -> Iterable[Finding]:
        for key, value in server.headers.items():
            if key.lower() != "authorization":
                continue
            stripped = value.strip()
            if not stripped.lower().startswith("bearer "):
                continue
            token = stripped.split(" ", 1)[1] if " " in stripped else ""
            if not token or token.startswith(("${", "$(")):
                continue
            return (
                self.build_finding(
                    target=target,
                    title=self.title,
                    description=(
                        f"Server '{server.name}' Authorization header embeds a literal "
                        "bearer token."
                    ),
                    evidence=(
                        Evidence(
                            kind="source-range",
                            summary=f"{server.name} literal bearer",
                            path=str(config.path),
                        ),
                    ),
                ),
            )
        return ()
