"""Detect hardcoded secrets in server env blocks.

Two complementary checks:

1. ``MCP-SEC-SECRET-PATTERN``: regex match against well-known credential
   formats (GitHub PATs, Slack, Stripe, OpenAI, AWS access keys, JWT, ...).
2. ``MCP-SEC-SECRET-ENTROPY``: Shannon entropy on long opaque values.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from collections.abc import Iterable

from argos_core import Evidence, Finding, Severity, Target

from argos_scanner.models import MCPConfig, MCPServer
from argos_scanner.registry import register
from argos_scanner.rules._base import BaseRule

_SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("github-pat", re.compile(r"\bghp_[A-Za-z0-9]{30,}\b")),
    ("github-oauth", re.compile(r"\bgho_[A-Za-z0-9]{30,}\b")),
    ("github-app", re.compile(r"\b(ghu|ghs|ghr)_[A-Za-z0-9]{30,}\b")),
    ("github-fine-grained", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{60,}\b")),
    ("slack-token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("stripe-live", re.compile(r"\bsk_live_[A-Za-z0-9]{24,}\b")),
    ("stripe-test", re.compile(r"\bsk_test_[A-Za-z0-9]{24,}\b")),
    ("openai-key", re.compile(r"\bsk-[A-Za-z0-9]{20,}\b")),
    ("anthropic-key", re.compile(r"\bsk-ant-[A-Za-z0-9\-_]{20,}\b")),
    ("aws-access-key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("aws-temp-key", re.compile(r"\bASIA[0-9A-Z]{16}\b")),
    ("google-api-key", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9\-_]{8,}\.[A-Za-z0-9\-_]{8,}\.[A-Za-z0-9\-_]{8,}\b")),
    (
        "private-key-pem",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----"),
    ),
)

_ENTROPY_MIN_LENGTH = 20
_ENTROPY_THRESHOLD = 4.0  # bits/char; opaque tokens typically score 4.5+
_PLACEHOLDER_VALUES: frozenset[str] = frozenset(
    {
        "",
        "xxx",
        "your-key-here",
        "your-api-key",
        "changeme",
        "placeholder",
        "example",
        "dummy",
        "fake",
        "test",
        "secret",
        "password",
    },
)


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    total = len(s)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


@register
class HardcodedSecretPatternRule(BaseRule):
    rule_id = "MCP-SEC-SECRET-PATTERN"
    title = "Hardcoded secret detected in server env"
    severity = Severity.CRITICAL
    description = (
        "A value under the server's `env` block matches a well-known credential "
        "format (GitHub PAT, AWS access key, OpenAI API key, JWT, PEM block, ...). "
        "Credentials committed to config files leak to every reader of the "
        "repository and to every process that loads the agent."
    )
    remediation = (
        "Move the credential into a secret manager or a user-scoped env file "
        "excluded from version control, and reference it at runtime."
    )
    compliance_refs = (
        "owasp_asi:ASI03",
        "owasp_asi:ASI03-01",
        "eu_ai_act:ART-15",
        "nist_ai_rmf:MS-2.6",
        "iso_42001:A.6.2.8",
        "csa_aicm:IAM-01",
    )
    tags = ("secret", "iam")

    def scan_server(
        self,
        *,
        target: Target,
        config: MCPConfig,
        server: MCPServer,
    ) -> Iterable[Finding]:
        findings: list[Finding] = []
        for key, value in server.env.items():
            if not value:
                continue
            for label, pattern in _SECRET_PATTERNS:
                if pattern.search(value):
                    findings.append(
                        self.build_finding(
                            target=target,
                            title=f"{self.title} ({label})",
                            description=(
                                f"Server '{server.name}' env variable '{key}' contains a "
                                f"value matching the '{label}' credential format."
                            ),
                            evidence=(
                                Evidence(
                                    kind="source-range",
                                    summary=f"{server.name}.env[{key}] matches {label}",
                                    path=str(config.path),
                                ),
                            ),
                        ),
                    )
                    break  # one finding per env value; avoid double-reporting
        return findings


@register
class HighEntropySecretRule(BaseRule):
    rule_id = "MCP-SEC-SECRET-ENTROPY"
    title = "High-entropy value in server env suggests a hardcoded secret"
    severity = Severity.HIGH
    description = (
        "An opaque value in the server's `env` block exhibits Shannon entropy "
        "above 4.0 bits per character and is at least 20 characters long. That "
        "combination is characteristic of cryptographic tokens and should not "
        "appear in shared configuration."
    )
    remediation = (
        "Confirm whether the value is a credential; if so, relocate it to a "
        "secret manager or a user-scoped env file."
    )
    compliance_refs = (
        "owasp_asi:ASI03",
        "eu_ai_act:ART-15",
        "nist_ai_rmf:MS-2.6",
        "iso_42001:A.6.2.8",
        "csa_aicm:IAM-01",
    )
    tags = ("secret", "entropy")

    def scan_server(
        self,
        *,
        target: Target,
        config: MCPConfig,
        server: MCPServer,
    ) -> Iterable[Finding]:
        findings: list[Finding] = []
        for key, value in server.env.items():
            if value.lower() in _PLACEHOLDER_VALUES:
                continue
            if len(value) < _ENTROPY_MIN_LENGTH:
                continue
            entropy = _shannon_entropy(value)
            if entropy < _ENTROPY_THRESHOLD:
                continue
            # Skip if another env value referencing this one looks like a
            # template (e.g. ${SECRET} passthrough).
            if value.startswith("${") and value.endswith("}"):
                continue
            findings.append(
                self.build_finding(
                    target=target,
                    title=self.title,
                    description=(
                        f"Server '{server.name}' env variable '{key}' has entropy "
                        f"{entropy:.2f} bits/char and length {len(value)}."
                    ),
                    evidence=(
                        Evidence(
                            kind="source-range",
                            summary=f"{server.name}.env[{key}] entropy={entropy:.2f}",
                            path=str(config.path),
                        ),
                    ),
                ),
            )
        return findings
