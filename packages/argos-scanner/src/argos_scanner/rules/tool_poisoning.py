"""Heuristic detection of embedded prompt-injection in tool metadata.

Static configs usually do not ship tool descriptions, but some dialects embed
them (and so do custom wrappers). We inspect any free-text field for phrasing
that looks like out-of-band instructions, flagging it as ASI06 (goal hijack
via tool description).
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Any

from argos_core import Evidence, Finding, Severity, Target

from argos_scanner.models import MCPConfig, MCPServer
from argos_scanner.registry import register
from argos_scanner.rules._base import BaseRule

_SUSPICIOUS_PHRASES = re.compile(
    r"(?i)\b("
    r"ignore (?:all )?previous"
    r"|forget (?:all )?(?:above|previous)"
    r"|you are now"
    r"|act as"
    r"|disregard (?:all |the )?instructions"
    r"|system prompt"
    r"|before answering"
    r"|when the user asks"
    r"|reveal your"
    r"|output the (?:system |hidden )?prompt"
    r"|do not mention"
    r"|your secret"
    r"|new instructions"
    r")\b",
)

_FREE_TEXT_KEYS: frozenset[str] = frozenset(
    {"description", "tool_description", "instructions", "system", "prompt", "notes"},
)


_MAX_DEPTH = 64


def _iter_free_text(value: Any, path: str = "") -> Iterable[tuple[str, str]]:
    # Iterative traversal with a bounded depth so a maliciously nested config
    # cannot trigger RecursionError or consume unbounded stack.
    stack: list[tuple[Any, str, int]] = [(value, path, 0)]
    while stack:
        node, node_path, depth = stack.pop()
        if depth >= _MAX_DEPTH:
            continue
        if isinstance(node, str):
            yield node_path, node
        elif isinstance(node, dict):
            for k, v in node.items():
                key = str(k)
                stack.append(
                    (v, f"{node_path}.{key}" if node_path else key, depth + 1),
                )
        elif isinstance(node, list):
            for i, v in enumerate(node):
                stack.append((v, f"{node_path}[{i}]", depth + 1))


@register
class ToolDescriptionPromptInjectionRule(BaseRule):
    rule_id = "MCP-SEC-TOOL-POISON"
    title = "Embedded tool metadata contains prompt-injection phrasing"
    severity = Severity.HIGH
    description = (
        "A free-text field inside the server configuration (description, "
        "instructions, prompt, notes, ...) contains phrasing that a large "
        "language model is likely to treat as out-of-band instructions "
        "('ignore previous', 'you are now', 'system prompt', ...)."
    )
    remediation = (
        "Remove the phrasing or move the text to a location the model does "
        "not see. If the text is intentional for the operator's eyes only, "
        "quote-delimit it and add a sentinel explaining it is data."
    )
    compliance_refs = (
        "owasp_asi:ASI06",
        "owasp_asi:ASI06-01",
        "owasp_asi:ASI01",
        "eu_ai_act:ART-15",
        "nist_ai_rmf:MS-2.6",
        "csa_aicm:AIS-04",
    )
    tags = ("prompt-injection", "tool-def")

    def scan_server(
        self,
        *,
        target: Target,
        config: MCPConfig,
        server: MCPServer,
    ) -> Iterable[Finding]:
        findings: list[Finding] = []
        for subpath, text in _iter_free_text(server.raw):
            last = subpath.rsplit(".", 1)[-1].split("[", 1)[0]
            if last not in _FREE_TEXT_KEYS:
                continue
            match = _SUSPICIOUS_PHRASES.search(text)
            if match is None:
                continue
            findings.append(
                self.build_finding(
                    target=target,
                    title=self.title,
                    description=(
                        f"Server '{server.name}' field '{subpath}' contains "
                        f"suspicious phrasing: {match.group(0)!r}."
                    ),
                    evidence=(
                        Evidence(
                            kind="source-range",
                            summary=f"{server.name}.{subpath} contains {match.group(0)!r}",
                            path=str(config.path),
                        ),
                    ),
                ),
            )
        return findings
