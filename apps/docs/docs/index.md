# ARGOS

**Agent Risk Governance and Operational Security** is a local-first security
audit framework for AI agents built on the Model Context Protocol (MCP). It
turns the OWASP Agentic Security Initiative taxonomy into something an auditor
can run: a static scanner, a red-teaming suite, a transparent audit proxy, an
in-process LangChain callback, an evaluation lab and compliance-mapped
reports, all behind one CLI.

## Why

Agents differ from chat models in three ways that existing tooling ignores:
they act on real systems, they keep persistent memory, and they talk to other
agents. Garak and Promptfoo probe the model; Semgrep and Bandit read source
code; Nuclei scans HTTP. None of them look at the whole system:

```
model + tool descriptions + configuration + credentials
      + runtime invocations + downstream responses
```

ARGOS covers that gap without sending anything to the cloud. Every finding
carries evidence and resolves to controls in five frameworks (OWASP ASI, CSA
AICM, EU AI Act, NIST AI RMF, ISO/IEC 42001).

## What you get

| Capability | Command | Detail |
|------------|---------|--------|
| Static configuration audit | `argos scan`, `argos doctor` | 17 built-in rules over three MCP config dialects, plus your own YAML rules |
| Red teaming | `argos redteam` | 20 probes, two per ASI category, single- or multi-turn |
| Runtime audit | `argos proxy run` | Transparent JSON-RPC proxy with tool-drift, PII and scope detectors, OTel spans, SQLite forensics |
| In-process audit | `ArgosCallbackHandler` | Same detectors for LangChain / LangGraph agents that call tools in-process |
| Empirical evaluation | `argos eval` | Six lab agents, ground truth, confusion matrix with Wilson intervals |
| Reporting | `argos report` | Self-contained HTML with a cross-framework compliance matrix, secrets redacted |
| Compliance graph | `argos compliance` | 125 controls, N:M mapping anchored on OWASP ASI, integrity manifest |

## Principles

1. **CLI-first.** The terminal is the primary surface.
2. **Local-only.** No cloud, no SaaS, no telemetry unless you configure an
   OTLP endpoint yourself.
3. **Zero-trust LLM.** The model is a potentially hostile user.
4. **Verifiable.** Every prompt, response and tool call is logged and tied to
   an evidence artefact.
5. **Simple.** Less agentic complexity, smaller attack surface.
6. **Plugin-extensible.** Rules, probes, detectors and reporters load through
   entry points.
7. **Open standards.** OpenTelemetry, JSON-RPC 2.0, YAML, Pydantic.

## Next steps

- [Getting started](getting-started.md): install and run the guided tour.
- [Methodology](methodology/index.md): the compliance graph and the CBRA
  risk score.
- [Modules](modules/scanner.md): one page per capability.
- [Security](security.md): how ARGOS defends itself.
