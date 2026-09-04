# ARGOS

**Agent Risk Governance and Operational Security**

A local-first security audit framework for AI agents built on the Model Context
Protocol (MCP). ARGOS combines static configuration scanning, agentic red
teaming, a transparent audit proxy, an in-process LangChain / LangGraph
callback, an empirical evaluation lab and compliance-mapped reporting into a
single CLI, designed to be fast, verifiable, and extensible through plugins.

> Status: pre-release. Every module of the roadmap (M0-M7) is implemented and
> audited; the first PyPI release (M8) is the next milestone. See
> [`CHANGELOG.md`](CHANGELOG.md) for what shipped,
> [`docs-internal/PLAN.md`](docs-internal/PLAN.md) for the roadmap and
> [`docs-internal/project-proposal.pdf`](docs-internal/project-proposal.pdf) for the
> underlying academic proposal.

---

## Design principles

1. **CLI-first.** The terminal is the primary surface.
2. **Local-only.** No cloud, no SaaS, no telemetry leaves the machine unless
   you point ARGOS at your own collector.
3. **Zero-trust LLM.** The model is a potentially hostile user.
4. **Verifiable.** Every prompt, response, and tool call is logged and tied to
   an evidence artefact in the report.
5. **Simple.** Less agentic complexity, smaller attack surface.
6. **Plugin-extensible.** The core does not know about specific rules or
   probes; they load via entry points.
7. **Open standards.** OpenTelemetry, JSON-RPC 2.0, YAML, Pydantic.

---

## What ARGOS does

| Module           | Package             | Purpose                                                           |
| ---------------- | ------------------- | ----------------------------------------------------------------- |
| Static scanner   | `argos-scanner`     | 17 rules over MCP configurations (three dialects): secrets, shell and Docker patterns, supply chain, tool poisoning, filesystem scope |
| YAML rules       | `argos-rules`       | Nuclei-style DSL with a published JSON Schema for custom detection |
| Red teaming      | `argos-redteam`     | 20 probes mapped to OWASP ASI01-ASI10, single- or multi-turn, four detector families |
| Audit proxy      | `argos-proxy`       | Transparent JSON-RPC 2.0 interceptor (stdio, TCP, streamable-HTTP, SSE) with tool-drift, PII and scope detectors, OpenTelemetry spans and SQLite forensics |
| LangChain hook   | `argos-proxy`       | Callback handler that runs in-process tool calls through the same detector chain |
| Evaluation lab   | `argos-eval`        | Six deterministic agents, ground truth, confusion matrix with Wilson intervals |
| Reporting        | `argos-reporter`    | Self-contained HTML (strict CSP, redaction on by default) and JSONL with a cross-framework compliance matrix |
| CLI              | `argos-cli`         | `argos demo | quickstart | status | doctor | scan | redteam | proxy | report | eval | rules | compliance` |
| Core             | `argos-core`        | Shared types, interfaces, compliance data with integrity manifest, redaction, autonomy taxonomy |

Compliance mappings cover OWASP ASI, CSA AICM, EU AI Act (Annex III/IV),
NIST AI RMF, and ISO/IEC 42001: 125 controls, every ASI threat linked to at
least three auditable controls in four other frameworks, verified in CI.

Probe identifiers follow the February 2025 OWASP *Agentic AI: Threats and
Mitigations* numbering (T1-T10). The December 2025 *Top 10 for Agentic
Applications* reuses the `ASI` prefix with a different order; the
cross-reference is in [`docs/asi-taxonomy-crossref.md`](docs/asi-taxonomy-crossref.md).

---

## Install (preview)

```bash
# Recommended: uv
uv pip install argos-ai-audit

# Or pip
python -m pip install argos-ai-audit

argos --help
argos --version
```

Requirements: Python 3.11 or newer. Linux, macOS, Windows. Until the first
PyPI release, install from a clone with `make bootstrap`.

---

## Try it in 30 seconds

```bash
argos demo
```

That single command runs the full guided tour: a static scan over the bundled
vulnerable fixture (20 findings, 5 critical), the canonical lab benchmark
(120 trials, perfect confusion matrix), the proxy latency benchmark (sub-100µs
p95) and the multi-framework compliance summary. End-to-end in ~10 seconds,
zero arguments, zero setup.

Stuck? Print the cheat sheet:

```bash
argos quickstart       # copy-paste recipes for every workflow
argos status           # what is loaded right now, including plugins
argos --help           # the full command tree
```

## Common workflows

```bash
# 1. Audit a static MCP configuration.
argos scan config/agent.mcp.json --severity high

# 2. Auto-detect every MCP config on this machine and scan it.
argos doctor

# 3. Red-team a running agent endpoint.
argos redteam -t http://localhost:11434/api/chat

# 4. Run the empirical lab benchmark (reproducible).
argos eval --json out.json --markdown out.md

# 5. Audit live MCP traffic through the proxy (loopback by default).
argos proxy run -u stdio:'python -m my_mcp_server'

# 6. Render a polished report (HTML + compliance heatmap, secrets redacted).
argos report findings.jsonl -o report.html

# 7. Check that the bundled compliance data has not been tampered with.
argos compliance verify
```

Every subcommand carries an **Examples** epilog in its `--help`, so
`argos <verb> --help` always finishes with a working command you can copy.

### Auditing an in-process agent

```python
from argos_proxy.integrations import ArgosCallbackHandler

handler = ArgosCallbackHandler(allowed_tools=("search", "calendar.*"))
agent.invoke({"input": "book a room"}, config={"callbacks": [handler]})
handler.close()
print(handler.findings)
```

See [`examples/README.md`](examples/README.md) for the full walkthrough.

---

## Evidence

- `argos eval`: 120 trials over six lab agents, TP=20, TN=100, FP=FN=0,
  Wilson 95 % lower bound on recall above 0.84. Pinned as a regression test.
- `argos proxy bench`: p95 = 0.054 ms with the full detector chain against a
  50 ms budget.
- `scripts/argos_self_audit.py`: ARGOS audits its own repository with every
  CLI verb in one command; CI runs it on each push and archives the report.
- 1,368 automated tests, `mypy --strict`, 35 `ruff` rule families, CodeQL,
  OpenSSF Scorecard, pinned actions, SLSA provenance on release.

Methodology and results: [`docs/empirical-evaluation.md`](docs/empirical-evaluation.md).

---

## Development

```bash
git clone https://github.com/DiegoRodriguez-GL/A.R.G.O.S
cd A.R.G.O.S
make bootstrap       # installs deps + pre-commit hooks
make ci              # lint + typecheck + test
```

Design tokens live in [`design-system/tokens.json`](design-system/tokens.json)
and generate to CSS / Python / TypeScript via `make tokens`. Do not edit the
generated files. The compliance data manifest is regenerated with
`python scripts/build_compliance_manifest.py` after any change under
`packages/argos-core/src/argos_core/compliance/data/`.

Useful entry points:

- [`docs-internal/PLAN.md`](docs-internal/PLAN.md) — modular roadmap
- [`docs-internal/ARCHITECTURE.md`](docs-internal/ARCHITECTURE.md) — C4 brief
- [`docs-internal/THREAT_MODEL.md`](docs-internal/THREAT_MODEL.md) — ARGOS as a
  target itself
- [`design-system/DESIGN_SYSTEM.md`](design-system/DESIGN_SYSTEM.md) — visual
  conventions
- [`CONTRIBUTING.md`](CONTRIBUTING.md) — how to propose a change

---

## License

[AGPL-3.0-or-later](LICENSE). If you deploy ARGOS as a service, you must make
the modified source available under the same license. A commercial license
path will be announced when there is something worth commercialising.
