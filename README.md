# ARGOS

**Agent Risk Governance and Operational Security**

A local-first security audit framework for AI agents built on the Model Context
Protocol (MCP). ARGOS combines static configuration scanning, agentic red
teaming, a transparent audit proxy, and compliance-mapped reporting into a
single CLI — designed to be fast, verifiable, and extensible through plugins.

> Status: pre-alpha. Module 0 (Foundation) just landed. See
> [`docs-internal/PLAN.md`](docs-internal/PLAN.md) for the full roadmap and
> [`docs-internal/TFM_proposal.pdf`](docs-internal/TFM_proposal.pdf) for the
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
| Static scanner   | `argos-scanner`     | 15+ rules over MCP configurations (tool poisoning, excessive perms, hardcoded secrets, ...) |
| Red teaming      | `argos-redteam`     | 20+ probes mapped to OWASP ASI01-ASI10, single- or multi-turn     |
| Audit proxy      | `argos-proxy`       | Transparent JSON-RPC 2.0 interceptor with OpenTelemetry traces    |
| Reporting        | `argos-reporter`    | HTML (Jinja2) and JSONL reports with compliance matrix            |
| YAML rules       | `argos-rules`       | Nuclei-style DSL for custom detection                             |
| CLI              | `argos-cli`         | `argos scan | redteam | proxy | report`                           |
| Core             | `argos-core`        | Shared types, interfaces, compliance data, autonomy taxonomy      |

Compliance mappings cover OWASP ASI, CSA AICM, EU AI Act (Annex III/IV),
NIST AI RMF, and ISO/IEC 42001.

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

Requirements: Python 3.11 or newer. Linux, macOS, Windows.

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
argos status           # what is loaded right now
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

# 5. Audit live MCP traffic through the proxy.
argos proxy run -u stdio:'python -m my_mcp_server'

# 6. Render a polished report (HTML + compliance heatmap).
argos report findings.jsonl -o report.html
```

Every subcommand carries an **Examples** epilog in its `--help`, so
`argos <verb> --help` always finishes with a working command you can copy.

---

## Development

```bash
git clone https://github.com/argos-ai-audit/argos
cd argos
make bootstrap       # installs deps + pre-commit hooks
make ci              # lint + typecheck + test
```

Design tokens live in [`design-system/tokens.json`](design-system/tokens.json)
and generate to CSS / Python / TypeScript via `make tokens`. Do not edit the
generated files.

Useful entry points:

- [`docs-internal/PLAN.md`](docs-internal/PLAN.md) — modular roadmap
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
