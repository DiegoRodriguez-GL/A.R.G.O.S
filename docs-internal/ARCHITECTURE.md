# ARGOS Architecture (C4 sketch)

This is the short architecture brief. Deep designs live in module-specific
RFCs under `docs-internal/RFCs/` and in the changelog.

## C1 -- System context

ARGOS runs locally on the auditor's machine. It interacts with four kinds of
external systems:

```
  ┌──────────────┐    static config     ┌────────┐    JSON/YAML     ┌─────────────┐
  │   Auditor    │ ───────────────────▶ │ ARGOS  │ ◀──────────────  │ MCP configs │
  │ (human user) │ ◀──────────────────  │        │                  └─────────────┘
  └──────────────┘   HTML / JSONL       │  (CLI) │    JSON-RPC 2.0  ┌─────────────┐
                                        │        │ ◀──────────────▶ │ MCP servers │
                                        │        │                  └─────────────┘
                                        │        │    HTTP / SSE    ┌─────────────┐
                                        │        │ ◀──────────────▶ │  Agents     │
                                        │        │    callbacks     │ (under test)│
                                        │        │    OTLP (opt.)   └─────────────┘
                                        │        │ ─ ─ ─ ─ ─ ─ ─ ─▶ ┌─────────────┐
                                        │        │                  │ OTel        │
                                        └────────┘                  │ collector   │
                                                                    └─────────────┘
```

OpenTelemetry export is opt-in. Everything else runs without network access.

## C2 -- Containers (packages)

```
                         ┌─────────────────────────┐
                         │        argos-cli        │  ◀── single entry point
                         └────────────┬────────────┘
          ┌───────────┬───────────┬───┴──────┬───────────┬───────────┐
          │           │           │          │           │           │
  ┌───────▼─────┐ ┌───▼─────┐ ┌───▼─────┐ ┌──▼───────┐ ┌─▼───────┐ ┌─▼───────┐
  │argos-scanner│ │argos-   │ │argos-   │ │argos-    │ │argos-   │ │argos-   │
  │  (static)   │ │redteam  │ │proxy    │ │reporter  │ │eval     │ │rules    │
  └───────┬─────┘ └───┬─────┘ └───┬─────┘ └──┬───────┘ └─┬───────┘ └─▲───────┘
          │           │           │          │           │           │
          └───────────┴───────────┴────┬─────┴───────────┘   optional│
                                       │                    (scanner)│
                                       ▼                             │
                            ┌──────────────────────┐                 │
                            │     argos-core       │◀────────────────┘
                            │ models, interfaces,  │
                            │ compliance, redaction│
                            │ telemetry            │
                            └──────────────────────┘
```

No package imports upwards. `argos-core` is the sink. Two horizontal edges are
allowed and documented: `argos-scanner` imports `argos-rules` (optional YAML
rules in the same `ScanResult`), and `argos-eval` imports `argos-redteam`
(the lab agents implement the red-team `AgentTransport` contract).

## C3 -- Components

### `argos-core`

- `models/` -- Pydantic types (`Finding`, `Severity`, `ScanResult`, `Target`,
  `Evidence`). Frozen, `extra="forbid"`, control characters rejected.
- `interfaces/` -- ABCs (`IPlugin`, `IScanner`, `IProbe`, `IDetector`,
  `IReporter`).
- `autonomy.py` -- CSA L0-L5 enum + CBRA scoring.
- `compliance/` -- YAML loader, five framework files, N:M mapping and the
  `MANIFEST.sha256` integrity check (THREAT_MODEL T4).
- `redaction.py` -- shared credential / PII masking used by the red-team
  runner and the reporter (THREAT_MODEL T6).
- `telemetry.py` -- OpenTelemetry bootstrap (no exporter by default).

### `argos-cli`

- `app.py` -- Typer application root.
- `commands/` -- `demo`, `quickstart`, `status`, `doctor`, `scan`, `redteam`,
  `report`, `eval`, `rules {list,show,validate}`,
  `compliance {list,show,map,verify}`, `proxy {run,bench}`.
- `console.py` -- shared `rich` console wired to the design-system palette.
- `plugins.py` -- entry-point discovery loader (`argos.*` groups).

### `argos-scanner`

- `parser.py` -- normalises `claude_desktop`, `vscode` and `mcp-spec` dialects
  into `MCPConfig`.
- `rules/` -- 17 built-in rules registered through `@register` (secrets,
  shell, Docker, supply chain, filesystem, TLS, tool poisoning, env keys).
- `engine.py` -- runs built-in and YAML rules over one config, emits a
  `ScanResult`.

### `argos-rules`

Nuclei-style YAML DSL: `parser` (limits, JSON Schema), `selectors` (dotted
paths over `MCPConfig`), `matchers` (word / regex / glob), `extractors`,
`engine`.

### `argos-redteam`

- `probes/` -- 20 probes, two per OWASP ASI category (February 2025 T1-T10
  numbering, see `docs/asi-taxonomy-crossref.md`).
- `detectors/` -- `StringMatch`, `Regex`, `LLMJudge` (optional), `Behavior`.
- `strategies/` -- single-turn and multi-turn delivery.
- `transport.py` -- `HttpTransport` (retries, denial-of-wallet cap) and
  `MockTransport`.
- `runner.py` -- concurrent execution with per-probe error isolation.

### `argos-proxy`

- `jsonrpc/` -- typed messages, NDJSON / `Content-Length` / HTTP / SSE framing
  with anti-smuggling checks.
- `transport/` -- stdio, TCP, in-memory, streamable-HTTP and SSE transports plus
  per-session upstream factories.
- `server.py`, `listener.py` -- one `ProxyServer` per accepted session, bounded
  concurrency, idle and drain timeouts.
- `interceptor.py`, `detectors/` -- `ChainInterceptor` running
  `ToolDriftDetector`, `PIIDetector`, `ScopeDetector`; `detectors/adapter.py`
  lifts proxy findings into `argos_core.Finding`.
- `forensics/` -- SQLite store with WAL.
- `otel.py` -- one span per observed message.
- `integrations/langchain.py` -- LangChain / LangGraph callback handler that
  feeds in-process tool calls into the same interceptor chain.

### `argos-reporter`

Jinja2 templates with the design tokens inlined, strict CSP, print stylesheet.
`render_html` (scan / red-team results, compliance matrix, redaction on by
default) and `render_eval_html` (evaluation reports).

### `argos-eval`

Six deterministic lab agents (ReAct, LangGraph supervisor-worker, memory + RAG;
vulnerable and hardened variants), YAML ground truth, async suite runner,
binary-classification metrics with Wilson intervals and bootstrap, report
export (JSON / Markdown / CSV / HTML) and `EvalReport.diff`.

## C4 -- Code (invariants enforced at the type level)

- `Finding.id` matches `ARGOS-[0-9A-F]{12}` (a Pydantic `StringConstraints`).
- `Finding` is frozen -- pipeline stages use `model_copy(update=...)` rather
  than mutation (the reporter's redaction pass is an example).
- `ScanResult` exposes `started_at`/`finished_at`; all timestamps are timezone
  aware and `finished_at < started_at` is rejected.
- `Severity` implements a total order so `severity >= Severity.HIGH` filters
  are well defined.
- JSON-RPC models reject unknown fields, NaN / inf ids and oversized method
  names before a message can reach an upstream server.

## Cross-cutting concerns

- **Logging** -- standard-library `logging` under the `argos.*` namespace;
  `rich` is used only for CLI presentation. `structlog` was considered in M0
  and not adopted (no structured sink existed to justify the dependency).
- **Telemetry** -- OpenTelemetry spans are created by the proxy and by the
  LangChain callback handler. No telemetry leaves the machine without an
  explicit OTLP endpoint configuration.
- **Configuration** -- `argos_cli.config.Config` merges env vars + YAML +
  defaults. The config object is read once per process.
- **Errors** -- each package raises its own small set of typed exceptions
  (`ParserError`, `RuleError`, `TransportError`, `JsonRpcError`,
  `ArgosPolicyViolationError`, ...). A shared `argos_core.errors` module was
  planned in M0 and dropped: per-package exceptions kept the dependency graph
  flatter.
- **Integrity** -- compliance data is digest-checked on every load; the
  self-audit harness (`scripts/argos_self_audit.py`) runs every CLI verb in CI
  and uploads the report as a build artefact.

## Deployment

ARGOS is distributed as PyPI wheels. Reproducible builds go through
`hatchling` and GitHub Actions with PyPI Trusted Publishers (OIDC) and SLSA
provenance. A Docker image is an option for a later release, not a
requirement.
