# ARGOS Architecture (C4 sketch)

This is the short architecture brief. Deep designs live in module-specific
RFCs under `docs-internal/RFCs/`.

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
                                        │        │                  │ (under test)│
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
                 ┌───────────┬────────┼────────┬────────────┐
                 │           │        │        │            │
         ┌───────▼──────┐ ┌──▼──────┐ │ ┌──────▼──────┐ ┌───▼────────┐
         │argos-scanner │ │argos-   │ │ │argos-       │ │argos-      │
         │  (static)    │ │redteam  │ │ │proxy        │ │reporter    │
         └───────┬──────┘ └──┬──────┘ │ └──────┬──────┘ └───┬────────┘
                 │           │        │        │            │
                 │     ┌─────▼────────▼────────▼────────────┘
                 │     │            argos-rules
                 │     │      (YAML DSL for custom detection)
                 └─────┴──────────────┬─────────┐
                                      │         │
                                      ▼         ▼
                            ┌──────────────────────┐
                            │     argos-core       │
                            │  (models, ifaces,    │
                            │   compliance, otel)  │
                            └──────────────────────┘
```

No package imports upwards. `argos-core` is the sink.

## C3 -- Components (high level)

### `argos-core`

- `models/` -- Pydantic types (`Finding`, `Severity`, `ScanResult`, `Target`,
  `Evidence`).
- `interfaces/` -- ABCs (`IPlugin`, `IScanner`, `IProbe`, `IDetector`,
  `IReporter`).
- `autonomy.py` -- CSA L0-L5 enum + CBRA scoring.
- `compliance/` -- YAML loader, data ships with Module 1.
- `telemetry.py` -- OpenTelemetry bootstrap.

### `argos-cli`

- `app.py` -- Typer application root.
- `commands/scan.py`, `redteam.py`, `proxy.py`, `report.py` -- sub-commands.
- `console.py` -- shared `rich` console wired to the design-system palette.
- `plugins.py` -- entry-point discovery loader.

### `argos-scanner`, `argos-redteam`, `argos-proxy`, `argos-reporter`, `argos-rules`

M0 ships only package skeletons. Each module RFC fleshes out the component
map; the canonical tree lives in `docs-internal/PLAN.md` §3.

## C4 -- Code (examples of invariants enforced at the type level)

- `Finding.id` matches `ARGOS-[0-9A-F]{12}` (a Pydantic `StringConstraints`).
- `Finding` is frozen -- pipeline stages use `model_copy(update=...)` rather
  than mutation.
- `ScanResult` exposes `started_at`/`finished_at`; all timestamps are timezone
  aware (`datetime.now(UTC)`).
- `Severity` implements `__lt__` so `severity >= Severity.HIGH` filters are
  total.

## Cross-cutting concerns

- **Logging** -- every module uses `structlog` (planned M1). M0 relies on
  `rich` for CLI output only.
- **Telemetry** -- OpenTelemetry spans are created by the proxy (M5) and the
  scanner engine (M2). No telemetry leaves the machine without an explicit
  `ARGOS_OTEL_ENDPOINT`.
- **Configuration** -- `argos_cli.config.Config` merges env vars + YAML +
  defaults. The config object is read once per process.
- **Errors** -- every public function raises one of a finite set of typed
  exceptions defined in `argos_core.errors` (to be introduced with M1).

## Deployment

ARGOS is distributed as PyPI wheels. Reproducible builds go through
`hatchling` and GitHub Actions with PyPI Trusted Publishers (OIDC). A Docker
image is an option for M8, not a requirement.
