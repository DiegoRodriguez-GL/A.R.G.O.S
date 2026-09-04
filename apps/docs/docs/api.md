# API reference

The public Python surface, package by package. Everything listed here is
exported from the package's top-level module and covered by `mypy --strict`.

## `argos_core`

| Symbol | Purpose |
|--------|---------|
| `Finding`, `Evidence`, `Target`, `TargetKind`, `Severity`, `ScanResult` | Frozen Pydantic models exchanged across the pipeline |
| `IPlugin`, `IScanner`, `IProbe`, `IDetector`, `IReporter`, `PluginMetadata`, `ProbeContext`, `Detection` | Plugin interfaces |
| `AutonomyLevel`, `cbra_score` | CSA autonomy taxonomy and CBRA risk score |
| `argos_core.compliance.load_controls()` | Cached `ControlIndex` (`by_qid`, `by_framework`, `mappings_for`) |
| `argos_core.compliance.verify_manifest()` | Integrity check returning a `VerificationResult` |
| `argos_core.redaction.redact(text, *, extras=(), include_pii=False)` | Credential / PII masking |
| `argos_core.telemetry.init_telemetry()` | OpenTelemetry tracer provider (no exporter by default) |

## `argos_scanner`

| Symbol | Purpose |
|--------|---------|
| `scan(path, *, rules=None, min_severity=None, yaml_rules_dir=None)` | Run built-in and YAML rules over one configuration |
| `load(path)` | Parse a configuration into `MCPConfig` |
| `all_rules()`, `select(pattern)` | Rule registry |
| `ParserError` | Raised for unreadable or malformed inputs |

## `argos_rules`

| Symbol | Purpose |
|--------|---------|
| `load_rule(path)`, `load_rules_dir(path)` | Parse and validate YAML rules |
| `run_rules(rules, config)` | Evaluate rules against an `MCPConfig` |
| `Rule`, `Info`, matcher and extractor models | Frozen DSL models |
| `RuleError` | Validation or limit violation |

## `argos_redteam`

| Symbol | Purpose |
|--------|---------|
| `all_probes()`, `select(pattern)`, `BaseProbe` | Probe catalogue |
| `StringMatchDetector`, `RegexDetector`, `LLMJudgeDetector`, `BehaviorDetector` | Detectors |
| `SingleTurnStrategy`, `MultiTurnStrategy` | Delivery strategies |
| `HttpTransport`, `MockTransport`, `AgentTransport`, `TransportError` | Transports |
| `run`, `run_async`, `run_errors`, `summarise` | Runner |
| `Message`, `Role`, `Transcript`, `ProbeResult`, `ProbeOutcome` | Domain models |

## `argos_proxy`

| Symbol | Purpose |
|--------|---------|
| `Request`, `Response`, `Notification`, `Batch`, `ErrorObject`, `JsonRpcError`, `parse_payload` | JSON-RPC 2.0 layer |
| `ProxyServer`, `ProxyListener`, `SessionManager` | Relay and listener |
| `ProxyInterceptor`, `ChainInterceptor`, `PassThroughInterceptor`, `InterceptContext` | Interception seam |
| `ToolDriftDetector`, `PIIDetector`, `ScopeDetector`, `DetectorFinding`, `InMemoryFindingSink` | Detectors |
| `ForensicsStore`, `SqliteForensicsSink` | SQLite forensics |
| `OtelTracingInterceptor` | Spans per message |
| `StdioTransport`, `TcpTransport`, `HttpStreamableTransport`, `SseTransport`, `InMemoryTransport`, `make_transport_pair` and the `*UpstreamFactory` classes | Transports |
| `argos_proxy.integrations.ArgosCallbackHandler`, `AsyncArgosCallbackHandler`, `ArgosPolicyViolationError` | LangChain / LangGraph integration |
| `argos_proxy.detectors.adapter.to_core_finding` | Lift proxy findings into `argos_core.Finding` |

## `argos_reporter`

| Symbol | Purpose |
|--------|---------|
| `render_html(result, *, generator_version="0.0.1", redact_evidence=True)` | Scan / red-team report |
| `render_eval_html(report)` | Evaluation report |
| `redact_finding`, `redact_result` | Redacted copies of the models |

## `argos_eval`

| Symbol | Purpose |
|--------|---------|
| `all_agents()`, the six `Lab*` agent classes | Deterministic lab agents |
| `default_ground_truth()`, `GroundTruth` | Expected outcomes |
| `run_suite(agents, probes, ground_truth)` | Async suite runner returning an `EvalReport` |
| `EvalReport`, `EvalReport.diff` | Report model and comparison |
| `wilson_interval`, `bootstrap_ci` | Statistics |

## Plugin entry-point groups

`argos.scanner_rules`, `argos.probes`, `argos.proxy_detectors`,
`argos.reporters`, `argos.rule_matchers`. Declare them in your package's
`pyproject.toml`; `argos status` lists what was discovered.
