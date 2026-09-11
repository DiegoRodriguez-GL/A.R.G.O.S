# Changelog

All notable changes to ARGOS are recorded here. Versioning follows
[Semantic Versioning](https://semver.org/) once `0.1.0` ships. The format is
inspired by [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added -- Real-world validation (September 2026)

- `argos proxy wrap`: the proxy as a stdio server inside any MCP client that
  launches servers as commands (Claude Desktop, VS Code, Cursor, MCP
  Inspector). The client talks to ARGOS, ARGOS launches the real server;
  `--upstream https://...` targets a remote server instead, `-H 'Name:
  env:VAR'` adds headers whose values come from the environment.
- `argos_proxy.StdioServerTransport`: downstream transport over the
  process's own stdin/stdout.
- `argos_scanner.registry_format`: `argos scan` reads `server.json` entries
  of the official MCP Registry (bare or inside the API envelope) and audits
  each package and remote as the client entry an installer would write.
- `argos proxy run/wrap --stdio-framing`, `--header`, and `sse+https://`
  upstreams.
- `benchmarks/real-world/`: scripts, manual labels and aggregated results of
  the three real-world campaigns (the whole MCP Registry, seven reference
  servers, nine public remote servers); see `docs/real-world-validation.md`.
- 103 new tests (1,473 total), most of them reproducing behaviour observed
  in real servers and registry entries.

### Fixed -- Real-world validation (September 2026)

- stdio upstreams speak newline-delimited JSON, as the MCP specification
  defines; `Content-Length` framing is now an explicit option.
- Bare launcher names (`npx`, `uvx`) are resolved through `PATH`/`PATHEXT`,
  so `.cmd` shims start on Windows.
- The stdio transport drains the child's stderr, skips non-JSON lines on
  stdout and follows the specification's shutdown sequence (close stdin,
  terminate, kill, the whole process tree on Windows).
- stdio, TCP and accepted-TCP transports no longer drop every message but
  the first when several arrive in one read.
- Streamable-HTTP client rewritten to MCP 2025-03-26 / 2025-06-18: TLS with
  certificate verification, answers read from each POST response (JSON or
  SSE, chunked or not), `Mcp-Session-Id`, `MCP-Protocol-Version`, optional
  GET stream, `DELETE` on close, connection reuse, and HTTP failures
  answered with a JSON-RPC error. The legacy SSE transport gained TLS and
  chunked decoding.
- `Request`/`Notification` no longer serialise an absent `params` as `null`,
  which strict servers silently drop.
- PII detector recognises IBANs in the printed four-character groups.
- Scanner rules, measured against the MCP Registry: bearer placeholders
  (`{name}`, `${VAR}`, `<name>`) are not tokens; the entropy rule skips
  URLs without credentials, paths, word-like identifiers, user agents,
  e-mails and public EVM addresses; templated hosts are not judged as
  plaintext; the host-mount rule targets the root, the whole home or known
  credential stores; npx and uvx arguments are parsed like the launchers do;
  registry documentation is not treated as model-facing text.

### Added -- Consolidation (September 2026)

- `argos_core.compliance.manifest`: `MANIFEST.sha256` shipped next to the
  compliance data, verified on every `load_controls()`
  (`ComplianceIntegrityWarning` on drift) and through the new
  `argos compliance verify` command (exit 1 on modified / missing / unlisted
  files). `scripts/build_compliance_manifest.py [--check]` regenerates it.
- `argos_core.redaction`: shared credential and PII masking (OpenAI,
  Anthropic, GitHub, Google, AWS, Slack, Stripe, JWT, bearer values, PEM
  private keys, emails). The red-team runner keeps its import path;
  `render_html` now redacts every free-text field by default and
  `argos report --no-redact` requires confirmation or `--yes`.
- `argos_proxy.integrations.langchain`: `ArgosCallbackHandler` and
  `AsyncArgosCallbackHandler` translate LangChain / LangGraph callbacks into
  `tools/call` requests, responses and `notifications/argos/*` and run them
  through the proxy detector chain (OTel + PII + scope), with optional SQLite
  forensics and `enforce=True` to veto out-of-scope tools before they run.
  `langchain-core` is optional.
- `argos_proxy.detectors.adapter.to_core_finding`: lifts proxy findings into
  `argos_core.Finding` with compliance references resolved from the M1 graph.
- `argos proxy run --allow-external`: non-loopback binds are refused unless
  the flag is present; a machine-readable JSON identity line (pid, socket,
  upstream, forensics database) is printed at startup.
- `argos status` lists every plugin discovered through entry points with its
  distribution and version.
- CI: new `self-audit` job runs `scripts/argos_self_audit.py` and
  `argos compliance verify` on every push and uploads the report.
- 82 new tests (1,368 total).

### Changed -- Consolidation (September 2026)

- CI pins `uv` 0.11.6 (the previous 0.4.18 could not read the lockfile) and
  every workflow references the Dependabot-bumped action versions
  (setup-python 6.2.0, upload-artifact 7.0.1, upload-pages-artifact 5.0.0,
  setup-uv 8.1.0, gh-action-pypi-publish 1.14.0).
- `pydantic` is declared as a direct dependency of `argos-cli`, `argos-proxy`,
  `argos-redteam` and `argos-rules`.
- Repository metadata, README and policies point to the real repository
  (`DiegoRodriguez-GL/A.R.G.O.S`).
- `THREAT_MODEL.md` 0.3 and `ARCHITECTURE.md` describe what the code does
  today; planned controls are labelled as such.

### Fixed -- Consolidation (September 2026)

- Three `ruff` findings that had kept the `lint` job red since April
  (`RUF100`, `TRY004`).
- `ANTHROPIC_KEY` is matched before `OPENAI_KEY` so `sk-ant-` tokens carry the
  correct redaction label.

### Added -- Proxy transports (A1)

- Streamable-HTTP (MCP 2025-03-26) and legacy SSE transports implemented over
  raw asyncio with a hand-written HTTP/1.1 parser (`ChunkedDecoder`,
  anti-smuggling checks: conflicting `Content-Length`, `Content-Length` +
  chunked, oversized headers) and a WHATWG SSE parser.
- `ProxyListener(framing="http")`, `HttpStreamableUpstreamFactory`,
  `SseUpstreamFactory`; `argos proxy run -u http://... | sse://...`.
- 92 tests over real TCP sockets, including smuggling and slowloris cases.

### Added -- Onboarding and self-audit

- `argos demo`: guided tour (scan, canonical eval, proxy bench, compliance)
  in under ten seconds with zero arguments; `argos quickstart` cheat sheet.
- `scripts/argos_self_audit.py`: runs every CLI verb over the repository's own
  fixtures and writes a consolidated `REPORT.md` with the captured artefacts.

### Added -- Proxy listener (P1)

- Real multi-session TCP listener with `max_sessions`, per-session idle
  timeout, graceful drain on shutdown and a `server_busy` notice when the cap
  is reached. Per-session upstream factories (stdio, TCP, in-memory).
- `argos proxy run` wired to the listener with detector flags
  (`--drift/--no-drift`, `--pii/--no-pii`, `--allow-tool`, `--otel/--no-otel`).

### Added -- Module 7 (empirical evaluation)

- `argos-eval` package: six deterministic lab agents (ReAct, LangGraph
  supervisor-worker, memory + RAG; vulnerable and hardened variants), YAML
  ground truth, async suite runner, precision / recall / specificity /
  accuracy / F1 / MCC with Wilson intervals and bootstrap, JSON / Markdown /
  CSV / HTML exports and `EvalReport.diff`.
- `argos eval` command and `scripts/canonical_eval.py`; canonical result
  pinned by `test_canonical_metrics.py` (120 trials, TP=20, TN=100, FP=FN=0).
- Public methodology in `docs/empirical-evaluation.md`.

### Added -- Module 6 (HTML reports)

- `render_html` for scan and red-team results: cover, executive summary,
  ASI category breakdown, cross-framework compliance matrix, finding cards
  with evidence, methodology appendix, print stylesheet.
- `render_eval_html` for evaluation reports.
- `argos report [--demo]`.

### Added -- Module 5 (audit proxy)

- Typed JSON-RPC 2.0 layer with NDJSON and `Content-Length` framing.
- `ProxyServer` with `ChainInterceptor`; upstream-initiated requests
  (sampling / elicitation) pass through the interceptor as well.
- Detectors: `ToolDriftDetector` (baseline pinning, warn / block),
  `PIIDetector` (emails, IBAN mod-97, Luhn cards, DNI / NIE),
  `ScopeDetector` (method / tool allowlists).
- OpenTelemetry spans per message; SQLite forensics store with WAL.
- `argos proxy bench` enforcing RNF-02 (p95 < 50 ms; measured 0.054 ms).
- Three adversarial audit passes: six real defects fixed with regression
  tests.

### Added -- Module 4 (red teaming)

- 20 probes across OWASP ASI01-ASI10 (two per category, February 2025
  T1-T10 numbering), `StringMatch` / `Regex` / `LLMJudge` / `Behavior`
  detectors, single-turn and multi-turn strategies.
- `HttpTransport` with retries, `User-Agent` identification and a
  `--max-requests` denial-of-wallet cap; `MockTransport` for tests.
- Concurrent runner with per-probe error isolation.
- Adversarial audit: eight detector / runner defects fixed with regression
  guards (`test_bugs_audit.py`).
- `argos redteam` and `argos doctor` (auto-detection of MCP client configs).

### Added -- Module 3 (YAML rules engine)

- `argos-rules` package: Nuclei-inspired DSL with frozen Pydantic models,
  validated by a published JSON Schema (`schema/rule.schema.json`).
- Matchers: `word`, `regex`, `glob`, each with `condition` (or/and),
  `negative` and (for word/regex) `case-insensitive` flags.
- Extractors: `regex` (with capture groups) and `word`; capture concrete
  evidence snippets for every finding.
- Selectors resolve dotted paths against MCPConfig / MCPServer:
  `server.name`, `server.command`, `server.args`, `server.args[N]`,
  `server.argv`, `server.url`, `server.env.<KEY>`, `server.env.*`,
  `server.env.keys`, `server.headers.<KEY>`, `server.headers.*`,
  `server.raw`, `server.transport`, `server.cwd`, `config.dialect`,
  `config.path`, `config.raw`.
- Defence-in-depth limits: max rule size 64 KiB, max matchers 16,
  max extractors 8, max words 64, max regexes 32, max regex length 1000,
  max rules per directory 1000. Patterns compile at load time.
- Five example rules under `packages/argos-rules/examples/`.
- Scanner engine accepts `yaml_rules_dir=` to combine built-in + YAML
  findings in a single `ScanResult` with the same Finding shape.
- New CLI flags: `argos scan --rules-dir PATH` and
  `argos rules validate FILE_OR_DIR`.

### Added -- Module 2 (static MCP scanner)

- Parser that normalises `claude_desktop`, `vscode` and `mcp-spec` dialects
  into a single `MCPConfig` model (frozen, extra-forbid).
- Seventeen built-in rules under `argos_scanner.rules` covering secrets
  (pattern + entropy), plaintext transport, shell patterns (pipe-to-shell,
  interpreters with `-c`, destructive commands, eval/substitution),
  Docker (`--privileged`, host mounts, `--network host`, unpinned images),
  filesystem-server root access, supply chain (`npx -y`, `uvx`, docker
  tags), tool poisoning heuristics, and sensitive env keys.
- Rule registry with `@register` decorator and glob selection.
- Scanner engine (`argos_scanner.scan`) wired into the CLI:
  `argos scan <path> [--rules ...] [--severity ...] [--format table|jsonl]`.
- Table and JSONL output; exit code 1 when any HIGH/CRITICAL finding is
  present.
- Fixtures: `clean.claude_desktop.json`, `risky.claude_desktop.json`,
  `mcp_spec.json`.
- Every finding carries `compliance_refs` qualified ids that resolve in
  the Module 1 mapping graph.

### Changed -- hardening pass

- Pinned every GitHub Action by commit SHA (supply-chain defence; OpenSSF
  Scorecard recommendation).
- Added `step-security/harden-runner` with `egress-policy: audit` to every
  CI job for detection of unexpected outbound network traffic.
- Added `gitleaks` to the pre-commit hook set (secret scanning before
  commit hits the index).
- Added a strict `Content-Security-Policy` meta tag and `X-Content-Type-
  Options: nosniff` to the HTML reporter base template; reports now render
  with `default-src 'none'` and no referrer leakage.
- Extended `ruff` lint selection from 22 to 35 rule categories, including
  `FURB`, `LOG`, `EM`, `PERF`, `SLF`, `TRY`, `ARG`, `TID`, `PYI`, `FLY`.
- Added a `bandit` configuration block to `pyproject.toml` so the tool
  runs with identical exclusions to the `ruff S` rule set.
- Added `.well-known/security.txt` (RFC 9116) for future serving from the
  docs site.
- Consolidated the four CLI skeleton commands onto a single
  `not_implemented()` helper (`commands/_placeholder.py`); per-command
  files now contain only their Typer signature.
- Property-based tests with Hypothesis; unicode, ANSI and denial-of-wallet
  hardening across parsers, models and the red-team transport.

### Added -- Module 1 (Methodology and compliance mapping)

- Enriched Pydantic models for compliance data: `Control`, `FrameworkMeta`,
  `FrameworkData`, `Mapping`, `MappingEntry`, `MappingMeta`.
- Five bundled framework YAMLs under
  `packages/argos-core/src/argos_core/compliance/data/`:
  `owasp_asi.yaml` (hub, 10 threats + operational refinements), `csa_aicm.yaml`
  (AI-specific subset), `eu_ai_act.yaml` (Articles 9-15 + Annex III/IV),
  `nist_ai_rmf.yaml` (GOVERN/MAP/MEASURE/MANAGE), `iso_42001.yaml`
  (Annex A controls).
- `mapping.yaml` with N:M cross-framework relationships anchored on OWASP ASI.
- Integrity tests guaranteeing the OE1 invariant (>= 3 cross-framework
  controls per ASI threat, >= 4 frameworks touched) and resolving every
  qualified id against real controls.
- Methodology documentation at `apps/docs/docs/methodology/index.md` with
  Mermaid diagrams.
- RFC 0002 documenting the compliance data model and design rationale.

### Added -- Module 0 (Foundation)

- Monorepo scaffolding: `packages/argos-core`, `argos-cli`, `argos-scanner`,
  `argos-redteam`, `argos-proxy`, `argos-reporter`, `argos-rules`.
- Design system v0: `design-system/tokens.json` + generated
  `tokens.css`/`tokens.py`/`tokens.ts` via `scripts/build_tokens.py`.
- Jinja2 base layout (`packages/argos-reporter/.../templates/base.html.j2`).
- `argos-core` Pydantic models (`Finding`, `Severity`, `ScanResult`, `Target`,
  `Evidence`) and ABC interfaces (`IPlugin`, `IScanner`, `IProbe`,
  `IDetector`, `IReporter`).
- Autonomy taxonomy (CSA L0-L5) and CBRA scoring helper.
- Typer CLI skeleton exposing `argos --help`, `argos --version`, and
  sub-command stubs for `scan`, `redteam`, `proxy`, `report`.
- Quality tooling: ruff, mypy (strict), pytest with coverage gate,
  pre-commit, Makefile targets.
- GitHub Actions workflows for CI, release (PyPI Trusted Publishers) and
  documentation/landing deployment to GitHub Pages.
- Issue/PR templates, Code of Conduct, Security policy, Dependabot config,
  CODEOWNERS.
- Threat model (`docs-internal/THREAT_MODEL.md`), architecture brief
  (`docs-internal/ARCHITECTURE.md`), RFC template and RFC 0001 on the
  monorepo layout.
