# ARGOS -- Self Threat Model

**Revision:** 0.3 (post-M7 consolidation, September 2026)
**Status:** Living document. Every module delta must revisit the relevant
entry and either update the control or file a deviation RFC.
**Scope:** ARGOS as a *target*. Threats to the systems ARGOS audits are covered
by the product requirements, not this document.

ARGOS ships to auditors who run it with elevated expectations: they will use
its findings to decide whether to deploy an agent in production. If ARGOS is
compromised, the blind spot it creates is asymmetric. Self-defense is
therefore a first-class product requirement, not a background concern.

Every control listed below is either **implemented** (with the code path and
the test that pins it) or explicitly marked **planned**. Revision 0.1 and 0.2
described several controls in the future tense; 0.3 reconciles the document
with the code so the memoria and the repository tell the same story.

## 1. Assets

| ID   | Asset                              | Confidentiality | Integrity | Availability |
| ---- | ---------------------------------- | :-------------: | :-------: | :----------: |
| A1   | MCP configurations under audit     | Medium          | High      | Low          |
| A2   | Captured request/response pairs    | High            | High      | Low          |
| A3   | Findings and report artefacts      | Medium          | High      | Medium       |
| A4   | Compliance mapping data            | Low             | High      | Medium       |
| A5   | ARGOS binaries and wheels          | Low             | Critical  | Medium       |
| A6   | User credentials / tokens (when provided for probing) | Critical | High | Low |
| A7   | In-process agent traffic seen by the LangChain callback | High | High | Low |

## 2. Trust boundaries

```
┌──────────── Auditor machine ────────────┐     ┌────── Audited agent ──────┐
│  CLI / shell   --→   argos-cli          │     │                           │
│                       │                 │     │                           │
│                       ├→ argos-scanner  │     │                           │
│                       ├→ argos-redteam ──HTTP/JSON-RPC→ agent endpoint    │
│                       ├→ argos-proxy  ←─MCP bi-directional traffic→  MCP │
│                       │    └ integrations.langchain ←─ callbacks ─ agent │
│                       ├→ argos-reporter → report.html (local fs)         │
│                       └→ argos-core                                       │
└────────────────────────────────────────┘     └──────────────────────────┘
         ▲                                             ▲
         │ untrusted YAML / JSON inputs                │ untrusted MCP payloads
```

Every arrow crossing the double border is an untrusted input boundary. The
LangChain callback handler is a boundary too: tool arguments, tool outputs and
prompts arrive from the agent process and are treated as hostile data.

## 3. Threats (STRIDE against each asset)

### T1. Malicious MCP configuration (targets A1, A5)

Input: YAML/JSON crafted by an adversary, parsed by `argos-scanner`.

- **Spoofing:** A config claims false tool identity to evade an allow-list.
  *Control (implemented):* rules treat tool identity as opaque; the proxy's
  `ToolDriftDetector` hashes the full tool definition (canonical JSON, sha256).
- **Tampering:** A config exploits a YAML parser quirk (tag abuse,
  `!!python/object`) to execute code.
  *Control (implemented):* scanner uses `yaml.safe_load` exclusively; `yaml.load`
  is banned via `ruff` `S506`.
- **Denial:** Deeply nested JSON blows the stack.
  *Control (implemented):* `MAX_CONFIG_BYTES = 8 MiB` checked before reading;
  `RecursionError` is caught and converted to `ParserError`. Pinned by
  `packages/argos-scanner/tests/test_security_audit.py`.

### T2. Prompt injection via scanned artefacts (target A2, A6)

The scanner reads tool descriptions, resource URIs, and prompt templates.
Malicious text inside them may be designed to manipulate the operator's LLM
later, or to trick LLM-judge evaluators used by the red-team module.

- *Control (implemented):* when content is displayed in reports it is
  HTML-escaped (Jinja2 autoescape + `StrictUndefined`). When content is passed
  to `LLMJudgeDetector` it is wrapped in an unambiguous delimiter and the judge
  prompt states explicitly that everything inside the delimiter is data, not
  instruction.
- *Control (implemented):* every `Finding` text field rejects ANSI escape and
  control characters at the model boundary (`argos_core.models.finding`), so a
  hostile description cannot repaint a terminal or a CI log.

### T3. Compromised plugin (targets A3, A5)

ARGOS loads plugins via entry points. A malicious package installed in the
auditor's environment can emit false negatives.

- *Control (implemented):* every emitted finding carries a `producer` field;
  `argos status` lists every plugin discovered through the
  `argos.*` entry-point groups together with the distribution and version that
  provides it, so the trusted set is visible before a run.
- *Control (implemented):* first-party rules, probes and detectors are imported
  from the wheel itself, never from entry points, so a plugin cannot shadow a
  built-in by reusing its name.
- *Planned:* a signed manifest of first-party plugin hashes checked at release
  time. Deferred until the plugin ecosystem exists; tracked in
  the roadmap section of the README.

### T4. Tampered compliance data (target A4)

If the YAML under `argos_core/compliance/data` is modified, reports lose the
cross-framework guarantees that auditors rely on.

- *Control (implemented):* `MANIFEST.sha256` ships next to the data files in
  `sha256sum` format. `load_controls()` verifies every digest before parsing and
  raises `ComplianceIntegrityWarning` on drift; `argos compliance verify` exits
  non-zero so a pipeline can gate on it. `scripts/build_compliance_manifest.py
  --check` fails CI when the data changes without a manifest update. Pinned by
  `packages/argos-core/tests/test_compliance_manifest.py`.
- *Control (implemented):* load-time Pydantic validation plus the seven OE1
  integrity invariants in `test_compliance_integrity.py`.

### T5. Supply-chain attack on dependencies (target A5)

A typosquat or compromised maintainer upstream injects a backdoor.

- *Control (implemented):* minimum pinning in every `pyproject.toml`;
  Dependabot grouped updates; `uv.lock` committed and `uv sync --frozen` in CI;
  every GitHub Action pinned by commit SHA; `step-security/harden-runner` with
  egress auditing on every job.
- *Control (implemented in workflow, unexercised until the first release):*
  PyPI Trusted Publishers (OIDC), no long-lived tokens; SLSA build provenance
  attestation on release artefacts.

### T6. Report exfiltration (targets A2, A3, A6)

Reports may contain captured credentials or customer data. Shipping them to a
third party by mistake is a confidentiality breach.

- *Control (implemented):* reports are local files. No telemetry is emitted
  unless an OTLP endpoint is explicitly configured; the default OpenTelemetry
  setup uses an in-process no-op exporter (`argos_core.telemetry`).
- *Control (implemented):* `render_html` masks credentials (OpenAI, Anthropic,
  GitHub, Google, AWS, Slack, Stripe, JWT, bearer values, PEM private keys) and
  emails in every free-text field before rendering, through the shared
  `argos_core.redaction` module. `argos report --no-redact` requires an
  interactive confirmation or `--yes`, and prints a warning when it writes raw
  evidence. Pinned by `packages/argos-reporter/tests/test_report_redaction.py`
  and `packages/argos-cli/tests/test_threat_model_controls.py`.
- *Control (implemented):* reports ship with a strict `Content-Security-Policy`
  meta tag (`default-src 'none'`; `style-src 'unsafe-inline'` only; no external
  origins), `referrer: no-referrer`, and `X-Content-Type-Options: nosniff`.
  Opening a compromised report in a browser cannot trigger outbound requests.

### T7. Proxy man-in-the-middle (targets A1, A2, A6)

The audit proxy sits between an agent and its MCP servers. A rogue process
binding to the proxy's port could impersonate it; a network-reachable proxy
lets any peer read the traffic.

- *Control (implemented):* `argos proxy run` refuses to bind a non-loopback
  address unless `--allow-external` is passed, and prints a warning banner when
  it is. `localhost`, `127.0.0.0/8` and `::1` are the only accepted defaults.
- *Control (implemented):* at startup the proxy prints one machine-readable
  JSON identity line (`event=argos.proxy.identity`, pid, listen address,
  upstream, forensics database, version, timestamp) so the operator can audit
  the socket owner.
- *Control (implemented):* HTTP/SSE transports reject request smuggling shapes
  (conflicting `Content-Length`, `Content-Length` + chunked, oversized headers)
  before any byte reaches the JSON-RPC layer.

### T8. Local-file write abuse (target A3)

Report generation writes arbitrary paths supplied by the user.

- *Control (implemented):* output paths come only from explicit CLI flags
  (`--output`, `--forensics-db`, `--json`); nothing derived from scanned data is
  ever used as a path.

### T9. Hostile in-process agent through the callback handler (targets A7, A3)

`argos_proxy.integrations.langchain` receives tool names, arguments, outputs
and prompts directly from the agent process.

- *Control (implemented):* every payload is truncated to
  `DEFAULT_MAX_TEXT_CHARS` before it reaches a detector or the SQLite store, so
  an agent streaming megabytes cannot exhaust the forensics database.
- *Control (implemented):* a detector that raises anything other than a policy
  veto is logged and ignored; the agent keeps running. The handler never blocks
  a tool unless `enforce=True` was requested explicitly (proposal §7 excludes
  runtime blocking by default).
- *Control (implemented):* the synchronous handler drives detectors on a private
  event loop thread, so a slow detector cannot deadlock an async agent loop.

## 4. Non-goals

- ARGOS does not defend against a compromised auditor workstation. Once an
  attacker is root on your machine, our trust boundary is gone. We do limit
  the blast radius (no lateral expansion through ARGOS), but we do not claim
  runtime attestation.
- ARGOS does not attempt to certify the *audited* agent. It reports evidence;
  the certification process is outside scope.

## 5. Review log

| Revision | Trigger | Outcome |
| -------- | ------- | ------- |
| 0.1 | Module 0 | Initial eight threats, controls stated as design intent |
| 0.2 | Modules 2, 4, 5 | Hardening passes: recursion limits, ANSI rejection, reverse-request interception |
| 0.3 | Post-M7 consolidation | T3/T4/T6/T7 controls implemented in code; T9 added for the callback integration; planned items labelled explicitly |

External review is requested before the first tagged release.
