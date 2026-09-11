# ARGOS

**Agent Risk Governance and Operational Security**

A local-first security audit framework for AI agents built on the
[Model Context Protocol](https://modelcontextprotocol.io) (MCP). ARGOS turns
the OWASP Agentic Security Initiative threat taxonomy into something an
auditor can run: a static configuration scanner, an agentic red-teaming suite,
a transparent audit proxy, an in-process callback for LangChain and LangGraph
agents, a reproducible evaluation lab and compliance-mapped reporting, all
behind one command-line tool.

[![CI](https://github.com/DiegoRodriguez-GL/A.R.G.O.S/actions/workflows/ci.yml/badge.svg)](https://github.com/DiegoRodriguez-GL/A.R.G.O.S/actions/workflows/ci.yml)
[![CodeQL](https://github.com/DiegoRodriguez-GL/A.R.G.O.S/actions/workflows/codeql.yml/badge.svg)](https://github.com/DiegoRodriguez-GL/A.R.G.O.S/actions/workflows/codeql.yml)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/DiegoRodriguez-GL/A.R.G.O.S/badge)](https://securityscorecards.dev/viewer/?uri=github.com/DiegoRodriguez-GL/A.R.G.O.S)
[![License: AGPL-3.0-or-later](https://img.shields.io/badge/license-AGPL--3.0--or--later-059669.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-1f2937.svg)](pyproject.toml)
[![Typed: mypy strict](https://img.shields.io/badge/typing-mypy%20strict-1f2937.svg)](pyproject.toml)

> Status: pre-release (`0.0.1`). Every module is implemented, tested and
> audited; the first PyPI release and the hosted documentation are the two
> remaining steps of the release plan.

---

## Table of contents

1. [Why ARGOS](#why-argos)
2. [What it does](#what-it-does)
3. [Thirty-second tour](#thirty-second-tour)
4. [Installation](#installation)
5. [Usage](#usage)
   - [Static scanning](#static-scanning)
   - [Custom YAML rules](#custom-yaml-rules)
   - [Red teaming](#red-teaming)
   - [Audit proxy](#audit-proxy)
   - [In-process agents (LangChain / LangGraph)](#in-process-agents-langchain--langgraph)
   - [Reports](#reports)
   - [Compliance graph](#compliance-graph)
   - [Evaluation lab](#evaluation-lab)
   - [Exit codes](#exit-codes)
6. [Architecture](#architecture)
7. [Compliance mapping](#compliance-mapping)
8. [Empirical results](#empirical-results)
9. [Security of ARGOS itself](#security-of-argos-itself)
10. [Development](#development)
11. [Project layout](#project-layout)
12. [Roadmap](#roadmap)
13. [Contributing](#contributing)
14. [License](#license)

---

## Why ARGOS

Agents differ from chat models in three ways that existing tooling ignores:
they **act** on real systems, they keep **persistent memory**, and they
**talk to other agents**. A security failure in an agent is not a wrong
sentence on screen; it is an executed transaction, a poisoned memory that
survives sessions, or an instruction propagated to a peer that runs it with
its own authority.

The threat language for this class of system exists: the OWASP Agentic
Security Initiative catalogues ten threat categories (ASI01 to ASI10). The
technical substrate exists too: MCP has become the de-facto protocol between
agents and tools. What was missing is a tool that connects the two. Garak and
Promptfoo probe the model; Semgrep and Bandit read source code; Nuclei scans
HTTP endpoints. None of them looks at the whole system:

```
model + tool descriptions + configuration + credentials
      + runtime invocations + downstream responses
```

ARGOS covers that gap without sending a byte to the cloud. Every finding
carries evidence and resolves to controls in five frameworks (OWASP ASI, CSA
AICM, EU AI Act, NIST AI RMF and ISO/IEC 42001).

### Design principles

| # | Principle | What it means in practice |
|---|-----------|---------------------------|
| 1 | **CLI-first** | The terminal is the primary surface. Reports are static files. |
| 2 | **Local-only** | No cloud, no SaaS, no telemetry unless you point ARGOS at your own OpenTelemetry collector. |
| 3 | **Zero-trust LLM** | The model is treated as a potentially hostile user in every detector. |
| 4 | **Verifiable** | Every prompt, response and tool call is logged and tied to an evidence artefact. |
| 5 | **Simple** | Less agentic complexity, smaller attack surface. Minimal correct components over versatile opaque ones. |
| 6 | **Plugin-extensible** | The core knows no concrete rules, probes or reporters; they load through entry points. |
| 7 | **Open standards** | OpenTelemetry, JSON-RPC 2.0, YAML, Pydantic. |

---

## What it does

| Capability | Command | Detail |
|------------|---------|--------|
| Static configuration audit | `argos scan`, `argos doctor` | 17 built-in rules over the MCP configuration dialects in use (Claude Desktop, VS Code, MCP spec) and over `server.json` entries of the official MCP Registry, plus your own YAML rules |
| Red teaming | `argos redteam` | 20 probes, two per ASI category, single- or multi-turn, four detector families |
| Runtime audit | `argos proxy wrap`, `argos proxy run` | Transparent JSON-RPC 2.0 proxy with tool-drift, PII and scope detectors, OpenTelemetry spans and a SQLite forensic trail. `wrap` sits inside any MCP client over stdio; `run` exposes a TCP listener. Upstreams: stdio, TCP, streamable HTTP and SSE, over TLS for remote servers |
| In-process audit | `ArgosCallbackHandler` | The same detector chain for LangChain / LangGraph agents that call tools in-process |
| Empirical evaluation | `argos eval` | Six deterministic lab agents, YAML ground truth, confusion matrix with Wilson intervals, pinned as a regression test |
| Reporting | `argos report` | Self-contained HTML with a cross-framework compliance matrix, strict CSP and secrets redacted by default; JSONL export |
| Compliance graph | `argos compliance` | 125 controls, N:M mapping anchored on OWASP ASI, integrity manifest verified on every load |
| Self-audit | `scripts/argos_self_audit.py` | ARGOS runs every CLI verb against its own repository and archives the evidence; also a CI job |

---

## Thirty-second tour

```bash
argos demo
```

One command, zero arguments, about ten seconds: a static scan over the bundled
vulnerable fixture (20 findings, 5 critical), the canonical evaluation lab
(120 trials, perfectly diagonal confusion matrix), the proxy latency benchmark
(sub-100 µs p95 with all detectors) and the multi-framework compliance summary.

```bash
argos quickstart       # copy-paste recipes for every workflow
argos status           # version, rules, frameworks, controls, discovered plugins
argos <verb> --help    # every subcommand ends with working examples
```

---

## Installation

Requirements: Python 3.11 or newer (3.11 and 3.12 are exercised in CI on
Linux, macOS and Windows), and either [`uv`](https://docs.astral.sh/uv/)
(recommended) or `pip`.

### From the repository

```bash
git clone https://github.com/DiegoRodriguez-GL/A.R.G.O.S
cd A.R.G.O.S
make bootstrap         # uv sync --all-extras + pre-commit hooks
uv run argos --version
```

### From PyPI (once the first release is published)

```bash
uv pip install argos-ai-audit
# or
python -m pip install argos-ai-audit
argos --version
```

### Verify

```bash
argos status
argos compliance verify    # integrity manifest of the bundled compliance data
argos demo
```

---

## Usage

### Static scanning

```bash
argos scan ~/.config/Claude/claude_desktop_config.json
argos scan .vscode/mcp.json --severity high
argos scan config.json --rules 'MCP-SEC-DOCKER-*'
argos scan config.json --format jsonl --output findings.jsonl
argos doctor                 # auto-detect every known MCP config on this machine and scan it
argos doctor --paths         # only list the paths

# audit a server before installing it, straight from its MCP Registry entry
curl -s "https://registry.modelcontextprotocol.io/v0/servers?search=filesystem&limit=1" \
  | jq '.servers[0]' > server.json
argos scan server.json
```

The parser normalises every dialect into one `MCPConfig` model and applies
stateless rules to it. A registry `server.json` (bare or inside the API's
`{"server": ..., "_meta": ...}` envelope) is translated into the client entry
an installer would write for each package (`npx`, `uvx`, `docker run`,
`dnx`) and each remote, so the same rules audit what the client would end up
running. Defensive limits: 8 MiB per file (checked before reading),
BOM-tolerant decoding, `yaml.safe_load` only, recursion overflow converted
into a typed parser error.

| Rule | Severity | Detects |
|------|----------|---------|
| `MCP-SEC-SECRET-PATTERN` | Critical | Hard-coded credentials (GitHub, AWS, OpenAI, Anthropic, JWT, PEM, Slack, Stripe, Google) |
| `MCP-SEC-SECRET-ENTROPY` | High | Opaque env values with Shannon entropy ≥ 4.0 and length ≥ 20 (URLs without credentials, paths, user agents, e-mails and public EVM addresses excluded) |
| `MCP-SEC-TLS-PLAINTEXT` | High | `http://` URLs to a real non-loopback host (templated hosts are not judged) |
| `MCP-SEC-SHELL-PIPE` | Critical | `curl … \| sh`, `wget … \| bash` |
| `MCP-SEC-SHELL-INTERPRETER` | High | `bash -c`, `sh -c`, `pwsh -c` |
| `MCP-SEC-SHELL-DESTRUCTIVE` | High | `rm -rf /`, `mkfs`, `dd of=/dev/…`, fork bombs |
| `MCP-SEC-SHELL-EVAL` | Medium | `eval(…)`, `$(…)`, backticks |
| `MCP-SEC-DOCKER-PRIVILEGED` | Critical | `docker run --privileged` |
| `MCP-SEC-DOCKER-HOST-MOUNT` | Critical | Mounts of `/`, the whole home (`$HOME`, `~`, `%USERPROFILE%`) or a credential store under it (`~/.ssh`, `~/.aws`, `~/.kube`, ...) |
| `MCP-SEC-DOCKER-HOST-NET` | High | `--network host` |
| `MCP-SEC-SUPPLY-NPX-AUTO` | High | `npx -y` installing an unpinned package (`--package`/`-p` included) |
| `MCP-SEC-SUPPLY-UVX-AUTO` | High | `uvx` / `pipx run` installing an unpinned package (`--from` included) |
| `MCP-SEC-SUPPLY-DOCKER-TAG` | Medium | Docker image without an `@sha256:` digest |
| `MCP-SEC-FS-ROOT` | High | Filesystem server rooted at `/` or a system directory |
| `MCP-SEC-TOOL-POISON` | High | Prompt-injection phrasing in descriptions, prompts and notes |
| `MCP-SEC-ENV-SENSITIVE-KEY` | Medium | Sensitive env prefixes (`AWS_`, `OPENAI_`, `GITHUB_`, …) |
| `MCP-SEC-REMOTE-BEARER-HARDCODED` | High | A literal token in `Authorization: Bearer ...` (placeholders such as `${VAR}`, `{name}` or `<name>` are not tokens) |

Every finding carries at least one `Evidence` and a tuple of qualified
`compliance_refs` (for example `owasp_asi:ASI03`, `eu_ai_act:ART-15`) that
resolve in the compliance graph.

### Custom YAML rules

Write organisation-specific checks without Python, in a Nuclei-style DSL
validated by a published JSON Schema
(`packages/argos-rules/schema/rule.schema.json`):

```yaml
id: CUSTOM-INTERNAL-HOST-REMOTE
info:
  name: "Remote MCP server pointing at an internal corporate host"
  author: argos
  severity: high
  compliance: [owasp_asi:ASI03, csa_aicm:IAM-02, eu_ai_act:ART-15]
matchers:
  - type: regex
    part: server.url
    regex:
      - "^https?://([A-Za-z0-9.\\-]+\\.)?(corp|lan|local|internal)\\b"
```

```bash
argos rules validate ./custom_rules/
argos scan config.json --rules-dir ./custom_rules/
argos rules list -c            # compact listing of the built-ins
argos rules show MCP-SEC-SECRET-PATTERN
```

Selectors: `server.name`, `server.command`, `server.args`, `server.args[N]`,
`server.argv`, `server.url`, `server.env.<KEY>`, `server.env.*`,
`server.env.keys`, `server.headers.<KEY>`, `server.headers.*`, `server.raw`,
`server.transport`, `server.cwd`, `config.dialect`, `config.path`,
`config.raw`. Matchers: `word`, `regex`, `glob` with `condition`, `negative`
and `case-insensitive`. Resource limits (64 KiB per rule, 1000 rules per
directory, 16 matchers, 32 regexes of at most 1000 characters, no symlink
following) keep a hostile rules directory from exhausting the process.

### Red teaming

```bash
argos redteam -t http://localhost:11434/api/chat
argos redteam -t URL -p 'ASI06-*'              # filter probes by category glob
argos redteam -t URL --max-requests 200        # denial-of-wallet cap
argos redteam -t URL -f jsonl -o redteam.jsonl
```

The catalogue holds 20 probes, two per ASI category, each with a seed prompt
and a detector. Detectors: `StringMatchDetector` (needles with
`case_insensitive`, `min_payload_length` and `negations`), `RegexDetector`
(structured tokens such as CVE ids, IBANs or trace ids), `LLMJudgeDetector`
(optional; wraps the reply in an explicit data delimiter) and
`BehaviorDetector` (looks at the sequence of actions instead of the text).
Strategies: single-turn and multi-turn. The HTTP transport speaks the
`{"messages": [...]}` shape shared by OpenAI, Anthropic and most minimal
wrappers, retries transient failures with backoff, identifies itself with a
`User-Agent`, and runs probes concurrently with per-probe error isolation.

Probe ids follow the numbering of *Agentic AI: Threats and Mitigations*
(February 2025, T1 to T10 relabelled as ASI01 to ASI10). The December 2025
*Top 10 for Agentic Applications* reuses the prefix in a different order;
[`docs/asi-taxonomy-crossref.md`](docs/asi-taxonomy-crossref.md) holds the
cross-reference table.

### Audit proxy

```bash
# inside any MCP client that launches servers as commands
argos proxy wrap -- npx -y @modelcontextprotocol/server-filesystem /data
argos proxy wrap --allow-tool 'read_*' --allow-tool 'list_*' -- uvx mcp-server-git
argos proxy wrap --upstream https://mcp.example.com/mcp -H 'Authorization: env:MCP_TOKEN'

# as a TCP listener
argos proxy run -u stdio:'npx -y @modelcontextprotocol/server-filesystem /tmp'
argos proxy run -u https://mcp.example.com/mcp --allow-tool 'fs.read*' --no-pii
argos proxy run -u sse+https://mcp.example.com/sse -l 0.0.0.0:8765 --allow-external
argos proxy bench                              # latency benchmark, exit 1 above the 50 ms p95 budget
```

`wrap` is the simplest deployment: replace the server command in the client
configuration with `argos proxy wrap -- <server command>`. The client talks
to ARGOS over stdio, ARGOS launches the real server, and every message
crosses the detectors on the way. For example, in `claude_desktop_config.json`
or `.vscode/mcp.json`:

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "argos",
      "args": ["proxy", "wrap", "-f", "/var/log/argos/fs.sqlite3", "--",
               "npx", "-y", "@modelcontextprotocol/server-filesystem@2026.8.31", "/data"]
    }
  }
}
```

With `run`, point a TCP client at `127.0.0.1:8765` instead of the server.
Either way the proxy forwards every JSON-RPC 2.0 message unchanged (requests,
responses, notifications and batches, including server-initiated sampling and
elicitation requests, which are inspected too), runs the detector chain, and
writes every message and finding to a SQLite database in WAL mode.

| Detector | What it flags |
|----------|---------------|
| `ToolDriftDetector` | Pins a SHA-256 baseline of every tool on the first `tools/list`; later additions, removals or mutations raise HIGH. `mode="block"` restores the baseline definitions (rug-pull defence). |
| `PIIDetector` | Emails, IBANs (mod-97), payment cards (Luhn), Spanish DNI/NIE in requests, responses and notifications; snippets are redacted before they reach the sink. |
| `ScopeDetector` | Method and tool allowlists (globs). Out-of-scope `tools/call` is answered with `-32601` and never reaches the upstream. |

Upstream transports: stdio (newline-delimited JSON as the MCP specification
defines it, `--stdio-framing content-length` for legacy servers), TCP
(NDJSON), streamable HTTP (MCP 2025-03-26 and 2025-06-18: JSON or SSE
answers to each POST, `Mcp-Session-Id`, `MCP-Protocol-Version`, optional GET
stream, TLS with certificate verification) and legacy SSE. The HTTP/1.1 and
SSE parsers are hand-written and reject request-smuggling shapes (conflicting
`Content-Length`, `Content-Length` plus chunked encoding, oversized headers).
If a remote server fails at the HTTP level, the pending requests are answered
with a JSON-RPC error instead of leaving the client waiting. The listener
bounds concurrency (`--max-sessions`), applies per-session idle timeouts,
drains sessions gracefully on shutdown, refuses non-loopback binds unless
`--allow-external` is given, and prints one machine-readable JSON identity
line (pid, socket, upstream, forensics database) at startup.

### In-process agents (LangChain / LangGraph)

Agents that call tools in-process never cross the wire. The callback handler
translates framework events into the same JSON-RPC shapes the proxy
understands and runs them through the same detector chain, sink and
forensics store:

```python
from argos_proxy.integrations import ArgosCallbackHandler

handler = ArgosCallbackHandler(
    allowed_tools=("search", "calendar.*"),    # scope policy (globs)
    forensics_db="argos-callbacks.sqlite3",     # optional SQLite trail
    enforce=False,                              # observe only (default)
)
result = agent.invoke({"input": "book a room"}, config={"callbacks": [handler]})
handler.close()
for finding in handler.findings:
    print(finding.detector_id, finding.severity, finding.message)
```

`enforce=True` raises `ArgosPolicyViolationError` from `on_tool_start` for
tools outside the allowlist, before the tool runs. Use
`AsyncArgosCallbackHandler` with `ainvoke`. `langchain-core` is optional: the
handlers subclass its base classes when it is installed and expose the same
attribute surface otherwise.

### Reports

```bash
argos report findings.jsonl -o report.html
argos report findings.jsonl -o report.html --no-redact --yes
argos report --demo
```

A single HTML file with no external assets: cover, executive summary by
severity and ASI category, cross-framework compliance matrix, one card per
finding with evidence and remediation, methodology appendix and a print
stylesheet. The document ships with `Content-Security-Policy: default-src
'none'`, `X-Content-Type-Options: nosniff` and `referrer: no-referrer`, so a
compromised report opened in a browser cannot start outbound requests.
Credentials (OpenAI, Anthropic, GitHub, Google, AWS, Slack, Stripe, JWT,
bearer values, PEM blocks) and emails are masked in every free-text field by
default; `--no-redact` asks for confirmation.

### Compliance graph

```bash
argos compliance list
argos compliance show owasp_asi:ASI01
argos compliance show iso_42001:A.6.2.8
argos compliance map owasp_asi:ASI03
argos compliance verify        # exit 1 on modified, missing or unlisted data files
```

### Evaluation lab

```bash
argos eval
argos eval --json out.json --markdown out.md --csv out.csv --output eval.html
uv run python scripts/canonical_eval.py
```

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | Success; for `scan`, no HIGH or CRITICAL findings |
| 1 | `scan`: HIGH/CRITICAL present; `proxy bench`: latency budget missed; `compliance verify`: data drifted; `report --no-redact`: aborted |
| 2 | Invalid arguments or unparseable input |

---

## Architecture

ARGOS is a monorepo of eight independently publishable Python packages. No
package imports upwards; `argos-core` is the sink of the dependency graph.
Two horizontal edges are documented: `argos-scanner` uses `argos-rules`
(optional YAML rules in the same `ScanResult`) and `argos-eval` implements the
`AgentTransport` contract of `argos-redteam`.

```
                         ┌─────────────────────────┐
                         │        argos-cli        │  single entry point (Typer + rich)
                         └────────────┬────────────┘
          ┌───────────┬───────────┬───┴──────┬───────────┬───────────┐
  ┌───────▼─────┐ ┌───▼─────┐ ┌───▼─────┐ ┌──▼───────┐ ┌─▼───────┐ ┌─▼───────┐
  │argos-scanner│ │argos-   │ │argos-   │ │argos-    │ │argos-   │ │argos-   │
  │  (static)   │ │redteam  │ │proxy    │ │reporter  │ │eval     │ │rules    │
  └───────┬─────┘ └───┬─────┘ └───┬─────┘ └──┬───────┘ └─┬───────┘ └─▲───────┘
          └───────────┴───────────┴────┬─────┴───────────┘           │ (optional)
                                       ▼                             │
                            ┌──────────────────────┐                 │
                            │      argos-core      │◀────────────────┘
                            │ models · interfaces  │
                            │ compliance · redaction│
                            │ telemetry            │
                            └──────────────────────┘
```

| Package | Responsibility |
|---------|----------------|
| `argos-core` | Frozen Pydantic models (`Finding`, `Evidence`, `Target`, `Severity`, `ScanResult`), plugin ABCs, CSA autonomy taxonomy and CBRA risk score, compliance data with integrity manifest, shared redaction, OpenTelemetry bootstrap |
| `argos-cli` | The `argos` command, entry-point plugin discovery |
| `argos-scanner` | Multi-dialect MCP config parser and 17 built-in rules |
| `argos-rules` | Nuclei-style YAML rule engine with published JSON Schema |
| `argos-redteam` | 20 probes, four detector families, two strategies, HTTP and mock transports, concurrent runner |
| `argos-proxy` | JSON-RPC 2.0 layer, four transports, listener, interceptor chain, three detectors, SQLite forensics, OTel spans, LangChain callback |
| `argos-reporter` | Jinja2 HTML reports with strict CSP, redaction and compliance matrix; evaluation reports |
| `argos-eval` | Six lab agents, ground truth, async runner, metrics with Wilson and bootstrap intervals, JSON/Markdown/CSV/HTML exports, report diffing |

Key patterns: immutable models that reject unknown fields; pluggable
transports behind a three-method abstraction; one upstream factory per
session so detector state never leaks between clients; a middleware-style
interceptor chain where a policy veto becomes a JSON-RPC error and an
unexpected detector exception falls back to pass-through; WAL-mode SQLite
with a single writer and concurrent readers. The full C4 description lives in
[`docs-internal/ARCHITECTURE.md`](docs-internal/ARCHITECTURE.md).

---

## Compliance mapping

The compliance graph ships as data, not prose. OWASP ASI is the hub and four
frameworks are satellites; ten N:M mapping entries (one per ASI threat) carry
the target controls, a rationale and a confidence level.

| Framework | Controls | Coverage |
|-----------|----------|----------|
| OWASP Agentic Security Initiative | 24 | 10 top-level threats plus operational refinements |
| CSA AI Controls Matrix v1.0 | 21 | AI-specific subset |
| EU AI Act (Regulation 2024/1689) | 16 | Articles 9 to 15, Annex III, Annex IV |
| NIST AI RMF 1.0 | 25 | GOVERN / MAP / MEASURE / MANAGE |
| ISO/IEC 42001:2023 | 39 | Annex A (original summaries, no verbatim text) |

Seven invariants are verified in CI on every push: at least three
cross-framework controls per ASI threat, at least four non-hub frameworks per
mapping entry, every reference resolves, every parent resolves within its
framework, ids are unique per framework, the hub is declared, and every ASI
threat is a mapping source. A `MANIFEST.sha256` next to the data files is
checked on every load (a `ComplianceIntegrityWarning` is raised on drift) and
on demand with `argos compliance verify`. Regenerate it after editing the
data with `python scripts/build_compliance_manifest.py`.

Severity alone does not prioritise well: a critical finding in an assistive
agent matters less than a medium one in an autonomous agent. The CBRA score
(Capability-Based Risk Attribution) weights severity by the CSA autonomy level
(L0 to L5), exposure to untrusted input, plausible blast radius and
reversibility. See [`apps/docs/docs/methodology/index.md`](apps/docs/docs/methodology/index.md).

---

## Empirical results

The evaluation lab answers two questions with a fully reproducible benchmark:
does ARGOS detect every attack a vulnerable agent exposes (sensitivity), and
does it stay silent on a hardened version of the same agent (specificity)?
Six deterministic agents (ReAct with MCP tools, LangGraph supervisor-worker,
memory + RAG, each in a vulnerable and a hardened variant) are exercised
against all 20 probes: 120 trials, byte-identical across runs.

| Metric | Value | Wilson 95 % CI |
|--------|-------|----------------|
| TP / FP / TN / FN | 20 / 0 / 100 / 0 | |
| Precision, recall | 100 % | [83.89 %, 100 %] |
| Specificity | 100 % | [96.30 %, 100 %] |
| Accuracy | 100 % | [96.90 %, 100 %] |
| F1 / MCC | 1.0 / +1.0 | |

| Proxy latency (2000 round-trips, in-memory transport) | p95 | p99 | max |
|--------------------------------------------------------|-----|-----|-----|
| Without detectors | 0.029 ms | 0.041 ms | 0.135 ms |
| With drift + PII + scope detectors | 0.054 ms | 0.065 ms | 0.195 ms |

The operational budget is 50 ms at p95; the detector chain adds about
25 µs per round-trip. The confusion matrix is pinned by
`packages/argos-eval/tests/test_canonical_metrics.py`; any drift is a CI
failure. Methodology, threats to validity and the transferability plan are in
[`docs/empirical-evaluation.md`](docs/empirical-evaluation.md).

### Real-world validation

The lab proves ARGOS does what its author imagined; the ecosystem proves
whether that is what happens outside. Three campaigns against published
artefacts ([`benchmarks/real-world`](benchmarks/real-world),
[`docs/real-world-validation.md`](docs/real-world-validation.md)):

| Campaign | Result |
|----------|--------|
| Official MCP Registry, 30,871 `server.json` entries scanned | 0 crashes; manually validated precision 57.1 % with the original rules, 99.0 % after fixing their false-positive causes, every true positive kept |
| 7 official reference servers (npm, PyPI) through `argos proxy wrap` | All sessions succeed; 0.03 to 0.84 ms added per request at the median; PII, drift and scope detectors fire on real traffic |
| 9 public remote servers over HTTPS (Microsoft Learn, AWS Knowledge, Cloudflare docs, Hugging Face, DeepWiki, ...) | All 7 anonymous servers work through the proxy; the 2 OAuth-protected ones are answered with a JSON-RPC error instead of a hang |

The first contact failed: seven interoperability defects (stdio framing,
Windows launchers, lost messages, a non-conforming streamable-HTTP client,
`params: null`, printed IBANs, stderr handling) and one deployment gap (no
mode a real client could use) had passed every lab test, because the lab
fixtures shared the code's assumptions. All are fixed and pinned by
regression tests, and the official MCP Inspector client now runs through
`argos proxy wrap` unchanged.

---

## Security of ARGOS itself

A security tool is a target. [`docs-internal/THREAT_MODEL.md`](docs-internal/THREAT_MODEL.md)
models nine STRIDE threats against ARGOS, each with implemented controls
pinned by tests:

| Threat | Control |
|--------|---------|
| Malicious configuration (YAML tag abuse, deep nesting) | `yaml.safe_load` only, 8 MiB cap, recursion overflow converted to a parser error |
| Prompt injection through scanned text | HTML autoescape, data delimiters around judge prompts, control characters rejected in every finding field |
| Compromised plugin | `producer` on every finding, plugin inventory in `argos status`, first-party components never loaded through entry points |
| Tampered compliance data | `MANIFEST.sha256` verified on every load, `argos compliance verify`, integrity invariants in CI |
| Supply chain | Actions pinned by SHA, `uv.lock` with frozen installs, Dependabot, hardened runners, Trusted Publishers + SLSA provenance on release |
| Report exfiltration | Local files only, redaction on by default, strict CSP, no referrer, no telemetry without an explicit OTLP endpoint |
| Proxy man-in-the-middle | Loopback-only bind unless `--allow-external`, JSON identity line, anti-smuggling checks in HTTP and SSE |
| Arbitrary local writes | Output paths only from explicit flags, never derived from scanned content |
| Hostile in-process agent | Text truncated before detection and persistence, detector faults isolated, blocking only with `enforce=True` |

Report vulnerabilities through GitHub's private advisory flow; see
[`SECURITY.md`](SECURITY.md).

---

## Development

```bash
make bootstrap        # install everything + pre-commit hooks
make ci               # ruff check + ruff format --check + mypy --strict + pytest with coverage
make test-fast        # pytest without coverage
make tokens           # regenerate design-system/tokens.{css,py,ts} from tokens.json
python scripts/argos_self_audit.py            # dogfooding run with a Markdown report
python scripts/build_compliance_manifest.py   # after editing compliance data
```

Quality gates enforced in CI (Linux, macOS, Windows × Python 3.11, 3.12):

- `ruff` with 35 rule families, zero warnings; `ruff format --check`.
- `mypy --strict` over every package, zero errors.
- `pytest` with a 70 % coverage floor (measured: 89.7 % of statements, 1,473 tests),
  including property-based tests with Hypothesis and adversarial audit suites.
- Design tokens generated from a single source and diffed in CI.
- CodeQL (weekly and per push), OpenSSF Scorecard, `gitleaks` in pre-commit.
- A `self-audit` job that runs every CLI verb against the repository and
  uploads the report as a build artefact.
- Release workflow with PyPI Trusted Publishers (OIDC) and SLSA build
  provenance; every GitHub Action pinned by commit SHA.

The engineering method is the same for every module: models and interfaces
first, implementation, unit and property tests, an adversarial audit pass
whose findings become regression tests that fail before the fix and pass
after it, then documentation. Sixteen real defects were found and fixed that
way; each has a permanent regression guard.

Design tokens live in [`design-system/tokens.json`](design-system/tokens.json)
and generate to CSS, Python and TypeScript via `make tokens`. Do not edit the
generated files. Visual conventions are in
[`design-system/DESIGN_SYSTEM.md`](design-system/DESIGN_SYSTEM.md).

---

## Project layout

```
argos/
├── packages/
│   ├── argos-core/        models, interfaces, compliance data + manifest, redaction, telemetry
│   ├── argos-cli/         `argos` command and plugin discovery
│   ├── argos-scanner/     MCP config parser and built-in rules
│   ├── argos-rules/       YAML rule engine and JSON Schema
│   ├── argos-redteam/     probes, detectors, strategies, transports, runner
│   ├── argos-proxy/       JSON-RPC layer, transports, listener, detectors, forensics, OTel, LangChain callback
│   ├── argos-reporter/    Jinja2 HTML reports
│   └── argos-eval/        lab agents, ground truth, metrics, intervals, exports
├── apps/
│   ├── docs/              MkDocs Material site (getting started, one page per module, CLI and API reference)
│   └── landing/           static landing page
├── design-system/         tokens.json and generated tokens.{css,py,ts}
├── docs/                  public methodology notes (empirical evaluation, ASI cross-reference)
├── docs-internal/         architecture brief, threat model, RFCs
├── examples/              lab agent scenarios and callback usage
├── scripts/               self-audit harness, canonical evaluation, token and manifest builders
├── tests/                 cross-package invariants
└── .github/workflows/     ci, codeql, scorecard, release, docs
```

---

## Roadmap

- **0.1.0 on PyPI** through the existing Trusted Publishers workflow.
- **Hosted documentation and landing** via the `docs.yml` workflow (GitHub Pages).
- **Transferability study** against live LLM endpoints with a thin transport adapter and the existing request cap.
- **More runtime detectors**: additional PII jurisdictions, judge-based prompt-injection detection, per-client rate limiting.
- **OAuth 2.1 for protected remote servers** (today a bearer token can be passed with `--header`), and a streamable-HTTP listener for clients that only speak HTTP.
- **Secret patterns in headers and arguments**, not only in `env` (a gap found while auditing the MCP Registry).
- **Periodic registry audit** in CI against a fresh snapshot of the official MCP Registry.
- **Signed manifest of first-party plugin hashes** once an external plugin ecosystem exists.
- **Empirical calibration of the CBRA weights** from documented agentic incidents.

---

## Contributing

Issues and pull requests are welcome. Read [`CONTRIBUTING.md`](CONTRIBUTING.md)
for the workflow (Conventional Commits, RFCs for architectural changes,
`make ci` before review) and [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md).

---

## License

[AGPL-3.0-or-later](LICENSE). If you deploy ARGOS as a service, you must make
the modified source available under the same license.
