# ARGOS -- Self Threat Model

**Revision:** 0.1 (Module 0)
**Status:** Living document. Every module delta must revisit the relevant
entry and either update the control or file a deviation RFC.
**Scope:** ARGOS as a *target*. Threats to the systems ARGOS audits are covered
by the product requirements, not this document.

ARGOS ships to auditors who run it with elevated expectations: they will use
its findings to decide whether to deploy an agent in production. If ARGOS is
compromised, the blind spot it creates is asymmetric. Self-defense is
therefore a first-class product requirement, not a background concern.

## 1. Assets

| ID   | Asset                              | Confidentiality | Integrity | Availability |
| ---- | ---------------------------------- | :-------------: | :-------: | :----------: |
| A1   | MCP configurations under audit     | Medium          | High      | Low          |
| A2   | Captured request/response pairs    | High            | High      | Low          |
| A3   | Findings and report artefacts      | Medium          | High      | Medium       |
| A4   | Compliance mapping data            | Low             | High      | Medium       |
| A5   | ARGOS binaries and wheels          | Low             | Critical  | Medium       |
| A6   | User credentials / tokens (when provided for probing) | Critical | High | Low |

## 2. Trust boundaries

```
┌──────────── Auditor machine ────────────┐     ┌────── Audited agent ──────┐
│  CLI / shell   --→   argos-cli          │     │                           │
│                       │                 │     │                           │
│                       ├→ argos-scanner  │     │                           │
│                       ├→ argos-redteam ──HTTP/JSON-RPC→ agent endpoint    │
│                       ├→ argos-proxy  ←─MCP bi-directional traffic→  MCP │
│                       ├→ argos-reporter → report.html (local fs)         │
│                       └→ argos-core                                       │
└────────────────────────────────────────┘     └──────────────────────────┘
         ▲                                             ▲
         │ untrusted YAML / JSON inputs                │ untrusted MCP payloads
```

Every arrow crossing the double border is an untrusted input boundary.

## 3. Threats (STRIDE against each asset)

### T1. Malicious MCP configuration (targets A1, A5)

Input: YAML/JSON crafted by an adversary, parsed by `argos-scanner`.

- **Spoofing:** A config claims false tool identity to evade an allow-list.
  *Control:* rules treat tool identity as opaque; allow-lists hash the full
  tool definition (see Module 2 RFC-002).
- **Tampering:** A config exploits a YAML parser quirk (tag abuse,
  `!!python/object`) to execute code.
  *Control:* scanner uses `yaml.safe_load` exclusively; `yaml.load` is banned
  via `ruff` `S506`.
- **Denial:** Deeply nested JSON blows the stack.
  *Control:* JSON is parsed with the standard library's iterative decoder;
  reject payloads over a configurable size (default 8 MiB).

### T2. Prompt injection via scanned artefacts (target A2, A6)

The scanner reads tool descriptions, resource URIs, and prompt templates.
Malicious text inside them may be designed to manipulate the operator's LLM
later, or to trick LLM-judge evaluators used by the red-team module.

- *Control:* when content is displayed in reports it is HTML-escaped (Jinja2
  autoescape + StrictUndefined). When content is passed to an LLM judge it is
  wrapped in an unambiguous delimiter and the judge prompt states explicitly
  that everything inside the delimiter is data, not instruction. See Module 4
  RFC-004 for the judge envelope.

### T3. Compromised plugin (targets A3, A5)

ARGOS loads plugins via entry points. A malicious package installed in the
auditor's environment can emit false negatives.

- *Control:* plugin discovery records the entry-point distribution name and
  version in every emitted finding's `producer` field; reports list all active
  plugins with their pinned versions.
- *Control:* core ships with a signed manifest of first-party plugin hashes.
  CI fails the release if the manifest drifts.

### T4. Tampered compliance data (target A4)

If the YAML under `argos_core/compliance/data` is modified, reports lose the
cross-framework guarantees that auditors rely on.

- *Control:* the compliance loader checks the file digests against a manifest
  shipped with the wheel. Modifications result in a loud runtime warning and a
  non-zero exit in `--strict-compliance` mode.

### T5. Supply-chain attack on dependencies (target A5)

A typosquat or compromised maintainer upstream injects a backdoor.

- *Control:* minimum pinning in every `pyproject.toml`; Dependabot grouped
  updates reviewed weekly; `uv.lock` committed; release workflow uses PyPI
  Trusted Publishers (OIDC), no long-lived tokens.

### T6. Report exfiltration (targets A2, A3, A6)

Reports may contain captured credentials or customer data. Shipping them to a
third party by mistake is a confidentiality breach.

- *Control:* reports are local files. No telemetry is emitted unless an OTLP
  endpoint is explicitly configured. The default OpenTelemetry setup uses an
  in-process no-op exporter (see `argos_core.telemetry`).
- *Control:* the reporter redacts fields matching configured patterns (emails,
  bearer tokens, AWS access keys) before rendering. Opt-out requires an
  explicit `--no-redact` flag plus a confirmation prompt.
- *Control:* reports ship with a strict `Content-Security-Policy` meta tag
  (`default-src 'none'`; `style-src 'unsafe-inline'` only; no external
  origins), `referrer: no-referrer`, and `X-Content-Type-Options: nosniff`.
  Opening a compromised report in a browser cannot trigger outbound
  requests.

### T7. Proxy-man-in-the-middle (targets A1, A2, A6)

The audit proxy sits between an agent and its MCP servers. A rogue process
binding to the proxy's port could impersonate it.

- *Control:* default bind is loopback only. Wider binding requires `--allow-external`
  and a warning banner.
- *Control:* the proxy logs a machine-readable identity line on startup with
  its pid and listening socket so the operator can audit the socket owner.

### T8. Local-file write abuse (target A3)

Report generation writes arbitrary paths supplied by the user.

- *Control:* output paths are resolved with `Path.resolve(strict=False)`;
  paths traversing outside `cwd` must be passed explicitly through `--output`
  and cannot arise from scanned data.

## 4. Non-goals

- ARGOS does not defend against a compromised auditor workstation. Once an
  attacker is root on your machine, our trust boundary is gone. We do limit
  the blast radius (no lateral expansion through ARGOS), but we do not claim
  runtime attestation.
- ARGOS does not attempt to certify the *audited* agent. It reports evidence;
  the certification process is outside scope.

## 5. Review cadence

- Every new module opens a PR that includes a "threats delta" section.
- A full re-read of this document happens at the end of Modules 2, 4, 5 and
  before cutting `v1.0.0`.
- External review requested once before defending the TFM.
