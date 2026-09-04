# Security

ARGOS is a security tool, so it is also a target. The full self threat model
lives in `docs-internal/THREAT_MODEL.md`; this page summarises the controls
an operator relies on.

| Threat | Control |
|--------|---------|
| Malicious configuration (YAML tag abuse, deep nesting) | `yaml.safe_load` only, 8 MiB cap, `RecursionError` converted to a parser error |
| Prompt injection through scanned text | HTML autoescape in reports, data delimiters around judge prompts, control characters rejected in every finding field |
| Compromised plugin | `producer` on every finding, plugin inventory with distribution and version in `argos status`, first-party components never loaded through entry points |
| Tampered compliance data | `MANIFEST.sha256` verified on every load, `argos compliance verify` exit code, integrity invariants in CI |
| Supply chain | Pinned actions by SHA, `uv.lock` with frozen installs, Dependabot, hardened runners, Trusted Publishers and SLSA provenance on release |
| Report exfiltration | Local files only, redaction on by default, strict CSP, no referrer, no telemetry without an explicit OTLP endpoint |
| Proxy man-in-the-middle | Loopback-only bind unless `--allow-external`, JSON identity line with pid and socket, anti-smuggling checks in HTTP/SSE |
| Hostile in-process agent (callback) | Text truncation before detection, detector faults isolated from the agent, blocking only with `enforce=True` |

## Reporting a vulnerability

Use GitHub's private vulnerability reporting for the repository:
<https://github.com/DiegoRodriguez-GL/A.R.G.O.S/security/advisories/new>.
Do not open public issues for security problems. The full policy, response
targets and safe-harbour statement are in `SECURITY.md`.
