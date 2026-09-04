# YAML rules (`argos-rules`)

Auditors write organisation-specific checks without touching Python. The DSL
is inspired by Nuclei: a rule is an `id`, an `info` block, `matchers` and
optional `extractors`, validated against a published JSON Schema
(`packages/argos-rules/schema/rule.schema.json`).

## Example

```yaml
id: CUSTOM-INTERNAL-HOST-REMOTE
info:
  name: "Remote MCP server pointing at an internal corporate host"
  author: argos
  severity: high
  description: >
    The server url resolves to an internal hostname (internal.example.com,
    *.corp, *.lan, *.local).
  remediation: >
    Route the agent's MCP traffic through the ARGOS proxy and restrict
    internal URLs to an approved allowlist.
  compliance:
    - owasp_asi:ASI03
    - owasp_asi:ASI03-01
    - csa_aicm:IAM-02
    - eu_ai_act:ART-15
  tags: [network, ssrf, internal]

matchers:
  - type: regex
    part: server.url
    regex:
      - "^https?://([A-Za-z0-9.\\-]+\\.)?(corp|lan|local|internal)\\b"
      - "^https?://internal\\.[A-Za-z0-9.\\-]+"
```

## Selectors (`part`)

`server.name`, `server.command`, `server.args`, `server.args[N]`,
`server.argv`, `server.url`, `server.env.<KEY>`, `server.env.*`,
`server.env.keys`, `server.headers.<KEY>`, `server.headers.*`, `server.raw`,
`server.transport`, `server.cwd`, `config.dialect`, `config.path`,
`config.raw`. A selector that does not resolve yields an empty list, never an
error, so a typo cannot crash a scan.

## Matchers and extractors

- Matchers: `word`, `regex`, `glob`; each supports `condition: or|and`,
  `negative: true` and (word / regex) `case-insensitive: true`.
  `matchers-condition` combines matchers.
- Extractors: `regex` (with capture groups) and `word`; they capture the
  concrete snippet that becomes the finding's evidence.

## Limits

| Limit | Value |
|-------|-------|
| Rule file size | 64 KiB |
| Rules per directory | 1000 |
| Matchers / extractors per rule | 16 / 8 |
| Words / regexes per matcher | 64 / 32 |
| Regex length | 1000 chars |
| Extractor hits / chars per hit | 16 / 256 |

Regexes compile at load time (shared cache), symlink loops are refused and
directory walks never follow links.

## Commands

```bash
argos rules validate ./custom_rules/        # parse and validate only
argos scan config.json --rules-dir ./custom_rules/
argos rules list -c                         # compact listing of built-ins
```

Findings from YAML rules carry `producer="argos-rules"` and the same shape as
built-in findings, so reports and compliance mapping treat them identically.
Five example rules live in `packages/argos-rules/examples/`.
