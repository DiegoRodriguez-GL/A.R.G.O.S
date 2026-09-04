# Static scanner (`argos-scanner`)

The scanner reads MCP client configurations and applies rules to the
normalised model. It never executes anything from the configuration.

## Supported dialects

| Dialect | Detection | Example file |
|---------|-----------|--------------|
| `claude-desktop` | top-level `mcpServers` | `claude_desktop_config.json` |
| `vscode` | `servers` plus `inputs` | `.vscode/mcp.json` |
| `mcp-spec` | `servers` without `inputs` | `mcp.json` |

Every server is normalised to `MCPServer` (name, transport, command, args,
env, cwd, url, headers, raw) inside an `MCPConfig`. Vendor-specific fields are
preserved in `raw` so rules can still reach them.

## Defensive limits

- 8 MiB maximum file size, checked before reading.
- `utf-8-sig` decoding (tolerates Windows BOMs).
- `yaml.safe_load` only; `RecursionError` on deeply nested documents is
  converted into a `ParserError`.
- Non-scalar `env` values and malformed `args` / `headers` are rejected.

## Built-in rules

| Rule | Severity | Detects |
|------|----------|---------|
| `MCP-SEC-SECRET-PATTERN` | Critical | Hard-coded credentials (GitHub, AWS, OpenAI, Anthropic, JWT, PEM, Slack, Stripe, Google) |
| `MCP-SEC-SECRET-ENTROPY` | High | Opaque env values with Shannon entropy >= 4.0 and length >= 20 |
| `MCP-SEC-TLS-PLAINTEXT` | High | Non-loopback `http://` URLs |
| `MCP-SEC-SHELL-PIPE` | Critical | `curl ... | sh` and friends |
| `MCP-SEC-SHELL-INTERPRETER` | High | `bash -c`, `sh -c`, `pwsh -c` |
| `MCP-SEC-SHELL-DESTRUCTIVE` | High | `rm -rf /`, `mkfs`, `dd of=/dev/...`, fork bombs |
| `MCP-SEC-SHELL-EVAL` | Medium | `eval(...)`, `$(...)`, backticks |
| `MCP-SEC-DOCKER-PRIVILEGED` | Critical | `docker run --privileged` |
| `MCP-SEC-DOCKER-HOST-MOUNT` | Critical | `-v /:/host`, `$HOME` or `%USERPROFILE%` mounts |
| `MCP-SEC-DOCKER-HOST-NET` | High | `--network host` |
| `MCP-SEC-SUPPLY-NPX-AUTO` | High | `npx -y <pkg>` without a pin |
| `MCP-SEC-SUPPLY-UVX-AUTO` | High | `uvx` / `pipx` without a pin |
| `MCP-SEC-SUPPLY-DOCKER-TAG` | Medium | Docker image without `@sha256:` digest |
| `MCP-SEC-FS-ROOT` | High | Filesystem server rooted at `/` or a system directory |
| `MCP-SEC-TOOL-POISON` | High | Prompt-injection phrasing in descriptions, prompts, notes |
| `MCP-SEC-ENV-SENSITIVE-KEY` | Medium | Sensitive env prefixes (`AWS_`, `OPENAI_`, `GITHUB_`, ...) |
| `MCP-SEC-REMOTE-BEARER-HARDCODED` | High | Literal `Bearer <token>` in `headers.Authorization` |

Rules are stateless visitors registered with `@register`; `argos rules list`
and `argos rules show <id>` print their metadata and compliance references.

## Usage

```bash
argos scan config.json
argos scan config.json --severity high
argos scan config.json --rules 'MCP-SEC-DOCKER-*'
argos scan config.json --format jsonl --output findings.jsonl
argos scan config.json --rules-dir ./custom_rules/     # add YAML rules
```

Every finding carries at least one `Evidence` (source range or raw snippet)
and a tuple of `compliance_refs` that resolve in the compliance graph. On the
bundled `risky.claude_desktop.json` fixture the scanner produces 20 findings
(5 critical, 12 high, 3 medium) across nine ASI categories.
