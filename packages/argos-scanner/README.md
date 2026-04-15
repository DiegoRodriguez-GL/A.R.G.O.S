# argos-scanner

Static scanner for Model Context Protocol (MCP) configurations.

Recognises three dialects (`claude_desktop_config.json`, VS Code
`.vscode/mcp.json`, draft `mcp.json`), normalises them to a single
`MCPConfig` model and applies seventeen built-in rules.

## Built-in rules

| Rule id                           | Severity  | What it catches                                           |
| --------------------------------- | --------- | --------------------------------------------------------- |
| `MCP-SEC-SECRET-PATTERN`          | Critical  | Hardcoded credentials matching well-known formats         |
| `MCP-SEC-SECRET-ENTROPY`          | High      | High-entropy env values that look like opaque tokens      |
| `MCP-SEC-TLS-PLAINTEXT`           | High      | Remote server over plaintext HTTP                         |
| `MCP-SEC-SHELL-PIPE`              | Critical  | `curl ... | sh`-style pipe-to-shell                       |
| `MCP-SEC-SHELL-INTERPRETER`       | High      | Shell interpreter with inline `-c` script                 |
| `MCP-SEC-SHELL-DESTRUCTIVE`       | High      | `rm -rf /`, `dd of=/dev/...`, `mkfs` patterns             |
| `MCP-SEC-SHELL-EVAL`              | Medium    | eval / backticks / `$(...)` substitution                  |
| `MCP-SEC-DOCKER-PRIVILEGED`       | Critical  | docker/podman run `--privileged`                          |
| `MCP-SEC-DOCKER-HOST-MOUNT`       | Critical  | Host `/`, `$HOME`, `%USERPROFILE%` mounted into container |
| `MCP-SEC-DOCKER-HOST-NET`         | High      | `--network host`                                          |
| `MCP-SEC-SUPPLY-DOCKER-TAG`       | Medium    | Docker image pinned by mutable tag instead of digest      |
| `MCP-SEC-FS-ROOT`                 | High      | `server-filesystem` rooted at a dangerous top-level path  |
| `MCP-SEC-SUPPLY-NPX-AUTO`         | High      | `npx -y` on an unpinned package                           |
| `MCP-SEC-SUPPLY-UVX-AUTO`         | High      | `uvx`/`pipx` on an unpinned PyPI package                  |
| `MCP-SEC-TOOL-POISON`             | High      | Prompt-injection phrasing inside tool metadata            |
| `MCP-SEC-ENV-SENSITIVE-KEY`       | Medium    | AWS/GCP/OpenAI/GitHub/... sensitive env prefixes          |
| `MCP-SEC-REMOTE-BEARER-HARDCODED` | High      | Remote server pins a literal bearer token in a header     |

Each finding carries `compliance_refs` that resolve in the Module 1
cross-framework mapping (OWASP ASI, CSA AICM, EU AI Act, NIST AI RMF,
ISO/IEC 42001).

## Usage

```bash
argos scan config.json                        # table output, exit 1 on HIGH+
argos scan config.json --severity high        # filter to HIGH and above
argos scan config.json --rules 'MCP-SEC-SECRET-*'
argos scan config.json --format jsonl --output findings.jsonl
```

## Exit codes

| Code | Meaning                                              |
| ---- | ---------------------------------------------------- |
| 0    | No findings, or only INFO / LOW / MEDIUM             |
| 1    | At least one HIGH or CRITICAL finding                |
| 2    | Parser error or unsupported dialect                  |

## License

AGPL-3.0-or-later.
