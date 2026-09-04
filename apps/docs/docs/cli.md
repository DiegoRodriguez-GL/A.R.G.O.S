# CLI reference

Every subcommand ends its `--help` with an *Examples* section. This page is
the condensed map.

## Onboarding

| Command | Purpose |
|---------|---------|
| `argos demo` | Ten-second guided tour of every capability |
| `argos quickstart` | Cheat sheet of common workflows |
| `argos status` | Version, rules, frameworks, controls, discovered plugins |
| `argos --version`, `argos --help` | |

## Audit

| Command | Key options |
|---------|-------------|
| `argos scan <config>` | `--severity`, `--rules <glob>`, `--rules-dir <dir>`, `--format table|jsonl`, `--output` |
| `argos doctor` | `--paths` (list only) |
| `argos redteam -t <url>` | `-p <probe-glob>`, `--strategy single-turn|multi-turn`, `--max-requests`, `--format`, `--output` |
| `argos proxy run -u <upstream>` | `--listen host:port`, `--allow-external`, `--forensics-db`, `--otel/--no-otel`, `--drift/--no-drift`, `--pii/--no-pii`, `--allow-tool <glob>`, `--max-sessions`, `--idle-timeout`, `--drain-timeout`, `--duration` |
| `argos proxy bench` | `-n <iterations>`, `--budget-ms`, `--detectors/--no-detectors` |
| `argos eval` | `--json`, `--markdown`, `--csv`, `--output <html>` |
| `argos report <findings>` | `-o <html>`, `--redact/--no-redact`, `--yes`, `--demo` |

## Catalogue and compliance

| Command | Purpose |
|---------|---------|
| `argos rules list [-c] [-s sev] [-m glob] [-f framework]` | Built-in rule catalogue |
| `argos rules show <id>` | One rule in full |
| `argos rules validate <file-or-dir>` | Validate YAML rules without running them |
| `argos compliance list` | Loaded frameworks and control counts |
| `argos compliance show <qid>` | One control |
| `argos compliance map <qid>` | Mapping entries touching a control |
| `argos compliance verify` | Integrity manifest check (exit 1 on drift) |

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | Success; for `scan`, no HIGH or CRITICAL findings |
| 1 | `scan`: HIGH/CRITICAL present; `proxy bench`: budget missed; `compliance verify`: drift; `report --no-redact`: aborted |
| 2 | Invalid arguments or unparseable input |

## Upstream URL forms for the proxy

```
stdio:<argv>                         stdio:'npx -y @modelcontextprotocol/server-filesystem /tmp'
tcp:<host>:<port>                    tcp:127.0.0.1:9000
http://<host>:<port>/<path>          http://localhost:9000/mcp      (streamable-HTTP)
sse://<host>:<port>/<sse>[#<post>]   sse://localhost:9000/sse        (legacy SSE)
```
