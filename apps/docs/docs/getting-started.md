# Getting started

## Requirements

- Python 3.11 or newer (3.11, 3.12 are exercised in CI on Linux, macOS and
  Windows).
- `uv` (recommended) or `pip`.

## Install

Until the first PyPI release, install from a clone:

```bash
git clone https://github.com/DiegoRodriguez-GL/A.R.G.O.S
cd A.R.G.O.S
make bootstrap        # uv sync --all-extras + pre-commit hooks
uv run argos --version
```

Once published, the same tool is one command away:

```bash
uv pip install argos-ai-audit
argos --version
```

## The guided tour

```bash
argos demo
```

`argos demo` runs every capability against fixtures bundled with the package:
a static scan over a deliberately vulnerable Claude Desktop configuration
(20 findings, 5 critical), the canonical evaluation lab (120 trials, perfect
confusion matrix), the proxy latency benchmark and the compliance summary.
It takes about ten seconds and needs no arguments.

`argos quickstart` prints a cheat sheet of the most common workflows;
`argos status` shows what is loaded (rules, frameworks, plugins).

## First real scan

Point ARGOS at any MCP client configuration:

```bash
argos scan ~/.config/Claude/claude_desktop_config.json
argos scan .vscode/mcp.json --severity high --format jsonl --output findings.jsonl
```

Or let it find them:

```bash
argos doctor            # auto-detect and scan every known config path
argos doctor --paths    # only list the paths
```

Exit code `1` means at least one HIGH or CRITICAL finding, `2` means the
input could not be parsed. Both are designed for CI gates.

## From findings to a report

```bash
argos report findings.jsonl -o report.html
```

The report is a single HTML file with no external assets, a strict
Content-Security-Policy and a print stylesheet. Credentials and emails in the
evidence are masked by default; `--no-redact --yes` disables that when you
really need the raw values.

## Auditing a running agent

```bash
# Red-team an HTTP chat endpoint (OpenAI / Anthropic compatible payloads).
argos redteam -t http://localhost:11434/api/chat --max-requests 200

# Put the audit proxy between your MCP client and a stdio server.
argos proxy run -u stdio:'npx -y @modelcontextprotocol/server-filesystem /tmp'
```

Then configure the client to talk to `127.0.0.1:8765` instead of the server.
Every message is recorded in `argos-proxy.sqlite3`; detector findings appear
in the same database.

## Reproduce the empirical results

```bash
argos eval --json out.json --markdown out.md --output eval.html
```

The numbers are pinned by a regression test, so any drift between your run
and the documented matrix is a bug worth reporting.
