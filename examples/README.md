# examples/

Executable examples that show ARGOS against realistic inputs. The three
agent scenarios named in the proposal (single ReAct agent, LangGraph
supervisor-worker, persistent-memory agent) live as deterministic lab agents
inside the `argos-eval` package, so they can be part of the reproducible
benchmark rather than loose scripts:

| Scenario | Vulnerable variant | Hardened variant | Source |
|----------|--------------------|------------------|--------|
| ReAct + MCP tools | `lab.react.vulnerable` | `lab.react.hardened` | `packages/argos-eval/src/argos_eval/lab/scenario_a.py` |
| LangGraph supervisor-worker | `lab.langgraph.vulnerable` | `lab.langgraph.hardened` | `packages/argos-eval/src/argos_eval/lab/scenario_b.py` |
| Memory + RAG | `lab.memory.vulnerable` | `lab.memory.hardened` | `packages/argos-eval/src/argos_eval/lab/scenario_c.py` |

Run them all with `argos eval` (or `argos demo` for the guided tour).

## Auditing an in-process LangChain / LangGraph agent

Agents that call tools in-process never cross the MCP wire, so the audit
proxy cannot see them. Attach the callback handler instead; it feeds every
tool call, prompt and generation into the same detector chain:

```python
from argos_proxy.integrations import ArgosCallbackHandler

handler = ArgosCallbackHandler(
    allowed_tools=("search", "calendar.*"),   # scope policy (glob)
    forensics_db="argos-callbacks.sqlite3",    # optional SQLite trail
    enforce=False,                             # observe only (default)
)

# LangChain / LangGraph
result = agent.invoke({"input": "book a room"}, config={"callbacks": [handler]})

handler.close()
for finding in handler.findings:      # only when no forensics_db was given
    print(finding.detector_id, finding.severity, finding.message)
```

`enforce=True` raises `ArgosPolicyViolationError` from `on_tool_start` when a
tool is outside the allowlist; LangChain propagates it because the handler
sets `raise_error=True` in that mode. Use `AsyncArgosCallbackHandler` with
`ainvoke`.

## Static configuration fixtures

`packages/argos-scanner/tests/fixtures/` contains one clean and one
deliberately vulnerable Claude Desktop configuration plus an `mcp-spec`
sample. `argos scan packages/argos-scanner/tests/fixtures/risky.claude_desktop.json`
produces 20 findings.

## Custom YAML rules

`packages/argos-rules/examples/` holds five rules written in the Nuclei-style
DSL. Combine them with the built-in set:

```bash
argos scan config.json --rules-dir packages/argos-rules/examples
```
