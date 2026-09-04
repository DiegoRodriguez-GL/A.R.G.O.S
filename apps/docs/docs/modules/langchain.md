# LangChain / LangGraph callback

Agents that call tools in-process never cross the MCP wire, so the audit
proxy cannot see them. `argos_proxy.integrations.langchain` provides a
callback handler that translates framework events into the message shapes the
proxy understands and runs them through the same detector chain.

| LangChain event | Translated to |
|-----------------|---------------|
| `on_tool_start` | `tools/call` request (client to upstream) |
| `on_tool_end` / `on_tool_error` | success / error response (upstream to client) |
| `on_llm_start`, `on_chat_model_start`, `on_llm_end`, `on_agent_action` | `notifications/argos/*` |

The default chain is `OtelTracingInterceptor` + `PIIDetector` +
`ScopeDetector`; tool drift is not applicable because LangChain never emits a
`tools/list`.

## Usage

```python
from argos_proxy.integrations import ArgosCallbackHandler

handler = ArgosCallbackHandler(
    allowed_tools=("search", "calendar.*"),
    forensics_db="argos-callbacks.sqlite3",   # optional
    enforce=False,                            # observe only (default)
)

result = agent.invoke({"input": "book a room"}, config={"callbacks": [handler]})
handler.close()

for finding in handler.findings:              # in-memory sink when no db
    print(finding.detector_id, finding.severity, finding.message)
```

For async agents use `AsyncArgosCallbackHandler` with `ainvoke` and
`await handler.aclose()`.

## Policy

- **Observe (default).** Out-of-scope tools and PII are recorded as findings;
  the agent keeps running.
- **Enforce.** `enforce=True` raises `ArgosPolicyViolationError` from
  `on_tool_start` when the scope detector vetoes a call. The handler sets
  `raise_error=True` in that mode so LangChain propagates the exception and
  the tool never executes.

## Safety properties

- Free text (prompts, arguments, outputs) is truncated to
  `DEFAULT_MAX_TEXT_CHARS` (8192) before detection and persistence.
- A detector that raises anything other than a policy veto is logged and
  ignored.
- The synchronous handler drives detectors on a private event loop thread, so
  it works from plain scripts and from code already running inside an event
  loop.
- `langchain-core` is optional. When installed, the handlers subclass
  `BaseCallbackHandler` / `AsyncCallbackHandler`; otherwise they expose the
  same attribute surface the dispatcher reads.

## Unified reporting

`argos_proxy.detectors.adapter.to_core_finding` lifts a proxy finding into the
shared `argos_core.Finding` model, with compliance references resolved from
the mapping graph, so callback and proxy captures render in `argos report`
next to scanner and red-team findings.
