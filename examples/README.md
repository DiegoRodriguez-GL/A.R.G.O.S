# examples/

Executable example agents used by documentation and by Module 7 validation:

- `single-react-agent/` -- a plain ReAct agent with two MCP tools.
- `supervisor-worker/` -- a LangGraph supervisor dispatching to workers.
- `persistent-memory/` -- an agent backed by a vector store (LangMem or
  similar).

Each example is a self-contained Python project with its own `pyproject.toml`
and a `README.md` describing what ARGOS is expected to find when audited
against it. Populated in Modules 4/7.
