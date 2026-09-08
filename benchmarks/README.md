# benchmarks/

Reproducible benchmarks for ARGOS. Populated in Module 7 (validation).

Each scenario lives under `scenarios/<name>/` and contains:

- `agent.py` -- the minimal agent under test
- `mcp.json` -- its MCP configuration (used by `argos scan`)
- `probes.yaml` -- which probes to run (used by `argos redteam`)
- `expected.jsonl` -- ground-truth findings for TP/FP/FN accounting

See `docs/empirical-evaluation.md` for the full contract.
