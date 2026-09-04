# Evaluation lab (`argos-eval`)

The lab answers two questions with a reproducible benchmark: does ARGOS detect
every attack a vulnerable agent exposes (sensitivity), and does it stay quiet
on a hardened version of the same agent (specificity)?

## Design

Six deterministic agents implement the red-team `AgentTransport` contract.
Each is a pure function from transcript to reply: no LLM, no network, no
temperature, so two runs are byte-identical.

| Scenario | Vulnerable | Hardened | ASI surface |
|----------|------------|----------|-------------|
| ReAct + MCP tools | `lab.react.vulnerable` | `lab.react.hardened` | ASI02, ASI04, ASI05, ASI06 |
| LangGraph supervisor-worker | `lab.langgraph.vulnerable` | `lab.langgraph.hardened` | ASI03, ASI07, ASI09 |
| Memory + RAG | `lab.memory.vulnerable` | `lab.memory.hardened` | ASI01, ASI05, ASI06, ASI08, ASI10 |

The ground truth (`ground_truth.yaml`) lists which (agent, probe) pairs must
fire; every other pair must block. All 20 probes run against all six agents:
120 trials.

## Metrics

Precision, recall, specificity, accuracy, F1 and Matthews correlation, with
Wilson 95 % confidence intervals for proportions and bootstrap resampling
for other statistics.

## Canonical result

| Metric | Value | Wilson 95 % CI |
|--------|-------|----------------|
| Trials | 120 | |
| TP / FP / TN / FN | 20 / 0 / 100 / 0 | |
| Precision, recall | 100 % | [83.89 %, 100 %] |
| Specificity | 100 % | [96.30 %, 100 %] |
| Accuracy | 100 % | [96.90 %, 100 %] |
| F1 / MCC | 1.0 / +1.0 | |

The matrix is pinned by `test_canonical_metrics.py`; any change in a probe,
detector or agent that moves a cell fails CI. `EvalReport.diff` reports which
pairs were added, removed or reclassified between two runs.

## Running

```bash
argos eval                                   # table on the terminal
argos eval --json out.json --markdown out.md --csv out.csv --output eval.html
uv run python scripts/canonical_eval.py      # stand-alone reproducer
```

## Threats to validity

The agents are vulnerable *by construction*, which guarantees the benchmark
exercises the detection surface but says nothing about real LLM endpoints.
That external-validity question is deliberately kept out of the lab; the
methodology document in `docs/empirical-evaluation.md` describes the
transferability study planned around a thin `LLMTransport` adapter and the
existing `--max-requests` cap.
