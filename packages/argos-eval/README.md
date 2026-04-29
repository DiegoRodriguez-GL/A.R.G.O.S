# argos-eval

Empirical evaluation framework for ARGOS. Standalone, self-contained.

The package gives ARGOS the same statistical rigour you would expect of
an academic ML benchmark: confusion matrices with strict validators,
precision / recall / F1 / accuracy / Matthews Correlation Coefficient,
Wilson score confidence intervals (Wilson 1927) and non-parametric
bootstrap intervals (Efron 1979). Everything is pure Python, fully
typed and reproducible from a fixed seed.

It is the foundation Module 7 (empirical validation, OE6) of the ARGOS
TFM builds on; later phases plug ARGOS probes plus deterministic lab
agents on top to produce the actual benchmark.

## Status

All five phases of Module 7 are complete:

- **Phase 1.** Metrics + intervals + report types.
- **Phase 2.** Six deterministic lab agents (three scenarios, two
  variants each) implementing `AgentTransport`.
- **Phase 3.** Ground-truth YAML + concurrent suite runner.
- **Phase 4.** `argos eval` CLI verb + extended HTML reporter.
- **Phase 5.** Empirical results chapter, public methodology doc and
  canonical metrics regression test.

## Canonical results

The suite produces a perfect diagonal confusion matrix on the
shipping lab. The cell counts are pinned by
`tests/test_canonical_metrics.py` so any regression in a probe or
agent surfaces as a CI failure.

| Metric | Value | Wilson 95% CI |
|--------|-------|---------------|
| Trials | 120 | - |
| TP / FP / TN / FN | 20 / 0 / 100 / 0 | - |
| Precision | 100.00% | [83.89%, 100.00%] |
| Recall | 100.00% | [83.89%, 100.00%] |
| Specificity | 100.00% | [96.30%, 100.00%] |
| Accuracy | 100.00% | [96.90%, 100.00%] |
| F1 | 100.00% | (harmonic mean) |
| MCC | +1.0000 | (Matthews 1975) |

See [`docs/empirical-evaluation.md`](../../docs/empirical-evaluation.md)
for methodology, lab design and threats to validity.

## Reproducing

```bash
argos eval --output report.html --json report.json
# or, without the CLI:
uv run python scripts/canonical_eval.py
```

## Public API

```python
from argos_eval import (
    ConfusionMatrix,
    EvalCase,
    EvalReport,
    Outcome,
    bootstrap_ci,
    f1_score,
    matthews_correlation,
    precision,
    recall,
    wilson_interval,
)
```
