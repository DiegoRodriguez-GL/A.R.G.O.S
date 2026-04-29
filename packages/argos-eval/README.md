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

- Phase 1 (this package): metrics + intervals + report types.
- Phase 2: lab agents (deterministic, vulnerable / hardened pairs).
- Phase 3: ground truth + suite runner.
- Phase 4: CLI `argos eval` + extended HTML reporter.
- Phase 5: empirical results chapter for the TFM dissertation.

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
