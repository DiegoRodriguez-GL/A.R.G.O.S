"""Campaign A: per-rule precision before and after a rule change.

Usage: python registry_precision.py OUT_DIR BEFORE_TAG AFTER_TAG LABELS.json

The labels file holds the manual review of a stratified sample (up to 25
findings per rule, one per entry): for every rule, the pseudonymous keys
of the sampled entries and the subset judged true positive. A finding is a
true positive when the weakness it names exists in the command a client
would build from the published entry; for the advisory rules (digest
pinning, credential scope) its literal claim must hold. Precision comes
with a Wilson 95 % interval. The script also checks that the rule change
kept every sampled true positive and introduced no new finding.
"""

from __future__ import annotations

import json
import math
import sys
from pathlib import Path


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    if n == 0:
        return (0.0, 0.0)
    p = k / n
    den = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / den
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / den
    return (max(0.0, centre - half), min(1.0, centre + half))


def load(path: Path) -> list[dict]:
    return [json.loads(x) for x in path.read_text(encoding="utf-8").splitlines() if x]


def main() -> None:
    out, before, after, labels_path = Path(sys.argv[1]), sys.argv[2], sys.argv[3], Path(sys.argv[4])
    labels = json.loads(labels_path.read_text(encoding="utf-8"))["rules"]
    v1 = load(out / f"findings_{before}.jsonl")
    v2 = load(out / f"findings_{after}.jsonl")
    flagged_after = {(f["key"], f["rule"]) for f in v2}
    flagged_before = {(f["key"], f["rule"]) for f in v1}
    table = []
    for rule, lab in labels.items():
        sample = lab["sample"]
        tps = set(lab["true_positives"])
        kept = [k for k in sample if (k, rule) in flagged_after]
        tp_kept = [k for k in kept if k in tps]
        table.append(
            {
                "rule": rule,
                "entries_before": len({f["key"] for f in v1 if f["rule"] == rule}),
                "entries_after": len({f["key"] for f in v2 if f["rule"] == rule}),
                "precision_before": [len(tps), len(sample), wilson(len(tps), len(sample))],
                "precision_after": [len(tp_kept), len(kept), wilson(len(tp_kept), len(kept))],
                "true_positives_kept": f"{len(tp_kept)}/{len(tps)}",
            }
        )
    report = {"rules": table, "new_findings_after": len(flagged_after - flagged_before)}
    (out / "comparison.json").write_text(json.dumps(report, indent=1), encoding="utf-8")
    print(json.dumps(report, indent=1))


if __name__ == "__main__":
    main()
