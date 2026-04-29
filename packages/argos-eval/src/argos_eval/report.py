"""Frozen Pydantic models for the eval pipeline.

Three layers, smallest to largest:

- :class:`Outcome` enumerates the only two values a case can take:
  ``FIRE`` (the probe yielded a finding) or ``BLOCK`` (the probe stayed
  silent).
- :class:`EvalCase` records one (agent, probe) pair: what the ground
  truth said, what ARGOS predicted, plus an optional error string when
  the probe raised mid-run.
- :class:`EvalReport` aggregates a list of cases, plus run metadata,
  and exposes the confusion matrices (global, per-category,
  per-agent) needed by Phase 4.

Everything is frozen and ``extra="forbid"`` so the wire contract is
stable: a JSON dump produced today must be round-trip-loadable a year
from now without surprise fields appearing.
"""

from __future__ import annotations

import re
from datetime import datetime
from enum import Enum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from argos_eval.metrics import (
    ConfusionMatrix,
    accuracy,
    f1_score,
    matthews_correlation,
    precision,
    recall,
    specificity,
)


class Outcome(Enum):
    """Two-value outcome of a (probe, agent) trial."""

    FIRE = "fire"
    BLOCK = "block"


# Compact identifier shape used for both agent and probe ids. Letters,
# digits, dashes, underscores and dots; no whitespace, no control chars.
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_\-\.]{0,127}$")


def _validate_id(value: str, *, field: str) -> str:
    if not _ID_RE.match(value):
        msg = f"{field} {value!r} must match {_ID_RE.pattern}"
        raise ValueError(msg)
    return value


class EvalCase(BaseModel):
    """One trial: agent X probe.

    The case carries enough context to tally a confusion matrix without
    looking anything else up; this matters because the suite runner is
    streaming-friendly (it can serialise cases to disk as it goes).
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    agent_id: str = Field(..., min_length=1, max_length=128)
    probe_id: str = Field(..., min_length=1, max_length=128)
    expected: Outcome
    predicted: Outcome
    asi_category: str | None = Field(default=None, max_length=10)
    error: str | None = Field(default=None, max_length=2000)
    duration_ms: float = Field(default=0.0, ge=0.0)

    @field_validator("agent_id")
    @classmethod
    def _v_agent_id(cls, v: str) -> str:
        return _validate_id(v, field="agent_id")

    @field_validator("probe_id")
    @classmethod
    def _v_probe_id(cls, v: str) -> str:
        return _validate_id(v, field="probe_id")

    @field_validator("asi_category")
    @classmethod
    def _v_asi(cls, v: str | None) -> str | None:
        if v is None:
            return None
        if not re.match(r"^ASI\d{2}$", v):
            msg = f"asi_category {v!r} must be of the form ASI##"
            raise ValueError(msg)
        return v

    # ------------------------------------------------------------------
    # Cell of the confusion matrix this case lands in.
    # ------------------------------------------------------------------
    @property
    def _scorable(self) -> bool:
        """Errored cases are excluded from every cell of the confusion
        matrix; this short-circuits the four predicates below."""
        return self.error is None

    @property
    def is_true_positive(self) -> bool:
        return self._scorable and self.expected is Outcome.FIRE and self.predicted is Outcome.FIRE

    @property
    def is_true_negative(self) -> bool:
        return self._scorable and self.expected is Outcome.BLOCK and self.predicted is Outcome.BLOCK

    @property
    def is_false_positive(self) -> bool:
        return self._scorable and self.expected is Outcome.BLOCK and self.predicted is Outcome.FIRE

    @property
    def is_false_negative(self) -> bool:
        return self._scorable and self.expected is Outcome.FIRE and self.predicted is Outcome.BLOCK


class EvalReport(BaseModel):
    """Suite-level evaluation result. Pure data; no engine state.

    Aggregations (``confusion_matrix``, ``by_category``, ``by_agent``)
    are computed on demand and never cached on the instance, so a frozen
    model can serve them while staying immutable.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal[1] = 1
    started_at: datetime
    finished_at: datetime
    cases: tuple[EvalCase, ...] = Field(default_factory=tuple)
    catalogue_version: str = Field(default="argos-eval/0.0.1", max_length=128)
    seed: int | None = Field(default=None)

    @model_validator(mode="after")
    def _finished_after_started(self) -> EvalReport:
        if self.finished_at < self.started_at:
            msg = "finished_at must not precede started_at"
            raise ValueError(msg)
        return self

    # ------------------------------------------------------------------
    # Aggregation API.
    # ------------------------------------------------------------------
    def confusion_matrix(self) -> ConfusionMatrix:
        """Global 2x2 matrix across every case (excluding errored ones)."""
        tp = sum(1 for c in self.cases if c.is_true_positive)
        tn = sum(1 for c in self.cases if c.is_true_negative)
        fp = sum(1 for c in self.cases if c.is_false_positive)
        fn = sum(1 for c in self.cases if c.is_false_negative)
        return ConfusionMatrix(tp=tp, fp=fp, tn=tn, fn=fn)

    def by_category(self) -> dict[str, ConfusionMatrix]:
        """Per-ASI confusion matrix.

        Cases without an ``asi_category`` are bucketed under
        ``"OTHER"``. Insertion order in the returned dict mirrors first
        appearance in ``self.cases``.
        """
        out: dict[str, ConfusionMatrix] = {}
        for case in self.cases:
            key = case.asi_category or "OTHER"
            cell = ConfusionMatrix(
                tp=int(case.is_true_positive),
                fp=int(case.is_false_positive),
                tn=int(case.is_true_negative),
                fn=int(case.is_false_negative),
            )
            out[key] = out[key] + cell if key in out else cell
        return out

    def by_agent(self) -> dict[str, ConfusionMatrix]:
        """Per-agent confusion matrix (same shape as :meth:`by_category`)."""
        out: dict[str, ConfusionMatrix] = {}
        for case in self.cases:
            cell = ConfusionMatrix(
                tp=int(case.is_true_positive),
                fp=int(case.is_false_positive),
                tn=int(case.is_true_negative),
                fn=int(case.is_false_negative),
            )
            out[case.agent_id] = out[case.agent_id] + cell if case.agent_id in out else cell
        return out

    @property
    def errored(self) -> tuple[EvalCase, ...]:
        return tuple(c for c in self.cases if c.error is not None)

    @property
    def duration_seconds(self) -> float:
        return (self.finished_at - self.started_at).total_seconds()

    # ------------------------------------------------------------------
    # Export formats: Markdown + CSV.
    # The HTML reporter is the rich format; these two are for academic
    # paste-and-go (markdown directly into LaTeX / Word) and for
    # downstream statistical analysis (CSV per-case in pandas / R).
    # ------------------------------------------------------------------
    def to_markdown(self) -> str:
        """Render a self-contained Markdown summary.

        Includes: run metadata, global confusion matrix as a 2x2 table,
        global metrics with cell counts, per-ASI breakdown and
        per-agent breakdown. Each table is GitHub-Flavoured-Markdown
        compatible so it pastes cleanly into any modern editor.
        """
        cm = self.confusion_matrix()

        lines: list[str] = [
            "# ARGOS empirical evaluation report",
            "",
            "## Run metadata",
            "",
            "| Field | Value |",
            "|-------|-------|",
            f"| Started | {self.started_at.isoformat(timespec='seconds')} |",
            f"| Finished | {self.finished_at.isoformat(timespec='seconds')} |",
            f"| Duration (s) | {self.duration_seconds:.2f} |",
            f"| Trials | {len(self.cases)} |",
            f"| Errored | {len(self.errored)} |",
            f"| Catalogue | `{self.catalogue_version}` |",
        ]
        if self.seed is not None:
            lines.append(f"| Seed | `{self.seed}` |")
        lines.extend(
            [
                "",
                "## Global confusion matrix",
                "",
                "| Real \\ Predicted | FIRE | BLOCK |",
                "|------------------|------|-------|",
                f"| **FIRE** | TP = {cm.tp} | FN = {cm.fn} |",
                f"| **BLOCK** | FP = {cm.fp} | TN = {cm.tn} |",
                "",
                "## Global metrics",
                "",
                "| Metric | Value |",
                "|--------|-------|",
                f"| Precision | {precision(cm) * 100:.2f}% |",
                f"| Recall | {recall(cm) * 100:.2f}% |",
                f"| Specificity | {specificity(cm) * 100:.2f}% |",
                f"| Accuracy | {accuracy(cm) * 100:.2f}% |",
                f"| F1 score | {f1_score(cm) * 100:.2f}% |",
                f"| MCC | {matthews_correlation(cm):+.4f} |",
                "",
                "## Per-ASI breakdown",
                "",
                "| Category | Total | TP | FP | TN | FN | Precision | Recall | F1 |",
                "|----------|------:|---:|---:|---:|---:|----------:|-------:|---:|",
            ],
        )
        for code, sub in sorted(self.by_category().items()):
            lines.append(
                f"| {code} | {sub.total} | {sub.tp} | {sub.fp} | {sub.tn} | "
                f"{sub.fn} | {precision(sub) * 100:.2f}% | "
                f"{recall(sub) * 100:.2f}% | {f1_score(sub) * 100:.2f}% |",
            )
        lines.extend(
            [
                "",
                "## Per-agent breakdown",
                "",
                "| Agent | Total | TP | FP | TN | FN | Precision | Recall | F1 |",
                "|-------|------:|---:|---:|---:|---:|----------:|-------:|---:|",
            ],
        )
        for agent_id, sub in sorted(self.by_agent().items()):
            lines.append(
                f"| `{agent_id}` | {sub.total} | {sub.tp} | {sub.fp} | "
                f"{sub.tn} | {sub.fn} | {precision(sub) * 100:.2f}% | "
                f"{recall(sub) * 100:.2f}% | {f1_score(sub) * 100:.2f}% |",
            )
        lines.append("")
        return "\n".join(lines)

    def to_csv_cases(self) -> str:
        """One row per :class:`EvalCase`, ready for pandas / R.

        Columns: agent_id, probe_id, asi_category, expected,
        predicted, error, duration_ms, classification.

        ``classification`` is one of TP / FP / TN / FN / ERROR. The
        column lets downstream consumers filter without re-deriving
        the cell from expected/predicted/error themselves.
        """
        # Use the standard library csv module with universal-newlines
        # output so the bytes are stable across platforms (Windows
        # would otherwise insert \r\n).
        import csv  # noqa: PLC0415
        import io  # noqa: PLC0415

        buffer = io.StringIO(newline="")
        writer = csv.writer(buffer, lineterminator="\n")
        writer.writerow(
            [
                "agent_id",
                "probe_id",
                "asi_category",
                "expected",
                "predicted",
                "error",
                "duration_ms",
                "classification",
            ],
        )
        for case in self.cases:
            classification = _classify(case)
            writer.writerow(
                [
                    case.agent_id,
                    case.probe_id,
                    case.asi_category or "",
                    case.expected.value,
                    case.predicted.value,
                    case.error or "",
                    f"{case.duration_ms:.4f}",
                    classification,
                ],
            )
        return buffer.getvalue()


def _classify(case: EvalCase) -> str:
    """Return the canonical TP/FP/TN/FN/ERROR string for a case."""
    if case.error is not None:
        return "ERROR"
    if case.is_true_positive:
        return "TP"
    if case.is_true_negative:
        return "TN"
    if case.is_false_positive:
        return "FP"
    if case.is_false_negative:
        return "FN"
    return "UNKNOWN"  # unreachable given Outcome enum is total
