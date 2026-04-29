"""Tests for the EvalCase / EvalReport pydantic types.

These pin the wire contract: a JSON dump made today must be loadable
years from now without surprise. The aggregation properties anchor
the relationship between cases and the confusion matrix used by the
metrics pipeline.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from argos_eval import ConfusionMatrix, EvalCase, EvalReport, Outcome
from pydantic import ValidationError


def _case(
    *,
    agent: str = "lab.react.vulnerable",
    probe: str = "ASI06-INTENT-TOOLDESC",
    expected: Outcome = Outcome.FIRE,
    predicted: Outcome = Outcome.FIRE,
    asi: str | None = "ASI06",
    error: str | None = None,
) -> EvalCase:
    return EvalCase(
        agent_id=agent,
        probe_id=probe,
        expected=expected,
        predicted=predicted,
        asi_category=asi,
        error=error,
    )


def _report(*cases: EvalCase) -> EvalReport:
    now = datetime.now(UTC)
    return EvalReport(
        started_at=now,
        finished_at=now + timedelta(seconds=1),
        cases=cases,
    )


# ---------------------------------------------------------------------------
# EvalCase validation.
# ---------------------------------------------------------------------------


def test_eval_case_minimum_construction_works() -> None:
    case = _case()
    assert case.is_true_positive
    assert not case.is_false_positive


def test_eval_case_rejects_invalid_agent_id() -> None:
    with pytest.raises(ValidationError):
        _case(agent="has spaces and bad chars!!")


def test_eval_case_rejects_invalid_probe_id() -> None:
    with pytest.raises(ValidationError):
        _case(probe="\x1bevil")


def test_eval_case_asi_category_must_be_canonical() -> None:
    with pytest.raises(ValidationError):
        _case(asi="ASI100")  # three digits, not two
    with pytest.raises(ValidationError):
        _case(asi="not-an-asi")


def test_eval_case_asi_category_can_be_none() -> None:
    case = _case(asi=None)
    assert case.asi_category is None


def test_eval_case_is_frozen() -> None:
    case = _case()
    with pytest.raises(ValidationError):
        case.expected = Outcome.BLOCK


def test_eval_case_with_error_is_excluded_from_all_cells() -> None:
    """An errored case lands in *no* cell of the confusion matrix; it
    is reported separately so the metrics are computed on the
    non-failing subset."""
    case = _case(error="probe raised RuntimeError")
    assert not case.is_true_positive
    assert not case.is_false_positive
    assert not case.is_true_negative
    assert not case.is_false_negative


def test_eval_case_cell_classification_is_mutually_exclusive() -> None:
    """For any non-errored case exactly one of TP/TN/FP/FN holds."""
    pairs = [
        (Outcome.FIRE, Outcome.FIRE),
        (Outcome.FIRE, Outcome.BLOCK),
        (Outcome.BLOCK, Outcome.FIRE),
        (Outcome.BLOCK, Outcome.BLOCK),
    ]
    for expected, predicted in pairs:
        case = _case(expected=expected, predicted=predicted)
        flags = (
            case.is_true_positive,
            case.is_true_negative,
            case.is_false_positive,
            case.is_false_negative,
        )
        assert sum(1 for f in flags if f) == 1


# ---------------------------------------------------------------------------
# EvalReport construction + temporal validation.
# ---------------------------------------------------------------------------


def test_eval_report_rejects_finished_before_started() -> None:
    now = datetime.now(UTC)
    with pytest.raises(ValidationError, match="finished_at"):
        EvalReport(
            started_at=now,
            finished_at=now - timedelta(seconds=1),
            cases=(),
        )


def test_eval_report_empty_aggregations_are_zero() -> None:
    report = _report()
    cm = report.confusion_matrix()
    assert cm == ConfusionMatrix()
    assert report.by_category() == {}
    assert report.by_agent() == {}


# ---------------------------------------------------------------------------
# Aggregation: global, per-category, per-agent.
# ---------------------------------------------------------------------------


def test_global_confusion_matrix_counts_each_cell() -> None:
    cases = (
        _case(expected=Outcome.FIRE, predicted=Outcome.FIRE),  # TP
        _case(expected=Outcome.FIRE, predicted=Outcome.FIRE),  # TP
        _case(expected=Outcome.BLOCK, predicted=Outcome.BLOCK),  # TN
        _case(expected=Outcome.BLOCK, predicted=Outcome.FIRE),  # FP
        _case(expected=Outcome.FIRE, predicted=Outcome.BLOCK),  # FN
        _case(error="boom"),  # excluded
    )
    cm = _report(*cases).confusion_matrix()
    assert cm.tp == 2
    assert cm.tn == 1
    assert cm.fp == 1
    assert cm.fn == 1


def test_by_category_buckets_by_asi() -> None:
    cases = (
        _case(asi="ASI06", expected=Outcome.FIRE, predicted=Outcome.FIRE),
        _case(asi="ASI06", expected=Outcome.BLOCK, predicted=Outcome.FIRE),
        _case(asi="ASI10", expected=Outcome.FIRE, predicted=Outcome.BLOCK),
    )
    grouped = _report(*cases).by_category()
    assert grouped["ASI06"].tp == 1
    assert grouped["ASI06"].fp == 1
    assert grouped["ASI10"].fn == 1


def test_by_category_uses_other_for_uncategorised_cases() -> None:
    cases = (_case(asi=None, expected=Outcome.FIRE, predicted=Outcome.FIRE),)
    grouped = _report(*cases).by_category()
    assert "OTHER" in grouped
    assert grouped["OTHER"].tp == 1


def test_by_agent_buckets_by_agent_id() -> None:
    cases = (
        _case(agent="lab.react.vulnerable", expected=Outcome.FIRE, predicted=Outcome.FIRE),
        _case(agent="lab.react.hardened", expected=Outcome.FIRE, predicted=Outcome.BLOCK),
    )
    grouped = _report(*cases).by_agent()
    assert grouped["lab.react.vulnerable"].tp == 1
    assert grouped["lab.react.hardened"].fn == 1


# ---------------------------------------------------------------------------
# JSON round-trip preserves the structure (the wire contract).
# ---------------------------------------------------------------------------


def test_eval_report_round_trips_through_json() -> None:
    cases = (
        _case(expected=Outcome.FIRE, predicted=Outcome.FIRE, asi="ASI06"),
        _case(expected=Outcome.BLOCK, predicted=Outcome.BLOCK, asi="ASI10"),
    )
    original = _report(*cases)
    rebuilt = EvalReport.model_validate_json(original.model_dump_json())
    assert rebuilt == original
    assert rebuilt.confusion_matrix() == original.confusion_matrix()


def test_eval_report_serialisation_does_not_leak_private_attrs() -> None:
    """The dump must contain only declared fields; ``extra="forbid"`` is
    the runtime check, this asserts the serialised payload too."""
    report = _report(_case())
    dumped = report.model_dump()
    expected_keys = {
        "schema_version",
        "started_at",
        "finished_at",
        "cases",
        "catalogue_version",
        "seed",
    }
    assert set(dumped.keys()) == expected_keys


def test_errored_property_collects_only_errored_cases() -> None:
    cases = (
        _case(),
        _case(error="x"),
        _case(),
    )
    errored = _report(*cases).errored
    assert len(errored) == 1
    assert errored[0].error == "x"


def test_duration_seconds_is_difference_between_timestamps() -> None:
    now = datetime.now(UTC)
    report = EvalReport(
        started_at=now,
        finished_at=now + timedelta(seconds=42),
        cases=(),
    )
    assert report.duration_seconds == 42.0
