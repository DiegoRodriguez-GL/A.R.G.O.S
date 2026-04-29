"""M7 audit, third pass: report diffing, pickle round-trip, YAML
loader fuzzing, thread safety of cached state, idempotent YAML
serialization, duplicate-case handling and lab agent regex hygiene.

Each section probes a property a TFM reviewer might raise on the
empirical chapter:

- ``diff()``: when the canonical run is pinned in main and a feature
  branch alters a probe, the regression CI gate must surface that as a
  precise structural delta, not a numeric drift.
- pickle: agents and reports cross process boundaries (multiprocessing,
  cache, etc.) -- they must round-trip without losing fidelity.
- YAML fuzz: the loader is a public surface; random bytes must never
  yield an exception other than ValueError / OSError / UnicodeError.
- threading: ``GroundTruth._cell_set`` is lazily cached. Confirm that
  hammering the property from many threads is benign.
- idempotent YAML: ``to_yaml(from_yaml(x))`` must equal ``x`` for the
  default catalogue (round-trip with no drift).
- duplicate cases: the report shouldn't crash on duplicates -- the
  aggregation contract must remain well-defined.
- regex overlap: lab agent surface patterns must not match seeds for
  probes outside their declared category.
"""

from __future__ import annotations

import pickle
import re
import threading
from datetime import UTC, datetime

import pytest
from argos_eval import (
    ALL_AGENT_CLASSES,
    ClassificationChange,
    ConfusionMatrix,
    EvalCase,
    EvalReport,
    EvalReportDiff,
    GroundTruth,
    Outcome,
    all_agents,
    default_ground_truth,
    run_suite,
)
from argos_eval.lab._base import LabAgent
from argos_redteam import all_probes
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from pydantic import ValidationError

# ---------------------------------------------------------------------------
# EvalReport.diff()
# ---------------------------------------------------------------------------


def _baseline() -> EvalReport:
    return run_suite(list(all_agents()), list(all_probes()), default_ground_truth(), seed=0)


def test_diff_against_self_is_empty() -> None:
    """A report diffed against itself yields the empty diff."""
    report = _baseline()
    diff = report.diff(report)
    assert diff.is_empty
    assert diff.cases_added == ()
    assert diff.cases_removed == ()
    assert diff.classifications_changed == ()
    assert diff.regressions == ()
    assert diff.improvements == ()


def test_diff_detects_added_cases() -> None:
    """Cases present in self but not in baseline land in ``cases_added``."""
    full = _baseline()
    # Build a stripped baseline that drops one specific case.
    target = (full.cases[0].agent_id, full.cases[0].probe_id)
    stripped_cases = tuple(c for c in full.cases if (c.agent_id, c.probe_id) != target)
    stripped = full.model_copy(update={"cases": stripped_cases})

    diff = full.diff(stripped)
    assert diff.cases_added == (target,)
    assert diff.cases_removed == ()
    assert diff.classifications_changed == ()


def test_diff_detects_removed_cases() -> None:
    """Symmetric: dropped from self surfaces in ``cases_removed``."""
    full = _baseline()
    target = (full.cases[0].agent_id, full.cases[0].probe_id)
    stripped_cases = tuple(c for c in full.cases if (c.agent_id, c.probe_id) != target)
    stripped = full.model_copy(update={"cases": stripped_cases})

    diff = stripped.diff(full)
    assert diff.cases_added == ()
    assert diff.cases_removed == (target,)
    assert diff.classifications_changed == ()


def test_diff_detects_classification_change_to_fp() -> None:
    """A previously-correct TN that flips to FP is a regression."""
    baseline = _baseline()
    # Find a TN to mutate.
    tn_case = next(c for c in baseline.cases if c.is_true_negative)
    mutated_cases = tuple(
        EvalCase(
            agent_id=c.agent_id,
            probe_id=c.probe_id,
            expected=c.expected,
            predicted=Outcome.FIRE if c is tn_case else c.predicted,
            asi_category=c.asi_category,
            error=c.error,
            duration_ms=c.duration_ms,
        )
        for c in baseline.cases
    )
    mutated = baseline.model_copy(update={"cases": mutated_cases})

    diff = mutated.diff(baseline)
    assert len(diff.classifications_changed) == 1
    change = diff.classifications_changed[0]
    assert change.agent_id == tn_case.agent_id
    assert change.probe_id == tn_case.probe_id
    assert change.old == "TN"
    assert change.new == "FP"
    assert change.is_regression
    assert diff.regressions == (change,)
    assert diff.improvements == ()


def test_diff_detects_improvement_fp_to_tn() -> None:
    """Symmetric: a former FP that becomes TN counts as improvement."""
    baseline = _baseline()
    # Manufacture a baseline FP by flipping one TN forward; then the
    # "new" run reverts it.
    tn_case = next(c for c in baseline.cases if c.is_true_negative)
    bad_baseline_cases = tuple(
        EvalCase(
            agent_id=c.agent_id,
            probe_id=c.probe_id,
            expected=c.expected,
            predicted=Outcome.FIRE if c is tn_case else c.predicted,
            asi_category=c.asi_category,
            error=c.error,
            duration_ms=c.duration_ms,
        )
        for c in baseline.cases
    )
    bad_baseline = baseline.model_copy(update={"cases": bad_baseline_cases})

    diff = baseline.diff(bad_baseline)
    assert len(diff.classifications_changed) == 1
    change = diff.classifications_changed[0]
    assert change.old == "FP"
    assert change.new == "TN"
    assert not change.is_regression
    assert diff.improvements == (change,)
    assert diff.regressions == ()


def test_diff_anything_into_error_is_regression() -> None:
    """ERROR is always treated as worse, even from FP/FN."""
    base_case = EvalCase(
        agent_id="lab.agent.a",
        probe_id="ASI01-X",
        expected=Outcome.FIRE,
        predicted=Outcome.BLOCK,  # FN
    )
    err_case = EvalCase(
        agent_id="lab.agent.a",
        probe_id="ASI01-X",
        expected=Outcome.FIRE,
        predicted=Outcome.BLOCK,
        error="boom",
    )
    now = datetime(2025, 1, 1, tzinfo=UTC)
    base = EvalReport(started_at=now, finished_at=now, cases=(base_case,))
    new = EvalReport(started_at=now, finished_at=now, cases=(err_case,))

    diff = new.diff(base)
    assert len(diff.classifications_changed) == 1
    assert diff.classifications_changed[0].old == "FN"
    assert diff.classifications_changed[0].new == "ERROR"
    assert diff.regressions == diff.classifications_changed


def test_diff_output_is_lexicographically_sorted() -> None:
    """The order of ``cases_added`` / ``cases_removed`` / changes must
    be deterministic so serialised diffs are textually comparable."""
    now = datetime(2025, 1, 1, tzinfo=UTC)
    cases_a = tuple(
        EvalCase(
            agent_id=f"lab.{c}",
            probe_id=f"ASI0{i + 1}-X",
            expected=Outcome.BLOCK,
            predicted=Outcome.BLOCK,
        )
        for i, c in enumerate(["zeta", "alpha", "mu"])
    )
    cases_b = tuple(
        EvalCase(
            agent_id=f"lab.{c}",
            probe_id=f"ASI0{i + 1}-Y",
            expected=Outcome.BLOCK,
            predicted=Outcome.BLOCK,
        )
        for i, c in enumerate(["mu", "zeta", "alpha"])
    )
    a = EvalReport(started_at=now, finished_at=now, cases=cases_a)
    b = EvalReport(started_at=now, finished_at=now, cases=cases_b)

    diff = a.diff(b)
    assert diff.cases_added == tuple(sorted(diff.cases_added))
    assert diff.cases_removed == tuple(sorted(diff.cases_removed))


def test_diff_is_frozen() -> None:
    diff = EvalReportDiff()
    with pytest.raises(ValidationError):
        diff.cases_added = (("lab.x", "ASI01-Y"),)


def test_classification_change_must_actually_differ() -> None:
    """Constructing a no-op change is a programming error."""
    with pytest.raises(ValidationError):
        ClassificationChange(agent_id="lab.x", probe_id="ASI01-Y", old="TP", new="TP")


def test_diff_is_json_serialisable_and_round_trips() -> None:
    """The diff is a wire artifact: emit JSON, reload, equal."""
    baseline = _baseline()
    head = _baseline()  # identical
    diff = head.diff(baseline)
    j = diff.model_dump_json()
    restored = EvalReportDiff.model_validate_json(j)
    assert restored == diff


# ---------------------------------------------------------------------------
# Pickle round-trip across the model surface.
# ---------------------------------------------------------------------------


def test_pickle_confusion_matrix() -> None:
    cm = ConfusionMatrix(tp=10, fp=2, tn=80, fn=8)
    blob = pickle.dumps(cm)
    assert pickle.loads(blob) == cm


def test_pickle_eval_case() -> None:
    case = EvalCase(
        agent_id="lab.x.a",
        probe_id="ASI01-Y",
        expected=Outcome.FIRE,
        predicted=Outcome.FIRE,
        asi_category="ASI01",
        duration_ms=12.5,
    )
    blob = pickle.dumps(case)
    restored = pickle.loads(blob)
    assert restored == case
    # Frozen behaviour preserved.
    with pytest.raises(ValidationError):
        restored.agent_id = "lab.other"


def test_pickle_eval_report_round_trip_preserves_aggregations() -> None:
    """A report restored from pickle must yield identical confusion
    matrices -- proving every field crossed the boundary."""
    report = _baseline()
    blob = pickle.dumps(report)
    restored = pickle.loads(blob)
    assert restored == report
    assert restored.confusion_matrix() == report.confusion_matrix()
    assert restored.by_category() == report.by_category()
    assert restored.by_agent() == report.by_agent()


def test_pickle_ground_truth_round_trip() -> None:
    gt = default_ground_truth()
    blob = pickle.dumps(gt)
    restored = pickle.loads(blob)
    assert restored == gt
    # The cached cell-set must still work (and not leak across the
    # pickle boundary as a stale frozenset).
    cells_a = {(a, p) for (a, p) in gt.fire_cells}
    cells_b = {(a, p) for (a, p) in restored.fire_cells}
    assert cells_a == cells_b


def test_pickle_diff_round_trip() -> None:
    base = _baseline()
    head = _baseline()
    diff = head.diff(base)
    blob = pickle.dumps(diff)
    restored = pickle.loads(blob)
    assert restored == diff


# ---------------------------------------------------------------------------
# YAML loader fuzzing: random bytes never raise unexpected exceptions.
# ---------------------------------------------------------------------------


_ALLOWED_LOADER_EXCEPTIONS = (ValueError, OSError, UnicodeError)


@settings(
    max_examples=200,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture],
)
@given(payload=st.binary(min_size=0, max_size=1024))
def test_yaml_loader_never_raises_unexpected_exception(
    payload: bytes, tmp_path_factory: pytest.TempPathFactory
) -> None:
    """Property: ``GroundTruth.from_yaml`` either loads or raises one of
    a small whitelist of exceptions. It must not surface
    ``yaml.YAMLError``, ``KeyError``, ``TypeError`` or anything else
    suggesting a defensive branch was missed."""
    p = tmp_path_factory.mktemp("yaml_fuzz") / "fuzz.yaml"
    p.write_bytes(payload)
    try:
        GroundTruth.from_yaml(p)
    except _ALLOWED_LOADER_EXCEPTIONS:
        return
    except BaseException as exc:
        msg = f"unexpected exception {type(exc).__name__}: {exc!r} on payload {payload!r}"
        raise AssertionError(msg) from exc


@settings(
    max_examples=80,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture],
)
@given(text=st.text(min_size=0, max_size=512))
def test_yaml_loader_handles_arbitrary_text(
    text: str, tmp_path_factory: pytest.TempPathFactory
) -> None:
    """Same property over text payloads (covers UTF-8 valid but
    semantically invalid YAML, e.g. dict-of-list instead of dict-of-dict)."""
    p = tmp_path_factory.mktemp("yaml_text_fuzz") / "fuzz.yaml"
    p.write_text(text, encoding="utf-8")
    try:
        GroundTruth.from_yaml(p)
    except _ALLOWED_LOADER_EXCEPTIONS:
        return
    except BaseException as exc:
        msg = f"unexpected exception {type(exc).__name__}: {exc!r} on text {text!r}"
        raise AssertionError(msg) from exc


# ---------------------------------------------------------------------------
# Thread safety of GroundTruth._cell_set lazy cache.
# ---------------------------------------------------------------------------


def test_ground_truth_expected_for_safe_under_concurrent_access() -> None:
    """Hammer ``expected_for`` (which lazily builds ``_cell_set``) from
    many threads at once. Verifies no thread saw a half-built cache."""
    gt = default_ground_truth()
    sample_cells = list(gt.fire_cells)[:10]
    expected = {(a, p): gt.expected_for(a, p) for a, p in sample_cells}

    barrier = threading.Barrier(16)
    errors: list[BaseException] = []
    iterations = 500

    def worker() -> None:
        try:
            barrier.wait(timeout=5.0)
            for _ in range(iterations):
                for a, p in sample_cells:
                    assert gt.expected_for(a, p) is expected[(a, p)]
                # Also exercise a non-fire cell -> BLOCK.
                assert gt.expected_for("lab.no.such", "ASI99-NOPE") is Outcome.BLOCK
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=worker, name=f"w{i}") for i in range(16)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=20.0)
        assert not t.is_alive(), "worker did not finish in time"
    assert not errors, f"workers raised: {errors!r}"


# ---------------------------------------------------------------------------
# Idempotent YAML serialization on the canonical ground truth.
# ---------------------------------------------------------------------------


def test_default_ground_truth_yaml_is_idempotent(tmp_path: object) -> None:
    """``from_yaml(to_yaml(x)) == x`` is the round-trip property; the
    stricter idempotency property is ``to_yaml(from_yaml(to_yaml(x)))
    == to_yaml(x)`` -- the textual form converges in one step."""
    from pathlib import Path

    gt = default_ground_truth()
    out = Path(tmp_path) / "rt1.yaml"  # type: ignore[arg-type]
    gt.to_yaml(out)
    text_1 = out.read_text(encoding="utf-8")

    reloaded = GroundTruth.from_yaml(out)
    out2 = Path(tmp_path) / "rt2.yaml"  # type: ignore[arg-type]
    reloaded.to_yaml(out2)
    text_2 = out2.read_text(encoding="utf-8")

    assert text_1 == text_2
    assert reloaded == gt


# ---------------------------------------------------------------------------
# Duplicate cases handling: aggregation must remain well-defined.
# ---------------------------------------------------------------------------


def test_eval_report_handles_duplicate_cases_deterministically() -> None:
    """If two cases share the same (agent, probe), the report must not
    raise; both contribute to the confusion matrix.

    The model deliberately allows duplicates: the runner emits exactly
    one case per pair, but a downstream consumer might concatenate
    reports from multiple shards. Aggregation is purely additive."""
    now = datetime(2025, 1, 1, tzinfo=UTC)
    case = EvalCase(
        agent_id="lab.x.a",
        probe_id="ASI01-Y",
        expected=Outcome.FIRE,
        predicted=Outcome.FIRE,
        asi_category="ASI01",
    )
    report = EvalReport(started_at=now, finished_at=now, cases=(case, case))
    cm = report.confusion_matrix()
    assert cm.tp == 2
    assert cm.fp == cm.tn == cm.fn == 0


def test_eval_report_diff_with_duplicates_is_well_defined() -> None:
    """Diff over duplicates uses the last-write-wins semantics of the
    index dict; at minimum, no exception."""
    now = datetime(2025, 1, 1, tzinfo=UTC)
    case_tp = EvalCase(
        agent_id="lab.x.a",
        probe_id="ASI01-Y",
        expected=Outcome.FIRE,
        predicted=Outcome.FIRE,
        asi_category="ASI01",
    )
    case_fn = EvalCase(
        agent_id="lab.x.a",
        probe_id="ASI01-Y",
        expected=Outcome.FIRE,
        predicted=Outcome.BLOCK,
        asi_category="ASI01",
    )
    base = EvalReport(started_at=now, finished_at=now, cases=(case_tp, case_tp))
    head = EvalReport(started_at=now, finished_at=now, cases=(case_fn, case_fn))
    diff = head.diff(base)
    # Both runs collapse to a single (lab.x.a, ASI01-Y) cell; one
    # change emitted (TP -> FN).
    assert len(diff.classifications_changed) == 1
    assert diff.classifications_changed[0].old == "TP"
    assert diff.classifications_changed[0].new == "FN"


# ---------------------------------------------------------------------------
# Lab agent regex hygiene: surface patterns must not bleed across categories.
# ---------------------------------------------------------------------------


def _instantiate(cls: type[LabAgent]) -> LabAgent:
    return cls()


@pytest.mark.parametrize("agent_cls", ALL_AGENT_CLASSES)
def test_lab_agent_script_patterns_are_valid_regex(agent_cls: type[LabAgent]) -> None:
    """Each pattern in every agent's script must compile under the
    flags the base class uses at runtime."""
    agent = _instantiate(agent_cls)
    for pattern, _reply in agent._script():
        re.compile(pattern, re.IGNORECASE | re.DOTALL)


@pytest.mark.parametrize("agent_cls", ALL_AGENT_CLASSES)
def test_lab_agent_script_patterns_have_no_trivial_overmatch(
    agent_cls: type[LabAgent],
) -> None:
    """An agent pattern that matches the empty string would fire on
    every probe regardless of seed -- a smoke-test for accidental
    ``.*?`` regressions or unanchored alternations."""
    agent = _instantiate(agent_cls)
    for pattern, _reply in agent._script():
        compiled = re.compile(pattern, re.IGNORECASE | re.DOTALL)
        assert not compiled.search(""), (
            f"agent {agent.agent_id} pattern {pattern!r} matches empty string"
        )


@pytest.mark.parametrize("agent_cls", ALL_AGENT_CLASSES)
def test_lab_agent_script_patterns_are_not_overly_permissive(
    agent_cls: type[LabAgent],
) -> None:
    """A pattern reduced to ``.*`` (with optional flags) is a defect:
    it would match every transcript and convert the agent into
    'always vulnerable'."""
    agent = _instantiate(agent_cls)
    bad_patterns = {".*", ".+", ".", "(.*)", "(.+)", ".*?", ".+?"}
    for pattern, _reply in agent._script():
        assert pattern not in bad_patterns, (
            f"agent {agent.agent_id} pattern {pattern!r} is overly permissive"
        )


def test_vulnerable_agents_do_not_match_random_innocuous_text() -> None:
    """Empirical check: an entirely benign transcript must not trigger
    any vulnerable agent's script. Counterpart to the construct
    validity test that verifies the probe seeds DO trigger the agents."""
    benign = "hola buenos dias, dame el clima en madrid por favor"
    for agent in all_agents():
        if "hardened" in agent.agent_id:
            continue
        for pattern, _reply in agent._script():
            compiled = re.compile(pattern, re.IGNORECASE | re.DOTALL)
            assert not compiled.search(benign), (
                f"agent {agent.agent_id} pattern {pattern!r} matches benign text"
            )


def test_hardened_agents_have_strict_refusal_default() -> None:
    """Hardened agents must fall back to a refusal that does NOT contain
    any compliance signal (e.g. 'sure', 'here is') that probes might
    trigger on. Otherwise an off-script probe could read 'no' and still
    flag a fire."""
    forbidden_substrings = ["here is", "sure,", "of course", "executing"]
    for agent in all_agents():
        if "hardened" not in agent.agent_id:
            continue
        reply = agent._default_reply().lower()
        for forbidden in forbidden_substrings:
            assert forbidden not in reply, (
                f"hardened agent {agent.agent_id} default reply contains "
                f"compliance signal {forbidden!r}"
            )
