"""Even deeper M7 audit: Markdown / CSV exports, Hypothesis property
tests, cross-validation invariants, subprocess determinism and a
probe-seed quality audit.

These tests sit alongside :mod:`test_m7_deep_audit`; together they
cover the pipeline from every angle a TFM reviewer is likely to
attack:

- Output formats beyond HTML / JSON.
- Mathematical invariants over random case lists (Hypothesis).
- Cross-validation: aggregating subsets equals aggregating the whole.
- End-to-end determinism via subprocess.
- Probe seed text quality (UTF-8, no control characters).
"""

from __future__ import annotations

import io
import json
import os
import re
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

from argos_eval import (
    ConfusionMatrix,
    EvalCase,
    EvalReport,
    Outcome,
    all_agents,
    default_ground_truth,
    run_suite,
)
from argos_redteam import all_probes
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

_REPO_ROOT = Path(__file__).resolve().parents[3]


def _python_with_argos_installed() -> str:
    """Return the venv Python (not the system one), even when
    ``sys.executable`` resolves to the system interpreter under
    ``uv run pytest``."""
    venv = os.environ.get("VIRTUAL_ENV")
    if venv:
        for candidate in (
            Path(venv, "Scripts", "python.exe"),
            Path(venv, "bin", "python"),
            Path(venv, "bin", "python3"),
        ):
            if candidate.is_file():
                return str(candidate)
    return sys.executable


# ===========================================================================
# 1. MARKDOWN EXPORT
# ===========================================================================


class TestMarkdownExport:
    """``EvalReport.to_markdown`` is the format reviewers paste into
    LaTeX or Word. We assert the structure matches GFM tables and
    every required section is present."""

    def _trivial_report(self) -> EvalReport:
        now = datetime.now(UTC)
        return EvalReport(
            started_at=now,
            finished_at=now + timedelta(seconds=1),
            cases=(
                EvalCase(
                    agent_id="lab.x.vulnerable",
                    probe_id="ASI01-X",
                    expected=Outcome.FIRE,
                    predicted=Outcome.FIRE,
                    asi_category="ASI01",
                ),
                EvalCase(
                    agent_id="lab.x.hardened",
                    probe_id="ASI01-X",
                    expected=Outcome.BLOCK,
                    predicted=Outcome.BLOCK,
                    asi_category="ASI01",
                ),
            ),
            seed=0,
        )

    def test_markdown_contains_every_section_header(self) -> None:
        md = self._trivial_report().to_markdown()
        for header in (
            "# ARGOS empirical evaluation report",
            "## Run metadata",
            "## Global confusion matrix",
            "## Global metrics",
            "## Per-ASI breakdown",
            "## Per-agent breakdown",
        ):
            assert header in md, f"missing section header: {header!r}"

    def test_markdown_global_metrics_table_is_well_formed(self) -> None:
        md = self._trivial_report().to_markdown()
        assert "| Precision |" in md
        assert "| Recall |" in md
        assert "| MCC |" in md
        # Score values rendered as percentages.
        assert "100.00%" in md

    def test_markdown_per_agent_table_lists_each_agent(self) -> None:
        md = self._trivial_report().to_markdown()
        assert "`lab.x.vulnerable`" in md
        assert "`lab.x.hardened`" in md

    def test_markdown_is_byte_stable_for_same_report(self) -> None:
        report = self._trivial_report()
        a = report.to_markdown()
        b = report.to_markdown()
        assert a == b

    def test_markdown_handles_empty_report(self) -> None:
        now = datetime.now(UTC)
        empty = EvalReport(
            started_at=now,
            finished_at=now + timedelta(seconds=1),
            cases=(),
        )
        md = empty.to_markdown()
        assert "Trials | 0" in md
        # No agents / categories means the breakdown tables exist but
        # are empty (header only). This is the expected behaviour.
        assert "## Per-agent breakdown" in md

    def test_markdown_matches_full_lab_run_under_perfect_detection(self) -> None:
        """Sanity: a real full-suite run produces a markdown summary
        that mentions all 6 lab agents and the full TP/FP/TN/FN
        composition."""
        report = run_suite(list(all_agents()), list(all_probes()), default_ground_truth())
        md = report.to_markdown()
        for agent in all_agents():
            assert f"`{agent.agent_id}`" in md
        # 20 TP, 0 FP, 100 TN, 0 FN in the canonical run.
        assert "TP = 20" in md
        assert "TN = 100" in md
        assert "FP = 0" in md
        assert "FN = 0" in md


# ===========================================================================
# 2. CSV EXPORT
# ===========================================================================


class TestCSVExport:
    """The CSV export is pandas / R bait. Verify it round-trips
    through Python's stdlib ``csv`` module."""

    def _trivial_report(self) -> EvalReport:
        now = datetime.now(UTC)
        return EvalReport(
            started_at=now,
            finished_at=now + timedelta(seconds=1),
            cases=(
                EvalCase(
                    agent_id="lab.x.y",
                    probe_id="ASI01-A",
                    expected=Outcome.FIRE,
                    predicted=Outcome.FIRE,
                    asi_category="ASI01",
                    duration_ms=1.5,
                ),
                EvalCase(
                    agent_id="lab.x.y",
                    probe_id="ASI01-B",
                    expected=Outcome.FIRE,
                    predicted=Outcome.BLOCK,
                    asi_category="ASI01",
                    duration_ms=2.5,
                ),
                EvalCase(
                    agent_id="lab.x.y",
                    probe_id="ASI01-C",
                    expected=Outcome.BLOCK,
                    predicted=Outcome.BLOCK,
                    asi_category="ASI01",
                    error="boom",
                    duration_ms=0.5,
                ),
            ),
        )

    def test_csv_header_matches_documented_columns(self) -> None:
        import csv

        text = self._trivial_report().to_csv_cases()
        reader = csv.reader(io.StringIO(text))
        header = next(reader)
        assert header == [
            "agent_id",
            "probe_id",
            "asi_category",
            "expected",
            "predicted",
            "error",
            "duration_ms",
            "classification",
        ]

    def test_csv_row_count_equals_case_count(self) -> None:
        import csv

        report = self._trivial_report()
        text = report.to_csv_cases()
        rows = list(csv.reader(io.StringIO(text)))
        # Header + one row per case.
        assert len(rows) == 1 + len(report.cases)

    def test_csv_classifies_each_case_correctly(self) -> None:
        import csv

        text = self._trivial_report().to_csv_cases()
        reader = csv.DictReader(io.StringIO(text))
        rows = list(reader)
        classifications = [r["classification"] for r in rows]
        assert classifications == ["TP", "FN", "ERROR"]

    def test_csv_escapes_commas_in_error_strings(self) -> None:
        """An error message containing a comma must round-trip
        through ``csv.reader`` without spilling fields."""
        import csv

        now = datetime.now(UTC)
        report = EvalReport(
            started_at=now,
            finished_at=now + timedelta(seconds=1),
            cases=(
                EvalCase(
                    agent_id="lab.x.y",
                    probe_id="ASI01-A",
                    expected=Outcome.FIRE,
                    predicted=Outcome.FIRE,
                    error="oops, things, broke",
                ),
            ),
        )
        text = report.to_csv_cases()
        rows = list(csv.DictReader(io.StringIO(text)))
        assert rows[0]["error"] == "oops, things, broke"

    def test_csv_uses_unix_lineterminator(self) -> None:
        """Cross-platform stability: the bytes must use ``\\n`` only,
        even on Windows (where csv would default to CRLF)."""
        text = self._trivial_report().to_csv_cases()
        assert "\r\n" not in text


# ===========================================================================
# 3. HYPOTHESIS PROPERTY TESTS ON AGGREGATION
# ===========================================================================


_SAFE_TEXT = st.text(
    alphabet=st.characters(
        min_codepoint=0x21,
        max_codepoint=0x7E,
        blacklist_characters="<>&\"'\\",
    ),
    min_size=1,
    max_size=20,
)


@st.composite
def _eval_cases(draw: st.DrawFn, *, count: int = 30) -> list[EvalCase]:
    """Generate a list of EvalCase with random valid content.

    Agent ids are drawn from a small pool so by_agent has multiple
    entries. ASI categories are similarly drawn so by_category buckets
    fill up. Outcomes are uniform; errors are rare so the aggregation
    has cases in every cell.
    """
    cases: list[EvalCase] = []
    agent_pool = ["lab.a.x", "lab.b.y", "lab.c.z"]
    asi_pool = ["ASI01", "ASI02", "ASI03"]
    for i in range(count):
        agent_id = draw(st.sampled_from(agent_pool))
        probe_seq = draw(st.integers(min_value=0, max_value=999))
        probe_id = f"P-{probe_seq:04d}-{i:02d}"
        expected = draw(st.sampled_from(list(Outcome)))
        predicted = draw(st.sampled_from(list(Outcome)))
        asi = draw(st.sampled_from(asi_pool))
        # 10% errored to exercise the exclusion path.
        errored = draw(st.booleans())
        cases.append(
            EvalCase(
                agent_id=agent_id,
                probe_id=probe_id,
                expected=expected,
                predicted=predicted,
                asi_category=asi,
                error="boom" if errored and i % 10 == 0 else None,
            ),
        )
    return cases


@st.composite
def _eval_reports(draw: st.DrawFn) -> EvalReport:
    cases = tuple(draw(_eval_cases(count=draw(st.integers(min_value=0, max_value=40)))))
    now = datetime.now(UTC)
    return EvalReport(
        started_at=now,
        finished_at=now + timedelta(seconds=1),
        cases=cases,
    )


class TestAggregationProperties:
    """Mathematical invariants that must hold over any random valid
    EvalReport."""

    @given(report=_eval_reports())
    @settings(suppress_health_check=[HealthCheck.too_slow], deadline=None, max_examples=80)
    def test_global_matrix_equals_sum_of_per_category(self, report: EvalReport) -> None:
        """The global confusion matrix is the elementwise sum of the
        per-category matrices."""
        global_cm = report.confusion_matrix()
        per_cat = report.by_category().values()
        accumulated = ConfusionMatrix()
        for cm in per_cat:
            accumulated = accumulated + cm
        assert accumulated == global_cm

    @given(report=_eval_reports())
    @settings(suppress_health_check=[HealthCheck.too_slow], deadline=None, max_examples=80)
    def test_global_matrix_equals_sum_of_per_agent(self, report: EvalReport) -> None:
        """Same invariant as above but along the agent axis."""
        global_cm = report.confusion_matrix()
        accumulated = ConfusionMatrix()
        for cm in report.by_agent().values():
            accumulated = accumulated + cm
        assert accumulated == global_cm

    @given(report=_eval_reports())
    @settings(suppress_health_check=[HealthCheck.too_slow], deadline=None, max_examples=80)
    def test_total_cell_count_equals_non_errored_case_count(self, report: EvalReport) -> None:
        """The total of the global confusion matrix matches the count
        of non-errored cases in the report."""
        non_errored = sum(1 for c in report.cases if c.error is None)
        assert report.confusion_matrix().total == non_errored

    @given(report=_eval_reports())
    @settings(suppress_health_check=[HealthCheck.too_slow], deadline=None, max_examples=80)
    def test_errored_cases_match_errored_property(self, report: EvalReport) -> None:
        """``report.errored`` returns exactly the cases with non-None
        error; the count complements the confusion matrix's total."""
        assert len(report.errored) + report.confusion_matrix().total == len(report.cases)


# ===========================================================================
# 4. CROSS-VALIDATION INVARIANT
# ===========================================================================


class TestCrossValidationInvariant:
    """Aggregating subsets of cases produces the same confusion matrix
    as aggregating the full set. This is the operational guarantee
    that lets a reviewer split the eval into folds without changing
    the cited cell counts."""

    def test_agent_subset_aggregation_equals_full(self) -> None:
        """Split agents into halves; sum of partial reports equals
        the full report's confusion matrix."""
        agents = list(all_agents())
        probes = list(all_probes())
        gt = default_ground_truth()
        full = run_suite(agents, probes, gt)

        first_half = run_suite(agents[: len(agents) // 2], probes, gt)
        second_half = run_suite(agents[len(agents) // 2 :], probes, gt)
        merged = first_half.confusion_matrix() + second_half.confusion_matrix()
        assert merged == full.confusion_matrix()

    def test_probe_subset_aggregation_equals_full(self) -> None:
        agents = list(all_agents())
        probes = list(all_probes())
        gt = default_ground_truth()
        full = run_suite(agents, probes, gt)

        first_half = run_suite(agents, probes[: len(probes) // 2], gt)
        second_half = run_suite(agents, probes[len(probes) // 2 :], gt)
        merged = first_half.confusion_matrix() + second_half.confusion_matrix()
        assert merged == full.confusion_matrix()


# ===========================================================================
# 5. SUBPROCESS DETERMINISM
# ===========================================================================


class TestSubprocessDeterminism:
    """Two CLI invocations of ``argos eval --json X.json`` with the
    same arguments must produce byte-identical case classifications.
    This is the guarantee a TFM reviewer expects when reproducing the
    canonical run."""

    def test_two_subprocess_runs_produce_identical_classifications(self, tmp_path: Path) -> None:
        first = tmp_path / "a.json"
        second = tmp_path / "b.json"
        py = _python_with_argos_installed()

        for path in (first, second):
            proc = subprocess.run(
                [
                    py,
                    "-m",
                    "argos_cli",
                    "eval",
                    "--probes",
                    "ASI02-*",
                    "--output",
                    str(tmp_path / "out.html"),
                    "--json",
                    str(path),
                    "--seed",
                    "0",
                    "--quiet",
                ],
                cwd=str(_REPO_ROOT),
                capture_output=True,
                text=True,
                check=False,
            )
            assert proc.returncode == 0, f"stderr: {proc.stderr!r}"

        a = json.loads(first.read_text(encoding="utf-8"))
        b = json.loads(second.read_text(encoding="utf-8"))

        # Exclude timestamps and durations (legitimately drift). Pin
        # everything else.
        def _classify_only(payload: dict[str, object]) -> list[tuple[str, ...]]:
            cases = payload.get("cases", [])
            assert isinstance(cases, list)
            return [
                (c["agent_id"], c["probe_id"], c["expected"], c["predicted"], c.get("error") or "")
                for c in cases
            ]

        assert _classify_only(a) == _classify_only(b)


# ===========================================================================
# 6. PROBE SEED QUALITY AUDIT
# ===========================================================================


class TestProbeSeedQuality:
    """Every probe's seed text must be clean UTF-8: no control
    characters that could break a CSV export, JSON dump or HTML
    rendering downstream. Newlines and tabs are allowed because they
    are legitimate prose; everything else below 0x20 is forbidden."""

    _ALLOWED_CONTROL = frozenset({"\t", "\n", "\r"})

    def test_every_probe_seed_is_clean_utf8(self) -> None:
        from argos_redteam.models import Role

        for probe in all_probes():
            seed = probe.build_seed()
            for msg in seed.messages:
                for ch in msg.content:
                    cp = ord(ch)
                    if ch in self._ALLOWED_CONTROL:
                        continue
                    if cp < 0x20 or cp == 0x7F:
                        msg_label = f"role={msg.role.value}, name={msg.name!r}"
                        raise AssertionError(
                            f"{probe.probe_id}: seed contains forbidden "
                            f"control char U+{cp:04X} in {msg_label}"
                        )
                # Must round-trip through utf-8 cleanly (no surrogates).
                msg.content.encode("utf-8")
                # Confirm role is one of the canonical enum values.
                assert isinstance(msg.role, Role)

    def test_every_probe_id_matches_canonical_form(self) -> None:
        """The catalog uses ``ASI##-WORD-WORD-...`` as canonical id;
        anything else would surface in CSV exports or JSON dumps as
        an unparseable token."""
        pattern = re.compile(r"^ASI\d{2}-[A-Z][A-Z0-9-]*$")
        for probe in all_probes():
            assert pattern.match(probe.probe_id), probe.probe_id

    def test_no_probe_seed_contains_zero_width_unicode(self) -> None:
        """Zero-width and bidi codepoints are visually invisible and
        could mask attack content. The seeds should be plain ASCII /
        Latin-1 prose."""
        forbidden = frozenset(
            chr(cp)
            for cp in (
                0x200B,
                0x200C,
                0x200D,
                0x200E,
                0x200F,
                0x2060,
                0x202A,
                0x202B,
                0x202C,
                0x202D,
                0x202E,
                0xFEFF,
            )
        )
        for probe in all_probes():
            for msg in probe.build_seed().messages:
                for ch in msg.content:
                    assert ch not in forbidden, (
                        f"{probe.probe_id}: zero-width / bidi U+{ord(ch):04X}"
                    )


# ===========================================================================
# 7. CONCURRENT RUNS SAFETY
# ===========================================================================


class TestConcurrentRunSafety:
    """Two ``run_suite_async`` calls scheduled in the same event loop
    must not interfere with each other; each gets its own
    deterministic output."""

    def test_two_concurrent_runs_are_independent(self) -> None:
        import asyncio

        from argos_eval import run_suite_async

        agents = list(all_agents())[:2]
        probes = list(all_probes())[:3]
        gt = default_ground_truth()

        async def _two_runs() -> tuple[EvalReport, EvalReport]:
            a, b = await asyncio.gather(
                run_suite_async(agents, probes, gt, seed=1),
                run_suite_async(agents, probes, gt, seed=2),
            )
            return a, b

        report_a, report_b = asyncio.run(_two_runs())
        # Same lab + same probes + same GT => identical classification
        # regardless of seed (lab is deterministic).
        cm_a = report_a.confusion_matrix()
        cm_b = report_b.confusion_matrix()
        assert cm_a == cm_b
        # And the seeds are recorded distinctly.
        assert report_a.seed == 1
        assert report_b.seed == 2
