"""Targeted audit of argos-core: models, autonomy, telemetry, compliance lookups."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from argos_core import (
    AutonomyLevel,
    Evidence,
    Finding,
    ScanResult,
    Severity,
    Target,
    cbra_score,
)
from argos_core.compliance import (
    Control,
    FrameworkMeta,
    load_controls,
)
from argos_core.models.target import TargetKind
from argos_core.telemetry import init_telemetry
from pydantic import ValidationError

# ---------- Severity ----------------------------------------------------


def test_severity_rank_is_total_and_matches_expected() -> None:
    assert Severity.INFO.rank == 0
    assert Severity.LOW.rank == 1
    assert Severity.MEDIUM.rank == 2
    assert Severity.HIGH.rank == 3
    assert Severity.CRITICAL.rank == 4


def test_severity_serialises_by_value() -> None:
    # Pydantic dumps enums by value in JSON mode.
    t = Target(kind=TargetKind.MCP_CONFIG, locator="x")
    f = Finding(
        rule_id="X-1",
        title="t",
        description="d",
        severity=Severity.CRITICAL,
        target=t,
        producer="test",
    )
    payload = f.model_dump_json()
    assert '"severity":"critical"' in payload


# ---------- Finding -----------------------------------------------------


def test_finding_id_is_unique_across_calls() -> None:
    t = Target(kind=TargetKind.MCP_CONFIG, locator="x")
    ids = {
        Finding(
            rule_id="X-1",
            title="t",
            description="d",
            severity=Severity.LOW,
            target=t,
            producer="test",
        ).id
        for _ in range(200)
    }
    assert len(ids) == 200


def test_finding_rule_id_validator_accepts_canonical_ids() -> None:
    t = Target(kind=TargetKind.MCP_CONFIG, locator="x")
    for good in ("MCP-SEC-SECRET-PATTERN", "ASI01-02", "CVE_2026_001", "X1"):
        f = Finding(
            rule_id=good,
            title="t",
            description="d",
            severity=Severity.LOW,
            target=t,
            producer="test",
        )
        f.validate_rule_id()


def test_finding_rule_id_validator_rejects_malformed() -> None:
    t = Target(kind=TargetKind.MCP_CONFIG, locator="x")
    for bad in ("lowercase", "starts-with-dash", "UPPER/CASE", "space inside"):
        f = Finding(
            rule_id=bad,
            title="t",
            description="d",
            severity=Severity.LOW,
            target=t,
            producer="test",
        )
        with pytest.raises(ValueError, match="canonical form"):
            f.validate_rule_id()


def test_finding_title_length_enforced() -> None:
    t = Target(kind=TargetKind.MCP_CONFIG, locator="x")
    with pytest.raises(ValidationError):
        Finding(
            rule_id="X-1",
            title="a" * 200,
            description="d",
            severity=Severity.LOW,
            target=t,
            producer="test",
        )


# ---------- Evidence ----------------------------------------------------


def test_evidence_rejects_invalid_kind() -> None:
    with pytest.raises(ValidationError):
        Evidence(kind="not-a-kind", summary="x")  # type: ignore[arg-type]


def test_evidence_line_numbers_must_be_positive() -> None:
    with pytest.raises(ValidationError):
        Evidence(kind="source-range", summary="x", line_start=0)


# ---------- Target ------------------------------------------------------


def test_target_rejects_empty_locator() -> None:
    with pytest.raises(ValidationError):
        Target(kind=TargetKind.MCP_CONFIG, locator="")


def test_target_is_frozen() -> None:
    t = Target(kind=TargetKind.MCP_CONFIG, locator="x")
    with pytest.raises(ValidationError):
        t.locator = "y"


# ---------- ScanResult --------------------------------------------------


def test_scan_result_duration_and_max_severity() -> None:
    t = Target(kind=TargetKind.MCP_CONFIG, locator="x")

    def _f(sev: Severity) -> Finding:
        return Finding(
            rule_id="X-1",
            title="t",
            description="d",
            severity=sev,
            target=t,
            producer="test",
        )

    start = datetime.now(UTC)
    r = ScanResult(
        target=t,
        producer="test@0",
        started_at=start,
        finished_at=start + timedelta(milliseconds=250),
        findings=(_f(Severity.LOW), _f(Severity.HIGH), _f(Severity.MEDIUM)),
    )
    assert r.duration_seconds == pytest.approx(0.250, rel=1e-3)
    assert r.max_severity() == Severity.HIGH
    counts = r.count_by_severity()
    assert counts[Severity.HIGH] == 1
    assert counts[Severity.INFO] == 0


# ---------- AutonomyLevel + cbra ---------------------------------------


@pytest.mark.parametrize("level", list(AutonomyLevel))
def test_cbra_non_negative_at_zero_exposure(level: AutonomyLevel) -> None:
    # Zero exposure and zero blast radius collapse the score to zero.
    assert cbra_score(autonomy=level, exposure=0.0, blast_radius=0.0, reversibility=0.0) == 0.0


def test_cbra_reversibility_reduces_score() -> None:
    fragile = cbra_score(
        autonomy=AutonomyLevel.L3_AUTONOMOUS,
        exposure=0.8,
        blast_radius=0.8,
        reversibility=0.0,
    )
    resilient = cbra_score(
        autonomy=AutonomyLevel.L3_AUTONOMOUS,
        exposure=0.8,
        blast_radius=0.8,
        reversibility=1.0,
    )
    assert resilient < fragile


def test_cbra_exposure_and_blast_radius_are_symmetric() -> None:
    a = cbra_score(
        autonomy=AutonomyLevel.L2_SEMI_AUTONOMOUS,
        exposure=0.2,
        blast_radius=0.8,
        reversibility=0.3,
    )
    b = cbra_score(
        autonomy=AutonomyLevel.L2_SEMI_AUTONOMOUS,
        exposure=0.8,
        blast_radius=0.2,
        reversibility=0.3,
    )
    assert a == pytest.approx(b)


# ---------- Telemetry --------------------------------------------------


def test_init_telemetry_is_idempotent() -> None:
    a = init_telemetry()
    b = init_telemetry()
    # Calling twice must not raise; returned tracers target the same name.
    assert a is not None
    assert b is not None


# ---------- Compliance lookup invariants -------------------------------


def test_control_index_by_id_first_match_wins() -> None:
    idx = load_controls()
    # "AIS-01" exists in csa_aicm; by_id returns the first match regardless of
    # framework. Qualified lookup is preferred for disambiguation.
    c = idx.by_id("AIS-01")
    assert c is not None
    assert isinstance(c, Control)


def test_control_index_by_qid_is_unambiguous() -> None:
    idx = load_controls()
    c = idx.by_qid("csa_aicm:AIS-01")
    assert c is not None
    assert c.framework == "csa_aicm"


def test_control_index_by_qid_returns_none_on_miss() -> None:
    idx = load_controls()
    assert idx.by_qid("nonexistent:X") is None


def test_control_index_cache_is_stable() -> None:
    # load_controls is lru_cache(maxsize=1); the same object should be returned.
    a = load_controls()
    b = load_controls()
    assert a is b


def test_every_framework_meta_is_dated_within_the_last_year() -> None:
    idx = load_controls()
    cutoff = datetime.now(UTC).date() - timedelta(days=365)
    for meta in idx.frameworks:
        assert isinstance(meta, FrameworkMeta)
        assert meta.updated >= cutoff, f"{meta.id} updated date is stale"


def test_mappings_for_is_bidirectional() -> None:
    idx = load_controls()
    # Any control referenced as a target in a mapping entry should surface
    # that entry when queried directly.
    for entry in idx.mapping.entries:  # type: ignore[union-attr]
        for target in entry.targets:
            found = idx.mappings_for(target)
            assert any(entry.source == e.source for e in found), (
                f"target {target!r} of {entry.source!r} does not round-trip"
            )


def test_control_index_is_frozen() -> None:
    idx = load_controls()
    # ControlIndex is frozen; direct mutation must raise.
    with pytest.raises(ValidationError):
        idx.controls = ()
