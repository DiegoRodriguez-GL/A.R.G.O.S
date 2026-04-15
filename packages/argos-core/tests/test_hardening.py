"""Hardening audit: invariants and limits that must hold under hostile input."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from argos_core import Evidence, Finding, ScanResult, Severity, Target
from argos_core.models.target import TargetKind
from pydantic import ValidationError


def _t() -> Target:
    return Target(kind=TargetKind.MCP_CONFIG, locator="x")


# ---------- Target: reject control characters in locator -----------------


def test_target_locator_rejects_control_characters() -> None:
    with pytest.raises(ValidationError):
        Target(kind=TargetKind.MCP_CONFIG, locator="bad\x00path")


def test_target_locator_rejects_newlines() -> None:
    # Locators appearing in reports must not smuggle terminal escapes.
    with pytest.raises(ValidationError):
        Target(kind=TargetKind.MCP_CONFIG, locator="x\n\rescape")


# ---------- ScanResult: finished_at must be >= started_at ----------------


def test_scan_result_rejects_time_travel() -> None:
    target = _t()
    now = datetime.now(UTC)
    with pytest.raises(ValidationError, match="finished_at"):
        ScanResult(
            target=target,
            producer="x@0",
            started_at=now,
            finished_at=now - timedelta(seconds=1),
        )


def test_scan_result_accepts_equal_timestamps() -> None:
    target = _t()
    now = datetime.now(UTC)
    r = ScanResult(target=target, producer="x@0", started_at=now, finished_at=now)
    assert r.duration_seconds == 0.0


# ---------- Finding: producer must be non-empty -------------------------


def test_finding_rejects_empty_producer() -> None:
    with pytest.raises(ValidationError):
        Finding(
            rule_id="X-1",
            title="t",
            description="d",
            severity=Severity.LOW,
            target=_t(),
            producer="",
        )


# ---------- Evidence: naked kind=source-range requires a path -----------


def test_evidence_source_range_without_path_is_rejected() -> None:
    # Evidence of kind 'source-range' is meaningless without a path.
    with pytest.raises(ValidationError, match="source-range"):
        Evidence(kind="source-range", summary="x")
