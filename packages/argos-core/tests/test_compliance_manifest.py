"""Integrity manifest for the bundled compliance data (THREAT_MODEL.md T4)."""

from __future__ import annotations

import warnings
from pathlib import Path

import pytest
from argos_core.compliance import (
    MANIFEST_FILENAME,
    ComplianceIntegrityWarning,
    load_controls,
    verify_manifest,
)
from argos_core.compliance import loader as loader_module
from argos_core.compliance.manifest import (
    VerificationResult,
    compute_digests,
    parse_manifest,
    render_manifest,
)

_EXPECTED_FILES = {
    "csa_aicm.yaml",
    "eu_ai_act.yaml",
    "iso_42001.yaml",
    "mapping.yaml",
    "nist_ai_rmf.yaml",
    "owasp_asi.yaml",
}


# ---------- shipped data ------------------------------------------------


def test_shipped_data_matches_its_manifest() -> None:
    result = verify_manifest()
    assert result.ok, result.summary()
    assert set(result.checked) == _EXPECTED_FILES


def test_shipped_manifest_covers_every_data_file() -> None:
    digests = compute_digests()
    assert set(digests) == _EXPECTED_FILES
    for digest in digests.values():
        assert len(digest) == 64


def test_load_controls_does_not_warn_on_pristine_data() -> None:
    load_controls.cache_clear()
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", ComplianceIntegrityWarning)
            load_controls()
    finally:
        load_controls.cache_clear()


# ---------- verification semantics --------------------------------------


def _populate(root: Path) -> None:
    (root / "a.yaml").write_text("a: 1\n", encoding="utf-8")
    (root / "b.yaml").write_text("b: 2\n", encoding="utf-8")
    (root / MANIFEST_FILENAME).write_text(render_manifest(compute_digests(root)), encoding="utf-8")


def test_verify_ok_on_consistent_directory(tmp_path: Path) -> None:
    _populate(tmp_path)
    result = verify_manifest(tmp_path)
    assert result.ok
    assert result.checked == ("a.yaml", "b.yaml")
    assert "match" in result.summary()


def test_verify_detects_modified_file(tmp_path: Path) -> None:
    _populate(tmp_path)
    (tmp_path / "a.yaml").write_text("a: 999\n", encoding="utf-8")
    result = verify_manifest(tmp_path)
    assert not result.ok
    assert result.mismatched == ("a.yaml",)
    assert "modified: a.yaml" in result.summary()


def test_verify_detects_missing_file(tmp_path: Path) -> None:
    _populate(tmp_path)
    (tmp_path / "b.yaml").unlink()
    result = verify_manifest(tmp_path)
    assert not result.ok
    assert result.missing == ("b.yaml",)


def test_verify_detects_unlisted_file(tmp_path: Path) -> None:
    _populate(tmp_path)
    (tmp_path / "c.yaml").write_text("c: 3\n", encoding="utf-8")
    result = verify_manifest(tmp_path)
    assert not result.ok
    assert result.unlisted == ("c.yaml",)


def test_verify_reports_absent_manifest(tmp_path: Path) -> None:
    (tmp_path / "a.yaml").write_text("a: 1\n", encoding="utf-8")
    result = verify_manifest(tmp_path)
    assert not result.ok
    assert not result.manifest_present
    assert MANIFEST_FILENAME in result.summary()


def test_non_yaml_files_are_ignored(tmp_path: Path) -> None:
    _populate(tmp_path)
    (tmp_path / "notes.txt").write_text("scratch", encoding="utf-8")
    assert verify_manifest(tmp_path).ok


# ---------- manifest grammar ----------------------------------------------


def test_parse_accepts_sha256sum_binary_prefix_and_comments() -> None:
    digest = "a" * 64
    text = f"# generated\n\n{digest} *file.yaml\n"
    assert parse_manifest(text) == {"file.yaml": digest}


def test_parse_normalises_uppercase_digest() -> None:
    digest = "A" * 64
    assert parse_manifest(f"{digest}  f.yaml") == {"f.yaml": "a" * 64}


@pytest.mark.parametrize(
    "line",
    [
        "not-a-digest  file.yaml",
        "abc  file.yaml",
        "a" * 64 + "  ../escape.yaml",
        "a" * 64 + "  sub/dir.yaml",
        "a" * 64,
    ],
)
def test_parse_rejects_malformed_lines(line: str) -> None:
    with pytest.raises(ValueError, match=MANIFEST_FILENAME):
        parse_manifest(line)


def test_render_is_sorted_and_round_trips() -> None:
    digests = {"z.yaml": "f" * 64, "a.yaml": "0" * 64}
    rendered = render_manifest(digests)
    assert rendered.splitlines()[0].endswith("a.yaml")
    assert parse_manifest(rendered) == digests


# ---------- loader integration --------------------------------------------


def test_load_controls_warns_when_manifest_drifts(monkeypatch: pytest.MonkeyPatch) -> None:
    drifted = VerificationResult(
        manifest_present=True,
        checked=("owasp_asi.yaml",),
        mismatched=("mapping.yaml",),
        missing=(),
        unlisted=(),
    )
    load_controls.cache_clear()
    monkeypatch.setattr(loader_module, "verify_manifest", lambda _root: drifted)
    try:
        with pytest.warns(ComplianceIntegrityWarning, match="mapping.yaml"):
            index = load_controls()
        # Drift is reported, not fatal: the data still loads.
        assert index.controls
    finally:
        load_controls.cache_clear()
