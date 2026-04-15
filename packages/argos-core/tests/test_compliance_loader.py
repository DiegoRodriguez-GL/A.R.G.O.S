"""Tests for the compliance loader and the shipped framework YAMLs."""

from __future__ import annotations

import pytest
from argos_core.compliance import (
    Control,
    FrameworkMeta,
    Mapping,
    MappingEntry,
    load_controls,
)

_EXPECTED_FRAMEWORKS: tuple[str, ...] = (
    "owasp_asi",
    "csa_aicm",
    "eu_ai_act",
    "nist_ai_rmf",
    "iso_42001",
)


def test_every_declared_framework_is_loaded() -> None:
    index = load_controls()
    loaded = {m.id for m in index.frameworks}
    assert loaded == set(_EXPECTED_FRAMEWORKS)


def test_every_framework_has_meta() -> None:
    index = load_controls()
    for meta in index.frameworks:
        assert isinstance(meta, FrameworkMeta)
        assert meta.name
        assert meta.version
        assert meta.source_url
        assert meta.description


def test_controls_carry_canonical_framework_field() -> None:
    index = load_controls()
    for c in index.controls:
        assert isinstance(c, Control)
        assert c.framework in _EXPECTED_FRAMEWORKS


@pytest.mark.parametrize("framework", _EXPECTED_FRAMEWORKS)
def test_framework_is_not_empty(framework: str) -> None:
    index = load_controls()
    controls = index.by_framework(framework)
    assert len(controls) > 0, f"framework {framework} has no controls"


def test_mapping_is_loaded() -> None:
    index = load_controls()
    assert index.mapping is not None
    assert isinstance(index.mapping, Mapping)
    assert len(index.mapping.entries) > 0
    for entry in index.mapping.entries:
        assert isinstance(entry, MappingEntry)


def test_by_qid_lookup_works() -> None:
    index = load_controls()
    asi01 = index.by_qid("owasp_asi:ASI01")
    assert asi01 is not None
    assert asi01.title.startswith("Memory Poisoning")


def test_by_qid_returns_none_for_unknown() -> None:
    index = load_controls()
    assert index.by_qid("owasp_asi:DOES_NOT_EXIST") is None


def test_mappings_for_includes_both_source_and_targets() -> None:
    index = load_controls()
    asi01_mappings = index.mappings_for("owasp_asi:ASI01")
    assert len(asi01_mappings) >= 1
    # Inverse lookup: any control listed as a target should also surface the
    # same mapping entry when queried.
    target = asi01_mappings[0].targets[0]
    assert any(e.targets and target in e.targets for e in index.mappings_for(target))
