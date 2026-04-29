"""Tests for ``GroundTruth`` and the YAML loader / writer.

These pin the wire contract of the ground-truth file that the
dissertation cites alongside its empirical results: a tampered or
silently-renamed cell must surface as a load error, not as a quiet
metric drop.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from argos_eval import (
    GroundTruth,
    Outcome,
    all_agents,
    default_ground_truth,
    default_ground_truth_path,
)
from argos_redteam import all_probes
from pydantic import ValidationError

# ---------------------------------------------------------------------------
# Construction & invariants.
# ---------------------------------------------------------------------------


def test_default_construction_is_empty() -> None:
    gt = GroundTruth()
    assert gt.fire_cells == ()
    assert gt.total_fire_cells() == 0


def test_extra_fields_are_rejected() -> None:
    with pytest.raises(ValidationError):
        GroundTruth.model_validate({"fire_cells": [], "ufo": True})


def test_is_frozen() -> None:
    gt = GroundTruth(fire_cells=(("lab.x.y", "P1"),))
    with pytest.raises(ValidationError):
        gt.fire_cells = ()


def test_duplicate_cells_are_rejected() -> None:
    with pytest.raises(ValidationError, match=r"duplicate"):
        GroundTruth(
            fire_cells=(
                ("lab.react.vulnerable", "ASI02-TOOL-ARG-SMUGGLE"),
                ("lab.react.vulnerable", "ASI02-TOOL-ARG-SMUGGLE"),
            ),
        )


def test_empty_string_in_cell_is_rejected() -> None:
    with pytest.raises(ValidationError):
        GroundTruth(fire_cells=(("", "P1"),))
    with pytest.raises(ValidationError):
        GroundTruth(fire_cells=(("agent", " "),))


def test_cells_get_sorted_canonically_on_construction() -> None:
    """Reproducibility: the model normalises ``fire_cells`` to its
    sorted form so two value-equal GroundTruths serialise identically."""
    a = GroundTruth(
        fire_cells=(
            ("lab.react.vulnerable", "ASI06-INTENT-TOOLDESC"),
            ("lab.react.vulnerable", "ASI02-TOOL-ARG-SMUGGLE"),
        ),
    )
    b = GroundTruth(
        fire_cells=(
            ("lab.react.vulnerable", "ASI02-TOOL-ARG-SMUGGLE"),
            ("lab.react.vulnerable", "ASI06-INTENT-TOOLDESC"),
        ),
    )
    assert a == b
    assert a.fire_cells == b.fire_cells


# ---------------------------------------------------------------------------
# expected_for: simple lookup.
# ---------------------------------------------------------------------------


def test_expected_for_returns_fire_when_pair_is_listed() -> None:
    gt = GroundTruth(fire_cells=(("agent.x", "ASI01-X"),))
    assert gt.expected_for("agent.x", "ASI01-X") is Outcome.FIRE


def test_expected_for_returns_block_for_unlisted_pair() -> None:
    gt = GroundTruth(fire_cells=(("agent.x", "ASI01-X"),))
    assert gt.expected_for("agent.y", "ASI01-X") is Outcome.BLOCK
    assert gt.expected_for("agent.x", "ASI02-Y") is Outcome.BLOCK


# ---------------------------------------------------------------------------
# from_lab_agents: factory derives the matrix from declared surfaces.
# ---------------------------------------------------------------------------


def test_from_lab_agents_includes_only_vulnerable_variants() -> None:
    gt = GroundTruth.from_lab_agents(list(all_agents()))
    agents_in_cells = {agent_id for agent_id, _ in gt.fire_cells}
    # No hardened agent should appear: the factory never expects a
    # hardened agent to fire on its surface.
    for agent_id in agents_in_cells:
        assert ".hardened" not in agent_id, agent_id


def test_from_lab_agents_covers_every_vulnerable_surface_entry() -> None:
    """Every (vulnerable_agent, probe_in_surface) pair must end up as a
    fire cell. Otherwise Phase 3 would silently under-count expected
    detections."""
    agents = list(all_agents())
    gt = GroundTruth.from_lab_agents(agents)
    expected = {(a.agent_id, p) for a in agents if a.is_vulnerable for p in a.vulnerability_surface}
    assert set(gt.fire_cells) == expected


# ---------------------------------------------------------------------------
# YAML round-trip.
# ---------------------------------------------------------------------------


def test_to_yaml_round_trips_through_file(tmp_path: Path) -> None:
    original = GroundTruth.from_lab_agents(list(all_agents()))
    path = tmp_path / "gt.yaml"
    original.to_yaml(path)
    rebuilt = GroundTruth.from_yaml(path)
    assert rebuilt.fire_cells == original.fire_cells
    assert rebuilt.schema_version == original.schema_version


def test_to_yaml_returns_text_and_optionally_writes(tmp_path: Path) -> None:
    gt = GroundTruth(fire_cells=(("a.x.y", "P1"),))
    text = gt.to_yaml()
    assert "schema_version" in text
    assert "P1" in text
    # Without a path, no file is written; this lets the CLI echo to stdout.
    assert not (tmp_path / "should-not-exist.yaml").exists()


def test_from_yaml_rejects_oversized_file(tmp_path: Path) -> None:
    """A huge YAML is either misconfiguration or an attempt at a tag
    bomb; we cap and refuse before the parser runs."""
    big = tmp_path / "huge.yaml"
    big.write_text("x: " + ("y" * (2 * 1024 * 1024)), encoding="utf-8")
    with pytest.raises(ValueError, match=r"exceeds"):
        GroundTruth.from_yaml(big)


def test_from_yaml_rejects_symlink(tmp_path: Path) -> None:
    target = tmp_path / "real.yaml"
    target.write_text("schema_version: 1\nfire: {}\n", encoding="utf-8")
    link = tmp_path / "link.yaml"
    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks not supported on this filesystem/account")
    with pytest.raises(ValueError, match=r"symbolic link"):
        GroundTruth.from_yaml(link)


def test_from_yaml_rejects_invalid_yaml(tmp_path: Path) -> None:
    path = tmp_path / "bad.yaml"
    path.write_text("[ this is :: not valid", encoding="utf-8")
    with pytest.raises(ValueError, match=r"invalid YAML"):
        GroundTruth.from_yaml(path)


def test_from_yaml_rejects_non_mapping_root(tmp_path: Path) -> None:
    path = tmp_path / "list.yaml"
    path.write_text("- 1\n- 2\n", encoding="utf-8")
    with pytest.raises(ValueError, match=r"YAML mapping"):
        GroundTruth.from_yaml(path)


def test_from_yaml_rejects_non_list_fire_entry(tmp_path: Path) -> None:
    path = tmp_path / "bad-fire.yaml"
    path.write_text(
        "schema_version: 1\nfire:\n  agent.x: not-a-list\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match=r"must be a list"):
        GroundTruth.from_yaml(path)


def test_from_yaml_handles_missing_fire_section(tmp_path: Path) -> None:
    """A YAML with no ``fire`` key is valid: an empty matrix where
    every cell defaults to BLOCK."""
    path = tmp_path / "empty.yaml"
    path.write_text("schema_version: 1\nnote: empty file\n", encoding="utf-8")
    gt = GroundTruth.from_yaml(path)
    assert gt.total_fire_cells() == 0


def test_from_yaml_missing_file_raises_filenotfound(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        GroundTruth.from_yaml(tmp_path / "nope.yaml")


# ---------------------------------------------------------------------------
# Validation against a live catalogue.
# ---------------------------------------------------------------------------


def test_validate_against_passes_on_clean_inputs() -> None:
    gt = GroundTruth.from_lab_agents(list(all_agents()))
    gt.validate_against(
        known_agents={a.agent_id for a in all_agents()},
        known_probes={p.probe_id for p in all_probes()},
    )  # no exception


def test_validate_against_rejects_unknown_agent() -> None:
    gt = GroundTruth(fire_cells=(("not.a.lab.agent", "ASI01-MEM-PROGRESSIVE"),))
    with pytest.raises(ValueError, match=r"unknown agent_id"):
        gt.validate_against(
            known_agents={"lab.react.vulnerable"},
            known_probes={"ASI01-MEM-PROGRESSIVE"},
        )


def test_validate_against_rejects_unknown_probe() -> None:
    gt = GroundTruth(fire_cells=(("lab.react.vulnerable", "ASI99-DOES-NOT-EXIST"),))
    with pytest.raises(ValueError, match=r"unknown probe_id"):
        gt.validate_against(
            known_agents={"lab.react.vulnerable"},
            known_probes={"ASI01-MEM-PROGRESSIVE"},
        )


# ---------------------------------------------------------------------------
# Packaged default file.
# ---------------------------------------------------------------------------


def test_default_ground_truth_file_exists_in_wheel() -> None:
    path = default_ground_truth_path()
    assert path.is_file(), "ground_truth.yaml is not packaged with the wheel"


def test_default_ground_truth_loads_cleanly() -> None:
    gt = default_ground_truth()
    assert gt.total_fire_cells() > 0


def test_default_ground_truth_validates_against_live_catalogues() -> None:
    """Tripwire: the YAML on disk must reference only probe ids and
    agent ids that exist today. A renamed probe in a future commit
    will fail this test loudly instead of zeroing out a metric."""
    gt = default_ground_truth()
    gt.validate_against(
        known_agents={a.agent_id for a in all_agents()},
        known_probes={p.probe_id for p in all_probes()},
    )


def test_default_ground_truth_matches_factory_from_lab_agents() -> None:
    """The on-disk YAML must equal the factory output. If they drift,
    one of two things happened: someone edited the YAML by hand
    (intentional override -> add a regression test) or someone changed
    a surface and forgot to regenerate (defect)."""
    on_disk = default_ground_truth()
    from_factory = GroundTruth.from_lab_agents(list(all_agents()))
    assert on_disk.fire_cells == from_factory.fire_cells, (
        "Ground truth YAML is out of sync with lab agents' "
        "vulnerability_surface; regenerate or document the override."
    )
