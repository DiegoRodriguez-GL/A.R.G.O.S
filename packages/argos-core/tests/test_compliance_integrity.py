"""Integrity invariants over the bundled compliance data.

These tests are the OE1 guarantee in code: every ASI threat is covered by at
least three controls from other frameworks; every mapping reference resolves
to a real control; every parent_id points at an existing control.
"""

from __future__ import annotations

import pytest
from argos_core.compliance import load_controls

_ASI_TOP_LEVEL = (
    "ASI01",
    "ASI02",
    "ASI03",
    "ASI04",
    "ASI05",
    "ASI06",
    "ASI07",
    "ASI08",
    "ASI09",
    "ASI10",
)


def test_all_ten_asi_categories_are_defined() -> None:
    index = load_controls()
    ids = {c.id for c in index.by_framework("owasp_asi")}
    for expected in _ASI_TOP_LEVEL:
        assert expected in ids, f"missing top-level ASI category: {expected}"


@pytest.mark.parametrize("asi_id", _ASI_TOP_LEVEL)
def test_each_asi_threat_has_at_least_three_cross_framework_controls(asi_id: str) -> None:
    """OE1 invariant: every ASI threat must be auditable through >=3 controls
    from frameworks other than OWASP ASI itself."""
    index = load_controls()
    assert index.mapping is not None
    source_qid = f"owasp_asi:{asi_id}"
    entry = next((e for e in index.mapping.entries if e.source == source_qid), None)
    assert entry is not None, f"no mapping entry for {source_qid}"
    foreign_targets = [t for t in entry.targets if not t.startswith("owasp_asi:")]
    assert len(foreign_targets) >= 3, (
        f"{asi_id} is cross-referenced by only {len(foreign_targets)} non-ASI "
        f"controls; OE1 requires >= 3 auditable controls per threat"
    )


def test_every_mapping_reference_resolves() -> None:
    """No dangling qualified ids. Every source and target must exist."""
    index = load_controls()
    assert index.mapping is not None
    known: set[str] = {c.qid for c in index.controls}
    missing: list[tuple[str, str]] = []
    for entry in index.mapping.entries:
        if entry.source not in known:
            missing.append(("source", entry.source))
        missing.extend(("target", t) for t in entry.targets if t not in known)
    assert not missing, f"unresolved qualified ids: {missing}"


def test_every_parent_id_resolves_within_its_framework() -> None:
    index = load_controls()
    by_fw: dict[str, set[str]] = {}
    for c in index.controls:
        by_fw.setdefault(c.framework, set()).add(c.id)
    orphans: list[tuple[str, str, str]] = []
    for c in index.controls:
        if c.parent_id is None:
            continue
        if c.parent_id not in by_fw.get(c.framework, set()):
            orphans.append((c.framework, c.id, c.parent_id))
    assert not orphans, f"controls pointing at missing parents: {orphans}"


def test_control_ids_are_unique_within_a_framework() -> None:
    index = load_controls()
    seen: dict[str, set[str]] = {}
    for c in index.controls:
        ids = seen.setdefault(c.framework, set())
        assert c.id not in ids, f"duplicate control id in {c.framework}: {c.id}"
        ids.add(c.id)


def test_asi_hub_is_declared_in_mapping_meta() -> None:
    index = load_controls()
    assert index.mapping is not None
    assert index.mapping.meta.hub == "owasp_asi"


def test_mapping_covers_every_asi_top_level() -> None:
    index = load_controls()
    assert index.mapping is not None
    sources = {e.source for e in index.mapping.entries}
    for asi_id in _ASI_TOP_LEVEL:
        assert f"owasp_asi:{asi_id}" in sources, f"ASI top-level {asi_id} has no mapping entry"


def test_every_mapping_entry_targets_at_least_four_frameworks() -> None:
    """Each ASI threat should touch at least four frameworks to ensure
    regulation-agnostic coverage (CSA + EU + NIST + ISO)."""
    index = load_controls()
    assert index.mapping is not None
    for entry in index.mapping.entries:
        frameworks = {t.split(":", 1)[0] for t in entry.targets}
        assert len(frameworks) >= 4, (
            f"{entry.source} touches only {frameworks}; expected >= 4 non-hub frameworks"
        )


def test_framework_meta_ids_match_their_filenames_via_controls() -> None:
    """Every control's framework field matches the framework meta id that
    owns it (caught by the loader, double-checked here)."""
    index = load_controls()
    declared = {m.id for m in index.frameworks}
    used = {c.framework for c in index.controls}
    assert used.issubset(declared), f"orphan framework ids in controls: {used - declared}"
