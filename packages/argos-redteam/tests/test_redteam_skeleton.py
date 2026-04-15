"""Skeleton-only checks for Module 0."""

from __future__ import annotations


def test_imports_cleanly() -> None:
    import argos_redteam
    from argos_redteam import detectors, probes, strategies

    assert argos_redteam.__version__ == "0.0.1"
    for mod in (probes, detectors, strategies):
        assert mod is not None
