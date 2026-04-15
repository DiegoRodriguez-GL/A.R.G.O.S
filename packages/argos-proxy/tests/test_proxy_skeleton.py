"""Skeleton-only checks for Module 0."""

from __future__ import annotations


def test_imports_cleanly() -> None:
    import argos_proxy
    from argos_proxy import detectors

    assert argos_proxy.__version__ == "0.0.1"
    assert detectors is not None
