"""The scanner ships no rules in Module 0 -- verify the import surface only."""

from __future__ import annotations


def test_package_imports_cleanly() -> None:
    import argos_scanner

    assert argos_scanner.__version__ == "0.0.1"


def test_rules_namespace_is_empty() -> None:
    from argos_scanner import rules

    # `annotations` comes from ``from __future__ import annotations`` in the
    # module; it is part of the Python runtime, not the ARGOS public surface.
    public = [name for name in dir(rules) if not name.startswith("_") and name != "annotations"]
    assert public == []
