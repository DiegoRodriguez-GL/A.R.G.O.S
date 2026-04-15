"""Smoke tests at the argos_scanner package boundary."""

from __future__ import annotations


def test_package_imports_cleanly() -> None:
    import argos_scanner

    assert argos_scanner.__version__ == "0.0.1"


def test_builtin_rules_are_discoverable() -> None:
    from argos_scanner import all_rules

    ids = {r.rule_id for r in all_rules()}
    assert len(ids) >= 15
    assert all(i.startswith("MCP-SEC-") for i in ids)
