"""Parser and validation tests for the YAML rules DSL."""

from __future__ import annotations

from pathlib import Path

import pytest
from argos_rules import Rule, RuleError, load_rule_file, load_rules_dir, parse_rule

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"


_MINIMAL = """
id: TEST-RULE-01
info:
  name: "minimal"
  severity: low
matchers:
  - type: word
    words: ["foo"]
"""


def test_parse_minimal_rule_succeeds() -> None:
    rule = parse_rule(_MINIMAL)
    assert isinstance(rule, Rule)
    assert rule.id == "TEST-RULE-01"
    assert rule.info.severity.value == "low"


def test_parse_rule_rejects_extra_keys() -> None:
    bad = _MINIMAL + "extra: nope\n"
    with pytest.raises(RuleError):
        parse_rule(bad)


def test_parse_rule_rejects_unknown_severity() -> None:
    bad = _MINIMAL.replace("severity: low", "severity: bananas")
    with pytest.raises(RuleError):
        parse_rule(bad)


def test_parse_rule_rejects_invalid_id() -> None:
    bad = _MINIMAL.replace("TEST-RULE-01", "lowercase")
    with pytest.raises(RuleError):
        parse_rule(bad)


def test_parse_rule_rejects_malformed_regex() -> None:
    bad = """
id: TEST-RULE-01
info:
  name: "x"
  severity: low
matchers:
  - type: regex
    regex: ["[unterminated"]
"""
    with pytest.raises(RuleError):
        parse_rule(bad)


def test_parse_rule_rejects_oversized_file() -> None:
    # Build text just above the 64 KiB limit.
    padding = "x" * (70 * 1024)
    bad = _MINIMAL + f"# {padding}\n"
    with pytest.raises(RuleError, match="exceeds"):
        parse_rule(bad)


def test_parse_rule_requires_mapping_root() -> None:
    with pytest.raises(RuleError):
        parse_rule("- a list\n- at the root")


def test_compliance_refs_must_be_qualified() -> None:
    bad = (
        _MINIMAL.replace('    words: ["foo"]', '    words: ["foo"]')
        + """
"""
    )
    bad = bad.replace(
        "  severity: low",
        "  severity: low\n  compliance:\n    - not_qualified",
    )
    with pytest.raises(RuleError, match="qualified id"):
        parse_rule(bad)


def test_load_rule_file_round_trips() -> None:
    rule = load_rule_file(EXAMPLES / "custom-deprecated-mcp-filesystem.yaml")
    assert rule.id == "CUSTOM-DEPRECATED-FS-PACKAGE"
    assert any(ref.startswith("owasp_asi:") for ref in rule.info.compliance)


def test_load_rule_file_rejects_non_yaml(tmp_path: Path) -> None:
    txt = tmp_path / "not.yaml.txt"
    txt.write_text("id: X\n", encoding="utf-8")
    with pytest.raises(RuleError):
        load_rule_file(txt)


def test_load_rules_dir_loads_every_example() -> None:
    rules = load_rules_dir(EXAMPLES)
    assert len(rules) >= 5
    ids = {r.id for r in rules}
    assert "CUSTOM-DEPRECATED-FS-PACKAGE" in ids
    assert "CUSTOM-INTERNAL-HOST-REMOTE" in ids


def test_load_rules_dir_rejects_duplicates(tmp_path: Path) -> None:
    (tmp_path / "a.yaml").write_text(_MINIMAL, encoding="utf-8")
    (tmp_path / "b.yaml").write_text(_MINIMAL, encoding="utf-8")
    with pytest.raises(RuleError, match="duplicate"):
        load_rules_dir(tmp_path)


def test_load_rules_dir_rejects_non_directory(tmp_path: Path) -> None:
    missing = tmp_path / "nope"
    with pytest.raises(RuleError):
        load_rules_dir(missing)
