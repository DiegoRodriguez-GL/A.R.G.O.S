"""Cross-package invariants that protect the whole ARGOS pipeline.

These tests catch drift between subsystems: every scanner finding must
cite a compliance ref that resolves in the M1 mapping graph; every rule
must declare at least one OWASP ASI anchor; rule ids must follow a
canonical pattern; and the ARGOS-prefixed Finding id must stay unique
under load.
"""

from __future__ import annotations

import re
from pathlib import Path

from argos_core.compliance import load_controls
from argos_scanner import all_rules, scan

FIXTURES = Path(__file__).resolve().parents[2] / "argos-scanner" / "tests" / "fixtures"

_RULE_ID_RE = re.compile(r"^MCP-SEC-[A-Z0-9][A-Z0-9\-]*$")


def test_every_scanner_rule_declares_an_owasp_anchor() -> None:
    for rule in all_rules():
        anchors = [r for r in rule.compliance_refs if r.startswith("owasp_asi:")]
        assert anchors, f"rule {rule.rule_id} has no OWASP ASI anchor"


def test_every_scanner_rule_id_is_canonical() -> None:
    for rule in all_rules():
        assert _RULE_ID_RE.match(rule.rule_id), rule.rule_id


def test_every_scanner_compliance_ref_resolves_in_the_mapping() -> None:
    idx = load_controls()
    known_qids: set[str] = {c.qid for c in idx.controls}
    missing: list[tuple[str, str]] = []
    for rule in all_rules():
        missing.extend((rule.rule_id, ref) for ref in rule.compliance_refs if ref not in known_qids)
    assert not missing, f"rule compliance_refs not present in the control index: {missing}"


def test_no_duplicate_rule_ids() -> None:
    ids = [r.rule_id for r in all_rules()]
    assert len(ids) == len(set(ids))


def test_every_rule_metadata_is_well_formed() -> None:
    for rule in all_rules():
        meta = rule.metadata()
        assert meta.name == rule.rule_id
        assert meta.kind == "scanner-rule"
        assert meta.description


def test_findings_from_real_fixture_all_resolve_in_mapping_graph() -> None:
    idx = load_controls()
    known_qids: set[str] = {c.qid for c in idx.controls}
    result = scan(FIXTURES / "risky.claude_desktop.json")
    assert result.findings
    for f in result.findings:
        for ref in f.compliance_refs:
            assert ref in known_qids, f"finding {f.rule_id} cites unknown {ref}"


def test_findings_ids_are_unique_within_a_run() -> None:
    result = scan(FIXTURES / "risky.claude_desktop.json")
    ids = [f.id for f in result.findings]
    assert len(ids) == len(set(ids))


def test_every_rule_has_remediation_guidance() -> None:
    # Rules without remediation leave auditors without a clear next step.
    no_remediation = [r.rule_id for r in all_rules() if not r.remediation]
    assert not no_remediation, f"rules missing remediation: {no_remediation}"
