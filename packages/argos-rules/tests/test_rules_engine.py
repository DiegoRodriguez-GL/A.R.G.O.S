"""End-to-end engine tests: rules applied to real MCPConfig instances."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from argos_core import Severity
from argos_rules import evaluate, evaluate_all, load_rule_file, load_rules_dir, parse_rule
from argos_scanner.parser import load as load_config

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"
SCANNER_FIXTURES = Path(__file__).resolve().parents[2] / "argos-scanner" / "tests" / "fixtures"


@pytest.fixture
def tarball_fixture(tmp_path: Path):  # type: ignore[no-untyped-def]
    def _make() -> Path:
        payload = {
            "mcpServers": {
                "pinned": {
                    "command": "pip",
                    "args": [
                        "install",
                        "https://files.example.com/mcp/tool-0.1.tar.gz",
                    ],
                },
            },
        }
        p = tmp_path / "cfg.json"
        p.write_text(json.dumps(payload), encoding="utf-8")
        return p

    return _make


def test_tarball_example_rule_fires(tarball_fixture) -> None:  # type: ignore[no-untyped-def]
    rule = load_rule_file(EXAMPLES / "custom-package-tarball-install.yaml")
    cfg = load_config(tarball_fixture())
    findings = evaluate(rule, cfg)
    assert len(findings) == 1
    assert findings[0].rule_id == "CUSTOM-PKG-TARBALL-URL"
    assert findings[0].severity == Severity.HIGH
    assert findings[0].producer == "argos-rules"


def test_internal_host_rule_fires_on_corp_tld(tmp_path: Path) -> None:
    rule = load_rule_file(EXAMPLES / "custom-internal-host-remote.yaml")
    cfg_path = tmp_path / "cfg.json"
    cfg_path.write_text(
        json.dumps({"mcpServers": {"x": {"url": "https://svc.internal.acme.com/mcp"}}}),
        encoding="utf-8",
    )
    cfg = load_config(cfg_path)
    findings = evaluate(rule, cfg)
    assert [f.rule_id for f in findings] == ["CUSTOM-INTERNAL-HOST-REMOTE"]


def test_internal_host_rule_does_not_fire_on_public(tmp_path: Path) -> None:
    rule = load_rule_file(EXAMPLES / "custom-internal-host-remote.yaml")
    cfg_path = tmp_path / "cfg.json"
    cfg_path.write_text(
        json.dumps({"mcpServers": {"x": {"url": "https://api.example.com/mcp"}}}),
        encoding="utf-8",
    )
    cfg = load_config(cfg_path)
    assert evaluate(rule, cfg) == ()


def test_rule_with_and_condition_requires_all_matchers(tmp_path: Path) -> None:
    source = """
id: TEST-AND
info:
  name: "require all"
  severity: medium
matchers-condition: and
matchers:
  - type: word
    part: server.command
    words: ["uvx"]
  - type: word
    part: server.env.MODE
    words: ["prod"]
"""
    rule = parse_rule(source)
    cfg_path = tmp_path / "cfg.json"
    cfg_path.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "ok": {"command": "uvx", "args": ["pkg==1"], "env": {"MODE": "prod"}},
                    "half": {"command": "uvx", "args": ["pkg==1"], "env": {"MODE": "dev"}},
                    "none": {"command": "node", "env": {"MODE": "prod"}},
                },
            },
        ),
        encoding="utf-8",
    )
    cfg = load_config(cfg_path)
    findings = evaluate(rule, cfg)
    fired_servers = {f.evidence[0].summary.split(":")[0] for f in findings}
    assert fired_servers == {"ok"}


def test_evaluate_all_aggregates(tmp_path: Path) -> None:
    rules = load_rules_dir(EXAMPLES)
    # Build a config that trips two example rules simultaneously.
    cfg_path = tmp_path / "cfg.json"
    cfg_path.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "tarball": {
                        "command": "pip",
                        "args": [
                            "install",
                            "https://files.example.com/mcp/tool.tar.gz",
                        ],
                    },
                    "internal": {"url": "https://intra.internal.acme.com/mcp"},
                },
            },
        ),
        encoding="utf-8",
    )
    cfg = load_config(cfg_path)
    findings = evaluate_all(rules, cfg)
    ids = {f.rule_id for f in findings}
    assert {"CUSTOM-PKG-TARBALL-URL", "CUSTOM-INTERNAL-HOST-REMOTE"} <= ids


def test_findings_carry_rule_compliance_refs(tmp_path: Path) -> None:
    rule = load_rule_file(EXAMPLES / "custom-internal-host-remote.yaml")
    cfg_path = tmp_path / "cfg.json"
    cfg_path.write_text(
        json.dumps({"mcpServers": {"x": {"url": "https://svc.internal.x.com/mcp"}}}),
        encoding="utf-8",
    )
    cfg = load_config(cfg_path)
    findings = evaluate(rule, cfg)
    assert findings[0].compliance_refs == rule.info.compliance


def test_extractors_attach_captured_evidence(tmp_path: Path) -> None:
    rule = load_rule_file(EXAMPLES / "custom-package-tarball-install.yaml")
    cfg_path = tmp_path / "cfg.json"
    cfg_path.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "x": {
                        "command": "bash",
                        "args": [
                            "-c",
                            "curl https://files.example.com/mcp.tar.gz -o /tmp/x",
                        ],
                    },
                },
            },
        ),
        encoding="utf-8",
    )
    cfg = load_config(cfg_path)
    findings = evaluate(rule, cfg)
    assert findings
    # extractor hit should be the tarball URL
    blob = findings[0].evidence[0].blob or ""
    assert "https://files.example.com/mcp.tar.gz" in blob


def test_engine_no_servers_returns_empty(tmp_path: Path) -> None:
    rule = load_rule_file(EXAMPLES / "custom-env-debug-flag.yaml")
    cfg_path = tmp_path / "cfg.json"
    cfg_path.write_text('{"mcpServers": {}}', encoding="utf-8")
    cfg = load_config(cfg_path)
    assert evaluate(rule, cfg) == ()


def test_clean_scanner_fixture_triggers_zero_yaml_rules() -> None:
    rules = load_rules_dir(EXAMPLES)
    cfg = load_config(SCANNER_FIXTURES / "clean.claude_desktop.json")
    findings = evaluate_all(rules, cfg)
    # Clean fixture must not fire any built-in example.
    assert findings == ()
