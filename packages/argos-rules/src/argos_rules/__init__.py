"""ARGOS YAML rules engine.

Canonical DSL lives under ``schema/rule.schema.json``.
Public API:

    load_rule_file(path)     -> Rule
    load_rules_dir(path)     -> tuple[Rule, ...]
    load_rules(paths)        -> tuple[Rule, ...]
    parse_rule(text)         -> Rule
    evaluate(rule, config)   -> tuple[Finding, ...]
    evaluate_all(rules, cfg) -> tuple[Finding, ...]
"""

from __future__ import annotations

from argos_rules.engine import evaluate, evaluate_all
from argos_rules.models import (
    Extractor,
    GlobMatcher,
    Info,
    Matcher,
    RegexExtractor,
    RegexMatcher,
    Rule,
    WordExtractor,
    WordMatcher,
)
from argos_rules.parser import (
    RuleError,
    load_rule_file,
    load_rules,
    load_rules_dir,
    parse_rule,
)

__all__ = [
    "Extractor",
    "GlobMatcher",
    "Info",
    "Matcher",
    "RegexExtractor",
    "RegexMatcher",
    "Rule",
    "RuleError",
    "WordExtractor",
    "WordMatcher",
    "evaluate",
    "evaluate_all",
    "load_rule_file",
    "load_rules",
    "load_rules_dir",
    "parse_rule",
]

__version__ = "0.0.1"
