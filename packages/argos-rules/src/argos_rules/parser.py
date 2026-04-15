"""Load and validate YAML rule documents into :class:`Rule` models."""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from argos_rules.models import Rule

_MAX_RULE_BYTES = 64 * 1024
_MAX_RULES_PER_DIR = 1000
_YAML_SUFFIXES: frozenset[str] = frozenset({".yaml", ".yml"})


class RuleError(Exception):
    """Raised when a rule document cannot be loaded."""


def parse_rule(text: str, *, origin: str = "<string>") -> Rule:
    """Parse YAML text into a :class:`Rule` model."""
    if len(text.encode("utf-8")) > _MAX_RULE_BYTES:
        msg = f"{origin}: rule exceeds {_MAX_RULE_BYTES} bytes"
        raise RuleError(msg)
    try:
        raw: Any = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        msg = f"{origin}: invalid YAML ({exc})"
        raise RuleError(msg) from exc
    if not isinstance(raw, dict):
        msg = f"{origin}: top-level must be a YAML mapping"
        raise RuleError(msg)
    try:
        return Rule.model_validate(raw)
    except ValidationError as exc:
        msg = f"{origin}: {exc.error_count()} validation error(s)\n{exc}"
        raise RuleError(msg) from exc


def load_rule_file(path: Path) -> Rule:
    """Load a single ``.yaml``/``.yml`` file as a :class:`Rule`."""
    if not path.is_file():
        msg = f"not a file: {path}"
        raise RuleError(msg)
    if path.suffix.lower() not in _YAML_SUFFIXES:
        msg = f"not a YAML file: {path}"
        raise RuleError(msg)
    text = path.read_text(encoding="utf-8-sig")
    return parse_rule(text, origin=str(path))


def load_rules_dir(path: Path) -> tuple[Rule, ...]:
    """Load every YAML file under ``path`` (recursive). Duplicated rule ids
    inside the directory are rejected."""
    if not path.is_dir():
        msg = f"not a directory: {path}"
        raise RuleError(msg)

    files = sorted(p for p in path.rglob("*") if p.is_file() and p.suffix.lower() in _YAML_SUFFIXES)
    if len(files) > _MAX_RULES_PER_DIR:
        msg = f"directory {path} contains {len(files)} rules; max is {_MAX_RULES_PER_DIR}"
        raise RuleError(msg)

    rules: list[Rule] = []
    seen: set[str] = set()
    for f in files:
        rule = load_rule_file(f)
        if rule.id in seen:
            msg = f"duplicate rule id {rule.id!r} found at {f}"
            raise RuleError(msg)
        seen.add(rule.id)
        rules.append(rule)
    return tuple(rules)


def load_rules(paths: Iterable[Path]) -> tuple[Rule, ...]:
    """Load every rule file / directory in ``paths``."""
    rules: list[Rule] = []
    seen: set[str] = set()
    for p in paths:
        new = load_rules_dir(p) if p.is_dir() else (load_rule_file(p),)
        for rule in new:
            if rule.id in seen:
                msg = f"duplicate rule id {rule.id!r} across input paths"
                raise RuleError(msg)
            seen.add(rule.id)
            rules.append(rule)
    return tuple(rules)
