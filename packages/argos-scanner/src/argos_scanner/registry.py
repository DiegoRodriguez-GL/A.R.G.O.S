"""Rule registry with a ``@register`` decorator for built-in rules."""

from __future__ import annotations

import fnmatch
from collections.abc import Iterable, Iterator

from argos_scanner.rules._base import BaseRule

_REGISTRY: dict[str, BaseRule] = {}


def register(rule_cls: type[BaseRule]) -> type[BaseRule]:
    """Class decorator: instantiate and register a built-in rule."""
    instance = rule_cls()
    if instance.rule_id in _REGISTRY:
        msg = f"duplicate rule id: {instance.rule_id}"
        raise ValueError(msg)
    _REGISTRY[instance.rule_id] = instance
    return rule_cls


def all_rules() -> tuple[BaseRule, ...]:
    """Snapshot of every currently registered rule."""
    return tuple(_REGISTRY.values())


def select(patterns: Iterable[str] | None) -> tuple[BaseRule, ...]:
    """Return rules whose id matches any of the glob patterns.

    ``None`` or an empty iterable returns every registered rule.
    """
    patterns_tuple = tuple(patterns or ())
    if not patterns_tuple:
        return all_rules()
    return tuple(
        r for r in _REGISTRY.values() if any(fnmatch.fnmatch(r.rule_id, p) for p in patterns_tuple)
    )


def _load_builtins() -> None:
    # Importing the rules subpackages triggers each module's @register call.
    # Done lazily to avoid a circular import at module load time.
    from argos_scanner.rules import (  # noqa: F401, PLC0415
        credentials,
        docker,
        filesystem,
        secrets,
        shell,
        supply_chain,
        tls,
        tool_poisoning,
    )


def iter_rules() -> Iterator[BaseRule]:
    if not _REGISTRY:
        _load_builtins()
    yield from _REGISTRY.values()


# Trigger loading at import time so `all_rules()` returns the full set.
_load_builtins()
