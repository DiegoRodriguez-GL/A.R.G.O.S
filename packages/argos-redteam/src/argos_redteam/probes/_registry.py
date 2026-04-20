"""Decorator-based registry for built-in probes (mirror of the scanner's)."""

from __future__ import annotations

import fnmatch
from collections.abc import Iterable

from argos_redteam.probes._base import BaseProbe

_REGISTRY: dict[str, BaseProbe] = {}


def register(cls: type[BaseProbe]) -> type[BaseProbe]:
    instance = cls()
    if instance.probe_id in _REGISTRY:
        msg = f"duplicate probe id: {instance.probe_id}"
        raise ValueError(msg)
    _REGISTRY[instance.probe_id] = instance
    return cls


def all_probes() -> tuple[BaseProbe, ...]:
    return tuple(_REGISTRY.values())


def select(patterns: Iterable[str] | None) -> tuple[BaseProbe, ...]:
    tup = tuple(patterns or ())
    if not tup:
        return all_probes()
    return tuple(p for p in _REGISTRY.values() if any(fnmatch.fnmatch(p.probe_id, g) for g in tup))


def _load_builtins() -> None:
    # Side-effect imports: each module decorates its probes with @register.
    from argos_redteam.probes import (  # noqa: F401, PLC0415
        asi01_memory_poisoning,
        asi02_tool_misuse,
        asi03_privilege_compromise,
        asi04_resource_overload,
        asi05_cascading_hallucination,
        asi06_intent_breaking,
        asi07_misaligned_deceptive,
        asi08_repudiation,
        asi09_identity_spoofing,
        asi10_hitl_overwhelm,
    )


_load_builtins()
