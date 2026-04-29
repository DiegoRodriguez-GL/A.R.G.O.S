"""Deterministic benchmark agents.

Six classes (three scenarios x vulnerable / hardened) plus
``ALL_AGENT_CLASSES`` for downstream phases that need to iterate every
agent in the suite without referencing them by name.
"""

from __future__ import annotations

from argos_eval.lab._base import LabAgent
from argos_eval.lab.scenario_a import ReActHardened, ReActVulnerable
from argos_eval.lab.scenario_b import LangGraphHardened, LangGraphVulnerable
from argos_eval.lab.scenario_c import MemoryHardened, MemoryVulnerable

ALL_AGENT_CLASSES: tuple[type[LabAgent], ...] = (
    ReActVulnerable,
    ReActHardened,
    LangGraphVulnerable,
    LangGraphHardened,
    MemoryVulnerable,
    MemoryHardened,
)


def all_agents() -> tuple[LabAgent, ...]:
    """Instantiate every lab agent. Construction is cheap (no I/O); a
    fresh tuple per call keeps tests free of cross-test state leaks."""
    return tuple(cls() for cls in ALL_AGENT_CLASSES)


__all__ = [
    "ALL_AGENT_CLASSES",
    "LabAgent",
    "LangGraphHardened",
    "LangGraphVulnerable",
    "MemoryHardened",
    "MemoryVulnerable",
    "ReActHardened",
    "ReActVulnerable",
    "all_agents",
]
