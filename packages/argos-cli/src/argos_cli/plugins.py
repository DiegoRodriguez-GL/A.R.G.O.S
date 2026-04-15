"""Plugin discovery via importlib.metadata entry points."""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from importlib.metadata import EntryPoint, entry_points
from typing import Literal

PluginGroup = Literal[
    "argos.scanner_rules",
    "argos.probes",
    "argos.proxy_detectors",
    "argos.reporters",
    "argos.rule_matchers",
]

_ALL_GROUPS: tuple[PluginGroup, ...] = (
    "argos.scanner_rules",
    "argos.probes",
    "argos.proxy_detectors",
    "argos.reporters",
    "argos.rule_matchers",
)


@dataclass(frozen=True, slots=True)
class DiscoveredPlugin:
    group: PluginGroup
    name: str
    entry_point: EntryPoint

    def load(self) -> object:
        return self.entry_point.load()


def discover(group: PluginGroup | None = None) -> Iterator[DiscoveredPlugin]:
    """Yield every plugin registered in ``group`` (or all known groups)."""
    groups: tuple[PluginGroup, ...] = (group,) if group else _ALL_GROUPS
    for g in groups:
        for ep in entry_points(group=g):
            yield DiscoveredPlugin(group=g, name=ep.name, entry_point=ep)
