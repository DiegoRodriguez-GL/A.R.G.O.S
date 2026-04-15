"""Reporter contract."""

from __future__ import annotations

from abc import abstractmethod
from pathlib import Path

from argos_core.interfaces.plugin import IPlugin
from argos_core.models import ScanResult


class IReporter(IPlugin):
    @abstractmethod
    def render(self, result: ScanResult, output: Path) -> None: ...
