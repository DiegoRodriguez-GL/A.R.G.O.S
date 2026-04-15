"""Static scanner rule contract."""

from __future__ import annotations

from abc import abstractmethod
from collections.abc import Iterable
from typing import Any

from argos_core.interfaces.plugin import IPlugin
from argos_core.models import Finding, Target


class IScanner(IPlugin):
    """Single static-analysis rule over a parsed artefact.

    Implementations MUST be stateless; ``scan`` is safe to call concurrently
    against independent ``artefact`` payloads.
    """

    @abstractmethod
    def scan(self, *, target: Target, artefact: Any) -> Iterable[Finding]: ...
