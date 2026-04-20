"""Strategy abstraction: how a probe drives the transcript."""

from __future__ import annotations

from abc import ABC, abstractmethod

from argos_redteam.models import Transcript
from argos_redteam.transport import AgentTransport


class BaseStrategy(ABC):
    """Given an initial transcript, produce the full transcript after N turns."""

    @abstractmethod
    async def run(self, transport: AgentTransport, initial: Transcript) -> Transcript: ...
