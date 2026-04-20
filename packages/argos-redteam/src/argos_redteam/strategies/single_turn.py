"""Single-turn delivery: send the seed prompt once, collect the reply."""

from __future__ import annotations

from argos_redteam.models import Transcript
from argos_redteam.strategies._base import BaseStrategy
from argos_redteam.transport import AgentTransport


class SingleTurnStrategy(BaseStrategy):
    async def run(self, transport: AgentTransport, initial: Transcript) -> Transcript:
        reply = await transport.send(initial)
        return initial.with_message(reply)
