"""Multi-turn delivery: iterate a fixed sequence of follow-up prompts."""

from __future__ import annotations

from collections.abc import Iterable

from argos_redteam.models import Message, Role, Transcript
from argos_redteam.strategies._base import BaseStrategy
from argos_redteam.transport import AgentTransport


class MultiTurnStrategy(BaseStrategy):
    """Send every follow-up in order, letting the agent reply between turns."""

    def __init__(self, follow_ups: Iterable[str], *, max_turns: int = 8) -> None:
        self._follow_ups = tuple(follow_ups)
        self._max_turns = max_turns

    async def run(self, transport: AgentTransport, initial: Transcript) -> Transcript:
        transcript = initial
        # Always start by letting the agent answer the seed prompt.
        reply = await transport.send(transcript)
        transcript = transcript.with_message(reply)

        for i, follow_up in enumerate(self._follow_ups):
            if i >= self._max_turns:
                break
            transcript = transcript.with_message(Message(role=Role.USER, content=follow_up))
            reply = await transport.send(transcript)
            transcript = transcript.with_message(reply)
        return transcript
