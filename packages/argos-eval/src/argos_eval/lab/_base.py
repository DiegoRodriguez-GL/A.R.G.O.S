"""Common base for the deterministic lab agents.

A lab agent is a pure function from a probe transcript to an assistant
reply. It implements :class:`argos_redteam.AgentTransport` so any
existing probe runs against it unchanged. Two design choices keep the
benchmark academically defensible:

- **Construct validity by construction.** Each agent is built to be
  vulnerable to a specific list of probe ids; the
  ``vulnerability_surface`` attribute records that list explicitly so
  the ground truth is visible without having to read the body of the
  class. Probes outside the surface are expected to BLOCK regardless
  of the variant; that is what makes "ReAct vulnerable does not fire
  on a memory-poisoning probe" meaningful evidence.

- **Full-transcript pattern matching.** Real agents see the system,
  user and tool messages; the lab agent does too. The base class
  concatenates every message in the transcript into a single haystack
  before scanning the regex script, so a tool-description injection
  (which lives in a SYSTEM message) can fire correctly even when the
  USER message is benign. This is the smallest faithful simulation of
  the actual attacker behaviour.
"""

from __future__ import annotations

import re
from abc import abstractmethod
from typing import ClassVar, Final

from argos_redteam.models import Message, Role, Transcript
from argos_redteam.transport import AgentTransport

_AGENT_ID_RE: Final[re.Pattern[str]] = re.compile(r"^lab\.[a-z][a-z0-9]*\.[a-z][a-z0-9]*$")


class LabAgent(AgentTransport):
    """Base class for the six deterministic benchmark agents.

    Subclasses MUST set the three ClassVar fields and override
    :meth:`_script` to return a list of ``(compiled_regex, response)``
    pairs. The first matching regex wins. When no pattern matches the
    agent falls back to :meth:`_default_reply`.
    """

    agent_id: ClassVar[str]
    vulnerability_surface: ClassVar[tuple[str, ...]]
    is_vulnerable: ClassVar[bool]

    def __init__(self) -> None:
        # Validate at instance construction. Class-level invariants
        # (id format, non-empty surface) cannot be enforced at class
        # definition because abstract base classes don't run
        # __init_subclass__ checks until subclassing time, and we want
        # the failure mode to surface in tests where the user actually
        # builds the agent.
        if not _AGENT_ID_RE.match(self.agent_id):
            msg = (
                f"{type(self).__name__}.agent_id must match "
                f"{_AGENT_ID_RE.pattern!r}; got {self.agent_id!r}"
            )
            raise ValueError(msg)
        if not self.vulnerability_surface:
            msg = f"{type(self).__name__}.vulnerability_surface must not be empty"
            raise ValueError(msg)
        # Pre-compile once. Patterns are case-insensitive by default to
        # mirror MockTransport's behaviour and the probe detectors'.
        self._compiled: list[tuple[re.Pattern[str], str]] = [
            (re.compile(pattern, re.IGNORECASE | re.DOTALL), reply)
            for pattern, reply in self._script()
        ]

    @abstractmethod
    def _script(self) -> list[tuple[str, str]]:
        """Ordered list of ``(pattern, response)``. First match wins."""

    def _default_reply(self) -> str:
        """Reply when no script pattern matches.

        Hardened agents return a strong refusal so probes off-surface
        cannot accidentally fire. Vulnerable agents return a neutral
        acknowledgement; their attack surface is purely what the script
        captures.
        """
        if self.is_vulnerable:
            return "Acknowledged. Continuing."
        return (
            "I cannot help with that request. Please review the policy "
            "or contact your administrator if you believe this is a mistake."
        )

    async def send(self, transcript: Transcript) -> Message:
        # Concatenate every message so a pattern can match content in
        # SYSTEM, USER, TOOL or AGENT roles equally. This is a faithful
        # simulation: real LLM agents see all of these as part of their
        # context window.
        haystack = "\n".join(
            f"[{m.role.value}{(':' + m.name) if m.name else ''}] {m.content}"
            for m in transcript.messages
        )
        for pattern, reply in self._compiled:
            if pattern.search(haystack):
                return Message(role=Role.ASSISTANT, content=reply)
        return Message(role=Role.ASSISTANT, content=self._default_reply())
