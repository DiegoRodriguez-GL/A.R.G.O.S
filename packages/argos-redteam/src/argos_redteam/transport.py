"""Transports used to interact with an agent under test.

Two concrete transports ship today:

- :class:`HttpTransport` talks to any agent that exposes an
  OpenAI-compatible or Anthropic-compatible chat endpoint, or a minimal
  ``POST /chat`` that accepts ``{"messages": [...]}``.
- :class:`MockTransport` deterministic in-memory agent for tests. It is
  configured with a script of ``(pattern, response)`` pairs.

Both implement :class:`AgentTransport`. New transports plug in by
subclassing the ABC. LangGraph integration lives on top of HttpTransport
as a thin adapter in ``argos_redteam.adapters.langgraph``.
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field

import httpx

from argos_redteam.models import Message, Role, Transcript

DEFAULT_TIMEOUT_SECONDS = 30.0


class TransportError(Exception):
    """Raised when a transport cannot complete a request."""


class AgentTransport(ABC):
    """Abstract contract: send a transcript, get the next assistant message."""

    @abstractmethod
    async def send(self, transcript: Transcript) -> Message: ...

    async def close(self) -> None:  # noqa: B027
        """Release resources (HTTP clients, sockets, ...).

        Default no-op: transports without long-lived state simply inherit.
        """


@dataclass(frozen=True)
class HttpTransport(AgentTransport):
    """HTTP POST transport for a chat-completions-style endpoint.

    The default payload shape is the subset common to OpenAI, Anthropic
    and most minimal wrappers:

        {"messages": [{"role": "user", "content": "..."}, ...]}

    and it expects a response with ``{"content": "..."}`` or OpenAI's
    ``{"choices": [{"message": {"content": "..."}}]}``. Override
    ``payload_fn`` / ``extract_fn`` to support other shapes.
    """

    endpoint: str
    headers: dict[str, str] = field(default_factory=dict)
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS

    async def send(self, transcript: Transcript) -> Message:
        payload = {
            "messages": [{"role": m.role.value, "content": m.content} for m in transcript.messages],
        }
        try:
            async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
                response = await client.post(
                    self.endpoint,
                    headers=self.headers,
                    json=payload,
                )
                response.raise_for_status()
                body = response.json()
        except httpx.HTTPError as exc:  # network / status errors
            msg = f"transport error talking to {self.endpoint}: {exc}"
            raise TransportError(msg) from exc
        except ValueError as exc:  # invalid JSON
            msg = f"transport got non-JSON from {self.endpoint}: {exc}"
            raise TransportError(msg) from exc

        content = _extract_content(body)
        return Message(role=Role.ASSISTANT, content=content)


def _extract_content(body: object) -> str:
    """Pull the assistant content out of common response shapes."""
    if isinstance(body, dict):
        content = body.get("content")
        if isinstance(content, str):
            return content
        choices = body.get("choices")
        if isinstance(choices, list) and choices:
            first = choices[0]
            if isinstance(first, dict):
                message = first.get("message")
                if isinstance(message, dict):
                    inner = message.get("content")
                    if isinstance(inner, str):
                        return inner
        text = body.get("text")
        if isinstance(text, str):
            return text
    msg = f"cannot extract assistant content from response: {body!r}"
    raise TransportError(msg)


@dataclass
class _ScriptEntry:
    pattern: re.Pattern[str]
    response: str


class MockTransport(AgentTransport):
    """In-process scripted transport. Only used by tests and examples.

    Accepts a list of ``(pattern, response)`` pairs; on each ``send`` it
    looks at the last user message and returns the first response whose
    pattern matches. Falls back to ``default`` when none matches.
    """

    def __init__(
        self,
        script: list[tuple[str, str]] | None = None,
        default: str = "I cannot help with that.",
    ) -> None:
        self._entries = [
            _ScriptEntry(pattern=re.compile(p, re.IGNORECASE), response=r)
            for p, r in (script or [])
        ]
        self._default = default
        self.history: list[Transcript] = []

    async def send(self, transcript: Transcript) -> Message:
        self.history.append(transcript)
        last_user = next(
            (m for m in reversed(transcript.messages) if m.role == Role.USER),
            None,
        )
        haystack = last_user.content if last_user else ""
        for entry in self._entries:
            if entry.pattern.search(haystack):
                return Message(role=Role.ASSISTANT, content=entry.response)
        return Message(role=Role.ASSISTANT, content=self._default)
