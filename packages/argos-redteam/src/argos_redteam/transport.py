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

import asyncio
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass

import httpx

from argos_redteam.models import Message, Role, Transcript

DEFAULT_TIMEOUT_SECONDS = 30.0
_DEFAULT_USER_AGENT = "argos-redteam/0.0.1 (+https://github.com/DiegoRodriguez-GL/A.R.G.O.S)"
_RETRYABLE_STATUSES = frozenset({408, 425, 429, 500, 502, 503, 504})
_MAX_ERROR_BODY_CHARS = 256


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


class HttpTransport(AgentTransport):
    """HTTP POST transport for a chat-completions-style endpoint.

    The default payload shape is the subset common to OpenAI, Anthropic
    and most minimal wrappers:

        {"messages": [{"role": "user", "content": "..."}, ...]}

    and it expects a response with ``{"content": "..."}`` or OpenAI's
    ``{"choices": [{"message": {"content": "..."}}]}``.

    The transport reuses a single :class:`httpx.AsyncClient` across
    sends to avoid paying TLS-handshake cost on every probe turn, and
    retries transient HTTP failures (429 + 5xx family) with exponential
    backoff. A default ``User-Agent`` identifies ARGOS traffic so that
    defenders can whitelist or filter red-team probes in their logs.
    """

    def __init__(
        self,
        endpoint: str,
        headers: dict[str, str] | None = None,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
        *,
        max_retries: int = 2,
        backoff_seconds: float = 0.5,
        max_requests: int | None = None,
    ) -> None:
        self.endpoint = endpoint
        self.headers = dict(headers or {})
        self.timeout_seconds = timeout_seconds
        self.max_retries = max(0, int(max_retries))
        self.backoff_seconds = max(0.0, float(backoff_seconds))
        # Denial-of-wallet guard: if a run calls the agent more than
        # ``max_requests`` times the transport fails closed. None means
        # unbounded (compatible with prior behaviour).
        self.max_requests = None if max_requests is None else max(0, int(max_requests))
        self._sent_count = 0
        self.headers.setdefault("User-Agent", _DEFAULT_USER_AGENT)
        self._client: httpx.AsyncClient | None = None
        self._client_lock = asyncio.Lock()

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            async with self._client_lock:
                if self._client is None:
                    self._client = httpx.AsyncClient(timeout=self.timeout_seconds)
        return self._client

    async def send(self, transcript: Transcript) -> Message:
        # Enforce the denial-of-wallet budget BEFORE any network work so
        # a misconfigured probe set cannot drive traffic past the cap
        # while we are already mid-retry on a 503.
        if self.max_requests is not None and self._sent_count >= self.max_requests:
            msg = (
                f"request budget exhausted: max_requests={self.max_requests} "
                f"reached for {self.endpoint}; refusing further calls to "
                "protect against denial-of-wallet runs"
            )
            raise TransportError(msg)
        self._sent_count += 1

        payload = {
            "messages": [{"role": m.role.value, "content": m.content} for m in transcript.messages],
        }
        client = await self._get_client()
        last_exc: Exception | None = None
        for attempt in range(self.max_retries + 1):
            try:
                response = await client.post(
                    self.endpoint,
                    headers=self.headers,
                    json=payload,
                )
                response.raise_for_status()
                body = response.json()
            except httpx.HTTPStatusError as exc:
                status = exc.response.status_code
                if status in _RETRYABLE_STATUSES and attempt < self.max_retries:
                    last_exc = exc
                    await asyncio.sleep(self.backoff_seconds * (2**attempt))
                    continue
                msg = f"transport error talking to {self.endpoint}: HTTP {status}"
                raise TransportError(msg) from exc
            except httpx.HTTPError as exc:  # connection / timeout errors
                if attempt < self.max_retries:
                    last_exc = exc
                    await asyncio.sleep(self.backoff_seconds * (2**attempt))
                    continue
                msg = f"transport error talking to {self.endpoint}: {type(exc).__name__}"
                raise TransportError(msg) from exc
            except ValueError as exc:  # invalid JSON
                msg = f"transport got non-JSON from {self.endpoint}: {type(exc).__name__}"
                raise TransportError(msg) from exc
            else:
                content = _extract_content(body)
                return Message(role=Role.ASSISTANT, content=content)
        # Unreachable: the retry loop either returns or raises.
        msg = f"transport retries exhausted for {self.endpoint}"
        raise TransportError(msg) from last_exc

    async def close(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None


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
    # Do not embed the raw body in the exception message: it may be
    # megabytes long and may contain credentials echoed by the agent.
    preview = repr(body)
    if len(preview) > _MAX_ERROR_BODY_CHARS:
        preview = preview[:_MAX_ERROR_BODY_CHARS] + "...(truncated)"
    msg = f"cannot extract assistant content from response: {preview}"
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
