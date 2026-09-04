"""LangChain / LangGraph callback handler backed by the ARGOS detector chain.

Proposal T3.3 asks for a LangGraph integration that emits OpenTelemetry
spans and audits tool use. Rather than re-implementing detection for a
second data path, every framework event is translated into the message
shapes the audit proxy already understands:

- ``on_tool_start``  -> ``tools/call`` :class:`Request` (client -> upstream)
- ``on_tool_end``    -> success :class:`Response` (upstream -> client)
- ``on_tool_error``  -> error :class:`Response`
- ``on_llm_start`` / ``on_chat_model_start`` / ``on_llm_end`` /
  ``on_agent_action`` -> :class:`Notification` under
  ``notifications/argos/*``

and pushed through a :class:`ProxyInterceptor` chain. The default chain
is the same one ``argos proxy run`` uses minus tool drift (LangChain
never emits a ``tools/list``): :class:`OtelTracingInterceptor` for
spans, :class:`PIIDetector` for personal data in prompts, arguments and
outputs, and :class:`ScopeDetector` for tools outside the declared
allowlist. Findings go to the configured :class:`FindingSink`; messages
are optionally persisted to the SQLite :class:`ForensicsStore` so the
callback trail is queryable with the same tooling as proxy captures.

Two handler classes are provided:

- :class:`ArgosCallbackHandler` for synchronous LangChain callbacks. The
  detector chain is async, so the handler owns a private event loop on a
  daemon thread and drives every event through it. This keeps the
  handler usable from plain scripts and from code that is itself running
  inside an event loop (the private loop never blocks on the caller's).
- :class:`AsyncArgosCallbackHandler` for ``AsyncCallbackHandler`` users:
  every hook is a coroutine awaited on the caller's loop.

``langchain-core`` is an optional dependency. When it is importable the
handlers subclass ``BaseCallbackHandler`` / ``AsyncCallbackHandler`` so
LangChain's type checks are satisfied; otherwise they subclass
``object`` and expose the same attribute surface (``raise_error``,
``run_inline``, ``ignore_*``), which is all LangChain's dispatcher reads.

Policy: the handler *observes* by default (proposal §7 excludes runtime
blocking). ``enforce=True`` turns a :class:`ScopeDetector` veto into an
:class:`ArgosPolicyViolationError` raised from ``on_tool_start``; with
``raise_error=True`` LangChain propagates it and the tool never runs.
"""

from __future__ import annotations

import asyncio
import json
import logging
import threading
import time
from collections.abc import Coroutine, Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final, TypeVar
from uuid import UUID

from argos_proxy.detectors import (
    DetectorFinding,
    FindingSink,
    InMemoryFindingSink,
    PIIDetector,
    ScopeDetector,
)
from argos_proxy.forensics import ForensicsStore, SqliteForensicsSink
from argos_proxy.interceptor import (
    ChainInterceptor,
    InterceptContext,
    ProxyInterceptor,
    new_correlation_id,
)
from argos_proxy.jsonrpc import (
    INTERNAL_ERROR,
    ErrorObject,
    JsonRpcError,
    Notification,
    Request,
    Response,
)
from argos_proxy.otel import OtelTracingInterceptor

if TYPE_CHECKING:
    # mypy sees plain ``object`` bases; at runtime the real LangChain
    # classes are used when the optional dependency is installed.
    _SyncBase = object
    _AsyncBase = object
else:  # pragma: no cover - exercised only when langchain-core is installed
    try:
        from langchain_core.callbacks import AsyncCallbackHandler as _AsyncBase
        from langchain_core.callbacks import BaseCallbackHandler as _SyncBase
    except ImportError:
        _SyncBase = object
        _AsyncBase = object

_log = logging.getLogger("argos.proxy.integrations.langchain")

_T = TypeVar("_T")

#: Free text captured from prompts, arguments and outputs is truncated
#: to this many characters before it reaches the detectors and the
#: forensics store. Keeps SQLite rows bounded when an agent streams a
#: multi-megabyte document through a tool.
DEFAULT_MAX_TEXT_CHARS: Final[int] = 8192

#: Timeout for driving one event through the private loop (sync handler).
_DRIVE_TIMEOUT_SECONDS: Final[float] = 30.0

_NOTIFICATION_PREFIX: Final[str] = "notifications/argos/"


class ArgosPolicyViolationError(Exception):
    """Raised by ``on_tool_start`` when ``enforce=True`` and a detector vetoed the call.

    Carries the JSON-RPC error triple the detector produced so the
    caller can log or surface it without re-parsing the message.
    """

    def __init__(self, code: int, message: str, data: object = None) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.data = data


@dataclass(frozen=True)
class _OpenCall:
    tool_name: str
    correlation_id: str
    started_at: float


def _truncate(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + f"...[truncated {len(text) - limit} chars]"


def _stringify(value: object, limit: int) -> str:
    if isinstance(value, str):
        return _truncate(value, limit)
    try:
        rendered = json.dumps(value, ensure_ascii=False, default=str, sort_keys=True)
    except (TypeError, ValueError):
        rendered = repr(value)
    return _truncate(rendered, limit)


def _run_id_str(run_id: UUID | str | None) -> str:
    if run_id is None:
        return new_correlation_id()
    return str(run_id)


def _tool_name(serialized: object, fallback: object) -> str:
    if isinstance(serialized, dict):
        name = serialized.get("name")
        if isinstance(name, str) and name:
            return name
    if isinstance(fallback, str) and fallback:
        return fallback
    return "unknown_tool"


def _generation_texts(response: object, limit: int) -> list[str]:
    """Pull generated text out of a LangChain ``LLMResult`` duck-typed."""
    generations = getattr(response, "generations", None)
    texts: list[str] = []
    if isinstance(generations, list):
        for batch in generations:
            if not isinstance(batch, list):
                continue
            for gen in batch:
                text = getattr(gen, "text", None)
                if isinstance(text, str):
                    texts.append(_truncate(text, limit))
                else:
                    message = getattr(gen, "message", None)
                    content = getattr(message, "content", None)
                    if isinstance(content, str):
                        texts.append(_truncate(content, limit))
    if not texts:
        texts.append(_stringify(response, limit))
    return texts


def _message_texts(messages: object, limit: int) -> list[list[str]]:
    """Flatten ``on_chat_model_start`` batches into plain strings."""
    out: list[list[str]] = []
    if not isinstance(messages, list):
        return out
    for batch in messages:
        if not isinstance(batch, list):
            continue
        row: list[str] = []
        for msg in batch:
            content = getattr(msg, "content", msg)
            row.append(_stringify(content, limit))
        out.append(row)
    return out


class _LoopThread:
    """A private asyncio loop on a daemon thread for the sync handler."""

    def __init__(self) -> None:
        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(
            target=self._loop.run_forever,
            name="argos-langchain-callbacks",
            daemon=True,
        )
        self._thread.start()

    def run(self, coro: Coroutine[Any, Any, _T], timeout: float) -> _T:
        future = asyncio.run_coroutine_threadsafe(coro, self._loop)
        return future.result(timeout)

    def close(self) -> None:
        if self._loop.is_closed():
            return
        self._loop.call_soon_threadsafe(self._loop.stop)
        self._thread.join(timeout=5.0)
        if not self._thread.is_alive():
            self._loop.close()


class _ArgosCallbackCore:
    """Framework-agnostic event translation shared by both handlers."""

    def __init__(
        self,
        *,
        interceptor: ProxyInterceptor,
        sink: FindingSink | None,
        store: ForensicsStore | None,
        enforce: bool,
        agent_id: str,
        max_text_chars: int,
    ) -> None:
        if max_text_chars <= 0:
            msg = f"max_text_chars must be positive, got {max_text_chars}"
            raise ValueError(msg)
        self._interceptor = interceptor
        self._sink = sink
        self._store = store
        self._enforce = enforce
        self._agent_id = agent_id
        self._max_text_chars = max_text_chars
        self._open: dict[str, _OpenCall] = {}
        self._violations: int = 0
        self._events: int = 0

    # --- introspection ---------------------------------------------------
    @property
    def interceptor(self) -> ProxyInterceptor:
        return self._interceptor

    @property
    def sink(self) -> FindingSink | None:
        return self._sink

    @property
    def store(self) -> ForensicsStore | None:
        return self._store

    @property
    def violations(self) -> int:
        """Number of detector vetoes seen so far (whether enforced or not)."""
        return self._violations

    @property
    def events(self) -> int:
        """Number of framework events translated so far."""
        return self._events

    @property
    def findings(self) -> list[DetectorFinding]:
        """Findings collected when the sink is an :class:`InMemoryFindingSink`."""
        if isinstance(self._sink, InMemoryFindingSink):
            return list(self._sink.findings)
        return []

    # --- context helpers -------------------------------------------------
    def _context(
        self,
        *,
        request_id: str,
        correlation_id: str | None = None,
        **extra: Any,
    ) -> InterceptContext:
        return InterceptContext(
            correlation_id=correlation_id or new_correlation_id(),
            received_at=time.monotonic(),
            client_request_id=request_id,
            extra={"source": "langchain", "agent_id": self._agent_id, **extra},
        )

    async def _ensure_store_open(self) -> None:
        if self._store is not None:
            await self._store.open()

    async def _record(
        self,
        ctx: InterceptContext,
        message: Request | Response | Notification,
        direction: str,
    ) -> None:
        if self._store is None:
            return
        await self._ensure_store_open()
        await self._store.record_message(ctx=ctx, message=message, direction=direction)

    # --- event translation ----------------------------------------------
    async def tool_start(
        self,
        *,
        tool_name: str,
        arguments: object,
        run_id: str,
        parent_run_id: str | None,
        tags: Sequence[str] | None,
    ) -> None:
        self._events += 1
        if isinstance(arguments, dict):
            args: object = {k: _stringify(v, self._max_text_chars) for k, v in arguments.items()}
        else:
            args = {"input": _stringify(arguments, self._max_text_chars)}
        request = Request(
            method="tools/call",
            params={"name": tool_name, "arguments": args},
            id=run_id,
        )
        ctx = self._context(
            request_id=run_id,
            parent_run_id=parent_run_id,
            tags=list(tags or ()),
            tool_name=tool_name,
        )
        self._open[run_id] = _OpenCall(
            tool_name=tool_name,
            correlation_id=ctx.correlation_id,
            started_at=ctx.received_at,
        )
        await self._record(ctx, request, "client_to_upstream")
        try:
            await self._interceptor.on_request_in(request, ctx)
        except JsonRpcError as err:
            self._violations += 1
            if self._enforce:
                raise ArgosPolicyViolationError(err.code, err.message, err.data) from err
            _log.warning("tool %r vetoed by detector (observe mode): %s", tool_name, err.message)
        except Exception:  # noqa: BLE001 - a buggy detector must not break the agent
            _log.exception("interceptor raised on tool_start; continuing")

    async def tool_end(self, *, output: object, run_id: str) -> None:
        self._events += 1
        text = _stringify(output, self._max_text_chars)
        response = Response(result={"content": [{"type": "text", "text": text}]}, id=run_id)
        await self._finish(run_id, response)

    async def tool_error(self, *, error: BaseException, run_id: str) -> None:
        self._events += 1
        message = _truncate(f"{type(error).__name__}: {error}", 1024) or "tool error"
        response = Response(
            error=ErrorObject(code=INTERNAL_ERROR, message=message),
            id=run_id,
        )
        await self._finish(run_id, response)

    async def _finish(self, run_id: str, response: Response) -> None:
        opened = self._open.pop(run_id, None)
        ctx = self._context(
            request_id=run_id,
            correlation_id=opened.correlation_id if opened else None,
            tool_name=opened.tool_name if opened else None,
            elapsed_ms=(time.monotonic() - opened.started_at) * 1000 if opened else None,
        )
        await self._record(ctx, response, "upstream_to_client")
        try:
            await self._interceptor.on_response_out(response, ctx)
        except JsonRpcError as err:
            # The tool already ran; a veto on the response is recorded
            # as a violation but cannot be enforced retroactively.
            self._violations += 1
            _log.warning("tool response vetoed by detector: %s", err.message)
        except Exception:  # noqa: BLE001
            _log.exception("interceptor raised on tool_end; continuing")

    async def notify(self, *, kind: str, params: dict[str, Any], run_id: str) -> None:
        self._events += 1
        notification = Notification(method=_NOTIFICATION_PREFIX + kind, params=params)
        ctx = self._context(request_id=run_id, event=kind)
        await self._record(ctx, notification, "client_to_upstream")
        try:
            await self._interceptor.on_notification(notification, ctx, from_client=True)
        except JsonRpcError as err:
            self._violations += 1
            _log.warning("notification %s vetoed by detector: %s", kind, err.message)
        except Exception:  # noqa: BLE001
            _log.exception("interceptor raised on %s; continuing", kind)

    async def aclose(self) -> None:
        if self._store is not None:
            await self._store.close()

    # --- payload builders (shared by sync and async handlers) -----------
    def llm_start_params(self, prompts: object) -> dict[str, Any]:
        items = prompts if isinstance(prompts, list) else [prompts]
        return {"prompts": [_stringify(p, self._max_text_chars) for p in items]}

    def chat_start_params(self, messages: object) -> dict[str, Any]:
        return {"messages": _message_texts(messages, self._max_text_chars)}

    def llm_end_params(self, response: object) -> dict[str, Any]:
        return {"generations": _generation_texts(response, self._max_text_chars)}

    def agent_action_params(self, action: object) -> dict[str, Any]:
        return {
            "tool": _stringify(getattr(action, "tool", action), 256),
            "tool_input": _stringify(getattr(action, "tool_input", None), self._max_text_chars),
        }


def _default_chain(
    *,
    sink: FindingSink | None,
    allowed_tools: Iterable[str],
    otel: bool,
) -> ProxyInterceptor:
    allowed = tuple(allowed_tools)
    chain: list[ProxyInterceptor] = []
    if otel:
        chain.append(OtelTracingInterceptor())
    chain.append(PIIDetector(sink))
    chain.append(
        ScopeDetector(
            sink,
            allowed_tools=allowed,
            block_on_violation=bool(allowed),
        ),
    )
    return ChainInterceptor(*chain)


class ArgosCallbackHandler(_SyncBase):
    """Synchronous LangChain callback handler routed through ARGOS detectors.

    Parameters
    ----------
    interceptor:
        The detector chain. ``None`` builds the default chain (OTel +
        PII + scope) from ``allowed_tools`` and ``sink``.
    sink:
        Where detector findings go. Defaults to an in-memory sink
        exposed via :attr:`findings`.
    allowed_tools:
        Tool names (or globs) the agent may call. Empty means "observe
        only, no scope policy". Ignored when ``interceptor`` is given.
    forensics_db:
        Optional SQLite path; every translated message is persisted
        with the same schema ``argos proxy run`` uses.
    enforce:
        Raise :class:`ArgosPolicyViolationError` from ``on_tool_start`` when
        the scope detector vetoes a call. Set ``raise_error=True`` as
        well so LangChain propagates the exception and skips the tool.
    """

    # LangChain dispatcher attributes. ``run_inline`` keeps ordering
    # deterministic (no thread pool between events).
    raise_error: bool = False
    run_inline: bool = True
    ignore_llm: bool = False
    ignore_chat_model: bool = False
    ignore_chain: bool = True
    ignore_agent: bool = False
    ignore_retriever: bool = True
    ignore_retry: bool = True
    ignore_custom_event: bool = True

    def __init__(
        self,
        *,
        interceptor: ProxyInterceptor | None = None,
        sink: FindingSink | None = None,
        allowed_tools: Iterable[str] = (),
        forensics_db: Path | str | None = None,
        enforce: bool = False,
        agent_id: str = "langchain",
        otel: bool = True,
        max_text_chars: int = DEFAULT_MAX_TEXT_CHARS,
    ) -> None:
        super().__init__()
        effective_sink = sink if sink is not None else InMemoryFindingSink()
        store = ForensicsStore(Path(forensics_db)) if forensics_db is not None else None
        if store is not None and sink is None:
            # Persist findings alongside messages when a database is given.
            effective_sink = SqliteForensicsSink(store)
        chain = interceptor or _default_chain(
            sink=effective_sink,
            allowed_tools=allowed_tools,
            otel=otel,
        )
        self._core = _ArgosCallbackCore(
            interceptor=chain,
            sink=effective_sink,
            store=store,
            enforce=enforce,
            agent_id=agent_id,
            max_text_chars=max_text_chars,
        )
        self.raise_error = enforce
        self._loop: _LoopThread | None = None
        self._closed = False

    # --- lifecycle -------------------------------------------------------
    def _drive(self, coro: Coroutine[Any, Any, _T]) -> _T:
        if self._closed:
            coro.close()
            msg = "ArgosCallbackHandler is closed"
            raise RuntimeError(msg)
        if self._loop is None:
            self._loop = _LoopThread()
        return self._loop.run(coro, _DRIVE_TIMEOUT_SECONDS)

    def close(self) -> None:
        """Flush the forensics store and stop the private loop. Idempotent."""
        if self._closed:
            return
        if self._loop is not None:
            try:
                self._loop.run(self._core.aclose(), _DRIVE_TIMEOUT_SECONDS)
            finally:
                self._loop.close()
                self._loop = None
        self._closed = True

    def __enter__(self) -> ArgosCallbackHandler:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    # --- introspection ---------------------------------------------------
    @property
    def findings(self) -> list[DetectorFinding]:
        return self._core.findings

    @property
    def violations(self) -> int:
        return self._core.violations

    @property
    def events(self) -> int:
        return self._core.events

    @property
    def sink(self) -> FindingSink | None:
        return self._core.sink

    @property
    def store(self) -> ForensicsStore | None:
        return self._core.store

    # --- LangChain hooks -------------------------------------------------
    def on_tool_start(
        self,
        serialized: dict[str, Any],
        input_str: str,
        *,
        run_id: UUID | str | None = None,
        parent_run_id: UUID | str | None = None,
        tags: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
        inputs: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> None:
        self._drive(
            self._core.tool_start(
                tool_name=_tool_name(serialized, kwargs.get("name")),
                arguments=inputs if inputs is not None else input_str,
                run_id=_run_id_str(run_id),
                parent_run_id=str(parent_run_id) if parent_run_id is not None else None,
                tags=tags,
            ),
        )

    def on_tool_end(
        self,
        output: Any,
        *,
        run_id: UUID | str | None = None,
        parent_run_id: UUID | str | None = None,
        **kwargs: Any,
    ) -> None:
        self._drive(self._core.tool_end(output=output, run_id=_run_id_str(run_id)))

    def on_tool_error(
        self,
        error: BaseException,
        *,
        run_id: UUID | str | None = None,
        parent_run_id: UUID | str | None = None,
        **kwargs: Any,
    ) -> None:
        self._drive(self._core.tool_error(error=error, run_id=_run_id_str(run_id)))

    def on_llm_start(
        self,
        serialized: dict[str, Any],
        prompts: list[str],
        *,
        run_id: UUID | str | None = None,
        **kwargs: Any,
    ) -> None:
        self._drive(
            self._core.notify(
                kind="llm_start",
                params=self._core.llm_start_params(prompts),
                run_id=_run_id_str(run_id),
            ),
        )

    def on_chat_model_start(
        self,
        serialized: dict[str, Any],
        messages: list[list[Any]],
        *,
        run_id: UUID | str | None = None,
        **kwargs: Any,
    ) -> None:
        self._drive(
            self._core.notify(
                kind="chat_model_start",
                params=self._core.chat_start_params(messages),
                run_id=_run_id_str(run_id),
            ),
        )

    def on_llm_end(
        self,
        response: Any,
        *,
        run_id: UUID | str | None = None,
        **kwargs: Any,
    ) -> None:
        self._drive(
            self._core.notify(
                kind="llm_end",
                params=self._core.llm_end_params(response),
                run_id=_run_id_str(run_id),
            ),
        )

    def on_agent_action(
        self,
        action: Any,
        *,
        run_id: UUID | str | None = None,
        **kwargs: Any,
    ) -> None:
        self._drive(
            self._core.notify(
                kind="agent_action",
                params=self._core.agent_action_params(action),
                run_id=_run_id_str(run_id),
            ),
        )


class AsyncArgosCallbackHandler(_AsyncBase):
    """Async variant of :class:`ArgosCallbackHandler` for ``AsyncCallbackHandler`` users.

    Same constructor and policy; every hook is awaited on the caller's
    event loop, so the forensics store and detectors share that loop.
    Call :meth:`aclose` when the agent run finishes.
    """

    raise_error: bool = False
    run_inline: bool = True
    ignore_llm: bool = False
    ignore_chat_model: bool = False
    ignore_chain: bool = True
    ignore_agent: bool = False
    ignore_retriever: bool = True
    ignore_retry: bool = True
    ignore_custom_event: bool = True

    def __init__(
        self,
        *,
        interceptor: ProxyInterceptor | None = None,
        sink: FindingSink | None = None,
        allowed_tools: Iterable[str] = (),
        forensics_db: Path | str | None = None,
        enforce: bool = False,
        agent_id: str = "langchain",
        otel: bool = True,
        max_text_chars: int = DEFAULT_MAX_TEXT_CHARS,
    ) -> None:
        super().__init__()
        effective_sink = sink if sink is not None else InMemoryFindingSink()
        store = ForensicsStore(Path(forensics_db)) if forensics_db is not None else None
        if store is not None and sink is None:
            effective_sink = SqliteForensicsSink(store)
        chain = interceptor or _default_chain(
            sink=effective_sink,
            allowed_tools=allowed_tools,
            otel=otel,
        )
        self._core = _ArgosCallbackCore(
            interceptor=chain,
            sink=effective_sink,
            store=store,
            enforce=enforce,
            agent_id=agent_id,
            max_text_chars=max_text_chars,
        )
        self.raise_error = enforce

    async def aclose(self) -> None:
        await self._core.aclose()

    async def __aenter__(self) -> AsyncArgosCallbackHandler:
        return self

    async def __aexit__(self, *_exc: object) -> None:
        await self.aclose()

    @property
    def findings(self) -> list[DetectorFinding]:
        return self._core.findings

    @property
    def violations(self) -> int:
        return self._core.violations

    @property
    def events(self) -> int:
        return self._core.events

    @property
    def sink(self) -> FindingSink | None:
        return self._core.sink

    @property
    def store(self) -> ForensicsStore | None:
        return self._core.store

    async def on_tool_start(
        self,
        serialized: dict[str, Any],
        input_str: str,
        *,
        run_id: UUID | str | None = None,
        parent_run_id: UUID | str | None = None,
        tags: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
        inputs: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> None:
        await self._core.tool_start(
            tool_name=_tool_name(serialized, kwargs.get("name")),
            arguments=inputs if inputs is not None else input_str,
            run_id=_run_id_str(run_id),
            parent_run_id=str(parent_run_id) if parent_run_id is not None else None,
            tags=tags,
        )

    async def on_tool_end(
        self,
        output: Any,
        *,
        run_id: UUID | str | None = None,
        parent_run_id: UUID | str | None = None,
        **kwargs: Any,
    ) -> None:
        await self._core.tool_end(output=output, run_id=_run_id_str(run_id))

    async def on_tool_error(
        self,
        error: BaseException,
        *,
        run_id: UUID | str | None = None,
        parent_run_id: UUID | str | None = None,
        **kwargs: Any,
    ) -> None:
        await self._core.tool_error(error=error, run_id=_run_id_str(run_id))

    async def on_llm_start(
        self,
        serialized: dict[str, Any],
        prompts: list[str],
        *,
        run_id: UUID | str | None = None,
        **kwargs: Any,
    ) -> None:
        await self._core.notify(
            kind="llm_start",
            params=self._core.llm_start_params(prompts),
            run_id=_run_id_str(run_id),
        )

    async def on_chat_model_start(
        self,
        serialized: dict[str, Any],
        messages: list[list[Any]],
        *,
        run_id: UUID | str | None = None,
        **kwargs: Any,
    ) -> None:
        await self._core.notify(
            kind="chat_model_start",
            params=self._core.chat_start_params(messages),
            run_id=_run_id_str(run_id),
        )

    async def on_llm_end(
        self,
        response: Any,
        *,
        run_id: UUID | str | None = None,
        **kwargs: Any,
    ) -> None:
        await self._core.notify(
            kind="llm_end",
            params=self._core.llm_end_params(response),
            run_id=_run_id_str(run_id),
        )

    async def on_agent_action(
        self,
        action: Any,
        *,
        run_id: UUID | str | None = None,
        **kwargs: Any,
    ) -> None:
        await self._core.notify(
            kind="agent_action",
            params=self._core.agent_action_params(action),
            run_id=_run_id_str(run_id),
        )


__all__ = [
    "DEFAULT_MAX_TEXT_CHARS",
    "ArgosCallbackHandler",
    "ArgosPolicyViolationError",
    "AsyncArgosCallbackHandler",
]
