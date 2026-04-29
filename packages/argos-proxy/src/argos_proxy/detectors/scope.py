"""Scope detector: enforce an allowlist of permitted MCP method calls.

The MCP attack surface is: every server method the client knows about.
A common hardening is to declare an allowlist of *exactly* the methods
the audited agent should ever call. Anything else is either a bug in
the agent (wrong method name) or an exfiltration / privilege-escalation
attempt.

The detector short-circuits with :class:`argos_proxy.JsonRpcError` so
the request never reaches the upstream tool. The proxy server catches
that exception in ``_handle_client_to_upstream`` and answers the client
with a structured error response.

Two granularities:

- **method-level**: the ``method`` field is matched literally or by
  glob (``tools/*``).
- **tool-level**: when the method is ``tools/call``, the ``name`` field
  inside ``params`` is matched against the allowlist. This is the
  correct granularity for MCP because every tool call goes through the
  same JSON-RPC method.
"""

from __future__ import annotations

import fnmatch
from collections.abc import Iterable
from typing import Final

from argos_proxy.detectors._base import FindingSink, ProxyDetector
from argos_proxy.interceptor import InterceptContext
from argos_proxy.jsonrpc import (
    METHOD_NOT_FOUND,
    JsonRpcError,
    Notification,
    Request,
)

#: Methods the proxy never blocks regardless of the allowlist (the MCP
#: handshake itself; blocking these would deadlock the session).
_ALWAYS_ALLOWED: Final[frozenset[str]] = frozenset(
    {"initialize", "initialized", "ping", "shutdown", "exit"},
)


class ScopeDetector(ProxyDetector):
    """Block requests whose method/tool name is not in the allowlist."""

    detector_id = "argos.proxy.scope"

    def __init__(
        self,
        sink: FindingSink | None = None,
        *,
        allowed_methods: Iterable[str] = (),
        allowed_tools: Iterable[str] = (),
        block_on_violation: bool = True,
    ) -> None:
        super().__init__(sink)
        self._allowed_methods = tuple(allowed_methods)
        self._allowed_tools = tuple(allowed_tools)
        self._block = block_on_violation

    async def on_request_in(
        self,
        request: Request,
        ctx: InterceptContext,
    ) -> Request | None:
        if request.method in _ALWAYS_ALLOWED:
            return None
        method_ok = self._method_allowed(request.method)
        tool_name = self._extract_tool_name(request)
        tool_ok = self._tool_allowed(tool_name) if tool_name is not None else True

        if method_ok and tool_ok:
            return None

        evidence: dict[str, object] = {"method": request.method}
        if tool_name is not None:
            evidence["tool_name"] = tool_name
        await self.emit(
            ctx=ctx,
            severity="HIGH",
            message=(
                f"out-of-scope call: method={request.method!r}"
                + (f" tool={tool_name!r}" if tool_name else "")
            ),
            direction="client_to_upstream",
            method=request.method,
            evidence=evidence,
        )
        if not self._block:
            return None
        # Short-circuit. The proxy server converts this to a Response.
        msg = f"method {request.method!r} not in scope allowlist"
        if tool_name is not None and not tool_ok:
            msg = f"tool {tool_name!r} not in scope allowlist"
        raise JsonRpcError(METHOD_NOT_FOUND, msg, data=evidence)

    async def on_notification(
        self,
        notification: Notification,
        ctx: InterceptContext,
        *,
        from_client: bool,
    ) -> Notification | None:
        # Notifications cannot be answered; we still record the
        # violation for forensics but cannot block the message
        # because there is no response channel. The proxy server may
        # still forward it; that is intended.
        if not from_client or notification.method in _ALWAYS_ALLOWED:
            return None
        if not self._method_allowed(notification.method):
            await self.emit(
                ctx=ctx,
                severity="MEDIUM",
                message=f"out-of-scope notification: {notification.method!r}",
                direction="client_to_upstream",
                method=notification.method,
            )
        return None

    def _method_allowed(self, method: str) -> bool:
        if not self._allowed_methods:
            return True
        return any(fnmatch.fnmatchcase(method, pat) for pat in self._allowed_methods)

    def _tool_allowed(self, name: str) -> bool:
        if not self._allowed_tools:
            return True
        return any(fnmatch.fnmatchcase(name, pat) for pat in self._allowed_tools)

    @staticmethod
    def _extract_tool_name(request: Request) -> str | None:
        if request.method != "tools/call":
            return None
        params = request.params
        if not isinstance(params, dict):
            return None
        name = params.get("name")
        return name if isinstance(name, str) else None
