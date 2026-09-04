"""In-process integrations that feed the proxy detector chain.

The audit proxy observes MCP traffic on the wire. Agents built with
LangChain / LangGraph call many of their tools in-process, so there is
no wire to sit on. The integrations here bridge that gap: framework
callbacks are translated into the same JSON-RPC shapes the proxy sees
(``tools/call`` requests and responses) and pushed through the same
interceptor chain, so one set of detectors, one forensics store and one
OTel trace format cover both deployment styles.
"""

from __future__ import annotations

from argos_proxy.integrations.langchain import (
    ArgosCallbackHandler,
    ArgosPolicyViolationError,
    AsyncArgosCallbackHandler,
)

__all__ = [
    "ArgosCallbackHandler",
    "ArgosPolicyViolationError",
    "AsyncArgosCallbackHandler",
]
