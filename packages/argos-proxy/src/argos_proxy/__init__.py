"""ARGOS audit proxy: transparent JSON-RPC 2.0 / MCP interceptor.

The proxy sits between an MCP client and an upstream server, observes
every request and response, runs runtime detectors, and persists the
exchange for forensics. The public surface is intentionally narrow:

- :mod:`argos_proxy.jsonrpc` -- typed message models (Request,
  Response, Notification, Batch) plus framing helpers (NDJSON, stdio
  Content-Length).

Higher layers (the asyncio server, the interceptor, the detectors and
the SQLite forensics store) live in their own submodules and are wired
together by the ``argos proxy`` CLI.
"""

from __future__ import annotations

from argos_proxy.detectors import (
    DetectorFinding,
    FindingSink,
    InMemoryFindingSink,
    PIIDetector,
    ProxyDetector,
    ScopeDetector,
    ToolDriftDetector,
)
from argos_proxy.forensics import ForensicsStore, SqliteForensicsSink
from argos_proxy.interceptor import (
    ChainInterceptor,
    InterceptContext,
    PassThroughInterceptor,
    ProxyInterceptor,
)
from argos_proxy.jsonrpc import (
    Batch,
    ErrorObject,
    JsonRpcError,
    JsonRpcProtocolError,
    Message,
    Notification,
    Request,
    Response,
    parse_payload,
)
from argos_proxy.listener import (
    InterceptorFactory,
    ProxyListener,
    SessionManager,
    SessionMetrics,
)
from argos_proxy.otel import OtelTracingInterceptor
from argos_proxy.server import ProxyServer
from argos_proxy.transport import (
    CallableUpstreamFactory,
    ClosedTransportError,
    InMemoryTransport,
    InMemoryUpstreamFactory,
    SharedUpstreamFactory,
    StdioTransport,
    StdioUpstreamFactory,
    TcpAcceptedTransport,
    TcpTransport,
    TcpUpstreamFactory,
    Transport,
    TransportError,
    UpstreamFactory,
    make_transport_pair,
)

__all__ = [
    "Batch",
    "CallableUpstreamFactory",
    "ChainInterceptor",
    "ClosedTransportError",
    "DetectorFinding",
    "ErrorObject",
    "FindingSink",
    "ForensicsStore",
    "InMemoryFindingSink",
    "InMemoryTransport",
    "InMemoryUpstreamFactory",
    "InterceptContext",
    "InterceptorFactory",
    "JsonRpcError",
    "JsonRpcProtocolError",
    "Message",
    "Notification",
    "OtelTracingInterceptor",
    "PIIDetector",
    "PassThroughInterceptor",
    "ProxyDetector",
    "ProxyInterceptor",
    "ProxyListener",
    "ProxyServer",
    "Request",
    "Response",
    "ScopeDetector",
    "SessionManager",
    "SessionMetrics",
    "SharedUpstreamFactory",
    "SqliteForensicsSink",
    "StdioTransport",
    "StdioUpstreamFactory",
    "TcpAcceptedTransport",
    "TcpTransport",
    "TcpUpstreamFactory",
    "ToolDriftDetector",
    "Transport",
    "TransportError",
    "UpstreamFactory",
    "make_transport_pair",
    "parse_payload",
]

__version__ = "0.0.1"
