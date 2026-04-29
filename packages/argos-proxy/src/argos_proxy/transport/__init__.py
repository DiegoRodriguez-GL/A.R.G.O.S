"""Transport abstraction for the ARGOS audit proxy.

The proxy is bidirectional: it must send and receive JSON-RPC messages
on both the client side (downstream) and the upstream MCP server side.
A :class:`Transport` encapsulates one half of that exchange. Concrete
implementations:

- :class:`InMemoryTransport`: a paired pipe used in tests and in the
  Phase 6 benchmark; no syscalls, deterministic timing.
- :class:`StdioTransport` (Phase 2.2): forks an upstream subprocess
  speaking JSON-RPC over stdin/stdout with Content-Length framing.
- :class:`TcpTransport` (Phase 2.3): connects to a remote MCP server
  over TCP using NDJSON framing.

Every transport exposes the same minimal contract -- send/receive
typed messages -- so the server and interceptor never branch on which
transport is in play.
"""

from __future__ import annotations

from argos_proxy.transport._base import (
    ClosedTransportError,
    Transport,
    TransportError,
)
from argos_proxy.transport.memory import InMemoryTransport, make_transport_pair
from argos_proxy.transport.stdio import StdioTransport
from argos_proxy.transport.tcp import TcpTransport

__all__ = [
    "ClosedTransportError",
    "InMemoryTransport",
    "StdioTransport",
    "TcpTransport",
    "Transport",
    "TransportError",
    "make_transport_pair",
]
