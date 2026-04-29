"""Runtime detectors for intercepted MCP traffic.

A detector is a :class:`ProxyInterceptor` whose hooks observe (and
optionally veto or annotate) JSON-RPC traffic without altering it.
Three are shipped in M5.3:

- :class:`ToolDriftDetector`: flags ``tools/list`` responses whose
  schema diverges from a pinned baseline. Catches a hostile upstream
  that quietly mutates a tool definition mid-session ("rug-pull").
- :class:`PIIDetector`: scans request and response payloads for
  patterns matching common PII (emails, IBANs, payment cards, Spanish
  DNIs). Findings emit through the proxy's finding sink.
- :class:`ScopeDetector`: enforces an allowlist of permitted
  ``tools/call`` names; everything else is short-circuited with a
  ``-32601`` (or a configurable code) so the request never reaches
  the upstream tool.

Detectors emit :class:`argos_core.Finding` objects via a sink callback.
The sink is async so detectors can persist findings to SQLite (Phase 4)
or to an in-memory ring buffer (tests, benchmark).
"""

from __future__ import annotations

from argos_proxy.detectors._base import (
    DetectorFinding,
    FindingSink,
    InMemoryFindingSink,
    ProxyDetector,
)
from argos_proxy.detectors.pii import PIIDetector
from argos_proxy.detectors.scope import ScopeDetector
from argos_proxy.detectors.tool_drift import (
    ToolDefinitionSnapshot,
    ToolDriftDetector,
)

__all__ = [
    "DetectorFinding",
    "FindingSink",
    "InMemoryFindingSink",
    "PIIDetector",
    "ProxyDetector",
    "ScopeDetector",
    "ToolDefinitionSnapshot",
    "ToolDriftDetector",
]
