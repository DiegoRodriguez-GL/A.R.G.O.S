"""Detector base class and finding sink protocol.

A :class:`ProxyDetector` is a thin :class:`ProxyInterceptor` extension
that adds a :func:`emit` helper for funnelling structured findings to a
sink. The sink decouples detectors from persistence: in tests we use
:class:`InMemoryFindingSink`; in the live proxy the sink writes to
SQLite via the Phase 4 forensics module.

Findings the proxy emits are local to the proxy package -- they do NOT
inherit from :class:`argos_core.Finding` because the proxy's wire
contract differs from the static-scanner pipeline (correlation_id,
direction, request_id), and pinning that mismatch into an inheritance
relationship would tangle two unrelated lifecycles. A small adapter in
the CLI layer translates ``DetectorFinding`` -> ``argos_core.Finding``
when the operator asks for a unified report.
"""

from __future__ import annotations

import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any, Final, Literal, Protocol

from argos_proxy.interceptor import InterceptContext, ProxyInterceptor


@dataclass(frozen=True)
class DetectorFinding:
    """A structured detection emitted by a runtime detector.

    Fields chosen to be SQLite-friendly: every value is a primitive or
    a JSON-serialisable dict so the forensics writer can dump rows
    without bespoke encoders.
    """

    detector_id: str
    severity: Literal["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
    message: str
    correlation_id: str
    direction: Literal["client_to_upstream", "upstream_to_client"]
    method: str | None = None
    request_id: object = None
    evidence: dict[str, Any] = field(default_factory=dict)
    detected_at: float = field(default_factory=time.time)


class FindingSink(Protocol):
    """Async callable accepting one finding at a time."""

    async def __call__(self, finding: DetectorFinding) -> None: ...


class InMemoryFindingSink:
    """Test-only sink: collects findings into an in-memory list."""

    __slots__ = ("findings",)

    def __init__(self) -> None:
        self.findings: list[DetectorFinding] = []

    async def __call__(self, finding: DetectorFinding) -> None:
        self.findings.append(finding)

    def clear(self) -> None:
        self.findings.clear()

    def by_detector(self, detector_id: str) -> list[DetectorFinding]:
        return [f for f in self.findings if f.detector_id == detector_id]


_NOOP_SINK_SENTINEL: Final[FindingSink] = InMemoryFindingSink()


class ProxyDetector(ProxyInterceptor):
    """Base class for detectors with a finding sink.

    Subclasses receive a :class:`FindingSink` at construction; the
    :meth:`emit` helper builds a :class:`DetectorFinding`, fills in the
    correlation context and forwards to the sink. Building findings via
    the helper (instead of in each subclass) ensures consistent fields
    for the forensics store.
    """

    detector_id: str = "argos.proxy.detector"

    def __init__(self, sink: FindingSink | None = None) -> None:
        self._sink: FindingSink = sink if sink is not None else _NOOP_SINK_SENTINEL

    async def emit(
        self,
        *,
        ctx: InterceptContext,
        severity: Literal["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"],
        message: str,
        direction: Literal["client_to_upstream", "upstream_to_client"],
        method: str | None = None,
        evidence: dict[str, Any] | None = None,
    ) -> None:
        finding = DetectorFinding(
            detector_id=self.detector_id,
            severity=severity,
            message=message,
            correlation_id=ctx.correlation_id,
            direction=direction,
            method=method,
            request_id=ctx.client_request_id,
            evidence=dict(evidence) if evidence else {},
        )
        await self._sink(finding)


# Re-exported for typing convenience.
SinkCallback = Callable[[DetectorFinding], Awaitable[None]]
