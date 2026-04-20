"""Base class shared by every ARGOS red-team probe."""

from __future__ import annotations

from abc import abstractmethod
from collections.abc import AsyncIterable

from argos_core import Evidence, Finding, Severity, Target
from argos_core.interfaces import IProbe, PluginMetadata, ProbeContext

from argos_redteam.detectors._base import BaseDetector
from argos_redteam.models import (
    Message,
    ProbeOutcome,
    ProbeResult,
    Role,
    Transcript,
)
from argos_redteam.strategies._base import BaseStrategy
from argos_redteam.strategies.single_turn import SingleTurnStrategy
from argos_redteam.transport import AgentTransport

_PRODUCER = "argos-redteam"


class BaseProbe(IProbe):
    """Common skeleton: seed prompt -> strategy -> detector -> Finding."""

    # ------------------------------------------------------------------
    # Subclass contract (declarative attributes)
    # ------------------------------------------------------------------
    probe_id: str
    title: str
    description: str
    remediation: str
    severity: Severity
    asi_category: str  # canonical OWASP ASI top-level id, e.g. "ASI06"
    compliance_refs: tuple[str, ...] = ()
    tags: tuple[str, ...] = ()
    default_strategy: BaseStrategy | None = None

    # ------------------------------------------------------------------
    # Subclass contract (behaviour)
    # ------------------------------------------------------------------
    @abstractmethod
    def build_seed(self) -> Transcript: ...

    @abstractmethod
    def detector(self) -> BaseDetector: ...

    # ------------------------------------------------------------------
    # IPlugin / IProbe plumbing
    # ------------------------------------------------------------------
    def metadata(self) -> PluginMetadata:
        owasp = (
            f"owasp_asi:{self.asi_category}",
            *(r for r in self.compliance_refs if r.startswith("owasp_asi:")),
        )
        return PluginMetadata(
            name=self.probe_id,
            version="0.0.1",
            kind="probe",
            description=self.title,
            owasp_asi=tuple(dict.fromkeys(owasp)),  # de-dup preserving order
        )

    async def run(self, ctx: ProbeContext) -> AsyncIterable[Finding]:
        transport = ctx.transport
        if not isinstance(transport, AgentTransport):
            msg = f"{self.probe_id}: transport must be an AgentTransport"
            raise TypeError(msg)

        strategy = self.default_strategy or SingleTurnStrategy()
        seed = self.build_seed()
        transcript = await strategy.run(transport, seed)

        # Assistant's final reply (or empty if nothing came back).
        last_assistant = next(
            (m for m in reversed(transcript.messages) if m.role == Role.ASSISTANT),
            Message(role=Role.ASSISTANT, content=""),
        )
        verdict = self.detector().detect(last_assistant.content)
        outcome = ProbeOutcome.SUCCESS if verdict.matched else ProbeOutcome.BLOCKED

        if outcome != ProbeOutcome.SUCCESS:
            # Probes only emit findings when they succeed (i.e. when the
            # agent exhibited the risky behaviour). The ProbeRunSummary
            # covers the aggregate case.
            return

        yield self._finding_from(
            ctx.target,
            ProbeResult(
                probe_id=self.probe_id,
                outcome=outcome,
                rationale=verdict.rationale,
                confidence=verdict.confidence,
                transcript=transcript,
            ),
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def _finding_from(self, target: Target, result: ProbeResult) -> Finding:
        evidence = Evidence(
            kind="request-response",
            summary=f"{self.probe_id}: {result.rationale[:200]}",
            request=result.transcript.rendered()[:16_000],
            response=_final_assistant(result.transcript),
        )
        return Finding(
            rule_id=self.probe_id,
            title=self.title,
            description=self.description,
            severity=self.severity,
            target=target,
            evidence=(evidence,),
            compliance_refs=self.compliance_refs,
            remediation=self.remediation,
            producer=_PRODUCER,
        )


def _final_assistant(transcript: Transcript) -> str:
    for m in reversed(transcript.messages):
        if m.role == Role.ASSISTANT:
            return m.content[:16_000]
    return ""


class BaseProbeMeta(type):
    """Not used by the default registry; kept as an extension point."""

    # Intentionally empty: lets external tooling replace the metaclass if
    # it needs to decorate every BaseProbe subclass.
