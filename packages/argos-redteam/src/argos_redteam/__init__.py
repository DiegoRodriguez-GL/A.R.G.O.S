"""ARGOS red-team runtime (Module 4).

Public API:

    from argos_redteam import (
        all_probes, select,
        HttpTransport, MockTransport, AgentTransport,
        run, run_async, summarise,
    )

Probe catalog covers OWASP ASI01..ASI10 with at least two probes per
category. See ``argos_redteam.probes.*`` modules for per-probe detail.
"""

from __future__ import annotations

from argos_redteam.detectors import (
    BaseDetector,
    BehaviorDetector,
    Detection,
    LLMJudgeDetector,
    RegexDetector,
    StringMatchDetector,
)
from argos_redteam.models import Message, ProbeOutcome, ProbeResult, Role, Transcript
from argos_redteam.probes import BaseProbe, all_probes, select
from argos_redteam.runner import run, run_async, run_errors, summarise
from argos_redteam.strategies import BaseStrategy, MultiTurnStrategy, SingleTurnStrategy
from argos_redteam.transport import (
    AgentTransport,
    HttpTransport,
    MockTransport,
    TransportError,
)

__all__ = [
    "AgentTransport",
    "BaseDetector",
    "BaseProbe",
    "BaseStrategy",
    "BehaviorDetector",
    "Detection",
    "HttpTransport",
    "LLMJudgeDetector",
    "Message",
    "MockTransport",
    "MultiTurnStrategy",
    "ProbeOutcome",
    "ProbeResult",
    "RegexDetector",
    "Role",
    "SingleTurnStrategy",
    "StringMatchDetector",
    "Transcript",
    "TransportError",
    "all_probes",
    "run",
    "run_async",
    "run_errors",
    "select",
    "summarise",
]

__version__ = "0.0.1"
