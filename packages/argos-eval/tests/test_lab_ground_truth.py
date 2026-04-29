"""Behavioural tests over the lab benchmark.

For every (probe, agent) pair we assert the ground truth:

- A probe IN the agent's vulnerability surface MUST fire on the
  vulnerable variant and MUST NOT fire on the hardened variant. This
  is the construct-validity guarantee of the lab.
- A probe OUTSIDE the surface MUST NOT fire on either variant: a
  ReAct agent receiving a memory-poisoning probe is a different
  scenario, so the probe yielding no finding is the correct answer.

These two invariants together let Phase 3 build a clean
``EvalReport`` whose confusion matrix is 100% diagonal under perfect
detection. Any cell off the diagonal is then a real defect in either
the probe or the lab agent.
"""

from __future__ import annotations

import asyncio

import pytest
from argos_core import Target
from argos_core.interfaces import ProbeContext
from argos_core.models.target import TargetKind
from argos_eval import LabAgent, all_agents
from argos_redteam import all_probes
from argos_redteam.probes._base import BaseProbe


def _ctx(agent: LabAgent) -> ProbeContext:
    return ProbeContext(
        target=Target(kind=TargetKind.AGENT_HTTP, locator=f"lab://{agent.agent_id}"),
        transport=agent,
        timeout_seconds=5.0,
    )


def _probe_fires(probe: BaseProbe, agent: LabAgent) -> bool:
    async def _run() -> bool:
        ctx = _ctx(agent)
        async for _ in probe.run(ctx):
            return True
        return False

    return asyncio.run(_run())


def _all_pairs() -> list[tuple[LabAgent, BaseProbe]]:
    """Cartesian product (agent, probe), expanded once for parametrisation."""
    agents = all_agents()
    probes = list(all_probes())
    return [(a, p) for a in agents for p in probes]


@pytest.mark.parametrize(
    ("agent", "probe"),
    _all_pairs(),
    ids=lambda v: v.agent_id if hasattr(v, "agent_id") else v.probe_id,
)
def test_ground_truth_matrix(agent: LabAgent, probe: BaseProbe) -> None:
    """For each (agent, probe), assert the expected outcome matches
    the construct: in-surface fires only on the vulnerable variant;
    out-of-surface never fires."""
    in_surface = probe.probe_id in agent.vulnerability_surface
    fired = _probe_fires(probe, agent)

    if in_surface and agent.is_vulnerable:
        assert fired, (
            f"{probe.probe_id} did NOT fire on {agent.agent_id}; "
            "the vulnerable variant should expose this attack"
        )
    elif in_surface and not agent.is_vulnerable:
        assert not fired, (
            f"{probe.probe_id} fired on {agent.agent_id}; "
            "the hardened variant should block its own surface"
        )
    else:
        assert not fired, (
            f"{probe.probe_id} fired on {agent.agent_id}; "
            "this probe is outside the agent's scenario and should be silent"
        )
