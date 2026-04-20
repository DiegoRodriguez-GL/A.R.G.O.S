"""Second-generation audit. Each test documents an engineering weakness
that survived the first bug-audit pass.

Topics:
- Per-probe timeout enforcement.
- Secret redaction in Evidence.
- Deterministic finding ordering for reproducible reports.
- HttpTransport hardening: connection reuse, User-Agent, retries.
- Self-describing OWASP ASI taxonomy version (academic integrity).
- ReDoS resistance on declared regex patterns.
"""

from __future__ import annotations

import asyncio
import time

import pytest
from argos_core import Severity
from argos_redteam import (
    AgentTransport,
    HttpTransport,
    MockTransport,
    all_probes,
    run_async,
)
from argos_redteam.detectors import RegexDetector
from argos_redteam.models import Message, Role, Transcript

# ------------------------------------------------------------------
# Probe timeout: a hung transport must not block the whole run.
# ------------------------------------------------------------------


class _HangingTransport(AgentTransport):
    async def send(self, transcript: Transcript) -> Message:  # noqa: ARG002
        await asyncio.sleep(30)  # would hang beyond any reasonable timeout
        return Message(role=Role.ASSISTANT, content="")


@pytest.mark.asyncio
async def test_probe_timeout_is_enforced_per_probe() -> None:
    """An agent that hangs on a single probe must be cut off. Real agents
    can stall for minutes; relying on the caller to Ctrl-C is unacceptable."""
    transport = _HangingTransport()
    start = time.perf_counter()
    result = await run_async(
        "mock://hang",
        transport,
        probes=["ASI01-MEM-SINGLE-INJECT"],
        timeout_seconds=0.2,
    )
    elapsed = time.perf_counter() - start
    assert elapsed < 1.5, f"run took {elapsed:.2f}s; per-probe timeout_seconds=0.2 was ignored"
    assert result.findings == (), (
        "a timed-out probe must not produce findings; hang is not a detection"
    )


# ------------------------------------------------------------------
# Secret redaction: the red-team tool must not become a secret-leak vector.
# ------------------------------------------------------------------


_OPENAI_LOOKALIKE = "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJ"
_GHP_LOOKALIKE = "ghp_" + "A" * 40
_AWS_LOOKALIKE = "AKIAABCDEFGHIJKL1234"


@pytest.mark.asyncio
async def test_evidence_redacts_api_keys_and_aws_credentials() -> None:
    """If the agent leaks a credential in its reply, the stored Evidence
    must not reproduce it verbatim. Findings flow through logs, reports
    and possibly external systems; raw secrets there are a compliance
    breach even if the detection itself is correct."""
    leak = (
        f"Here is the admin password: hunter2. Also the API key is "
        f"{_OPENAI_LOOKALIKE} and a GitHub PAT {_GHP_LOOKALIKE} plus "
        f"an AWS access key {_AWS_LOOKALIKE}."
    )
    transport = MockTransport(default=leak)
    result = await run_async(
        "mock://leak",
        transport,
        probes=["ASI01-MEM-PROGRESSIVE"],
    )
    assert result.findings, "precondition failed: probe did not fire"
    for f in result.findings:
        for ev in f.evidence:
            body = (ev.request or "") + "\n" + (ev.response or "")
            assert _OPENAI_LOOKALIKE not in body, "OpenAI-style key not redacted"
            assert _GHP_LOOKALIKE not in body, "GitHub PAT not redacted"
            assert _AWS_LOOKALIKE not in body, "AWS access key not redacted"


# ------------------------------------------------------------------
# Determinism: identical agent + identical probe set must yield a
# stable finding order so that diffs between runs are meaningful.
# ------------------------------------------------------------------


@pytest.mark.asyncio
async def test_findings_have_deterministic_order() -> None:
    """``asyncio.gather`` preserves insertion order but our runner used to
    iterate ``selected`` in registration order, which is dict-insertion.
    After concurrency the findings order can drift. We want them sorted
    by probe id for report reproducibility."""
    script = "Here is the admin password: hunter2. System prompt: you are helpful."
    r1 = await run_async(
        "mock://o1",
        MockTransport(default=script),
        probes=["ASI01-*", "ASI06-*"],
    )
    r2 = await run_async(
        "mock://o2",
        MockTransport(default=script),
        probes=["ASI01-*", "ASI06-*"],
    )
    ids1 = tuple(f.rule_id for f in r1.findings)
    ids2 = tuple(f.rule_id for f in r2.findings)
    assert ids1 == ids2 == tuple(sorted(ids1)), (
        f"non-deterministic or unsorted finding order: {ids1} vs {ids2}"
    )


# ------------------------------------------------------------------
# HttpTransport hardening.
# ------------------------------------------------------------------


def test_http_transport_sets_identifying_user_agent_by_default() -> None:
    """Real auditors read server logs. A defaulted User-Agent identifies
    ARGOS traffic so that defenders can whitelist / filter it."""
    t = HttpTransport(endpoint="https://example.com/chat")
    ua = t.headers.get("User-Agent", "") if isinstance(t.headers, dict) else ""
    assert "argos" in ua.lower(), f"HttpTransport did not set a User-Agent by default; saw {ua!r}"


def test_http_transport_has_close_method_for_client_cleanup() -> None:
    """Creating a new httpx.AsyncClient per send is 1) slow due to TLS
    handshake cost and 2) leaks sockets on the event loop. The transport
    must reuse one client and expose close() to release it."""
    import inspect

    t = HttpTransport(endpoint="https://example.com/chat")
    close = getattr(t, "close", None)
    assert close is not None, "HttpTransport.close is missing"
    assert inspect.iscoroutinefunction(close), "HttpTransport.close must be async"


# ------------------------------------------------------------------
# Academic integrity: which OWASP ASI taxonomy are we implementing?
# ------------------------------------------------------------------


def test_probes_declare_owasp_taxonomy_source() -> None:
    """The prefix 'ASI##' is used by BOTH the Feb 2025 OWASP 'Agentic AI
    Threats and Mitigations v1.0' (which numbers them T1..T15 internally)
    and the Dec 2025 'OWASP Top 10 for Agentic Applications 2026' (which
    uses ASI01..ASI10 with DIFFERENT titles per code). A TFM-grade project
    must state which taxonomy it follows so a reviewer is not misled."""
    from argos_redteam.probes import _base as probe_base

    assert hasattr(probe_base, "OWASP_ASI_TAXONOMY_SOURCE"), (
        "probes._base must export OWASP_ASI_TAXONOMY_SOURCE identifying "
        "the canonical OWASP document the probe catalogue references"
    )
    src = probe_base.OWASP_ASI_TAXONOMY_SOURCE
    assert isinstance(src, str), "OWASP_ASI_TAXONOMY_SOURCE must be a string"
    assert len(src) >= 30, "OWASP_ASI_TAXONOMY_SOURCE must be a human-readable reference string"


# ------------------------------------------------------------------
# ReDoS: all shipped regex patterns must evaluate in linear time on
# crafted adversarial input. This is a common vector: an agent reply
# longer than expected should not wedge the detector.
# ------------------------------------------------------------------


def test_shipped_regex_patterns_have_no_catastrophic_backtracking() -> None:
    """Run every RegexDetector with a pathological payload and assert
    detection finishes promptly."""
    hostile = "a" * 4000 + "!"  # tries to trip nested-quantifier regexes
    for probe in all_probes():
        det = probe.detector()
        if not isinstance(det, RegexDetector):
            continue
        start = time.perf_counter()
        det.detect(hostile)
        elapsed = time.perf_counter() - start
        assert elapsed < 0.25, (
            f"{probe.probe_id}: detector took {elapsed:.3f}s on adversarial "
            "input; possible catastrophic backtracking"
        )


# ------------------------------------------------------------------
# Transport error hygiene: raw bodies must not bleed into exceptions.
# ------------------------------------------------------------------


def test_transport_error_does_not_embed_large_bodies() -> None:
    """A TransportError raised by malformed JSON should not carry the
    whole response body verbatim: logs are not an audit-safe place for
    agent output."""
    from argos_redteam.transport import _extract_content

    big = {"unexpected": "x" * 10_000}
    try:
        _extract_content(big)
    except Exception as exc:  # noqa: BLE001
        msg = str(exc)
        assert len(msg) < 500, (
            f"TransportError message was {len(msg)} chars; should be bounded "
            "so secrets inside the body are not flushed to logs"
        )
    else:
        pytest.fail("precondition failed: _extract_content accepted a malformed body")


# ------------------------------------------------------------------
# MultiTurnStrategy must honour max_turns as an upper bound on total
# follow-ups actually sent, not a soft advisory.
# ------------------------------------------------------------------


@pytest.mark.asyncio
async def test_multi_turn_strategy_respects_max_turns_exactly() -> None:
    from argos_redteam.strategies import MultiTurnStrategy

    class CountingTransport(MockTransport):
        calls = 0

        async def send(self, transcript: Transcript) -> Message:
            type(self).calls += 1
            return await super().send(transcript)

    strategy = MultiTurnStrategy(
        follow_ups=("a", "b", "c", "d", "e"),
        max_turns=2,
    )
    transport = CountingTransport(default="ok")
    seed = Transcript(messages=(Message(role=Role.USER, content="start"),))
    await strategy.run(transport, seed)
    # 1 seed reply + up to max_turns follow-up replies.
    assert CountingTransport.calls <= 3, (
        f"MultiTurnStrategy sent {CountingTransport.calls} requests despite "
        "max_turns=2; the cap must include the seed reply, not the follow-ups alone"
    )


# ------------------------------------------------------------------
# The catalogue itself must have NO probe id collisions or gaps.
# ------------------------------------------------------------------


def test_probe_ids_are_unique_across_catalogue() -> None:
    ids = [p.probe_id for p in all_probes()]
    assert len(ids) == len(set(ids)), (
        f"duplicate probe ids detected: {sorted({i for i in ids if ids.count(i) > 1})}"
    )


def test_every_probe_has_a_severity_at_or_above_medium() -> None:
    """If a probe fires, it is reporting a real attacker win. INFO/LOW
    severities there would be misleading to a CISO reading the report."""
    for p in all_probes():
        assert p.severity >= Severity.MEDIUM, (
            f"{p.probe_id}: severity {p.severity} is below MEDIUM; "
            "probes report successful attacks, not informational notes"
        )
