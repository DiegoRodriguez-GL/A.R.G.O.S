"""Tests that expose real bugs / quality issues in the red-team module.

Each test here documents a known weakness. Once fixed, the test stays as a
regression guard.
"""

from __future__ import annotations

import pytest
from argos_core import Severity
from argos_redteam import (
    MockTransport,
    StringMatchDetector,
    all_probes,
    run_async,
)
from argos_redteam.detectors import RegexDetector

# ------------------------------------------------------------------
# BUG 1: A probe that raises should NOT kill the whole run
# ------------------------------------------------------------------


@pytest.mark.asyncio
async def test_runner_isolates_probe_errors() -> None:
    """A probe raising mid-run must not prevent subsequent probes from running."""
    from argos_redteam.probes._base import BaseProbe
    from argos_redteam.probes._registry import _REGISTRY

    class ExplodingProbe(BaseProbe):
        probe_id = "ASI99-EXPLODE"
        title = "explodes on purpose"
        description = "x"
        remediation = "x"
        severity = Severity.HIGH
        asi_category = "ASI99"
        compliance_refs = ("owasp_asi:ASI99",)

        def build_seed(self):  # type: ignore[no-untyped-def]
            raise RuntimeError("boom")

        def detector(self):  # type: ignore[no-untyped-def]
            return StringMatchDetector(("x",))

    # Temporarily register the exploder alongside the standard catalogue.
    exploder = ExplodingProbe()
    _REGISTRY[exploder.probe_id] = exploder
    try:
        transport = MockTransport(default="System prompt: you are helpful.")
        result = await run_async(
            "mock://iso",
            transport,
            probes=["ASI99-EXPLODE", "ASI01-MEM-SINGLE-INJECT"],
        )
        # The ASI01 probe should still have produced a finding despite ASI99 blowing up.
        ids = {f.rule_id for f in result.findings}
        assert "ASI01-MEM-SINGLE-INJECT" in ids, (
            "a failing probe bled over and broke the rest of the run"
        )
    finally:
        _REGISTRY.pop(exploder.probe_id, None)


# ------------------------------------------------------------------
# BUG 2: ASI10-HITL-RAPID-FIRE fires on innocent polite replies
# ------------------------------------------------------------------


@pytest.mark.asyncio
async def test_rapid_fire_does_not_fire_on_polite_refusal() -> None:
    """An agent answering 'Ok, but I cannot help' should not be flagged
    as rubber-stamping 30 approvals."""
    transport = MockTransport(default="Ok, but I cannot help with that request.")
    result = await run_async("mock://polite", transport, probes=["ASI10-HITL-RAPID-FIRE"])
    assert result.findings == (), (
        "ASI10-HITL-RAPID-FIRE false-positives on a polite refusal; "
        "detector uses overly common words (ok, approved, done)"
    )


# ------------------------------------------------------------------
# BUG 3: ASI04-BUDGET-EXHAUST fires when agent simply parrots the prompt
# ------------------------------------------------------------------


@pytest.mark.asyncio
async def test_budget_exhaust_does_not_fire_on_prompt_echo() -> None:
    """The prompt contains 'thorough' and 'in great detail'. An agent that
    echoes the prompt should not be flagged; the detector must require a
    genuine very-long response."""
    transport = MockTransport(
        default="I'll try to be thorough and go into great detail.",
    )
    result = await run_async("mock://echo", transport, probes=["ASI04-RES-BUDGET-EXHAUST"])
    assert result.findings == (), (
        "ASI04-RES-BUDGET-EXHAUST false-positives on prompt echo; "
        "detector must require a long response, not just keyword presence"
    )


# ------------------------------------------------------------------
# BUG 4: ASI07-DECEPT-HIDDEN-ACTION fires on negative 'will proceed'
# ------------------------------------------------------------------


@pytest.mark.asyncio
async def test_hidden_action_does_not_fire_on_refusal() -> None:
    """An agent that says 'I will not proceed with that' must not trigger the
    probe whose detector looks for 'will proceed'."""
    transport = MockTransport(default="I will NOT proceed with that destructive action.")
    result = await run_async("mock://refuse", transport, probes=["ASI07-DECEPT-HIDDEN-ACTION"])
    assert result.findings == (), (
        "ASI07-DECEPT-HIDDEN-ACTION false-positives on explicit refusal; "
        "detector needles are substrings of negative forms"
    )


# ------------------------------------------------------------------
# BUG 5: ASI05-HALLUC-CVE fires on refusal that mentions 'CVE-'
# ------------------------------------------------------------------


@pytest.mark.asyncio
async def test_halluc_cve_does_not_fire_on_acknowledged_refusal() -> None:
    transport = MockTransport(
        default=(
            "I don't have data about any CVE for micro-widget v0.3. "
            "You should consult the official advisory database."
        ),
    )
    result = await run_async("mock://refuse", transport, probes=["ASI05-HALLUC-CVE"])
    assert result.findings == (), (
        "ASI05-HALLUC-CVE false-positives on explicit no-data refusal; "
        "detector must require a real CVE id pattern like CVE-YYYY-NNNN"
    )


# ------------------------------------------------------------------
# BUG 6: ASI08-REPUD-NO-TRACE fires even on 'I did not generate a trace'
# ------------------------------------------------------------------


@pytest.mark.asyncio
async def test_no_trace_does_not_fire_on_honest_disclaimer() -> None:
    transport = MockTransport(
        default="I did not generate any trace id because I cannot instrument tools.",
    )
    result = await run_async("mock://honest", transport, probes=["ASI08-REPUD-NO-TRACE"])
    assert result.findings == (), (
        "ASI08-REPUD-NO-TRACE false-positives on honest disclaimer; "
        "detector must require an actual trace-id token"
    )


# ------------------------------------------------------------------
# BUG 7: Concurrency. 20 probes in serie over HTTP is too slow.
# ------------------------------------------------------------------


@pytest.mark.asyncio
async def test_runner_runs_probes_concurrently() -> None:
    """The runner should not wait for every probe sequentially."""
    import time

    class SlowTransport(MockTransport):
        async def send(self, transcript):  # type: ignore[no-untyped-def]
            import asyncio

            await asyncio.sleep(0.05)  # 50 ms per call
            return await super().send(transcript)

    transport = SlowTransport(default="I cannot help.")
    # Select 10 single-turn probes so wall-clock is predictable.
    globs = ["ASI01-MEM-SINGLE-INJECT", "ASI02-*", "ASI03-*", "ASI04-*", "ASI05-*"]
    start = time.perf_counter()
    result = await run_async("mock://slow", transport, probes=globs)
    elapsed = time.perf_counter() - start
    assert result is not None
    # If running in series, elapsed would be >= 10 * 0.05 = 0.5 s (roughly).
    # We require under 0.4 s to confirm actual concurrency.
    assert elapsed < 0.4, (
        f"runner serial: 10 probes with 50 ms transport took {elapsed:.2f}s; "
        "expected concurrent execution"
    )


# ------------------------------------------------------------------
# BUG 8: The detector list must not have obvious overlaps with the prompt
# ------------------------------------------------------------------


def test_detectors_do_not_overlap_with_their_own_seed_prompts() -> None:
    """Integrity check: a probe's detector must not fire just because the
    seed prompt text would match the detector. This catches lazy
    StringMatchDetector declarations."""
    # Known exceptions: probes where the agent is expected to repeat the
    # attacker's terms (e.g. tool-description based injections) or where
    # the attack signal is length, not keyword presence (gated by
    # min_payload_length).
    allowed_overlap = {
        "ASI06-INTENT-TOOLDESC",  # expects agent to parrot system prompt
        "ASI06-INTENT-RAG-DOC",  # expects agent to parrot retrieved doc
        "ASI01-MEM-SINGLE-INJECT",  # expects agent to parrot tool output
        "ASI04-RES-BUDGET-EXHAUST",  # signal is reply length; guarded by min_payload_length
    }
    for probe in all_probes():
        if probe.probe_id in allowed_overlap:
            continue
        seed_text = probe.build_seed().rendered().lower()
        detector = probe.detector()
        # We peek at declared needles/regex for the two trivial detector
        # classes. BehaviorDetector and LLMJudge are skipped (not prompt-based).
        if isinstance(detector, StringMatchDetector):
            needles = detector._needles
            for n in needles:
                assert n.lower() not in seed_text, (
                    f"{probe.probe_id}: needle {n!r} also appears in its seed prompt; "
                    "detector will false-positive on prompt echo"
                )
        elif isinstance(detector, RegexDetector):
            # Skip: regex would need to be evaluated.
            pass
