"""LangChain / LangGraph callback handler tests.

The handler is exercised without ``langchain-core`` installed: every
hook is called directly with the argument shapes LangChain uses, which
is exactly what the dispatcher does at runtime. Detector behaviour is
asserted through the in-memory sink and the SQLite forensics store.
"""

from __future__ import annotations

import uuid
from pathlib import Path

import pytest
from argos_core import Finding
from argos_core.compliance import load_controls
from argos_proxy import InMemoryFindingSink, PIIDetector, ScopeDetector
from argos_proxy.detectors.adapter import compliance_refs_for, to_core_finding
from argos_proxy.integrations import (
    ArgosCallbackHandler,
    ArgosPolicyViolationError,
    AsyncArgosCallbackHandler,
)
from argos_proxy.interceptor import ChainInterceptor


class _Generation:
    def __init__(self, text: str) -> None:
        self.text = text


class _LLMResult:
    def __init__(self, *texts: str) -> None:
        self.generations = [[_Generation(t) for t in texts]]


class _AgentAction:
    def __init__(self, tool: str, tool_input: object) -> None:
        self.tool = tool
        self.tool_input = tool_input


# ---------------------------------------------------------------------------
# Sync handler
# ---------------------------------------------------------------------------


def test_allowed_tool_produces_no_finding() -> None:
    with ArgosCallbackHandler(allowed_tools=("search",), otel=False) as handler:
        rid = uuid.uuid4()
        handler.on_tool_start({"name": "search"}, "weather in Madrid", run_id=rid)
        handler.on_tool_end("sunny, 31C", run_id=rid)
        assert handler.findings == []
        assert handler.violations == 0
        assert handler.events == 2


def test_out_of_scope_tool_is_recorded_but_not_raised_by_default() -> None:
    with ArgosCallbackHandler(allowed_tools=("search",), otel=False) as handler:
        handler.on_tool_start({"name": "shell"}, "rm -rf /", run_id=uuid.uuid4())
        assert handler.violations == 1
        scope = [f for f in handler.findings if f.detector_id == "argos.proxy.scope"]
        assert len(scope) == 1
        assert scope[0].severity == "HIGH"
        assert scope[0].evidence["tool_name"] == "shell"
        assert scope[0].method == "tools/call"


def test_enforce_raises_policy_violation_before_tool_runs() -> None:
    handler = ArgosCallbackHandler(allowed_tools=("search",), enforce=True, otel=False)
    assert handler.raise_error is True  # LangChain must propagate the exception
    try:
        with pytest.raises(ArgosPolicyViolationError) as exc_info:
            handler.on_tool_start({"name": "shell"}, "id", run_id=uuid.uuid4())
        assert "shell" in exc_info.value.message
        data = exc_info.value.data
        assert isinstance(data, dict)
        assert data["tool_name"] == "shell"
        assert handler.violations == 1
    finally:
        handler.close()


def test_pii_in_tool_output_is_flagged_with_the_run_id() -> None:
    with ArgosCallbackHandler(otel=False) as handler:
        rid = uuid.uuid4()
        handler.on_tool_start({"name": "crm.lookup"}, "customer 42", run_id=rid)
        handler.on_tool_end({"email": "ana.perez@example.com"}, run_id=rid)
        pii = [f for f in handler.findings if f.detector_id == "argos.proxy.pii"]
        assert len(pii) == 1
        assert pii[0].direction == "upstream_to_client"
        assert pii[0].request_id == str(rid)
        assert pii[0].evidence["kind"] == "email"
        # The snippet is redacted: the address never lands in the sink.
        assert "ana.perez" not in pii[0].evidence["snippet"]


def test_pii_in_prompt_is_flagged_via_llm_start_notification() -> None:
    with ArgosCallbackHandler(otel=False) as handler:
        handler.on_llm_start({}, ["Transfer to IBAN GB82WEST12345698765432"], run_id=uuid.uuid4())
        pii = [f for f in handler.findings if f.detector_id == "argos.proxy.pii"]
        assert len(pii) == 1
        assert pii[0].evidence["kind"] == "iban"
        assert pii[0].method == "notifications/argos/llm_start"


def test_llm_end_and_agent_action_are_translated() -> None:
    with ArgosCallbackHandler(otel=False) as handler:
        handler.on_llm_end(_LLMResult("card 4111 1111 1111 1111"), run_id=uuid.uuid4())
        handler.on_agent_action(_AgentAction("mail.send", {"to": "x@y.io"}), run_id=uuid.uuid4())
        kinds = sorted(f.evidence["kind"] for f in handler.findings)
        assert kinds == ["card", "email"]


def test_tool_error_is_translated_to_error_response(tmp_path: Path) -> None:
    db = tmp_path / "callbacks.sqlite3"
    handler = ArgosCallbackHandler(forensics_db=db, otel=False)
    rid = uuid.uuid4()
    handler.on_tool_start({"name": "fs.read"}, "/etc/passwd", run_id=rid)
    handler.on_tool_error(PermissionError("denied"), run_id=rid)
    handler.close()

    import sqlite3

    conn = sqlite3.connect(db)
    rows = conn.execute(
        "SELECT kind, direction, method, payload FROM messages ORDER BY id"
    ).fetchall()
    conn.close()
    assert [r[0] for r in rows] == ["request", "response"]
    assert rows[0][2] == "tools/call"
    assert rows[0][1] == "client_to_upstream"
    assert rows[1][1] == "upstream_to_client"
    assert "PermissionError" in rows[1][3]


def test_forensics_rows_share_one_correlation_id_per_tool_call(tmp_path: Path) -> None:
    db = tmp_path / "callbacks.sqlite3"
    handler = ArgosCallbackHandler(forensics_db=db, allowed_tools=("search",), otel=False)
    rid = uuid.uuid4()
    handler.on_tool_start({"name": "search"}, "q", run_id=rid)
    handler.on_tool_end("answer", run_id=rid)
    handler.close()

    import sqlite3

    conn = sqlite3.connect(db)
    corr = conn.execute("SELECT DISTINCT correlation_id FROM messages").fetchall()
    conn.close()
    assert len(corr) == 1


def test_findings_persist_to_sqlite_when_db_given(tmp_path: Path) -> None:
    db = tmp_path / "callbacks.sqlite3"
    handler = ArgosCallbackHandler(forensics_db=db, allowed_tools=("search",), otel=False)
    handler.on_tool_start({"name": "shell"}, "id", run_id=uuid.uuid4())
    handler.close()

    import sqlite3

    conn = sqlite3.connect(db)
    rows = conn.execute("SELECT detector_id, severity FROM findings").fetchall()
    conn.close()
    assert rows == [("argos.proxy.scope", "HIGH")]


def test_tool_end_without_start_does_not_crash() -> None:
    with ArgosCallbackHandler(otel=False) as handler:
        handler.on_tool_end("orphan", run_id=uuid.uuid4())
        assert handler.events == 1


def test_close_is_idempotent_and_handler_refuses_events_afterwards() -> None:
    handler = ArgosCallbackHandler(otel=False)
    handler.on_tool_start({"name": "a"}, "x", run_id=uuid.uuid4())
    handler.close()
    handler.close()
    with pytest.raises(RuntimeError):
        handler.on_tool_end("late", run_id=uuid.uuid4())


def test_custom_interceptor_and_sink_are_honoured() -> None:
    sink = InMemoryFindingSink()
    chain = ChainInterceptor(PIIDetector(sink), ScopeDetector(sink, allowed_tools=("ok",)))
    with ArgosCallbackHandler(interceptor=chain, sink=sink) as handler:
        handler.on_tool_start({"name": "nope"}, "x", run_id=uuid.uuid4())
        assert handler.sink is sink
        assert [f.detector_id for f in sink.findings] == ["argos.proxy.scope"]


def test_long_text_is_truncated_before_detection() -> None:
    with ArgosCallbackHandler(otel=False, max_text_chars=64) as handler:
        # The email sits beyond the cap: the detector must not see it.
        handler.on_tool_end("x" * 100 + " hidden@example.com", run_id=uuid.uuid4())
        assert handler.findings == []


def test_string_run_ids_and_missing_run_ids_are_accepted() -> None:
    with ArgosCallbackHandler(otel=False) as handler:
        handler.on_tool_start({"name": "a"}, "x", run_id="run-1")
        handler.on_tool_end("y", run_id="run-1")
        handler.on_tool_start({}, "z")
        assert handler.events == 3


def test_otel_interceptor_in_default_chain_does_not_break_flow() -> None:
    with ArgosCallbackHandler(allowed_tools=("search",)) as handler:
        rid = uuid.uuid4()
        handler.on_tool_start({"name": "search"}, "q", run_id=rid)
        handler.on_tool_end("a", run_id=rid)
        assert handler.violations == 0


def test_invalid_max_text_chars_rejected() -> None:
    with pytest.raises(ValueError, match="max_text_chars"):
        ArgosCallbackHandler(max_text_chars=0)


# ---------------------------------------------------------------------------
# Async handler
# ---------------------------------------------------------------------------


async def test_async_handler_flags_scope_and_pii(tmp_path: Path) -> None:
    db = tmp_path / "async.sqlite3"
    async with AsyncArgosCallbackHandler(
        allowed_tools=("search",), forensics_db=db, otel=False
    ) as handler:
        rid = uuid.uuid4()
        await handler.on_tool_start({"name": "search"}, "q", run_id=rid)
        await handler.on_tool_end("mail me at bob@example.org", run_id=rid)
        await handler.on_tool_start({"name": "shell"}, "id", run_id=uuid.uuid4())
        assert handler.violations == 1
        assert handler.store is not None
        rows = await handler.store.findings()
        assert sorted(r["detector_id"] for r in rows) == ["argos.proxy.pii", "argos.proxy.scope"]


async def test_async_enforce_raises() -> None:
    async with AsyncArgosCallbackHandler(
        allowed_tools=("search",), enforce=True, otel=False
    ) as handler:
        with pytest.raises(ArgosPolicyViolationError):
            await handler.on_tool_start({"name": "shell"}, "id", run_id=uuid.uuid4())


async def test_async_llm_hooks() -> None:
    async with AsyncArgosCallbackHandler(otel=False) as handler:
        await handler.on_chat_model_start({}, [[type("M", (), {"content": "hi x@y.io"})()]])
        await handler.on_llm_end(_LLMResult("fine"), run_id=uuid.uuid4())
        await handler.on_agent_action(_AgentAction("t", "i"), run_id=uuid.uuid4())
        assert handler.events == 3
        assert [f.evidence["kind"] for f in handler.findings] == ["email"]


# ---------------------------------------------------------------------------
# Adapter to argos_core.Finding
# ---------------------------------------------------------------------------


def test_adapter_lifts_detector_findings_into_resolvable_core_findings() -> None:
    with ArgosCallbackHandler(allowed_tools=("search",), otel=False) as handler:
        rid = uuid.uuid4()
        handler.on_tool_start({"name": "shell"}, "id", run_id=rid)
        handler.on_tool_end("bob@example.org", run_id=rid)
        core = [to_core_finding(f) for f in handler.findings]
    assert len(core) == 2
    index = load_controls()
    for finding in core:
        assert isinstance(finding, Finding)
        assert finding.rule_id.startswith("PROXY-")
        assert finding.compliance_refs, finding.rule_id
        for ref in finding.compliance_refs:
            assert index.by_qid(ref) is not None, ref
        assert finding.evidence[0].kind == "trace"
        assert finding.producer == "argos-proxy"


def test_adapter_refs_cover_at_least_four_frameworks() -> None:
    for detector_id in ("argos.proxy.tool_drift", "argos.proxy.pii", "argos.proxy.scope"):
        refs = compliance_refs_for(detector_id)
        frameworks = {ref.split(":", 1)[0] for ref in refs}
        assert len(frameworks) >= 4, (detector_id, frameworks)


def test_adapter_unknown_detector_still_produces_a_finding() -> None:
    from argos_proxy.detectors import DetectorFinding

    raw = DetectorFinding(
        detector_id="argos.proxy.custom_thing",
        severity="LOW",
        message="custom",
        correlation_id="argos-corr-abc",
        direction="client_to_upstream",
    )
    finding = to_core_finding(raw)
    assert finding.rule_id == "PROXY-CUSTOM-THING"
    assert finding.compliance_refs == ()
