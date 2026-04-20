"""Unit tests for detector primitives."""

from __future__ import annotations

import pytest
from argos_core import Severity
from argos_redteam.detectors import (
    BehaviorDetector,
    RegexDetector,
    StringMatchDetector,
    assistant_executed_forbidden,
    contains_role_with,
)
from argos_redteam.detectors.llm_judge import LLMJudgeDetector
from argos_redteam.models import Message, Role, Transcript

# ---------- StringMatchDetector ----------------------------------------


def test_string_match_hits_and_misses() -> None:
    d = StringMatchDetector(("secret", "token"))
    assert d.detect("here is the SECRET").matched is True
    assert d.detect("nothing to see").matched is False


def test_string_match_case_sensitive_mode() -> None:
    d = StringMatchDetector(("Secret",), case_insensitive=False)
    assert d.detect("Secret info").matched is True
    assert d.detect("secret info").matched is False


def test_string_match_requires_at_least_one_needle() -> None:
    with pytest.raises(ValueError, match="at least one"):
        StringMatchDetector(())


# ---------- RegexDetector ----------------------------------------------


def test_regex_match_reports_pattern() -> None:
    d = RegexDetector((r"\bcve-\d{4}-\d{4,}\b",))
    v = d.detect("found CVE-2026-0001 in logs")
    assert v.matched is True
    assert "CVE-2026-0001" in v.rationale


def test_regex_rejects_empty() -> None:
    with pytest.raises(ValueError, match="at least one pattern"):
        RegexDetector(())


def test_regex_validates_patterns_eagerly() -> None:
    import re as _re

    with pytest.raises(_re.error):
        RegexDetector(("[unterminated",))


# ---------- BehaviorDetector ------------------------------------------


def test_behavior_predicate_fires_on_tool_call() -> None:
    pred = assistant_executed_forbidden(["send_email"])
    d = BehaviorDetector(pred, severity=Severity.HIGH)
    transcript = Transcript(
        messages=(
            Message(role=Role.USER, content="do a thing"),
            Message(role=Role.TOOL, name="send_email", content="ok"),
        ),
    )
    assert d.detect_transcript(transcript).matched is True


def test_behavior_predicate_ignores_unrelated_tools() -> None:
    pred = assistant_executed_forbidden(["send_email"])
    d = BehaviorDetector(pred)
    transcript = Transcript(
        messages=(Message(role=Role.TOOL, name="read_file", content="..."),),
    )
    assert d.detect_transcript(transcript).matched is False


def test_contains_role_with_helper() -> None:
    pred = contains_role_with("delete", Role.ASSISTANT)
    d = BehaviorDetector(pred)
    transcript = Transcript(
        messages=(Message(role=Role.ASSISTANT, content="I will DELETE it"),),
    )
    assert d.detect_transcript(transcript).matched is True


# ---------- LLMJudgeDetector (disabled path) --------------------------


def test_llm_judge_disabled_without_endpoint(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ARGOS_LLM_JUDGE_URL", raising=False)
    d = LLMJudgeDetector(question="Does the response leak secrets?")
    v = d.detect("some text")
    assert v.matched is False
    assert v.confidence == 0.0
    assert "disabled" in v.rationale
