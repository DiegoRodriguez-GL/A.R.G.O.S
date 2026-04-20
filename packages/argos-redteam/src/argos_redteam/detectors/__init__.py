"""Detector primitives used by probes."""

from __future__ import annotations

from argos_redteam.detectors._base import BaseDetector, Detection
from argos_redteam.detectors.behavior import (
    BehaviorDetector,
    assistant_executed_forbidden,
    contains_role_with,
)
from argos_redteam.detectors.llm_judge import LLMJudgeDetector
from argos_redteam.detectors.regex import RegexDetector
from argos_redteam.detectors.string_match import StringMatchDetector

__all__ = [
    "BaseDetector",
    "BehaviorDetector",
    "Detection",
    "LLMJudgeDetector",
    "RegexDetector",
    "StringMatchDetector",
    "assistant_executed_forbidden",
    "contains_role_with",
]
