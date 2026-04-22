"""Frozen Pydantic models for the ARGOS YAML rules DSL.

The DSL is deliberately small:

    id, info{name, severity, description, remediation, compliance, tags,
             references, author}
    matchers-condition: or | and
    matchers: list of matcher blocks (word / regex / glob)
    extractors: optional list of extractor blocks (regex / word)

Every rule evaluates per MCP server. Matchers select a "part" of the server
or config via a dotted selector (see :mod:`argos_rules.selectors`).
"""

from __future__ import annotations

import re
from typing import Annotated, Literal

from argos_core import Severity
from pydantic import BaseModel, ConfigDict, Field, StringConstraints, field_validator

# ---------------------------------------------------------------------------
# Hard limits (defence in depth: rules are untrusted user input).
# ---------------------------------------------------------------------------
MAX_WORDS = 64
MAX_REGEXES = 32
MAX_REGEX_LENGTH = 1000
MAX_GLOBS = 32
MAX_MATCHERS = 16
MAX_EXTRACTORS = 8


# Simple ReDoS heuristic: reject patterns whose structure is known to trigger
# catastrophic backtracking in Python's stdlib ``re``. Stdlib ``re`` has no
# timeout, and a rule-authored pattern like ``(a+)+$`` applied to a long run
# of ``a`` will hang the engine indefinitely. This linter catches the two
# common shapes: ``(X*)*``-style "quantifier-over-quantified-group" and
# ``(a|a)+``-style "alternation where branches share a prefix".
_NESTED_QUANTIFIER_RE = re.compile(
    r"""
    \(                        # group open
    (?:
        [^()\\]               # benign char
      | \\.                   # any escape
    )*?
    [*+?]\??                  # inner quantifier
    (?:
        [^()\\]
      | \\.
    )*?
    \)                        # group close
    [*+]                      # outer quantifier  <-- the smell
    """,
    re.VERBOSE,
)


def _reject_if_redos_risk(pattern: str) -> None:
    """Raise ``ValueError`` if ``pattern`` has an obvious ReDoS shape.

    Heuristic, not a solver: we reject the structural patterns that cause
    exponential backtracking in practice. False positives are acceptable
    (rule authors can rewrite their pattern); false negatives are not, so
    the match is deliberately eager.
    """
    if _NESTED_QUANTIFIER_RE.search(pattern):
        msg = (
            f"regex {pattern!r} has a nested-quantifier shape (e.g. "
            "'(X+)+') that may trigger catastrophic backtracking (ReDoS); "
            "rewrite with a bounded quantifier or an anchored alternative"
        )
        raise ValueError(msg)


Condition = Literal["or", "and"]

RuleId = Annotated[str, StringConstraints(pattern=r"^[A-Z0-9][A-Z0-9_\-\.]{1,127}$")]


class Info(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str = Field(..., min_length=1, max_length=200)
    severity: Severity
    description: str = Field(default="", max_length=4000)
    remediation: str | None = Field(default=None, max_length=2000)
    compliance: tuple[str, ...] = Field(default_factory=tuple)
    tags: tuple[str, ...] = Field(default_factory=tuple)
    references: tuple[str, ...] = Field(default_factory=tuple)
    author: str | None = None

    @field_validator("compliance")
    @classmethod
    def _validate_compliance_refs(cls, v: tuple[str, ...]) -> tuple[str, ...]:
        for ref in v:
            if ":" not in ref or not ref.split(":", 1)[1]:
                msg = f"compliance ref {ref!r} must be a qualified id 'framework:control'"
                raise ValueError(msg)
        return v


class WordMatcher(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    type: Literal["word"]
    words: tuple[str, ...] = Field(..., min_length=1, max_length=MAX_WORDS)
    part: str = "server.argv"
    condition: Condition = "or"
    case_insensitive: bool = Field(default=False, alias="case-insensitive")
    negative: bool = False


class RegexMatcher(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    type: Literal["regex"]
    regex: tuple[str, ...] = Field(..., min_length=1, max_length=MAX_REGEXES)
    part: str = "server.argv"
    condition: Condition = "or"
    negative: bool = False

    @field_validator("regex")
    @classmethod
    def _validate_patterns(cls, v: tuple[str, ...]) -> tuple[str, ...]:
        for pattern in v:
            if len(pattern) > MAX_REGEX_LENGTH:
                msg = f"regex exceeds max length {MAX_REGEX_LENGTH}"
                raise ValueError(msg)
            try:
                re.compile(pattern)
            except re.error as exc:
                msg = f"invalid regex {pattern!r}: {exc}"
                raise ValueError(msg) from exc
            _reject_if_redos_risk(pattern)
        return v


class GlobMatcher(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    type: Literal["glob"]
    globs: tuple[str, ...] = Field(..., min_length=1, max_length=MAX_GLOBS)
    part: str = "server.argv"
    condition: Condition = "or"
    negative: bool = False


Matcher = WordMatcher | RegexMatcher | GlobMatcher


class RegexExtractor(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    type: Literal["regex"]
    regex: str = Field(..., max_length=MAX_REGEX_LENGTH)
    part: str = "server.argv"
    group: int = Field(default=0, ge=0)

    @field_validator("regex")
    @classmethod
    def _compiles(cls, v: str) -> str:
        try:
            re.compile(v)
        except re.error as exc:
            msg = f"invalid extractor regex {v!r}: {exc}"
            raise ValueError(msg) from exc
        _reject_if_redos_risk(v)
        return v


class WordExtractor(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    type: Literal["word"]
    words: tuple[str, ...] = Field(..., min_length=1, max_length=MAX_WORDS)
    part: str = "server.argv"
    case_insensitive: bool = Field(default=False, alias="case-insensitive")


Extractor = RegexExtractor | WordExtractor


class Rule(BaseModel):
    """Top-level rule document parsed from YAML."""

    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    id: RuleId
    info: Info
    matchers_condition: Condition = Field(default="or", alias="matchers-condition")
    matchers: tuple[Matcher, ...] = Field(..., min_length=1, max_length=MAX_MATCHERS)
    extractors: tuple[Extractor, ...] = Field(default_factory=tuple, max_length=MAX_EXTRACTORS)
