"""Matcher primitives. Pure functions over a list of candidate strings."""

from __future__ import annotations

import fnmatch
import re
from collections.abc import Iterable
from functools import lru_cache

from argos_rules.models import GlobMatcher, Matcher, RegexMatcher, WordMatcher


@lru_cache(maxsize=1024)
def _compile(pattern: str) -> re.Pattern[str]:
    # Patterns are validated at rule-load time so compilation never raises here.
    # The cache keeps hot rules from recompiling on every server evaluated.
    return re.compile(pattern)


def _any_or_all(results: Iterable[bool], *, condition: str) -> bool:
    values = list(results)
    if not values:
        return False
    return all(values) if condition == "and" else any(values)


def _word_fires(haystack: str, matcher: WordMatcher) -> bool:
    if matcher.case_insensitive:
        haystack = haystack.lower()
        words: list[str] = [w.lower() for w in matcher.words]
    else:
        words = list(matcher.words)
    return _any_or_all((w in haystack for w in words), condition=matcher.condition)


def _regex_fires(haystack: str, matcher: RegexMatcher) -> bool:
    compiled = [_compile(p) for p in matcher.regex]
    return _any_or_all(
        (bool(r.search(haystack)) for r in compiled),
        condition=matcher.condition,
    )


def _glob_fires(haystack: str, matcher: GlobMatcher) -> bool:
    return _any_or_all(
        (fnmatch.fnmatchcase(haystack, g) for g in matcher.globs),
        condition=matcher.condition,
    )


def evaluate_matcher(matcher: Matcher, parts: list[str]) -> bool:
    """Return True if ``matcher`` fires over ``parts``.

    A matcher fires when any of the parts satisfies the inner condition.
    When ``matcher.negative`` is true the overall verdict is inverted.
    Empty parts never fire: absence of data is not a finding.
    """
    if not parts:
        return False

    if isinstance(matcher, WordMatcher):
        fired = any(_word_fires(p, matcher) for p in parts)
    elif isinstance(matcher, RegexMatcher):
        fired = any(_regex_fires(p, matcher) for p in parts)
    else:  # GlobMatcher
        fired = any(_glob_fires(p, matcher) for p in parts)

    return (not fired) if matcher.negative else fired
