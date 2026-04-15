"""Matcher primitive tests."""

from __future__ import annotations

from argos_rules.matchers import evaluate_matcher
from argos_rules.models import GlobMatcher, RegexMatcher, WordMatcher

# ---------- word matcher ------------------------------------------------


def test_word_or_fires_on_any() -> None:
    m = WordMatcher(type="word", words=("foo", "bar"), condition="or")
    assert evaluate_matcher(m, ["abcfooxyz"]) is True
    assert evaluate_matcher(m, ["xyz"]) is False


def test_word_and_requires_all() -> None:
    m = WordMatcher(type="word", words=("foo", "bar"), condition="and")
    assert evaluate_matcher(m, ["foobar"]) is True
    assert evaluate_matcher(m, ["foo only"]) is False


def test_word_case_insensitive_via_alias() -> None:
    m = WordMatcher.model_validate(
        {"type": "word", "words": ["FOO"], "case-insensitive": True},
    )
    assert evaluate_matcher(m, ["abcfooxyz"]) is True


def test_word_negative_inverts_result() -> None:
    m = WordMatcher(type="word", words=("foo",), negative=True)
    assert evaluate_matcher(m, ["no match here"]) is True
    assert evaluate_matcher(m, ["has foo"]) is False


def test_word_matcher_over_multiple_parts() -> None:
    m = WordMatcher(type="word", words=("banana",))
    assert evaluate_matcher(m, ["apples", "grapes", "bananacake"]) is True


# ---------- regex matcher -----------------------------------------------


def test_regex_or_matches_any_pattern() -> None:
    m = RegexMatcher(type="regex", regex=(r"^[a-z]+$", r"\d{3}"))
    assert evaluate_matcher(m, ["abcdef"]) is True
    assert evaluate_matcher(m, ["abc123"]) is True  # matches \d{3}
    assert evaluate_matcher(m, ["!!!"]) is False


def test_regex_and_requires_all_patterns() -> None:
    m = RegexMatcher(type="regex", regex=(r"foo", r"bar"), condition="and")
    assert evaluate_matcher(m, ["foobar"]) is True
    assert evaluate_matcher(m, ["foo only"]) is False


# ---------- glob matcher ------------------------------------------------


def test_glob_matches_trailing_wildcard() -> None:
    m = GlobMatcher(type="glob", globs=("ghp_*",))
    assert evaluate_matcher(m, ["ghp_abcdef"]) is True


def test_glob_rejects_non_match() -> None:
    m = GlobMatcher(type="glob", globs=("*.tar.gz",))
    assert evaluate_matcher(m, ["pkg.zip"]) is False


# ---------- edge cases -------------------------------------------------


def test_empty_parts_never_fire() -> None:
    m = WordMatcher(type="word", words=("foo",))
    assert evaluate_matcher(m, []) is False


def test_empty_parts_with_negative_still_does_not_fire() -> None:
    # Conservative: absence of data is not a finding. Users must declare a
    # selector that resolves to at least one value to use `negative`.
    m = WordMatcher(type="word", words=("foo",), negative=True)
    assert evaluate_matcher(m, []) is False
