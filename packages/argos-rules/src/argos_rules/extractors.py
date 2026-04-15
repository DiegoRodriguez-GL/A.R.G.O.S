"""Extract verbatim evidence snippets from parts selected by a rule.

An extractor never produces findings on its own: it enriches the Evidence
attached to a finding with concrete captured substrings so auditors can see
exactly what triggered the rule.
"""

from __future__ import annotations

import re
from functools import lru_cache

from argos_rules.models import Extractor, RegexExtractor, WordExtractor

_MAX_HITS_PER_EXTRACTOR = 16
_MAX_HIT_CHARS = 256


@lru_cache(maxsize=1024)
def _compile(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern)


def _truncate(s: str) -> str:
    if len(s) <= _MAX_HIT_CHARS:
        return s
    return s[: _MAX_HIT_CHARS - 1] + "..."


def _extract_regex(parts: list[str], extractor: RegexExtractor) -> list[str]:
    compiled = _compile(extractor.regex)
    hits: list[str] = []
    for part in parts:
        for match in compiled.finditer(part):
            try:
                captured = match.group(extractor.group)
            except IndexError:
                continue
            if captured is not None:
                hits.append(_truncate(captured))
                if len(hits) >= _MAX_HITS_PER_EXTRACTOR:
                    return hits
    return hits


def _extract_words(parts: list[str], extractor: WordExtractor) -> list[str]:
    hits: list[str] = []
    if extractor.case_insensitive:
        search_parts = [p.lower() for p in parts]
        words = [w.lower() for w in extractor.words]
    else:
        search_parts = list(parts)
        words = list(extractor.words)
    for part in search_parts:
        for w in words:
            if w in part:
                hits.append(_truncate(w))
                if len(hits) >= _MAX_HITS_PER_EXTRACTOR:
                    return hits
    return hits


def run_extractor(extractor: Extractor, parts: list[str]) -> list[str]:
    if isinstance(extractor, RegexExtractor):
        return _extract_regex(parts, extractor)
    return _extract_words(parts, extractor)
