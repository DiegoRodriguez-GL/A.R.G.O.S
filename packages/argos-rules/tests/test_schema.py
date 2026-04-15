"""The rule schema is shipped as part of the package and is valid draft-07."""

from __future__ import annotations

import json
from pathlib import Path

import jsonschema

_SCHEMA = Path(__file__).resolve().parents[1] / "schema" / "rule.schema.json"


def test_schema_is_valid_draft_07() -> None:
    data = json.loads(_SCHEMA.read_text(encoding="utf-8"))
    jsonschema.Draft7Validator.check_schema(data)


def test_schema_accepts_minimal_rule() -> None:
    data = json.loads(_SCHEMA.read_text(encoding="utf-8"))
    minimal = {
        "id": "ASI01-01",
        "info": {"name": "Goal hijack via tool output", "severity": "high"},
        "matchers": [{"type": "word", "words": ["forget previous"]}],
    }
    jsonschema.validate(minimal, data)


def test_schema_rejects_unknown_top_level_keys() -> None:
    import pytest

    data = json.loads(_SCHEMA.read_text(encoding="utf-8"))
    invalid = {
        "id": "ASI01-01",
        "info": {"name": "x", "severity": "low"},
        "matchers": [{"type": "word"}],
        "exploit": "yes",
    }
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(invalid, data)
