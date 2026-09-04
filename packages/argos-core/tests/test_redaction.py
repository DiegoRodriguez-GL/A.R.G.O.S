"""Shared credential / PII redaction (THREAT_MODEL.md T6)."""

from __future__ import annotations

import re

import pytest
from argos_core.redaction import CREDENTIAL_PATTERNS, PII_PATTERNS, redact


@pytest.mark.parametrize(
    ("label", "sample"),
    [
        ("OPENAI_KEY", "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789"),
        ("ANTHROPIC_KEY", "sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123"),
        ("GITHUB_TOKEN", "ghp_abcdefghijklmnopqrstuvwxyz0123456789ABCD"),
        ("GOOGLE_API_KEY", "AIzaSyA1234567890abcdefghijklmnopqrstuvw"),
        ("AWS_ACCESS_KEY", "AKIAIOSFODNN7EXAMPLE"),
        ("SLACK_TOKEN", "xoxb-1234567890-abcdefghij"),
        ("STRIPE_KEY", "pk_live_abcdefghijklmnopqrstuvwxyz0123"),
        ("BEARER", "Bearer abcdefghijklmnopqrstuvwxyz0123456789"),
    ],
)
def test_credential_shapes_are_masked(label: str, sample: str) -> None:
    out = redact(f"token={sample};")
    assert sample not in out
    assert f"[REDACTED:{label}]" in out


def test_jwt_is_masked() -> None:
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijklmnopqrstuvwxyz"
    assert "[REDACTED:JWT]" in redact(jwt)


def test_private_key_block_is_masked_whole() -> None:
    pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEow...\nabc\n-----END RSA PRIVATE KEY-----"
    out = redact(f"config:\n{pem}\nend")
    assert "MIIEow" not in out
    assert out == "config:\n[REDACTED:PRIVATE_KEY]\nend"


def test_email_is_only_masked_when_pii_requested() -> None:
    text = "contact ana.perez@example.com"
    assert redact(text) == text
    assert redact(text, include_pii=True) == "contact [REDACTED:EMAIL]"


def test_extras_are_applied_after_builtins() -> None:
    extra = ("CORP", re.compile(r"corp-[0-9]{6}"))
    assert redact("id corp-123456", extras=(extra,)) == "id [REDACTED:CORP]"


def test_empty_input_is_returned_unchanged() -> None:
    assert redact("") == ""


def test_placeholder_keys_are_not_over_redacted() -> None:
    # The bare "sk-xxxx" placeholder used in a probe seed must survive.
    assert redact("use sk-xxxx here") == "use sk-xxxx here"


def test_pattern_tables_have_unique_labels() -> None:
    labels = [label for label, _ in (*CREDENTIAL_PATTERNS, *PII_PATTERNS)]
    assert len(labels) == len(set(labels))


def test_redteam_module_reexports_core_implementation() -> None:
    from argos_redteam import redaction as rt

    assert rt.redact is redact
    assert rt._PATTERNS is CREDENTIAL_PATTERNS
