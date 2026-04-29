"""Hypothesis property tests for M5 invariants.

Lives in its own module because it carries no ``pytest.mark.asyncio``
-- the properties are pure (sync) functions over the typed message
layer and the validators. Mixing async marks with sync Hypothesis
tests confuses pytest-asyncio's collection.
"""

from __future__ import annotations

import asyncio

from argos_proxy import (
    InMemoryFindingSink,
    PIIDetector,
    Request,
    parse_payload,
)
from argos_proxy.detectors.pii import _dni_is_valid
from argos_proxy.interceptor import new_context
from argos_proxy.jsonrpc.framing import decode_message, encode_message
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

_ascii_text = st.text(
    alphabet=st.characters(min_codepoint=32, max_codepoint=126, blacklist_characters='"\\'),
    max_size=64,
)


@given(
    method=st.from_regex(r"^[A-Za-z_][A-Za-z0-9_./\-]{0,40}$", fullmatch=True),
    id_=st.integers(min_value=-(2**60), max_value=2**60),
)
@settings(max_examples=200, deadline=None, suppress_health_check=[HealthCheck.too_slow])
def test_request_id_round_trips_for_any_int(method: str, id_: int) -> None:
    """For any reasonable int id, the parser yields back the exact value."""
    wire = encode_message(Request(method=method, id=id_), framing="ndjson")
    decoded = parse_payload(decode_message(wire, framing="ndjson"))
    assert isinstance(decoded, Request)
    assert decoded.id == id_


@given(text=_ascii_text)
@settings(max_examples=200, deadline=None, suppress_health_check=[HealthCheck.too_slow])
def test_string_id_round_trips_byte_for_byte(text: str) -> None:
    if not text:
        return
    req = Request(method="m", id=text)
    wire = encode_message(req, framing="ndjson")
    decoded = parse_payload(decode_message(wire, framing="ndjson"))
    assert isinstance(decoded, Request)
    assert decoded.id == text


@given(digits=st.text(alphabet="0123456789", min_size=8, max_size=8))
@settings(max_examples=100, deadline=None)
def test_dni_letter_is_unique_per_modulo(digits: str) -> None:
    """For any valid 8-digit DNI prefix, exactly one letter satisfies
    the mod-23 check. Pins the algebraic property: the validator is a
    function (one-to-one)."""
    valid_count = sum(1 for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ" if _dni_is_valid(digits, letter))
    assert valid_count == 1


@given(payload=st.text(min_size=0, max_size=512))
@settings(max_examples=200, deadline=None, suppress_health_check=[HealthCheck.too_slow])
def test_pii_scanner_never_crashes(payload: str) -> None:
    """For any text payload the PII scanner either yields findings or
    returns silently; it never raises."""
    sink = InMemoryFindingSink()
    det = PIIDetector(sink)

    async def _scan() -> None:
        await det.on_request_in(
            Request(method="m", params={"x": payload}, id=1),
            new_context(),
        )

    asyncio.run(_scan())
