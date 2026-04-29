"""Hypothesis property tests for JSON-RPC 2.0 messages and framing.

Two invariants are pinned here:

- **Round-trip:** for any well-formed message, ``parse_payload(
  encode(model)) == model``. Fed by Hypothesis-generated requests,
  responses and notifications across the legal id/method/params space.
- **Robustness:** for any byte payload (random or arbitrary text), the
  parser either yields a typed message or raises one of a small
  whitelist of exceptions. It MUST NOT surface a TypeError, KeyError,
  AttributeError or any unbounded resource consumption.
"""

from __future__ import annotations

import json

import pytest
from argos_proxy import (
    JsonRpcProtocolError,
    Notification,
    Request,
    Response,
    parse_payload,
)
from argos_proxy.jsonrpc.framing import (
    FrameDecodeError,
    NDJSONFramer,
    StdioFramer,
    decode_message,
    encode_message,
)
from argos_proxy.jsonrpc.messages import ErrorObject
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from pydantic import ValidationError

# ---------------------------------------------------------------------------
# Strategies that produce only legal JSON-RPC values.
# ---------------------------------------------------------------------------


_methods = st.from_regex(r"^[A-Za-z_][A-Za-z0-9_./\-]{0,80}$", fullmatch=True)
_id_strategy = st.one_of(
    st.none(),
    st.integers(min_value=-(2**53), max_value=2**53),
    st.text(
        alphabet=st.characters(min_codepoint=32, max_codepoint=126, blacklist_characters='"\\'),
        max_size=64,
    ),
)
_json_scalar = st.one_of(
    st.none(),
    st.booleans(),
    st.integers(min_value=-(2**53), max_value=2**53),
    st.floats(allow_nan=False, allow_infinity=False, width=32),
    st.text(max_size=32),
)
_json_value = st.recursive(
    _json_scalar,
    lambda children: st.one_of(
        st.lists(children, max_size=4),
        st.dictionaries(st.text(min_size=1, max_size=8), children, max_size=4),
    ),
    max_leaves=12,
)
_params = st.one_of(
    st.none(),
    st.lists(_json_value, max_size=4),
    st.dictionaries(st.text(min_size=1, max_size=8), _json_value, max_size=4),
)


# ---------------------------------------------------------------------------
# Round-trip property.
# ---------------------------------------------------------------------------


@given(method=_methods, params=_params, id_=_id_strategy)
@settings(max_examples=200, deadline=None)
def test_request_round_trips_through_json(
    method: str,
    params: object,
    id_: object,
) -> None:
    req = Request(method=method, params=params, id=id_)  # type: ignore[arg-type]
    wire = encode_message(req, framing="ndjson")
    decoded = parse_payload(decode_message(wire, framing="ndjson"))
    assert decoded == req


@given(method=_methods, params=_params)
@settings(max_examples=200, deadline=None)
def test_notification_round_trips(method: str, params: object) -> None:
    n = Notification(method=method, params=params)  # type: ignore[arg-type]
    wire = encode_message(n, framing="ndjson")
    decoded = parse_payload(decode_message(wire, framing="ndjson"))
    assert decoded == n


@given(result=_json_value, id_=_id_strategy)
@settings(max_examples=200, deadline=None)
def test_success_response_round_trips(result: object, id_: object) -> None:
    r = Response(result=result, id=id_)  # type: ignore[arg-type]
    wire = encode_message(r, framing="ndjson")
    decoded = parse_payload(decode_message(wire, framing="ndjson"))
    assert decoded == r


@given(
    code=st.integers(min_value=-32768, max_value=2**31 - 1),
    message=st.text(min_size=1, max_size=128),
    data=_json_value,
    id_=_id_strategy,
)
@settings(max_examples=200, deadline=None)
def test_error_response_round_trips(
    code: int,
    message: str,
    data: object,
    id_: object,
) -> None:
    err = ErrorObject(code=code, message=message, data=data)
    r = Response(error=err, id=id_)  # type: ignore[arg-type]
    wire = encode_message(r, framing="ndjson")
    decoded = parse_payload(decode_message(wire, framing="ndjson"))
    assert decoded == r


# ---------------------------------------------------------------------------
# Robustness property: parser never panics on adversarial input.
# ---------------------------------------------------------------------------


_PARSE_ALLOWED = (JsonRpcProtocolError, ValidationError)


@given(payload=st.binary(min_size=0, max_size=2048))
@settings(max_examples=400, deadline=None, suppress_health_check=[HealthCheck.too_slow])
def test_parse_payload_never_raises_unexpected_exception(payload: bytes) -> None:
    try:
        parse_payload(payload)
    except _PARSE_ALLOWED:
        return
    except BaseException as exc:  # noqa: BLE001
        pytest.fail(f"unexpected {type(exc).__name__}: {exc!r} on payload {payload!r}")


@given(text=st.text(min_size=0, max_size=2048))
@settings(max_examples=200, deadline=None, suppress_health_check=[HealthCheck.too_slow])
def test_parse_payload_text_robustness(text: str) -> None:
    try:
        parse_payload(text)
    except _PARSE_ALLOWED:
        return
    except BaseException as exc:  # noqa: BLE001
        pytest.fail(f"unexpected {type(exc).__name__}: {exc!r} on text {text!r}")


# ---------------------------------------------------------------------------
# Framing property: streaming and one-shot agree on every input that
# round-trips through encode_message.
# ---------------------------------------------------------------------------


@given(
    payloads=st.lists(
        st.dictionaries(
            st.text(min_size=1, max_size=8, alphabet="abcdef"),
            _json_scalar,
            min_size=1,
            max_size=4,
        ),
        min_size=1,
        max_size=8,
    ),
    framing=st.sampled_from(["ndjson", "stdio"]),
)
@settings(max_examples=100, deadline=None, suppress_health_check=[HealthCheck.too_slow])
def test_streaming_framer_matches_one_shot(
    payloads: list[dict[str, object]],
    framing: str,
) -> None:
    """Concatenate every encoded payload, feed in arbitrary chunks to the
    streaming framer, expect the same bodies back as if we had decoded
    each frame independently."""
    encoded = b"".join(encode_message(p, framing=framing) for p in payloads)
    expected = [
        json.dumps(p, ensure_ascii=False, separators=(",", ":")).encode("utf-8") for p in payloads
    ]
    framer = NDJSONFramer() if framing == "ndjson" else StdioFramer()
    # Feed in 7-byte chunks to maximise mid-message splits.
    out: list[bytes] = []
    for i in range(0, len(encoded), 7):
        out.extend(framer.feed(encoded[i : i + 7]))
    assert out == expected
    assert framer.buffered_bytes() == 0


@given(payload=st.binary(min_size=0, max_size=512))
@settings(max_examples=200, deadline=None)
def test_streaming_framers_robustness(payload: bytes) -> None:
    """Random bytes fed to the streaming framers either parse, raise
    ``FrameDecodeError`` or buffer for more data. Nothing else."""
    for cls in (NDJSONFramer, StdioFramer):
        framer = cls()
        try:
            framer.feed(payload)
        except FrameDecodeError:
            continue
        # If we didn't raise we shouldn't crash on a final feed of empty.
        framer.feed(b"")
