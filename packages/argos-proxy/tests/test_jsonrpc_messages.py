"""JSON-RPC 2.0 message-layer spec compliance tests.

Covers every clause of section 4 (Request) and section 5 (Response) of
``https://www.jsonrpc.org/specification`` that has observable behaviour
on the wire. The tests are parametrised so a regression in one of the
hundred edge cases the spec cares about surfaces immediately as a
named failure rather than being lost in a generic ValidationError.
"""

from __future__ import annotations

import json

import pytest
from argos_proxy import (
    Batch,
    ErrorObject,
    JsonRpcProtocolError,
    Notification,
    Request,
    Response,
    parse_payload,
)
from argos_proxy.jsonrpc import (
    INTERNAL_ERROR,
    INVALID_PARAMS,
    INVALID_REQUEST,
    METHOD_NOT_FOUND,
    PARSE_ERROR,
    JsonRpcError,
    parse_message,
)
from argos_proxy.jsonrpc.errors import is_reserved_code
from pydantic import ValidationError

# ---------------------------------------------------------------------------
# Spec section 4: Request object.
# ---------------------------------------------------------------------------


class TestRequestSpec:
    def test_minimal_request_round_trips(self) -> None:
        req = Request(method="tools/list", id=1)
        assert req.jsonrpc == "2.0"
        assert req.method == "tools/list"
        assert req.id == 1
        assert req.params is None
        # Round-trip through JSON.
        decoded = parse_message(json.loads(req.model_dump_json()))
        assert decoded == req

    def test_request_with_object_params(self) -> None:
        req = Request(method="tools/call", params={"name": "echo", "arguments": {}}, id="x")
        assert req.params == {"name": "echo", "arguments": {}}

    def test_request_with_array_params(self) -> None:
        req = Request(method="x", params=[1, 2, 3], id=42)
        assert req.params == [1, 2, 3]

    def test_request_id_can_be_string(self) -> None:
        assert Request(method="m", id="abc").id == "abc"

    def test_request_id_can_be_null(self) -> None:
        # Spec discourages but permits.
        req = Request(method="m", id=None)
        assert req.id is None

    def test_request_id_can_be_float(self) -> None:
        # Spec permits numeric ids; floats are unusual but legal.
        assert Request(method="m", id=3.14).id == 3.14

    def test_request_id_rejects_nan(self) -> None:
        with pytest.raises(ValidationError):
            Request(method="m", id=float("nan"))

    def test_request_id_rejects_inf(self) -> None:
        with pytest.raises(ValidationError):
            Request(method="m", id=float("inf"))

    def test_request_id_rejects_boolean(self) -> None:
        # Python bool is int subclass; explicit reject.
        with pytest.raises(ValidationError):
            Request(method="m", id=True)

    def test_request_id_rejects_oversized_string(self) -> None:
        with pytest.raises(ValidationError):
            Request(method="m", id="x" * 257)

    def test_request_rejects_extra_fields(self) -> None:
        with pytest.raises(ValidationError):
            Request(method="m", id=1, extra_field="boom")  # type: ignore[call-arg]

    def test_request_rejects_invalid_method_chars(self) -> None:
        # Spec is permissive on method names but ARGOS rejects ones
        # carrying characters that would force log-injection escaping.
        with pytest.raises(ValidationError):
            Request(method="m\nfake-line", id=1)

    def test_request_rejects_empty_method(self) -> None:
        with pytest.raises(ValidationError):
            Request(method="", id=1)

    def test_request_jsonrpc_field_is_pinned(self) -> None:
        # Cannot construct with the wrong protocol version literal.
        with pytest.raises(ValidationError):
            Request(jsonrpc="1.0", method="m", id=1)  # type: ignore[arg-type]

    def test_request_is_frozen(self) -> None:
        r = Request(method="m", id=1)
        with pytest.raises(ValidationError):
            r.method = "other"


class TestNotificationSpec:
    def test_notification_carries_no_id(self) -> None:
        n = Notification(method="tools/list/changed")
        assert "id" not in n.model_dump()

    def test_notification_with_params(self) -> None:
        n = Notification(method="m", params={"k": "v"})
        assert n.params == {"k": "v"}

    def test_notification_rejects_id_field(self) -> None:
        # Pydantic's extra="forbid" catches this.
        with pytest.raises(ValidationError):
            Notification(method="m", id=1)  # type: ignore[call-arg]


# ---------------------------------------------------------------------------
# Spec section 5: Response object.
# ---------------------------------------------------------------------------


class TestResponseSpec:
    def test_success_response(self) -> None:
        r = Response(result={"ok": True}, id=1)
        assert r.is_success
        assert not r.is_error
        assert r.result == {"ok": True}
        assert r.error is None

    def test_error_response(self) -> None:
        err = ErrorObject(code=-32601, message="Method not found")
        r = Response(error=err, id=1)
        assert r.is_error
        assert not r.is_success

    def test_response_must_have_either_result_or_error(self) -> None:
        with pytest.raises(ValidationError):
            Response(id=1)

    def test_response_cannot_have_both_result_and_error(self) -> None:
        err = ErrorObject(code=-32603, message="x")
        with pytest.raises(ValidationError):
            Response(result={}, error=err, id=1)

    def test_response_id_may_be_null_for_parse_errors(self) -> None:
        # Spec section 5: when a parse error occurs the id is null
        # because the request was unparseable. That is legal.
        err = ErrorObject(code=PARSE_ERROR, message="parse")
        r = Response(error=err, id=None)
        assert r.id is None
        assert r.is_error

    def test_error_object_message_is_required(self) -> None:
        with pytest.raises(ValidationError):
            ErrorObject(code=-1, message="")

    def test_error_object_data_is_optional(self) -> None:
        e = ErrorObject(code=-1, message="x")
        assert e.data is None

    def test_response_rejects_invalid_jsonrpc_version(self) -> None:
        with pytest.raises(ValidationError):
            Response(jsonrpc="2.1", result={}, id=1)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Section 6: Batch.
# ---------------------------------------------------------------------------


class TestBatch:
    def test_batch_must_be_non_empty(self) -> None:
        with pytest.raises(ValidationError):
            Batch(messages=())

    def test_batch_with_mixed_message_kinds(self) -> None:
        msgs = (
            Request(method="a", id=1),
            Notification(method="b"),
            Request(method="c", id="x"),
        )
        b = Batch(messages=msgs)
        assert len(b.messages) == 3
        assert isinstance(b.messages[1], Notification)

    def test_batch_size_cap_enforced(self) -> None:
        big = tuple(Notification(method=f"m{i}") for i in range(2049))
        with pytest.raises(ValidationError):
            Batch(messages=big)


# ---------------------------------------------------------------------------
# parse_payload: top-level dispatch.
# ---------------------------------------------------------------------------


class TestParsePayload:
    def test_parses_request_object(self) -> None:
        msg = parse_payload('{"jsonrpc":"2.0","method":"m","id":1}')
        assert isinstance(msg, Request)

    def test_parses_notification_object(self) -> None:
        msg = parse_payload('{"jsonrpc":"2.0","method":"m"}')
        assert isinstance(msg, Notification)

    def test_parses_response_object(self) -> None:
        msg = parse_payload('{"jsonrpc":"2.0","result":42,"id":1}')
        assert isinstance(msg, Response)

    def test_parses_batch_array(self) -> None:
        payload = '[{"jsonrpc":"2.0","method":"a","id":1}]'
        msg = parse_payload(payload)
        assert isinstance(msg, Batch)
        assert len(msg.messages) == 1

    def test_empty_batch_rejected(self) -> None:
        with pytest.raises(JsonRpcProtocolError, match="batch must contain"):
            parse_payload("[]")

    def test_parse_error_on_bad_json(self) -> None:
        with pytest.raises(JsonRpcProtocolError, match="not valid JSON"):
            parse_payload("{bad")

    def test_parse_error_on_invalid_utf8(self) -> None:
        with pytest.raises(JsonRpcProtocolError, match="not valid UTF-8"):
            parse_payload(b"\xff\xfe\x00")

    def test_invalid_request_when_jsonrpc_field_missing(self) -> None:
        with pytest.raises(JsonRpcProtocolError, match="jsonrpc"):
            parse_payload('{"method":"m","id":1}')

    def test_invalid_request_when_jsonrpc_field_wrong(self) -> None:
        with pytest.raises(JsonRpcProtocolError, match="jsonrpc"):
            parse_payload('{"jsonrpc":"1.0","method":"m","id":1}')

    def test_invalid_request_when_neither_method_nor_result(self) -> None:
        with pytest.raises(JsonRpcProtocolError):
            parse_payload('{"jsonrpc":"2.0"}')

    def test_invalid_request_when_method_and_result_mixed(self) -> None:
        with pytest.raises(JsonRpcProtocolError):
            parse_payload('{"jsonrpc":"2.0","method":"m","result":1,"id":1}')

    def test_top_level_must_be_object_or_array(self) -> None:
        with pytest.raises(JsonRpcProtocolError):
            parse_payload('"a-string"')

    def test_accepts_bytes_payload(self) -> None:
        msg = parse_payload(b'{"jsonrpc":"2.0","method":"m","id":1}')
        assert isinstance(msg, Request)


# ---------------------------------------------------------------------------
# Error code helpers.
# ---------------------------------------------------------------------------


class TestErrorCodes:
    @pytest.mark.parametrize(
        "code",
        [PARSE_ERROR, INVALID_REQUEST, METHOD_NOT_FOUND, INVALID_PARAMS, INTERNAL_ERROR],
    )
    def test_standard_codes_are_in_reserved_range(self, code: int) -> None:
        assert is_reserved_code(code)

    @pytest.mark.parametrize("code", [-32099, -32000])
    def test_server_error_range_is_reserved(self, code: int) -> None:
        assert is_reserved_code(code)

    @pytest.mark.parametrize("code", [-1, 0, 100, -31999, -32769])
    def test_application_codes_are_not_reserved(self, code: int) -> None:
        assert not is_reserved_code(code)


class TestJsonRpcError:
    def test_basic_construction(self) -> None:
        err = JsonRpcError(METHOD_NOT_FOUND, "No such method")
        assert err.code == METHOD_NOT_FOUND
        assert err.message == "No such method"
        assert err.data is None

    def test_to_object_renders_spec_shape(self) -> None:
        err = JsonRpcError(INVALID_PARAMS, "Bad params", data={"hint": "missing 'name'"})
        obj = err.to_object()
        assert obj == {
            "code": INVALID_PARAMS,
            "message": "Bad params",
            "data": {"hint": "missing 'name'"},
        }

    def test_to_object_omits_data_when_none(self) -> None:
        err = JsonRpcError(-1, "x")
        assert err.to_object() == {"code": -1, "message": "x"}

    def test_message_must_be_non_empty(self) -> None:
        with pytest.raises(ValueError, match="message"):
            JsonRpcError(-1, "")

    def test_code_must_be_int(self) -> None:
        with pytest.raises(TypeError):
            JsonRpcError("string-code", "x")  # type: ignore[arg-type]

    def test_code_rejects_bool(self) -> None:
        with pytest.raises(TypeError):
            JsonRpcError(True, "x")

    def test_data_rejects_non_json(self) -> None:
        with pytest.raises(TypeError):
            JsonRpcError(-1, "x", data={"set": {1, 2}})

    def test_data_rejects_dict_with_non_string_keys(self) -> None:
        with pytest.raises(TypeError):
            JsonRpcError(-1, "x", data={1: "v"})

    def test_data_rejects_nesting_bomb(self) -> None:
        # 33-level nested dict triggers the depth cap.
        nested: dict[str, object] = {}
        cur = nested
        for _ in range(33):
            child: dict[str, object] = {}
            cur["k"] = child
            cur = child
        with pytest.raises(ValueError, match="nesting"):
            JsonRpcError(-1, "x", data=nested)

    def test_data_accepts_legal_json_types(self) -> None:
        for value in (None, True, 1, 1.5, "s", [1, "a"], {"k": [1, 2]}):
            err = JsonRpcError(-1, "x", data=value)
            assert err.data == value
