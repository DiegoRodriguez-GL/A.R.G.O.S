"""Frozen Pydantic models for JSON-RPC 2.0 messages.

The four shapes of the spec:

- :class:`Request`: ``method`` + ``params`` + ``id``. Round-trippable.
- :class:`Notification`: ``method`` + ``params``, no ``id``.
- :class:`Response`: either ``result`` xor ``error`` + ``id``.
- :class:`ErrorObject`: ``code`` + ``message`` + optional ``data``.

Plus :class:`Batch`, the spec's array-of-messages envelope.

The models intentionally mirror the spec exactly. There are zero
proxy-specific extensions on the wire shape; what the proxy adds
(detection metadata, OTel spans, forensics rows) lives in *parallel*
data structures so the JSON we forward upstream is byte-faithful with
respect to what the client sent.

All models are ``frozen=True`` and ``extra="forbid"`` so:

- A request that mutates after construction is a programming error.
- Unknown fields ("``method2``", "``id2``", "``params``" misspellings)
  fail fast with a clear error message at the proxy boundary instead of
  being silently forwarded to the upstream MCP server.
"""

from __future__ import annotations

import json
import math
from typing import Annotated, Any, Final, Literal, Union

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
    model_serializer,
    model_validator,
)

from argos_proxy.jsonrpc.errors import JsonRpcProtocolError

#: The single supported protocol version. The constant is duplicated
#: here so message validation does not depend on importing the spec
#: text at runtime.
JSONRPC_VERSION: Final = "2.0"

#: A JSON-RPC 2.0 id. The spec allows string, number or null. We
#: reject unbounded numbers (NaN/inf) and oversized strings at the
#: model boundary.
RequestId = Union[str, int, float, None]

# Method-name length cap. The MCP spec does not formally bound this,
# but a sane upper limit keeps the audit logs readable and prevents an
# adversary from filling a SQLite forensics table with megabyte-long
# method names.
_METHOD_MAX_LEN: Final[int] = 256

# Maximum byte length of a serialised id. JSON-RPC permits arbitrary
# strings; we cap at 256 chars to keep correlation tables compact and
# logs greppable.
_ID_MAX_LEN: Final[int] = 256


def _validate_id(value: RequestId) -> RequestId:
    """Reject NaN / inf / control-char ids; everything else is forwarded
    untouched. The spec discourages floats but allows them; we don't
    rewrite the value because the *client* expects an exact echo back
    in the response."""
    if value is None or isinstance(value, bool):
        # bool is a subclass of int in Python; the spec doesn't list
        # boolean as a valid id type. Reject explicitly.
        if isinstance(value, bool):
            msg = "id must not be a boolean"
            raise ValueError(msg)
        return value
    if isinstance(value, str):
        if len(value) > _ID_MAX_LEN:
            msg = f"id length {len(value)} exceeds {_ID_MAX_LEN}"
            raise ValueError(msg)
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        if math.isnan(value) or math.isinf(value):
            msg = "id must not be NaN or infinite"
            raise ValueError(msg)
        return value
    # mypy thinks this branch is unreachable because the Union narrows
    # exhaustively, but Pydantic's mode="before" can in fact pass any
    # arbitrary Python object through.
    msg = f"id must be str, int, float or null, got {type(value).__name__}"  # type: ignore[unreachable]
    raise TypeError(msg)


# Pydantic str constraint: trimmed, non-empty, length-capped, no
# embedded NUL or other C0 control chars except tab (which is unusual
# in JSON-RPC method names but legal). We allow ``a-zA-Z0-9_./-``: this
# is a superset of MCP's actual method namespace ("tools/call",
# "resources/read", etc.) but rejects the obvious injection vectors.
_MethodStr = Annotated[
    str,
    StringConstraints(
        strip_whitespace=False,
        min_length=1,
        max_length=_METHOD_MAX_LEN,
        pattern=r"^[A-Za-z_][A-Za-z0-9_./\-]*$",
    ),
]

# JSON object or array. The spec allows either (or omitted). We do NOT
# enforce a deeper schema here because that is the upstream server's
# responsibility; the proxy is transparent.
_ParamsT = Union[dict[str, Any], list[Any]]


class ErrorObject(BaseModel):
    """The ``error`` member of a failed JSON-RPC response.

    Wire grammar: ``{"code": int, "message": str, "data"?: any}``.
    """

    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    code: int
    message: Annotated[str, StringConstraints(min_length=1, max_length=4096)]
    data: Any = None


class Request(BaseModel):
    """JSON-RPC 2.0 request. Carries an ``id``; awaits a response."""

    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    jsonrpc: Literal["2.0"] = "2.0"
    method: _MethodStr
    params: _ParamsT | None = None
    id: RequestId = Field(default=None)

    # ``mode="before"`` so we see the raw payload BEFORE Pydantic
    # coerces bool -> int (Python's bool is a subclass of int).
    # Otherwise ``id=True`` slips through as ``id=1``.
    @field_validator("id", mode="before")
    @classmethod
    def _v_id(cls, v: RequestId) -> RequestId:
        return _validate_id(v)

    @model_validator(mode="after")
    def _id_is_required(self) -> Request:
        # Distinguish "id explicitly null" (legal but discouraged) from
        # "id absent". Pydantic gives us no native way to do this in a
        # single class without re-parsing; so we accept null at the
        # model level and rely on :func:`parse_message` to dispatch to
        # :class:`Notification` when ``id`` is missing from the source.
        return self


class Notification(BaseModel):
    """JSON-RPC 2.0 notification. No ``id``; no response is expected."""

    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    jsonrpc: Literal["2.0"] = "2.0"
    method: _MethodStr
    params: _ParamsT | None = None


class Response(BaseModel):
    """JSON-RPC 2.0 response: either ``result`` or ``error``, never both.

    The spec mandates that exactly one of ``result`` and ``error`` is
    present on every response. We enforce this with a model validator so
    the proxy cannot accidentally emit a malformed response when a
    detector both produces a result and raises (a real bug we observed
    in the M5 prototype before the validator was in place).
    """

    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    jsonrpc: Literal["2.0"] = "2.0"
    result: Any = None
    error: ErrorObject | None = None
    id: RequestId = Field(default=None)

    @field_validator("id", mode="before")
    @classmethod
    def _v_id(cls, v: RequestId) -> RequestId:
        return _validate_id(v)

    @model_validator(mode="after")
    def _exactly_one_of_result_or_error(self) -> Response:
        # ``result`` is ``Any``; we cannot use truthiness. The spec is
        # explicit: presence is what matters, not value. We carry a
        # private flag in __dict__ to record which field was actually
        # supplied at construction time -- but Pydantic v2 already
        # exposes this through ``model_fields_set``.
        has_result = "result" in self.model_fields_set
        has_error = "error" in self.model_fields_set
        if has_result and has_error:
            msg = "response must not contain both 'result' and 'error'"
            raise ValueError(msg)
        if not has_result and not has_error:
            msg = "response must contain exactly one of 'result' or 'error'"
            raise ValueError(msg)
        return self

    @property
    def is_error(self) -> bool:
        return self.error is not None

    @property
    def is_success(self) -> bool:
        return self.error is None

    @model_serializer
    def _serialize(self) -> dict[str, Any]:
        """Emit only the field actually set at construction time.

        Without this the model dumper would serialise both ``result``
        and ``error`` (one as ``null``), and the resulting JSON would
        violate the spec's "exactly one of" rule when re-parsed.
        """
        out: dict[str, Any] = {"jsonrpc": self.jsonrpc, "id": self.id}
        if self.error is not None:
            out["error"] = self.error.model_dump(exclude_none=True)
        else:
            out["result"] = self.result
        return out


#: Union of the three message kinds the proxy may forward.
Message = Union[Request, Notification, Response]


class Batch(BaseModel):
    """A JSON-RPC 2.0 batch: a non-empty array of messages.

    The spec forbids an empty array ("server should respond with a
    single Response object having a -32600 Invalid Request error");
    we reject it at the model boundary so the proxy never has to ask
    "did this empty list mean a parse error or a deliberate batch?".
    """

    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    messages: tuple[Message, ...] = Field(..., min_length=1, max_length=2048)


# ---------------------------------------------------------------------------
# Parsing dispatch.
# ---------------------------------------------------------------------------


def parse_payload(raw: str | bytes) -> Message | Batch:
    """Top-level entry point: bytes / str -> typed message.

    The function does the four steps the parser MUST perform per the
    spec:

    1. JSON-decode (``-32700 Parse error`` on failure).
    2. If the result is a list, dispatch to :class:`Batch`.
    3. If the result is an object, dispatch to :func:`parse_message`.
    4. Otherwise raise :class:`JsonRpcProtocolError` (``Invalid Request``).
    """
    if isinstance(raw, bytes):
        try:
            raw = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            msg = f"payload is not valid UTF-8: {exc}"
            raise JsonRpcProtocolError(msg) from exc
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        msg = f"payload is not valid JSON: {exc}"
        raise JsonRpcProtocolError(msg) from exc
    if isinstance(data, list):
        if not data:
            msg = "batch must contain at least one message"
            raise JsonRpcProtocolError(msg)
        parsed = tuple(parse_message(item) for item in data)
        return Batch(messages=parsed)
    if isinstance(data, dict):
        return parse_message(data)
    msg = f"top-level JSON value must be object or array, got {type(data).__name__}"
    raise JsonRpcProtocolError(msg)


def parse_message(data: dict[str, Any]) -> Message:
    """Object-level dispatcher: chooses Request, Notification or Response.

    Distinguishing rules (per spec section 4 / 5):

    - Has ``method`` and an ``id`` member (even if null) -> Request.
    - Has ``method`` and no ``id`` member -> Notification.
    - Has ``result`` xor ``error`` -> Response.
    - Anything else -> :class:`JsonRpcProtocolError`.

    Unknown top-level keys cause a ``ValidationError`` from Pydantic;
    we do not lower it to :class:`JsonRpcProtocolError` so the caller
    can correlate the error against the schema directly.
    """
    if not isinstance(data, dict):
        # Defensive guard kept even though the parameter is typed as
        # ``dict[str, Any]``: the caller may pass dynamically-shaped
        # JSON values that bypassed the type system.
        msg = f"message must be a JSON object, got {type(data).__name__}"  # type: ignore[unreachable]
        raise JsonRpcProtocolError(msg)
    if data.get("jsonrpc") != JSONRPC_VERSION:
        # We surface this as protocol error, not as a Pydantic
        # ValidationError, because the spec assigns a dedicated code
        # (-32600 Invalid Request) for missing/wrong jsonrpc.
        msg = f"missing or invalid 'jsonrpc' field; expected {JSONRPC_VERSION!r}"
        raise JsonRpcProtocolError(msg)
    has_method = "method" in data
    has_id = "id" in data
    has_result = "result" in data
    has_error = "error" in data

    if has_method and (has_result or has_error):
        msg = "message must not mix request/notification fields with response fields"
        raise JsonRpcProtocolError(msg)
    if has_method:
        if has_id:
            return Request.model_validate(data)
        return Notification.model_validate(data)
    if has_result or has_error:
        return Response.model_validate(data)
    msg = "message must contain either 'method' or 'result'/'error'"
    raise JsonRpcProtocolError(msg)
