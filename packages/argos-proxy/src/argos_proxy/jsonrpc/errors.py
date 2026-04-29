"""JSON-RPC 2.0 error codes and proxy-side exception hierarchy.

The spec reserves the range ``[-32768, -32000]`` for protocol-level
errors and assigns five well-known constants. Implementation-defined
server errors live in ``[-32099, -32000]``. Application errors must use
codes outside ``[-32768, -32000]``.

Two exception classes:

- :class:`JsonRpcError` carries a code/message/data tuple suitable for
  serialisation as a JSON-RPC error object. Detectors raise this when
  they want a structured response to flow back upstream.
- :class:`JsonRpcProtocolError` is for parser-level violations
  (malformed JSON, missing ``jsonrpc`` field). The framing layer raises
  it before any message object is built.
"""

from __future__ import annotations

from typing import Any, Final

# Reserved range for the protocol itself. Implementation-defined server
# errors are a sub-range; everything below -32768 is invalid.
_RESERVED_RANGE_LOW: Final[int] = -32768
_RESERVED_RANGE_HIGH: Final[int] = -32000

#: Standard error codes from the JSON-RPC 2.0 specification.
PARSE_ERROR: Final[int] = -32700
INVALID_REQUEST: Final[int] = -32600
METHOD_NOT_FOUND: Final[int] = -32601
INVALID_PARAMS: Final[int] = -32602
INTERNAL_ERROR: Final[int] = -32603

#: Inclusive bounds of the implementation-defined server-error range.
SERVER_ERROR_MIN: Final[int] = -32099
SERVER_ERROR_MAX: Final[int] = -32000


def is_reserved_code(code: int) -> bool:
    """True if ``code`` lies in the reserved JSON-RPC 2.0 range.

    Application code SHOULD use values outside this range. The proxy
    uses this check when a detector emits an error object and we want
    to confirm the chosen code does not collide with a protocol-level
    constant the client might already handle specially.
    """
    return _RESERVED_RANGE_LOW <= code <= _RESERVED_RANGE_HIGH


class JsonRpcProtocolError(ValueError):
    """A parser-level violation of the JSON-RPC 2.0 wire grammar.

    Raised by :func:`argos_proxy.jsonrpc.framing.decode_message` when
    the bytes do not parse as JSON, or when the resulting JSON does not
    carry the mandatory ``jsonrpc: "2.0"`` field. The proxy answers
    these with a :data:`PARSE_ERROR` or :data:`INVALID_REQUEST`
    response object built by the caller; the parser does not produce
    those itself because it has no request id to correlate with.
    """


class JsonRpcError(Exception):
    """Application-side failure that maps to a JSON-RPC error object.

    Carries the three fields of the spec's error structure: integer
    ``code``, human-readable ``message`` and optional ``data``. The
    exception is used as a control-flow signal: a detector or
    interceptor raises it, and the proxy serialises a response with
    matching fields back to the client.

    ``data`` is constrained to JSON-serialisable Python types
    (``None``, ``bool``, ``int``, ``float``, ``str``, ``list``,
    ``dict``); validation is enforced at construction so a misbehaving
    detector cannot smuggle a non-serialisable object onto the wire.
    """

    __slots__ = ("code", "data", "message")

    def __init__(self, code: int, message: str, data: Any = None) -> None:
        if not isinstance(code, int) or isinstance(code, bool):
            raise TypeError(f"code must be int, got {type(code).__name__}")
        if not isinstance(message, str) or not message:
            raise ValueError("message must be a non-empty string")
        _validate_json_data(data)
        super().__init__(f"[{code}] {message}")
        self.code = code
        self.message = message
        self.data = data

    def to_object(self) -> dict[str, Any]:
        """Render the spec-shaped JSON object suitable for a response."""
        out: dict[str, Any] = {"code": self.code, "message": self.message}
        if self.data is not None:
            out["data"] = self.data
        return out


def _validate_json_data(value: Any, *, depth: int = 0) -> None:
    """Reject non-JSON-serialisable values at the API boundary.

    A pathological ``data`` payload (e.g. a Python set, datetime or
    custom object) silently breaks ``json.dumps`` deep in the response
    pipeline, where the failure is hard to attribute. Catching it here
    pinpoints the offending detector immediately."""
    if depth > 32:  # cap on nesting to avoid recursion bombs
        raise ValueError("error data nesting exceeds 32 levels")
    if value is None or isinstance(value, (str, int, float, bool)):
        return
    if isinstance(value, list):
        for item in value:
            _validate_json_data(item, depth=depth + 1)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise TypeError(f"dict keys must be strings, got {type(key).__name__}")
            _validate_json_data(item, depth=depth + 1)
        return
    raise TypeError(
        f"error data must be JSON-serialisable, got {type(value).__name__}",
    )
