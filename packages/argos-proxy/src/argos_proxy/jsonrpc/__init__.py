"""JSON-RPC 2.0 typed message layer for the ARGOS audit proxy.

The proxy operates on three message kinds defined by the JSON-RPC 2.0
specification (`https://www.jsonrpc.org/specification`):

- :class:`Request`: a method call carrying an ``id``. Expects a paired
  :class:`Response` (success or error).
- :class:`Notification`: a method call without an ``id``. The server
  MUST NOT send a response; the proxy still records the message.
- :class:`Response`: either a success result tied to a request ``id``,
  or an :class:`ErrorObject`.

The wire grammar is enforced by frozen Pydantic models so a request
that fails validation never reaches the upstream MCP server. This is
defence-in-depth: even if a client passes a hostile payload, the proxy
either rejects it with ``-32600 Invalid Request`` or normalises it into
a typed object the rest of the pipeline can reason about.

Framing (content-length headers, NDJSON) lives in
:mod:`argos_proxy.jsonrpc.framing` because it is orthogonal to message
shape: a ``Request`` is the same value whether it travels over stdio,
TCP or an in-memory pipe.
"""

from __future__ import annotations

from argos_proxy.jsonrpc.errors import (
    INTERNAL_ERROR,
    INVALID_PARAMS,
    INVALID_REQUEST,
    METHOD_NOT_FOUND,
    PARSE_ERROR,
    SERVER_ERROR_MAX,
    SERVER_ERROR_MIN,
    JsonRpcError,
    JsonRpcProtocolError,
)
from argos_proxy.jsonrpc.framing import (
    FrameDecodeError,
    NDJSONFramer,
    StdioFramer,
    decode_message,
    encode_message,
)
from argos_proxy.jsonrpc.messages import (
    JSONRPC_VERSION,
    Batch,
    ErrorObject,
    Message,
    Notification,
    Request,
    RequestId,
    Response,
    parse_message,
    parse_payload,
)

__all__ = [
    "INTERNAL_ERROR",
    "INVALID_PARAMS",
    "INVALID_REQUEST",
    "JSONRPC_VERSION",
    "METHOD_NOT_FOUND",
    "PARSE_ERROR",
    "SERVER_ERROR_MAX",
    "SERVER_ERROR_MIN",
    "Batch",
    "ErrorObject",
    "FrameDecodeError",
    "JsonRpcError",
    "JsonRpcProtocolError",
    "Message",
    "NDJSONFramer",
    "Notification",
    "Request",
    "RequestId",
    "Response",
    "StdioFramer",
    "decode_message",
    "encode_message",
    "parse_message",
    "parse_payload",
]
