"""Unit tests for the HTTP/1.1 framing layer.

Spec compliance + adversarial inputs (smuggling vectors, malformed
headers, oversized chunks, partial bodies).
"""

from __future__ import annotations

import pytest
from argos_proxy.jsonrpc.framing import MAX_MESSAGE_BYTES
from argos_proxy.jsonrpc.http_framing import (
    MAX_CHUNK_BYTES,
    MAX_HTTP_HEADER_BYTES,
    ChunkedDecoder,
    Headers,
    HttpProtocolError,
    encode_chunk,
    encode_chunk_terminator,
    encode_request,
    encode_response,
    parse_request,
    parse_request_head,
    parse_response,
    parse_response_head,
)

# ---------------------------------------------------------------------------
# Headers.
# ---------------------------------------------------------------------------


class TestHeaders:
    def test_canonicalise_on_add(self) -> None:
        h = Headers()
        h.add("content-type", "application/json")
        h.add("CONTENT-LENGTH", "12")
        out = h.encode()
        assert b"Content-Type: application/json" in out
        assert b"Content-Length: 12" in out

    def test_get_case_insensitive(self) -> None:
        h = Headers()
        h.add("X-Custom", "v")
        assert h.get("x-CUSTOM") == "v"
        assert h.get_all("X-Custom") == ["v"]

    def test_repeated_header_returned_in_order(self) -> None:
        h = Headers()
        h.add("Set-Cookie", "a=1")
        h.add("set-cookie", "b=2")
        assert h.get_all("Set-Cookie") == ["a=1", "b=2"]

    def test_has(self) -> None:
        h = Headers()
        assert not h.has("Foo")
        h.add("Foo", "bar")
        assert h.has("foo")


# ---------------------------------------------------------------------------
# encode_request.
# ---------------------------------------------------------------------------


class TestEncodeRequest:
    def test_minimal_get(self) -> None:
        out = encode_request("GET", "/mcp", host="example.com")
        assert out.startswith(b"GET /mcp HTTP/1.1\r\n")
        assert b"Host: example.com" in out
        assert out.endswith(b"\r\n\r\n")

    def test_post_auto_content_length(self) -> None:
        body = b'{"jsonrpc":"2.0"}'
        out = encode_request("POST", "/mcp", body=body, host="example.com")
        assert b"Content-Length: 17" in out
        assert out.endswith(body)

    def test_explicit_content_length_not_overridden(self) -> None:
        h = Headers()
        h.add("Content-Length", "0")
        out = encode_request("POST", "/m", headers=h, body=b"X", host="ex.com")
        # When the caller declared Content-Length, encoder respects it.
        assert b"Content-Length: 0\r\n" in out

    def test_invalid_method_raises(self) -> None:
        with pytest.raises(ValueError, match="unsupported HTTP method"):
            encode_request("FOO", "/x")

    def test_path_must_start_with_slash(self) -> None:
        with pytest.raises(ValueError, match="path"):
            encode_request("GET", "no-slash")


# ---------------------------------------------------------------------------
# encode_response.
# ---------------------------------------------------------------------------


class TestEncodeResponse:
    def test_status_200_ok(self) -> None:
        out = encode_response(200, "OK")
        assert out.startswith(b"HTTP/1.1 200 OK\r\n")
        assert out.endswith(b"\r\n\r\n")

    def test_with_body_auto_content_length(self) -> None:
        out = encode_response(202, "Accepted", body=b"hi")
        assert b"Content-Length: 2\r\n" in out
        assert out.endswith(b"hi")

    def test_invalid_status_rejected(self) -> None:
        with pytest.raises(ValueError):
            encode_response(99, "x")
        with pytest.raises(ValueError):
            encode_response(600, "x")


# ---------------------------------------------------------------------------
# parse_request: spec compliance.
# ---------------------------------------------------------------------------


class TestParseRequest:
    def test_minimal_post(self) -> None:
        wire = b"POST /m HTTP/1.1\r\nHost: x\r\nContent-Length: 2\r\n\r\nhi"
        r = parse_request(wire)
        assert r.method == "POST"
        assert r.path == "/m"
        assert r.body == b"hi"

    def test_get_no_body(self) -> None:
        wire = b"GET /sse HTTP/1.1\r\nHost: x\r\n\r\n"
        r = parse_request(wire)
        assert r.method == "GET"
        assert r.body == b""

    def test_method_normalised_uppercase(self) -> None:
        wire = b"post /m HTTP/1.1\r\nHost: x\r\n\r\n"
        r = parse_request(wire)
        assert r.method == "POST"

    def test_unsupported_version_rejected(self) -> None:
        wire = b"GET /m HTTP/2.0\r\nHost: x\r\n\r\n"
        with pytest.raises(HttpProtocolError):
            parse_request(wire)

    def test_missing_separator_raises(self) -> None:
        with pytest.raises(HttpProtocolError, match="CRLF CRLF"):
            parse_request(b"GET /m HTTP/1.1\r\nHost: x\r\n")

    def test_oversized_header_section_raises(self) -> None:
        # Build a fake big head section (just under the cap is OK).
        padding = b"X-Pad: " + b"y" * (MAX_HTTP_HEADER_BYTES + 1) + b"\r\n"
        wire = b"GET /m HTTP/1.1\r\n" + padding + b"\r\n"
        with pytest.raises(HttpProtocolError, match="header section"):
            parse_request(wire)


# ---------------------------------------------------------------------------
# Smuggling defences.
# ---------------------------------------------------------------------------


class TestSmugglingDefences:
    def test_conflicting_content_length_rejected(self) -> None:
        wire = b"POST /m HTTP/1.1\r\nHost: x\r\nContent-Length: 2\r\nContent-Length: 7\r\n\r\nhi"
        with pytest.raises(HttpProtocolError, match="conflicting"):
            parse_request(wire)

    def test_duplicate_content_length_same_value_accepted(self) -> None:
        # Servers DO sometimes legitimately echo CL twice with the
        # same value (RFC 7230 §3.3.2 allows). We accept it.
        wire = b"POST /m HTTP/1.1\r\nHost: x\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\nhi"
        r = parse_request(wire)
        assert r.body == b"hi"

    def test_cl_and_te_chunked_simultaneously_rejected(self) -> None:
        wire = (
            b"POST /m HTTP/1.1\r\n"
            b"Host: x\r\n"
            b"Content-Length: 2\r\n"
            b"Transfer-Encoding: chunked\r\n"
            b"\r\n"
            b"hi"
        )
        with pytest.raises(HttpProtocolError, match="mutually exclusive"):
            parse_request(wire)

    def test_negative_content_length_rejected(self) -> None:
        wire = b"POST /m HTTP/1.1\r\nHost: x\r\nContent-Length: -1\r\n\r\n"
        with pytest.raises(HttpProtocolError):
            parse_request(wire)

    def test_oversized_content_length_rejected(self) -> None:
        wire = (
            b"POST /m HTTP/1.1\r\nHost: x\r\nContent-Length: "
            + str(MAX_MESSAGE_BYTES + 1).encode("ascii")
            + b"\r\n\r\n"
        )
        with pytest.raises(HttpProtocolError):
            parse_request(wire)


# ---------------------------------------------------------------------------
# parse_response.
# ---------------------------------------------------------------------------


class TestParseResponse:
    def test_minimal_200(self) -> None:
        wire = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
        r = parse_response(wire)
        assert r.status == 200
        assert r.reason == "OK"
        assert r.body == b""

    def test_no_reason_phrase(self) -> None:
        wire = b"HTTP/1.1 204 \r\nContent-Length: 0\r\n\r\n"
        r = parse_response(wire)
        assert r.status == 204

    def test_response_head_parser(self) -> None:
        head = b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\n"
        h = parse_response_head(head)
        assert h.status == 200
        assert h.headers.get("Content-Type") == "text/event-stream"


class TestParseRequestHead:
    def test_minimal_post_head(self) -> None:
        head = b"POST /m HTTP/1.1\r\nHost: x\r\nContent-Length: 99\r\n"
        r = parse_request_head(head)
        assert r.method == "POST"
        assert r.path == "/m"
        assert r.headers.get("Content-Length") == "99"
        assert r.body == b""

    def test_strips_separator_if_present(self) -> None:
        head = b"GET /m HTTP/1.1\r\nHost: x\r\n\r\n"
        r = parse_request_head(head)
        assert r.method == "GET"

    def test_smuggling_defences_still_apply(self) -> None:
        # Two conflicting Content-Length headers must still be rejected
        # by the head parser even though it does not validate the body.
        head = b"POST /m HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\nContent-Length: 7\r\n"
        with pytest.raises(HttpProtocolError, match="conflicting"):
            parse_request_head(head)


# ---------------------------------------------------------------------------
# ChunkedDecoder.
# ---------------------------------------------------------------------------


class TestChunkedDecoder:
    def test_single_chunk(self) -> None:
        d = ChunkedDecoder()
        out = d.feed(b"5\r\nhello\r\n0\r\n\r\n")
        assert out == [b"hello"]
        assert d.at_eof

    def test_multiple_chunks(self) -> None:
        d = ChunkedDecoder()
        out = d.feed(b"3\r\nabc\r\n4\r\ndefg\r\n0\r\n\r\n")
        assert out == [b"abc", b"defg"]
        assert d.at_eof

    def test_chunk_extension_ignored(self) -> None:
        d = ChunkedDecoder()
        # Hex size + ; foo=bar.
        out = d.feed(b"3;name=value\r\nabc\r\n0\r\n\r\n")
        assert out == [b"abc"]

    def test_streaming_partial_chunk(self) -> None:
        d = ChunkedDecoder()
        assert d.feed(b"5\r\nhe") == []
        assert d.feed(b"llo\r\n0") == [b"hello"]
        out = d.feed(b"\r\n\r\n")
        assert out == []
        assert d.at_eof

    def test_oversized_chunk_rejected(self) -> None:
        too_big = MAX_CHUNK_BYTES + 1
        d = ChunkedDecoder()
        with pytest.raises(HttpProtocolError, match="outside"):
            d.feed(f"{too_big:x}\r\n".encode("ascii"))

    def test_malformed_chunk_size_rejected(self) -> None:
        d = ChunkedDecoder()
        with pytest.raises(HttpProtocolError, match="chunk size"):
            d.feed(b"zz\r\n")

    def test_oversized_size_line_rejected(self) -> None:
        d = ChunkedDecoder()
        # Feed > 32 bytes without a CRLF.
        with pytest.raises(HttpProtocolError):
            d.feed(b"a" * 33)

    def test_chunk_data_must_be_followed_by_crlf(self) -> None:
        d = ChunkedDecoder()
        with pytest.raises(HttpProtocolError, match="CRLF"):
            d.feed(b"3\r\nabcXX")  # 'XX' instead of \r\n


# ---------------------------------------------------------------------------
# Round-trip.
# ---------------------------------------------------------------------------


class TestRoundTrip:
    def test_request_round_trip(self) -> None:
        body = b'{"jsonrpc":"2.0","method":"tools/list","id":1}'
        wire = encode_request(
            "POST",
            "/mcp",
            headers=Headers([("Content-Type", "application/json")]),
            body=body,
            host="example.com:8765",
        )
        r = parse_request(wire)
        assert r.method == "POST"
        assert r.body == body
        assert r.headers.get("Content-Type") == "application/json"
        assert r.headers.get("Host") == "example.com:8765"

    def test_chunked_encode_decode(self) -> None:
        chunks = [b"hello ", b"world", b"!"]
        wire = b"".join(encode_chunk(c) for c in chunks) + encode_chunk_terminator()
        d = ChunkedDecoder()
        out = d.feed(wire)
        assert out == chunks
        assert d.at_eof
