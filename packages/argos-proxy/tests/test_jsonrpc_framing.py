"""Wire framing tests for JSON-RPC 2.0 over stdio (Content-Length) and
NDJSON. Every adversarial input the proxy might see from a hostile
client or upstream is exercised here."""

from __future__ import annotations

import pytest
from argos_proxy import Request
from argos_proxy.jsonrpc.framing import (
    MAX_HEADER_BYTES,
    MAX_MESSAGE_BYTES,
    FrameDecodeError,
    NDJSONFramer,
    StdioFramer,
    decode_message,
    encode_message,
)

# ---------------------------------------------------------------------------
# encode_message
# ---------------------------------------------------------------------------


class TestEncodeMessage:
    def test_ndjson_appends_newline(self) -> None:
        req = Request(method="m", id=1)
        out = encode_message(req, framing="ndjson")
        assert out.endswith(b"\n")
        assert b"\n" not in out[:-1]

    def test_stdio_emits_content_length_header(self) -> None:
        req = Request(method="m", id=1)
        out = encode_message(req, framing="stdio")
        assert out.startswith(b"Content-Length: ")
        assert b"\r\n\r\n" in out

    def test_stdio_header_length_matches_body(self) -> None:
        req = Request(method="tools/list", id="abc")
        out = encode_message(req, framing="stdio")
        header, _, body = out.partition(b"\r\n\r\n")
        # Header is ASCII; pull the integer.
        decl = int(header.split(b": ", 1)[1])
        assert decl == len(body)

    def test_unknown_framing_raises(self) -> None:
        with pytest.raises(ValueError, match="unsupported framing"):
            encode_message({"k": "v"}, framing="msgpack")

    def test_dict_payload_serialises(self) -> None:
        out = encode_message({"jsonrpc": "2.0", "method": "m"}, framing="ndjson")
        assert b'"jsonrpc":"2.0"' in out

    def test_unicode_round_trip(self) -> None:
        out = encode_message({"k": "ñü€"}, framing="ndjson")
        # ensure_ascii=False -> non-ASCII bytes preserved
        assert "ñ".encode() in out

    def test_oversized_payload_rejected(self) -> None:
        big = {"k": "x" * (MAX_MESSAGE_BYTES + 1)}
        with pytest.raises(FrameDecodeError, match="exceeds"):
            encode_message(big, framing="ndjson")


# ---------------------------------------------------------------------------
# decode_message: single-shot
# ---------------------------------------------------------------------------


class TestDecodeMessage:
    def test_ndjson_strips_lf(self) -> None:
        assert decode_message(b'{"a":1}\n', framing="ndjson") == b'{"a":1}'

    def test_ndjson_strips_crlf(self) -> None:
        assert decode_message(b'{"a":1}\r\n', framing="ndjson") == b'{"a":1}'

    def test_ndjson_no_terminator_passthrough(self) -> None:
        # Last line in a file may not have a newline.
        assert decode_message(b'{"a":1}', framing="ndjson") == b'{"a":1}'

    def test_stdio_decodes_minimal_frame(self) -> None:
        body = b'{"a":1}'
        frame = b"Content-Length: 7\r\n\r\n" + body
        assert decode_message(frame, framing="stdio") == body

    def test_stdio_decodes_with_extra_headers(self) -> None:
        body = b'{"a":1}'
        frame = (
            b"Content-Type: application/vscode-jsonrpc; charset=utf-8\r\n"
            b"Content-Length: 7\r\n\r\n" + body
        )
        assert decode_message(frame, framing="stdio") == body

    def test_stdio_header_name_is_case_insensitive(self) -> None:
        body = b"{}"
        frame = b"content-length: 2\r\n\r\n" + body
        assert decode_message(frame, framing="stdio") == body

    def test_stdio_rejects_missing_separator(self) -> None:
        with pytest.raises(FrameDecodeError, match="CRLF CRLF"):
            decode_message(b"Content-Length: 7\r\n", framing="stdio")

    def test_stdio_rejects_missing_content_length(self) -> None:
        with pytest.raises(FrameDecodeError, match="missing Content-Length"):
            decode_message(b"X-Other: 1\r\n\r\n{}", framing="stdio")

    def test_stdio_rejects_duplicate_content_length(self) -> None:
        # Critical desync attack: two Content-Length headers cause the
        # proxy and upstream to disagree on message boundaries.
        frame = b"Content-Length: 2\r\nContent-Length: 7\r\n\r\n{}"
        with pytest.raises(FrameDecodeError, match="duplicate"):
            decode_message(frame, framing="stdio")

    def test_stdio_rejects_negative_content_length(self) -> None:
        # The is-digit check rejects '-' upfront; this confirms the
        # behaviour from the public surface rather than relying on
        # internal helpers.
        with pytest.raises(FrameDecodeError, match="non-numeric"):
            decode_message(b"Content-Length: -1\r\n\r\n{}", framing="stdio")

    def test_stdio_rejects_oversized_length_claim(self) -> None:
        oversized = MAX_MESSAGE_BYTES + 1
        frame = f"Content-Length: {oversized}\r\n\r\n".encode() + b"x"
        with pytest.raises(FrameDecodeError, match="outside"):
            decode_message(frame, framing="stdio")

    def test_stdio_rejects_length_mismatch(self) -> None:
        with pytest.raises(FrameDecodeError, match="declared"):
            decode_message(b"Content-Length: 5\r\n\r\n{}", framing="stdio")

    def test_stdio_rejects_malformed_header_line(self) -> None:
        # No colon after the header name.
        with pytest.raises(FrameDecodeError, match="malformed"):
            decode_message(b"NoColonHere\r\nContent-Length: 2\r\n\r\n{}", framing="stdio")

    def test_stdio_rejects_oversized_header_section(self) -> None:
        # Build a header section that exceeds MAX_HEADER_BYTES *before*
        # the CRLF CRLF appears.
        padding = b"X-Filler: " + b"x" * (MAX_HEADER_BYTES + 100) + b"\r\n"
        frame = padding + b"Content-Length: 2\r\n\r\n{}"
        with pytest.raises(FrameDecodeError, match="header"):
            decode_message(frame, framing="stdio")


# ---------------------------------------------------------------------------
# Streaming framers.
# ---------------------------------------------------------------------------


class TestNDJSONFramer:
    def test_emits_one_body_per_newline(self) -> None:
        f = NDJSONFramer()
        out = f.feed(b'{"a":1}\n{"b":2}\n')
        assert out == [b'{"a":1}', b'{"b":2}']
        assert f.buffered_bytes() == 0

    def test_holds_partial_message_until_newline(self) -> None:
        f = NDJSONFramer()
        assert f.feed(b'{"a":') == []
        assert f.buffered_bytes() == 5
        assert f.feed(b"1}\n") == [b'{"a":1}']
        assert f.buffered_bytes() == 0

    def test_handles_multiple_chunks(self) -> None:
        f = NDJSONFramer()
        f.feed(b"{")
        f.feed(b'"a":1')
        f.feed(b"}")
        out = f.feed(b"\n")
        assert out == [b'{"a":1}']

    def test_strips_optional_cr_before_lf(self) -> None:
        f = NDJSONFramer()
        out = f.feed(b'{"a":1}\r\n')
        assert out == [b'{"a":1}']

    def test_buffer_overflow_is_capped(self) -> None:
        f = NDJSONFramer()
        # Feed > MAX_MESSAGE_BYTES without ever sending a newline.
        chunk = b"x" * 1024
        with pytest.raises(FrameDecodeError, match="newline"):
            for _ in range(MAX_MESSAGE_BYTES // 1024 + 2):
                f.feed(chunk)


class TestStdioFramer:
    def test_emits_one_body_per_complete_frame(self) -> None:
        f = StdioFramer()
        body1 = b'{"a":1}'
        body2 = b'{"b":22}'
        chunk = b"Content-Length: 7\r\n\r\n" + body1 + b"Content-Length: 8\r\n\r\n" + body2
        out = f.feed(chunk)
        assert out == [body1, body2]
        assert f.buffered_bytes() == 0

    def test_holds_partial_frame_across_chunks(self) -> None:
        f = StdioFramer()
        body = b'{"hello":"world"}'
        header = f"Content-Length: {len(body)}\r\n\r\n".encode()
        # Split mid-header.
        f.feed(header[:8])
        f.feed(header[8:])
        # Body in two chunks.
        f.feed(body[:5])
        out = f.feed(body[5:])
        assert out == [body]
        assert f.buffered_bytes() == 0

    def test_partial_body_remains_buffered(self) -> None:
        f = StdioFramer()
        body = b"x" * 100
        header = f"Content-Length: {len(body)}\r\n\r\n".encode()
        f.feed(header)
        f.feed(body[:50])
        # Only half the body received -> nothing emitted.
        out = f.feed(b"")
        assert out == []
        out = f.feed(body[50:])
        assert out == [body]

    def test_oversized_header_section_is_rejected(self) -> None:
        f = StdioFramer()
        # Feed > MAX_HEADER_BYTES of header without the CRLF CRLF.
        with pytest.raises(FrameDecodeError, match="header"):
            f.feed(b"X-Filler: " + b"y" * (MAX_HEADER_BYTES + 100))


# ---------------------------------------------------------------------------
# Round-trip property: encode -> decode -> equality.
# ---------------------------------------------------------------------------


class TestRoundTrip:
    @pytest.mark.parametrize("framing", ["ndjson", "stdio"])
    def test_request_round_trip(self, framing: str) -> None:
        req = Request(method="tools/call", params={"name": "x"}, id=42)
        wire = encode_message(req, framing=framing)
        body = decode_message(wire, framing=framing)
        assert body.decode("utf-8") == req.model_dump_json()

    @pytest.mark.parametrize("framing", ["ndjson", "stdio"])
    def test_unicode_round_trip(self, framing: str) -> None:
        payload = {"jsonrpc": "2.0", "method": "m", "params": {"text": "ñü€😀"}, "id": 1}
        wire = encode_message(payload, framing=framing)
        body = decode_message(wire, framing=framing)
        # Round-trip through JSON to compare structurally.
        import json

        assert json.loads(body.decode("utf-8")) == payload
