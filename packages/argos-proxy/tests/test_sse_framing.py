"""WHATWG SSE parser tests.

Edge cases: multiple data lines, comments, retry hints, partial events,
\\r vs \\n vs \\r\\n line endings, NUL in id."""

from __future__ import annotations

import pytest
from argos_proxy.jsonrpc.sse_framing import (
    MAX_EVENT_BYTES,
    SseEventParser,
    SseProtocolError,
    encode_sse_event,
)


class TestParser:
    def test_simple_event(self) -> None:
        p = SseEventParser()
        out = p.feed(b"data: hello\n\n")
        assert len(out) == 1
        assert out[0].event == "message"
        assert out[0].data == "hello"

    def test_multi_data_line_concatenates(self) -> None:
        p = SseEventParser()
        out = p.feed(b"data: line1\ndata: line2\n\n")
        assert out[0].data == "line1\nline2"

    def test_named_event(self) -> None:
        p = SseEventParser()
        out = p.feed(b"event: heartbeat\ndata: ping\n\n")
        assert out[0].event == "heartbeat"
        assert out[0].data == "ping"

    def test_id_field(self) -> None:
        p = SseEventParser()
        out = p.feed(b"id: 42\ndata: x\n\n")
        assert out[0].id == "42"

    def test_id_with_nul_dropped(self) -> None:
        p = SseEventParser()
        out = p.feed(b"id: 4\x002\ndata: x\n\n")
        assert out[0].id is None

    def test_retry_field(self) -> None:
        p = SseEventParser()
        out = p.feed(b"retry: 5000\ndata: x\n\n")
        assert out[0].retry == 5000

    def test_retry_non_digit_ignored(self) -> None:
        p = SseEventParser()
        out = p.feed(b"retry: not-a-number\ndata: x\n\n")
        assert out[0].retry is None

    def test_comment_ignored(self) -> None:
        p = SseEventParser()
        out = p.feed(b": this is a comment\ndata: x\n\n")
        assert out[0].data == "x"

    def test_crlf_line_endings(self) -> None:
        p = SseEventParser()
        out = p.feed(b"data: a\r\ndata: b\r\n\r\n")
        assert out[0].data == "a\nb"

    def test_lone_cr_line_endings(self) -> None:
        # The streaming parser holds a trailing lone CR because it
        # might be the start of \r\n. flush() resolves the ambiguity
        # by treating it as a real terminator on stream end.
        p = SseEventParser()
        out = p.feed(b"data: a\rdata: b\r\r")
        out += p.flush()
        assert len(out) == 1
        assert out[0].data == "a\nb"

    def test_split_crlf_across_feeds_not_misinterpreted(self) -> None:
        # Adversarial: a TCP segment can split \r\n across feed calls.
        # The parser must NOT treat the trailing \r as a terminator
        # before the \n arrives; otherwise we lose data.
        p = SseEventParser()
        assert p.feed(b"data: hello\r") == []
        out = p.feed(b"\n\n")
        assert len(out) == 1
        assert out[0].data == "hello"

    def test_flush_on_empty_buffer_noop(self) -> None:
        p = SseEventParser()
        assert p.flush() == []
        # And after a clean event, flush stays a no-op.
        p.feed(b"data: x\n\n")
        assert p.flush() == []

    def test_empty_event_with_no_data_yields_nothing(self) -> None:
        p = SseEventParser()
        out = p.feed(b"\n\n\n")
        assert out == []

    def test_field_only_no_value(self) -> None:
        p = SseEventParser()
        out = p.feed(b"data\n\n")
        # Per spec: 'data' field with empty value -> data buffer == "".
        assert out[0].data == ""

    def test_streaming_partial_event(self) -> None:
        p = SseEventParser()
        assert p.feed(b"data: hel") == []
        assert p.feed(b"lo\n") == []
        out = p.feed(b"\n")
        assert out[0].data == "hello"

    def test_multiple_events_in_one_chunk(self) -> None:
        p = SseEventParser()
        out = p.feed(b"data: a\n\ndata: b\n\ndata: c\n\n")
        assert [e.data for e in out] == ["a", "b", "c"]

    def test_buffer_overflow_raises(self) -> None:
        p = SseEventParser()
        # Feed > MAX_EVENT_BYTES without a blank line.
        chunk = b"data: " + b"x" * 4096 + b"\n"
        with pytest.raises(SseProtocolError):
            for _ in range(MAX_EVENT_BYTES // 4096 + 4):
                p.feed(chunk)

    def test_value_after_colon_no_space_accepted(self) -> None:
        # Spec: ONE optional space after the colon. No space means
        # the value starts immediately.
        p = SseEventParser()
        out = p.feed(b"data:hello\n\n")
        assert out[0].data == "hello"

    def test_value_with_unicode(self) -> None:
        p = SseEventParser()
        out = p.feed("data: ñü€\n\n".encode())
        assert out[0].data == "ñü€"

    def test_invalid_utf8_replaced(self) -> None:
        p = SseEventParser()
        out = p.feed(b"data: \xff\xfe junk\n\n")
        # Replacement chars used; parser does not crash.
        assert out
        assert "junk" in out[0].data


class TestEncoder:
    def test_minimal(self) -> None:
        out = encode_sse_event("hi")
        assert out == b"data: hi\n\n"

    def test_with_event_name(self) -> None:
        out = encode_sse_event("pong", event="ping")
        assert out == b"event: ping\ndata: pong\n\n"

    def test_with_id_and_retry(self) -> None:
        out = encode_sse_event("x", id_="abc", retry_ms=2500)
        assert b"id: abc" in out
        assert b"retry: 2500" in out

    def test_multiline_data_split(self) -> None:
        out = encode_sse_event("line1\nline2")
        assert out == b"data: line1\ndata: line2\n\n"

    def test_event_with_newline_rejected(self) -> None:
        with pytest.raises(ValueError):
            encode_sse_event("x", event="bad\nname")

    def test_id_with_newline_rejected(self) -> None:
        with pytest.raises(ValueError):
            encode_sse_event("x", id_="bad\nid")

    def test_id_with_nul_rejected(self) -> None:
        with pytest.raises(ValueError):
            encode_sse_event("x", id_="bad\x00id")

    def test_negative_retry_rejected(self) -> None:
        with pytest.raises(ValueError):
            encode_sse_event("x", retry_ms=-1)


class TestRoundTrip:
    def test_encoder_to_parser_round_trip(self) -> None:
        out = encode_sse_event("hello world", event="message", id_="42")
        parser = SseEventParser()
        events = parser.feed(out)
        assert len(events) == 1
        e = events[0]
        assert e.event == "message"
        assert e.data == "hello world"
        assert e.id == "42"

    def test_burst_of_events_round_trip(self) -> None:
        wire = b"".join(encode_sse_event(f"msg-{i}", id_=str(i)) for i in range(10))
        parser = SseEventParser()
        events = parser.feed(wire)
        assert len(events) == 10
        assert [e.data for e in events] == [f"msg-{i}" for i in range(10)]
        assert [e.id for e in events] == [str(i) for i in range(10)]
