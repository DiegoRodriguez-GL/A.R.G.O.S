"""Tests for :class:`OtelTracingInterceptor` using the in-memory span
exporter so we can introspect the spans the interceptor records."""

from __future__ import annotations

import pytest
from argos_proxy import (
    InterceptContext,
    Notification,
    Request,
    Response,
)
from argos_proxy.interceptor import new_correlation_id
from argos_proxy.otel import OtelTracingInterceptor
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

pytestmark = pytest.mark.asyncio


@pytest.fixture
def exporter_and_tracer() -> tuple[InMemorySpanExporter, OtelTracingInterceptor]:
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    tracer = provider.get_tracer("argos.proxy.test")
    return exporter, OtelTracingInterceptor(tracer)


def _ctx() -> InterceptContext:
    return InterceptContext(
        correlation_id=new_correlation_id(),
        received_at=0.0,
        client_request_id=None,
    )


class TestSpans:
    async def test_request_emits_client_span(self, exporter_and_tracer) -> None:  # type: ignore[no-untyped-def]
        exporter, interceptor = exporter_and_tracer
        await interceptor.on_request_in(Request(method="tools/list", id=1), _ctx())
        spans = exporter.get_finished_spans()
        assert len(spans) == 1
        assert spans[0].name == "jsonrpc.request:tools/list"
        attrs = dict(spans[0].attributes or {})
        assert attrs.get("argos.method") == "tools/list"
        assert attrs.get("argos.direction") == "client_to_upstream"

    async def test_success_response_emits_ok_span(self, exporter_and_tracer) -> None:  # type: ignore[no-untyped-def]
        exporter, interceptor = exporter_and_tracer
        await interceptor.on_response_out(Response(result=42, id=1), _ctx())
        spans = exporter.get_finished_spans()
        assert spans[0].name == "jsonrpc.response"
        assert spans[0].status.status_code.name == "OK"

    async def test_error_response_marks_span_error(self, exporter_and_tracer) -> None:  # type: ignore[no-untyped-def]
        exporter, interceptor = exporter_and_tracer
        from argos_proxy.jsonrpc import ErrorObject

        err = ErrorObject(code=-32601, message="Method not found")
        await interceptor.on_response_out(Response(error=err, id=1), _ctx())
        span = exporter.get_finished_spans()[0]
        attrs = dict(span.attributes or {})
        assert attrs.get("argos.error.code") == -32601
        assert "Method not found" in (attrs.get("argos.error.message") or "")
        assert span.status.status_code.name == "ERROR"

    async def test_notification_span_kind_is_producer(self, exporter_and_tracer) -> None:  # type: ignore[no-untyped-def]
        exporter, interceptor = exporter_and_tracer
        await interceptor.on_notification(
            Notification(method="initialized"),
            _ctx(),
            from_client=True,
        )
        span = exporter.get_finished_spans()[0]
        assert span.kind.name == "PRODUCER"
        assert span.name == "jsonrpc.notification:initialized"

    async def test_correlation_id_attached_to_every_span(self, exporter_and_tracer) -> None:  # type: ignore[no-untyped-def]
        exporter, interceptor = exporter_and_tracer
        ctx = _ctx()
        await interceptor.on_request_in(Request(method="m", id=1), ctx)
        await interceptor.on_response_out(Response(result=None, id=1), ctx)
        spans = exporter.get_finished_spans()
        assert all(
            (span.attributes or {}).get("argos.correlation_id") == ctx.correlation_id
            for span in spans
        )

    async def test_default_tracer_when_none_passed(self) -> None:
        # No tracer argument: falls back to global provider; should not raise.
        interceptor = OtelTracingInterceptor()
        await interceptor.on_request_in(Request(method="m", id=1), _ctx())
