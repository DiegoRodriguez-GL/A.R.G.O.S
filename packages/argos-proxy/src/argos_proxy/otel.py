"""OpenTelemetry instrumentation for the audit proxy.

Every (request, response) pair becomes a span tagged with:

- ``argos.correlation_id``: the proxy's internal envelope id.
- ``argos.method``: JSON-RPC method name.
- ``argos.direction``: ``client_to_upstream`` / ``upstream_to_client``.
- ``argos.client_request_id``: the JSON-RPC ``id`` field, stringified.

The interceptor :class:`OtelTracingInterceptor` slots into the
:class:`ChainInterceptor`. It owns its own tracer; the operator can
replace it via ``set_tracer_provider`` before constructing the
interceptor.

OpenTelemetry is optional at runtime: if no tracer provider is
installed the interceptor still works -- spans are recorded against
the default no-op provider and can be safely ignored.
"""

from __future__ import annotations

import time
from typing import Final

from opentelemetry import trace
from opentelemetry.trace import SpanKind, Status, StatusCode, Tracer

from argos_proxy.interceptor import InterceptContext, ProxyInterceptor
from argos_proxy.jsonrpc import Notification, Request, Response

#: Tracer name reported on every span. Keep in sync with the package.
_TRACER_NAME: Final[str] = "argos.proxy"


class OtelTracingInterceptor(ProxyInterceptor):
    """Emit OTel spans for every observed JSON-RPC message.

    Span lifecycle:

    - ``on_request_in`` -> opens span with kind=CLIENT.
    - ``on_response_out`` -> opens span with kind=SERVER (the
      upstream is the "server" from the proxy's point of view).
    - ``on_notification`` -> opens span with kind=PRODUCER.

    Spans are short-lived; they end immediately after the hook returns.
    A future iteration could correlate request and response into a
    single span via the correlation_id; for the M5 milestone the
    one-span-per-message form is enough for grafana / jaeger inspection.
    """

    detector_id = "argos.proxy.otel"

    def __init__(self, tracer: Tracer | None = None) -> None:
        self._tracer = tracer or trace.get_tracer(_TRACER_NAME)

    async def on_request_in(
        self,
        request: Request,
        ctx: InterceptContext,
    ) -> None:
        with self._tracer.start_as_current_span(
            f"jsonrpc.request:{request.method}",
            kind=SpanKind.CLIENT,
        ) as span:
            self._tag(span, ctx, request.method, "client_to_upstream")
            span.set_attribute("argos.client_request_id", str(request.id))
            span.set_status(Status(StatusCode.OK))

    async def on_response_out(
        self,
        response: Response,
        ctx: InterceptContext,
    ) -> None:
        with self._tracer.start_as_current_span(
            "jsonrpc.response",
            kind=SpanKind.SERVER,
        ) as span:
            self._tag(span, ctx, None, "upstream_to_client")
            span.set_attribute("argos.client_request_id", str(response.id))
            if response.is_error and response.error is not None:
                span.set_attribute("argos.error.code", response.error.code)
                span.set_attribute("argos.error.message", response.error.message)
                span.set_status(Status(StatusCode.ERROR, response.error.message))
            else:
                span.set_status(Status(StatusCode.OK))

    async def on_notification(
        self,
        notification: Notification,
        ctx: InterceptContext,
        *,
        from_client: bool,
    ) -> None:
        direction = "client_to_upstream" if from_client else "upstream_to_client"
        with self._tracer.start_as_current_span(
            f"jsonrpc.notification:{notification.method}",
            kind=SpanKind.PRODUCER,
        ) as span:
            self._tag(span, ctx, notification.method, direction)
            span.set_status(Status(StatusCode.OK))

    @staticmethod
    def _tag(
        span: trace.Span,
        ctx: InterceptContext,
        method: str | None,
        direction: str,
    ) -> None:
        span.set_attribute("argos.correlation_id", ctx.correlation_id)
        if method is not None:
            span.set_attribute("argos.method", method)
        span.set_attribute("argos.direction", direction)
        span.set_attribute("argos.received_at", ctx.received_at)
        span.set_attribute("argos.elapsed_ms", (time.monotonic() - ctx.received_at) * 1000)
