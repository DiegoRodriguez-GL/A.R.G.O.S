"""OpenTelemetry bootstrap. No exporter is wired by default (privacy first)."""

from __future__ import annotations

import os
from functools import lru_cache

from opentelemetry import trace
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider

_SERVICE_NAME = "argos"


@lru_cache(maxsize=1)
def _build_provider() -> TracerProvider:
    resource = Resource.create(
        {
            "service.name": os.environ.get("OTEL_SERVICE_NAME", _SERVICE_NAME),
            "service.namespace": "argos",
        },
    )
    return TracerProvider(resource=resource)


def init_telemetry() -> trace.Tracer:
    """Idempotent. Returns the ARGOS tracer."""
    provider = _build_provider()
    trace.set_tracer_provider(provider)
    return trace.get_tracer("argos")
