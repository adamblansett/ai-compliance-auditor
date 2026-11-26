import time
import uuid

import structlog
from opentelemetry import trace
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.core.config import Settings

logger = structlog.get_logger(__name__)


class TelemetryMiddleware:
    """Pure ASGI OpenTelemetry span & structured latency instrumentation."""

    def __init__(self, app: ASGIApp, settings: Settings) -> None:
        self.app = app
        self.settings = settings
        self._tracer = trace.get_tracer(settings.otel_service_name)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or not self.settings.otel_enabled:
            await self.app(scope, receive, send)
            return

        method = str(scope.get("method") or "GET")
        path = str(scope.get("path") or "/")
        start = time.perf_counter()
        status_code = 500

        with self._tracer.start_as_current_span(f"{method} {path}") as span:
            span.set_attribute("http.method", method)
            span.set_attribute("http.target", path)
            span_ctx = span.get_span_context()
            trace_id = (
                f"{span_ctx.trace_id:032x}"
                if span_ctx is not None and span_ctx.trace_id
                else uuid.uuid4().hex
            )

            async def send_wrapper(message: Message) -> None:
                nonlocal status_code
                if message["type"] == "http.response.start":
                    status_code = int(message.get("status", 200))
                    headers = list(message.get("headers") or [])
                    headers.append((b"x-trace-id", trace_id.encode("ascii")))
                    message = {**message, "headers": headers}
                await send(message)

            try:
                await self.app(scope, receive, send_wrapper)
            finally:
                duration_ms = round((time.perf_counter() - start) * 1000.0, 2)
                span.set_attribute("http.status_code", status_code)
                logger.info(
                    "http_request_completed",
                    method=method,
                    path=path,
                    status_code=status_code,
                    duration_ms=duration_ms,
                    trace_id=trace_id,
                )
