import hashlib
import json
import time
import uuid
from collections import deque

from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.core.config import Settings


class SecurityHeadersMiddleware:
    """Pure ASGI middleware injecting X-Request-ID and baseline security headers."""

    def __init__(self, app: ASGIApp, settings: Settings) -> None:
        self.app = app
        self.settings = settings

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request_id: str | None = None
        for key, value in scope.get("headers") or []:
            if key.decode("latin-1").lower() == "x-request-id":
                candidate = value.decode("latin-1", errors="ignore").strip()[:128]
                if candidate:
                    request_id = candidate
                    break
        resolved_id = request_id or str(uuid.uuid4())

        async def send_wrapper(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = list(message.get("headers") or [])
                existing = {k.lower() for k, _ in headers}

                def _set_header(name: bytes, val: bytes) -> None:
                    if name.lower() not in existing:
                        headers.append((name, val))
                        existing.add(name.lower())

                _set_header(b"x-request-id", resolved_id.encode("latin-1"))
                _set_header(b"x-content-type-options", b"nosniff")
                _set_header(b"x-frame-options", b"DENY")
                _set_header(b"referrer-policy", b"strict-origin-when-cross-origin")
                _set_header(
                    b"permissions-policy",
                    b"camera=(), microphone=(), geolocation=()",
                )
                if self.settings.app_env.strip().lower() == "production":
                    _set_header(
                        b"strict-transport-security",
                        b"max-age=31536000; includeSubDomains",
                    )
                message = {**message, "headers": headers}
            await send(message)

        await self.app(scope, receive, send_wrapper)


class RateLimitMiddleware:
    """Pure ASGI sliding-window per-client rate limiter for API routes."""

    def __init__(self, app: ASGIApp, settings: Settings) -> None:
        self.app = app
        self.settings = settings
        self._buckets: dict[str, deque[float]] = {}
        self._window_seconds = 60.0

    def _client_key(self, scope: Scope) -> str:
        headers = {
            k.decode("latin-1").lower(): v.decode("latin-1", errors="ignore")
            for k, v in (scope.get("headers") or [])
        }
        auth = headers.get("authorization", "").strip()
        if auth:
            digest = hashlib.sha256(auth.encode("utf-8")).hexdigest()[:16]
            return f"tok:{digest}"
        forwarded = headers.get("x-forwarded-for", "").split(",")[0].strip()
        if forwarded:
            return f"ip:{forwarded}"
        client = scope.get("client")
        if client and isinstance(client, tuple | list) and client[0]:
            return f"ip:{client[0]}"
        return "ip:local"

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or not self.settings.rate_limit_enabled:
            await self.app(scope, receive, send)
            return

        path = str(scope.get("path") or "")
        health_prefix = f"{self.settings.api_v1_prefix}/health"
        if path.startswith(health_prefix):
            await self.app(scope, receive, send)
            return

        limit = max(1, self.settings.rate_limit_requests_per_minute)
        key = self._client_key(scope)
        now = time.monotonic()
        bucket = self._buckets.setdefault(key, deque())
        cutoff = now - self._window_seconds
        while bucket and bucket[0] <= cutoff:
            bucket.popleft()

        if len(bucket) >= limit:
            retry_after = max(1, int(self._window_seconds - (now - bucket[0])) + 1)
            body = json.dumps({"detail": "Rate limit exceeded. Try again shortly."}).encode("utf-8")
            await send(
                {
                    "type": "http.response.start",
                    "status": 429,
                    "headers": [
                        (b"content-type", b"application/json"),
                        (b"retry-after", str(retry_after).encode("ascii")),
                        (b"x-ratelimit-limit", str(limit).encode("ascii")),
                        (b"x-ratelimit-remaining", b"0"),
                    ],
                }
            )
            await send({"type": "http.response.body", "body": body})
            return

        bucket.append(now)
        remaining = max(0, limit - len(bucket))

        async def send_wrapper(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = list(message.get("headers") or [])
                headers.append((b"x-ratelimit-limit", str(limit).encode("ascii")))
                headers.append((b"x-ratelimit-remaining", str(remaining).encode("ascii")))
                message = {**message, "headers": headers}
            await send(message)

        await self.app(scope, receive, send_wrapper)
