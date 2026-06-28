"""Security headers and optional API rate limiting."""

from __future__ import annotations

import logging
import time
from collections import defaultdict
from typing import Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

logger = logging.getLogger(__name__)

SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
    "Cache-Control": "no-store",
}


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        response = await call_next(request)
        for key, value in SECURITY_HEADERS.items():
            if key not in response.headers:
                response.headers[key] = value
        return response


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Per-IP fixed-window rate limit (single-instance EC2). Uses Redis when available."""

    def __init__(self, app, *, limit_per_minute: int = 120) -> None:
        super().__init__(app)
        self._limit = max(limit_per_minute, 1)
        self._local: dict[str, tuple[int, float]] = defaultdict(lambda: (0, 0.0))

    def _client_ip(self, request: Request) -> str:
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(",")[0].strip()
        if request.client:
            return request.client.host
        return "unknown"

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        if request.url.path in {"/health", "/ready", "/openapi.json"}:
            return await call_next(request)

        ip = self._client_ip(request)
        window = int(time.time() // 60)
        key = f"ratelimit:{ip}:{window}"

        count = await self._increment(request, key)
        if count > self._limit:
            logger.warning("rate limit exceeded", extra={"client_ip": ip, "path": request.url.path})
            return JSONResponse(
                status_code=429,
                content={"detail": "rate limit exceeded"},
                headers={"Retry-After": "60"},
            )

        response = await call_next(request)
        response.headers["X-RateLimit-Limit"] = str(self._limit)
        response.headers["X-RateLimit-Remaining"] = str(max(0, self._limit - count))
        return response

    async def _increment(self, request: Request, key: str) -> int:
        redis_client = getattr(request.app.state, "redis", None)
        if redis_client is not None:
            try:
                pipe = redis_client.pipeline()
                pipe.incr(key)
                pipe.expire(key, 120)
                results = await pipe.execute()
                return int(results[0])
            except Exception:
                logger.debug("redis rate limit fallback to memory")

        window = int(time.time() // 60)
        ip_key = key.rsplit(":", 1)[0]
        count, stored_window = self._local[ip_key]
        if stored_window != window:
            count, stored_window = 0, float(window)
        count += 1
        self._local[ip_key] = (count, stored_window)
        return count
