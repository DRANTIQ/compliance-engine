"""Request timing, audit trail, and log sanitization."""

from __future__ import annotations

import logging
import re
import time
from typing import Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

logger = logging.getLogger(__name__)

AUDIT_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})

_SENSITIVE_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"(?i)(authorization|password|secret|token|api[_-]?key)\s*[:=]\s*\S+"), r"\1=***"),
    (re.compile(r"postgresql://[^\s]+"), "postgresql://***"),
    (re.compile(r"Bearer\s+[A-Za-z0-9\-._~+/]+=*"), "Bearer ***"),
]


class SanitizeFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        msg = record.getMessage()
        for pattern, repl in _SENSITIVE_PATTERNS:
            msg = pattern.sub(repl, msg)
        record.msg = msg
        record.args = ()
        return True


class RequestObservabilityMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        start = time.perf_counter()
        response = await call_next(request)
        duration_ms = round((time.perf_counter() - start) * 1000, 2)

        if request.url.path not in {"/health", "/ready"}:
            logger.info(
                "http_request",
                extra={
                    "method": request.method,
                    "path": request.url.path,
                    "status": response.status_code,
                    "duration_ms": duration_ms,
                    "client_ip": request.headers.get("X-Forwarded-For", request.client.host if request.client else ""),
                },
            )

        if request.method in AUDIT_METHODS and request.url.path.startswith("/v1/"):
            logger.info(
                "audit",
                extra={
                    "method": request.method,
                    "path": request.url.path,
                    "status": response.status_code,
                    "duration_ms": duration_ms,
                    "tenant_id": request.headers.get("X-Tenant-ID", ""),
                    "subject": request.headers.get("X-Subject", ""),
                },
            )

        response.headers["X-Response-Time-Ms"] = str(duration_ms)
        return response
