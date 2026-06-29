from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from platform_backend.api.middleware.observability import RequestObservabilityMiddleware, SanitizeFilter
from platform_backend.api.middleware.security import RateLimitMiddleware, SecurityHeadersMiddleware
from platform_backend.api.openapi import API_DESCRIPTION, configure_openapi
from platform_backend.api.routes import (
    admin,
    assets,
    billing,
    compliance,
    docs_redirect,
    findings,
    health,
    integrations,
    invitations,
    me,
    policies,
    scans,
    workspaces,
)
from platform_backend.config.settings import get_settings
from platform_backend.db.pool import DatabasePool
from platform_backend.queue.redis_client import close_redis_client, create_redis_client

logger = logging.getLogger(__name__)


def configure_logging() -> None:
    settings = get_settings()
    level = getattr(logging, settings.log_level.upper(), logging.INFO)
    logging.basicConfig(level=level)
    sanitize = SanitizeFilter()
    for handler in logging.root.handlers:
        handler.addFilter(sanitize)
        if settings.log_format == "json":
            handler.setFormatter(
                logging.Formatter(
                    '{"time":"%(asctime)s","level":"%(levelname)s","logger":"%(name)s","message":"%(message)s"}'
                )
            )


def _init_sentry(dsn: str) -> None:
    if not dsn.strip():
        return
    try:
        import sentry_sdk

        sentry_sdk.init(dsn=dsn, traces_sample_rate=0.1)
        logger.info("sentry initialized")
    except ImportError:
        logger.warning("SENTRY_DSN set but sentry-sdk not installed")


@asynccontextmanager
async def lifespan(app: FastAPI):
    configure_logging()
    settings = get_settings()
    _init_sentry(settings.sentry_dsn)
    db_pool = await DatabasePool.create(settings)
    redis_client = await create_redis_client(settings)
    app.state.db_pool = db_pool
    app.state.redis = redis_client
    logger.info("platform-backend started", extra={"port": settings.api_port})
    try:
        yield
    finally:
        await close_redis_client(redis_client)
        await db_pool.close()


def create_app() -> FastAPI:
    settings = get_settings()
    docs_url = "/docs" if settings.api_docs_enabled else None
    redoc_url = "/redoc" if settings.api_docs_enabled else None
    openapi_url = "/openapi.json" if settings.api_docs_enabled else None

    app = FastAPI(
        title="Platform V2 API",
        version="0.5.0",
        description=API_DESCRIPTION,
        lifespan=lifespan,
        docs_url=docs_url,
        redoc_url=redoc_url,
        openapi_url=openapi_url,
        swagger_ui_parameters={
            "docExpansion": "list",
            "filter": True,
            "tryItOutEnabled": True,
            "persistAuthorization": True,
        },
    )
    configure_openapi(app)
    app.add_middleware(RequestObservabilityMiddleware)
    app.add_middleware(RateLimitMiddleware, limit_per_minute=settings.rate_limit_per_minute)
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origin_list,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=[
            "X-Tenant-ID",
            "X-Role",
            "X-Subject",
            "X-Email",
            "Content-Type",
            "Authorization",
        ],
    )
    app.include_router(docs_redirect.router)
    app.include_router(health.router)
    app.include_router(me.router)
    app.include_router(workspaces.router)
    app.include_router(invitations.router)
    app.include_router(billing.router)
    app.include_router(integrations.router)
    app.include_router(scans.router)
    app.include_router(assets.router)
    app.include_router(findings.router)
    app.include_router(policies.router)
    app.include_router(compliance.router)
    app.include_router(admin.router)
    return app


app = create_app()
