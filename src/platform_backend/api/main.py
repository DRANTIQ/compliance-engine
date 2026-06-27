from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from platform_backend.api.routes import assets, compliance, findings, health, integrations, me, scans
from platform_backend.config.settings import get_settings
from platform_backend.db.pool import DatabasePool
from platform_backend.queue.redis_client import close_redis_client, create_redis_client

logger = logging.getLogger(__name__)


def configure_logging() -> None:
    settings = get_settings()
    level = getattr(logging, settings.log_level.upper(), logging.INFO)
    logging.basicConfig(level=level)
    if settings.log_format == "json":
        for handler in logging.root.handlers:
            handler.setFormatter(
                logging.Formatter(
                    '{"time":"%(asctime)s","level":"%(levelname)s","logger":"%(name)s","message":"%(message)s"}'
                )
            )


@asynccontextmanager
async def lifespan(app: FastAPI):
    configure_logging()
    settings = get_settings()
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
    app = FastAPI(
        title="Platform V2 API",
        version="0.5.0",
        description="Phase 4 prep — identity abstraction, inventory, policy, findings, compliance API",
        lifespan=lifespan,
    )
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
    app.include_router(health.router)
    app.include_router(me.router)
    app.include_router(integrations.router)
    app.include_router(scans.router)
    app.include_router(assets.router)
    app.include_router(findings.router)
    app.include_router(compliance.router)
    return app


app = create_app()
