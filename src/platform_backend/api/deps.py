from __future__ import annotations

from fastapi import Depends, Request

from platform_backend.config.settings import Settings, get_settings
from platform_backend.db.pool import DatabasePool
from platform_backend.identity.deps import get_principal, get_tenant_id, require_write_access
from platform_backend.identity.models import PlatformPrincipal
from platform_backend.platform.services.scan_service import IntegrationService, ScanService
import redis.asyncio as redis

__all__ = [
    "get_db_pool",
    "get_redis",
    "get_settings_dep",
    "get_tenant_id",
    "get_principal",
    "require_write_access",
    "get_scan_service",
    "get_integration_service",
]


async def get_db_pool(request: Request) -> DatabasePool:
    pool: DatabasePool = request.app.state.db_pool
    return pool


async def get_redis(request: Request) -> redis.Redis:
    client: redis.Redis = request.app.state.redis
    return client


def get_settings_dep() -> Settings:
    return get_settings()


async def get_scan_service(
    db: DatabasePool = Depends(get_db_pool),
    redis_client: redis.Redis = Depends(get_redis),
    settings: Settings = Depends(get_settings_dep),
) -> ScanService:
    return ScanService(db, redis_client, settings)


async def get_integration_service(
    db: DatabasePool = Depends(get_db_pool),
    settings: Settings = Depends(get_settings_dep),
) -> IntegrationService:
    return IntegrationService(db, settings)
