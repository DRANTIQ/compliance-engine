from __future__ import annotations

import logging
from uuid import UUID

import redis.asyncio as redis

from platform_backend.config.settings import Settings, get_settings

logger = logging.getLogger(__name__)


async def create_redis_client(settings: Settings | None = None) -> redis.Redis:
    cfg = settings or get_settings()
    client: redis.Redis = redis.from_url(cfg.redis_url, decode_responses=True)
    await client.ping()
    return client


async def close_redis_client(client: redis.Redis) -> None:
    await client.aclose()
