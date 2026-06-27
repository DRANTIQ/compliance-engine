from __future__ import annotations

import logging
from typing import Any
from uuid import UUID

import asyncpg

from platform_backend.config.settings import Settings, get_settings

logger = logging.getLogger(__name__)


class DatabasePool:
    def __init__(self, pool: asyncpg.Pool) -> None:
        self._pool = pool

    @classmethod
    async def create(cls, settings: Settings | None = None) -> DatabasePool:
        cfg = settings or get_settings()
        pool = await asyncpg.create_pool(
            dsn=cfg.database_url,
            min_size=1,
            max_size=10,
            command_timeout=30,
            statement_cache_size=0,
        )
        return cls(pool)

    async def close(self) -> None:
        await self._pool.close()

    async def ping(self) -> bool:
        async with self._pool.acquire() as conn:
            await conn.fetchval("SELECT 1")
        return True

    async def set_tenant(self, conn: asyncpg.Connection, tenant_id: UUID) -> None:
        await conn.execute("SELECT platform.set_tenant($1::uuid)", tenant_id)

    def acquire(self) -> asyncpg.pool.PoolAcquireContext:
        return self._pool.acquire()

    async def fetch(self, tenant_id: UUID, query: str, *args: Any) -> list[asyncpg.Record]:
        async with self._pool.acquire() as conn:
            async with conn.transaction():
                await self.set_tenant(conn, tenant_id)
                return await conn.fetch(query, *args)

    async def fetchrow(self, tenant_id: UUID, query: str, *args: Any) -> asyncpg.Record | None:
        async with self._pool.acquire() as conn:
            async with conn.transaction():
                await self.set_tenant(conn, tenant_id)
                return await conn.fetchrow(query, *args)

    async def execute(self, tenant_id: UUID, query: str, *args: Any) -> str:
        async with self._pool.acquire() as conn:
            async with conn.transaction():
                await self.set_tenant(conn, tenant_id)
                return await conn.execute(query, *args)

    async def executemany(self, tenant_id: UUID, query: str, args: list[tuple[Any, ...]]) -> None:
        async with self._pool.acquire() as conn:
            async with conn.transaction():
                await self.set_tenant(conn, tenant_id)
                await conn.executemany(query, args)

    async def fetch_global(self, query: str, *args: Any) -> list[asyncpg.Record]:
        async with self._pool.acquire() as conn:
            return await conn.fetch(query, *args)

    async def fetchrow_global(self, query: str, *args: Any) -> asyncpg.Record | None:
        async with self._pool.acquire() as conn:
            return await conn.fetchrow(query, *args)
