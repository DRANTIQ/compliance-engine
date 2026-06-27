from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status

from platform_backend.api.deps import get_db_pool, get_redis
from platform_backend.db.pool import DatabasePool
import redis.asyncio as redis

router = APIRouter(tags=["health"])


@router.get("/health")
async def health() -> dict[str, str]:
    return {"status": "healthy"}


@router.get("/ready")
async def ready(
    db: DatabasePool = Depends(get_db_pool),
    redis_client: redis.Redis = Depends(get_redis),
) -> dict[str, str]:
    try:
        await db.ping()
        await redis_client.ping()
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"dependency unavailable: {exc.__class__.__name__}",
        ) from exc
    return {"status": "ready"}
