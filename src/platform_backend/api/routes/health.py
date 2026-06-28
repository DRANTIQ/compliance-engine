from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status

from platform_backend.api.deps import get_db_pool, get_redis
from platform_backend.db.pool import DatabasePool
import redis.asyncio as redis

router = APIRouter(tags=["health"])


@router.get(
    "/health",
    summary="Liveness probe",
    description="Returns `healthy` if the API process is running. Used by load balancers and k8s liveness checks. **No auth.**",
    responses={200: {"description": "API process is alive"}},
)
async def health() -> dict[str, str]:
    return {"status": "healthy"}


@router.get(
    "/ready",
    summary="Readiness probe",
    description=(
        "Checks Postgres and Redis connectivity. Returns 503 if either dependency is down. "
        "Use before running E2E tests. **No auth.**"
    ),
    responses={
        200: {"description": "Postgres and Redis reachable"},
        503: {"description": "Database or Redis unavailable"},
    },
)
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
