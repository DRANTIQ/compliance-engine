from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any
from uuid import UUID

import redis.asyncio as redis


async def publish_policy_evaluate(
    redis_client: redis.Redis,
    queue_key: str,
    *,
    tenant_id: UUID,
    scan_id: UUID,
    payload: dict[str, Any] | None = None,
) -> None:
    envelope = {
        "event_type": "policy.evaluate",
        "tenant_id": str(tenant_id),
        "scan_id": str(scan_id),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "payload": payload or {},
    }
    await redis_client.lpush(queue_key, json.dumps(envelope))
