from __future__ import annotations

import json
from typing import Any
from uuid import UUID

from platform_backend.db.pool import DatabasePool


class AssetWriter:
    def __init__(self, db: DatabasePool) -> None:
        self._db = db

    async def append_event(
        self,
        tenant_id: UUID,
        scan_id: UUID,
        event_type: str,
        payload: dict[str, Any],
    ) -> None:
        await self._db.execute(
            tenant_id,
            """
            INSERT INTO assets.collection_events (tenant_id, scan_id, event_type, payload)
            VALUES ($1, $2, $3, $4::jsonb)
            """,
            tenant_id,
            scan_id,
            event_type,
            json.dumps(payload),
        )

    async def insert_resources(
        self,
        tenant_id: UUID,
        resources: list[dict[str, Any]],
    ) -> int:
        if not resources:
            return 0
        inserted = 0
        for resource in resources:
            result = await self._db.execute(
                tenant_id,
                """
                INSERT INTO assets.resources (
                  tenant_id, scan_id, resource_id, resource_type, provider, provider_type,
                  integration_id, account_id, region, properties, tags,
                  collected_at, first_seen_at, last_seen_at
                ) VALUES (
                  $1, $2, $3, $4, $5, $6, $7, $8, $9, $10::jsonb, $11::jsonb,
                  $12, $13, $14
                )
                ON CONFLICT (tenant_id, scan_id, resource_id) DO NOTHING
                """,
                resource["tenant_id"],
                resource["scan_id"],
                resource["resource_id"],
                resource["resource_type"],
                resource["provider"],
                resource["provider_type"],
                resource["integration_id"],
                resource["account_id"],
                resource["region"],
                json.dumps(resource["properties"]),
                json.dumps(resource["tags"]),
                resource["collected_at"],
                resource["first_seen_at"],
                resource["last_seen_at"],
            )
            if result.endswith("1"):
                inserted += 1
        return inserted

    async def insert_relationships(
        self,
        tenant_id: UUID,
        scan_id: UUID,
        relationships: list[dict[str, Any]],
    ) -> int:
        if not relationships:
            return 0
        inserted = 0
        for rel in relationships:
            result = await self._db.execute(
                tenant_id,
                """
                INSERT INTO assets.relationships (
                  tenant_id, scan_id, from_resource_id, to_resource_id,
                  relationship_type, properties
                ) VALUES ($1, $2, $3, $4, $5, $6::jsonb)
                ON CONFLICT (tenant_id, scan_id, from_resource_id, to_resource_id, relationship_type)
                DO NOTHING
                """,
                tenant_id,
                scan_id,
                rel["from_resource_id"],
                rel["to_resource_id"],
                rel["relationship_type"],
                json.dumps(rel.get("properties", {})),
            )
            if result.endswith("1"):
                inserted += 1
        return inserted

    async def count_resources(self, tenant_id: UUID, scan_id: UUID) -> int:
        row = await self._db.fetchrow(
            tenant_id,
            "SELECT count(*) AS c FROM assets.resources WHERE tenant_id = $1 AND scan_id = $2",
            tenant_id,
            scan_id,
        )
        return int(row["c"]) if row else 0
