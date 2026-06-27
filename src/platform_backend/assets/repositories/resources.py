from __future__ import annotations

import json
from typing import Any
from uuid import UUID

from platform_backend.db.pool import DatabasePool


class AssetRepository:
    def __init__(self, db: DatabasePool) -> None:
        self._db = db

    async def list(
        self,
        tenant_id: UUID,
        scan_id: UUID,
        *,
        resource_type: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        if resource_type:
            rows = await self._db.fetch(
                tenant_id,
                """
                SELECT resource_id, resource_type, provider, provider_type, account_id, region,
                       properties, tags, collected_at, ingested_at
                FROM assets.resources
                WHERE tenant_id = $1 AND scan_id = $2 AND resource_type = $3
                ORDER BY resource_id
                LIMIT $4 OFFSET $5
                """,
                tenant_id,
                scan_id,
                resource_type,
                limit,
                offset,
            )
        else:
            rows = await self._db.fetch(
                tenant_id,
                """
                SELECT resource_id, resource_type, provider, provider_type, account_id, region,
                       properties, tags, collected_at, ingested_at
                FROM assets.resources
                WHERE tenant_id = $1 AND scan_id = $2
                ORDER BY resource_type, resource_id
                LIMIT $3 OFFSET $4
                """,
                tenant_id,
                scan_id,
                limit,
                offset,
            )
        return [self._public(r) for r in rows]

    async def get(
        self,
        tenant_id: UUID,
        scan_id: UUID,
        resource_id: str,
    ) -> dict[str, Any] | None:
        row = await self._db.fetchrow(
            tenant_id,
            """
            SELECT resource_id, resource_type, provider, provider_type, account_id, region,
                   properties, tags, collected_at, ingested_at
            FROM assets.resources
            WHERE tenant_id = $1 AND scan_id = $2 AND resource_id = $3
            """,
            tenant_id,
            scan_id,
            resource_id,
        )
        return self._public(row) if row else None

    async def list_relationships(
        self,
        tenant_id: UUID,
        scan_id: UUID,
        resource_id: str,
    ) -> list[dict[str, Any]]:
        rows = await self._db.fetch(
            tenant_id,
            """
            SELECT from_resource_id, to_resource_id, relationship_type, properties, created_at
            FROM assets.relationships
            WHERE tenant_id = $1 AND scan_id = $2
              AND (from_resource_id = $3 OR to_resource_id = $3)
            ORDER BY relationship_type
            """,
            tenant_id,
            scan_id,
            resource_id,
        )
        return [
            {
                "from_resource_id": r["from_resource_id"],
                "to_resource_id": r["to_resource_id"],
                "relationship_type": r["relationship_type"],
                "properties": r["properties"] if isinstance(r["properties"], dict) else json.loads(r["properties"]),
                "created_at": r["created_at"].isoformat(),
            }
            for r in rows
        ]

    async def search(
        self,
        tenant_id: UUID,
        scan_id: UUID,
        *,
        q: str | None = None,
        resource_type: str | None = None,
        tag_key: str | None = None,
        tag_value: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        clauses = ["tenant_id = $1", "scan_id = $2"]
        params: list[Any] = [tenant_id, scan_id]
        idx = 3

        if q:
            clauses.append(
                f"(resource_id ILIKE ${idx} OR properties::text ILIKE ${idx} OR tags::text ILIKE ${idx})"
            )
            params.append(f"%{q}%")
            idx += 1
        if resource_type:
            clauses.append(f"resource_type = ${idx}")
            params.append(resource_type)
            idx += 1
        if tag_key:
            if tag_value is not None:
                clauses.append(f"tags ->> ${idx} = ${idx + 1}")
                params.extend([tag_key, tag_value])
                idx += 2
            else:
                clauses.append(f"tags ? ${idx}")
                params.append(tag_key)
                idx += 1

        params.extend([limit, offset])
        query = f"""
            SELECT resource_id, resource_type, provider, provider_type, account_id, region,
                   properties, tags, collected_at, ingested_at
            FROM assets.resources
            WHERE {" AND ".join(clauses)}
            ORDER BY resource_type, resource_id
            LIMIT ${idx} OFFSET ${idx + 1}
        """
        rows = await self._db.fetch(tenant_id, query, *params)
        return [self._public(r) for r in rows]

    @staticmethod
    def _public(row: Any) -> dict[str, Any]:
        props = row["properties"]
        tags = row["tags"]
        return {
            "resource_id": row["resource_id"],
            "resource_type": row["resource_type"],
            "provider": row["provider"],
            "provider_type": row["provider_type"],
            "account_id": row["account_id"],
            "region": row["region"],
            "properties": props if isinstance(props, dict) else json.loads(props),
            "tags": tags if isinstance(tags, dict) else json.loads(tags),
            "collected_at": row["collected_at"].isoformat(),
            "ingested_at": row["ingested_at"].isoformat(),
        }
