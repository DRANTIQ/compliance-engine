from __future__ import annotations

import json
from datetime import datetime
from typing import Any
from uuid import UUID

from platform_backend.db.pool import DatabasePool
from platform_backend.platform.models.scan import ScanStatus


class IntegrationRepository:
    def __init__(self, db: DatabasePool) -> None:
        self._db = db

    async def create_aws(
        self,
        tenant_id: UUID,
        *,
        account_id: str,
        role_arn: str,
        external_id_encrypted: str,
        regions: list[str],
    ) -> dict[str, Any]:
        row = await self._db.fetchrow(
            tenant_id,
            """
            INSERT INTO platform.integrations
              (tenant_id, provider, account_id, role_arn, external_id, regions)
            VALUES ($1, 'aws', $2, $3, $4, $5::jsonb)
            RETURNING id, tenant_id, provider, account_id, role_arn, regions, status,
                      azure_tenant_id, azure_client_id, created_at, updated_at
            """,
            tenant_id,
            account_id,
            role_arn,
            external_id_encrypted,
            json.dumps(regions),
        )
        assert row is not None
        return dict(row)

    async def create_azure(
        self,
        tenant_id: UUID,
        *,
        subscription_id: str,
        azure_tenant_id: str,
        azure_client_id: str,
        azure_client_secret_encrypted: str,
        locations: list[str],
    ) -> dict[str, Any]:
        row = await self._db.fetchrow(
            tenant_id,
            """
            INSERT INTO platform.integrations
              (tenant_id, provider, account_id, regions,
               azure_tenant_id, azure_client_id, azure_client_secret)
            VALUES ($1, 'azure', $2, $3::jsonb, $4, $5, $6)
            RETURNING id, tenant_id, provider, account_id, role_arn, regions, status,
                      azure_tenant_id, azure_client_id, created_at, updated_at
            """,
            tenant_id,
            subscription_id,
            json.dumps(locations),
            azure_tenant_id,
            azure_client_id,
            azure_client_secret_encrypted,
        )
        assert row is not None
        return dict(row)

    async def create(
        self,
        tenant_id: UUID,
        *,
        account_id: str,
        role_arn: str,
        external_id_encrypted: str,
        regions: list[str],
    ) -> dict[str, Any]:
        return await self.create_aws(
            tenant_id,
            account_id=account_id,
            role_arn=role_arn,
            external_id_encrypted=external_id_encrypted,
            regions=regions,
        )

    async def list(self, tenant_id: UUID) -> list[dict[str, Any]]:
        rows = await self._db.fetch(
            tenant_id,
            """
            SELECT id, tenant_id, provider, account_id, role_arn, regions, status,
                   azure_tenant_id, azure_client_id, created_at, updated_at
            FROM platform.integrations
            WHERE tenant_id = $1
            ORDER BY created_at DESC
            """,
            tenant_id,
        )
        return [dict(r) for r in rows]

    async def get(self, tenant_id: UUID, integration_id: UUID) -> dict[str, Any] | None:
        row = await self._db.fetchrow(
            tenant_id,
            """
            SELECT id, tenant_id, provider, account_id, role_arn, external_id, regions, status,
                   azure_tenant_id, azure_client_id, azure_client_secret,
                   created_at, updated_at
            FROM platform.integrations
            WHERE tenant_id = $1 AND id = $2
            """,
            tenant_id,
            integration_id,
        )
        return dict(row) if row else None

    async def update_status(
        self,
        tenant_id: UUID,
        integration_id: UUID,
        status: str,
    ) -> dict[str, Any] | None:
        row = await self._db.fetchrow(
            tenant_id,
            """
            UPDATE platform.integrations
            SET status = $3, updated_at = now()
            WHERE tenant_id = $1 AND id = $2
            RETURNING id, tenant_id, provider, account_id, role_arn, regions, status,
                      azure_tenant_id, azure_client_id, created_at, updated_at
            """,
            tenant_id,
            integration_id,
            status,
        )
        return dict(row) if row else None

    async def update_azure_client_secret(
        self,
        tenant_id: UUID,
        integration_id: UUID,
        *,
        azure_client_secret_encrypted: str,
        status: str = "active",
    ) -> dict[str, Any] | None:
        row = await self._db.fetchrow(
            tenant_id,
            """
            UPDATE platform.integrations
            SET azure_client_secret = $3,
                status = $4,
                updated_at = now()
            WHERE tenant_id = $1 AND id = $2 AND provider = 'azure'
            RETURNING id, tenant_id, provider, account_id, role_arn, regions, status,
                      azure_tenant_id, azure_client_id, created_at, updated_at
            """,
            tenant_id,
            integration_id,
            azure_client_secret_encrypted,
            status,
        )
        return dict(row) if row else None


class ScanRepository:
    def __init__(self, db: DatabasePool) -> None:
        self._db = db

    async def create(
        self,
        tenant_id: UUID,
        *,
        integration_id: UUID,
        account_id: str,
    ) -> dict[str, Any]:
        async with self._db.acquire() as conn:
            async with conn.transaction():
                await self._db.set_tenant(conn, tenant_id)
                scan_row = await conn.fetchrow(
                    """
                    INSERT INTO platform.scans (tenant_id, integration_id, status)
                    VALUES ($1, $2, $3)
                    RETURNING id, tenant_id, integration_id, status, trace_id,
                              started_at, completed_at, created_at, updated_at
                    """,
                    tenant_id,
                    integration_id,
                    ScanStatus.CREATED.value,
                )
                assert scan_row is not None
                run_row = await conn.fetchrow(
                    """
                    INSERT INTO platform.collection_runs
                      (tenant_id, scan_id, integration_id, account_id)
                    VALUES ($1, $2, $3, $4)
                    RETURNING id
                    """,
                    tenant_id,
                    scan_row["id"],
                    integration_id,
                    account_id,
                )
                assert run_row is not None
                result = dict(scan_row)
                result["collection_run_id"] = run_row["id"]
                return result

    async def update_status(
        self,
        tenant_id: UUID,
        scan_id: UUID,
        status: ScanStatus,
        *,
        error: dict[str, Any] | None = None,
        started: bool = False,
        completed: bool = False,
    ) -> dict[str, Any] | None:
        row = await self._db.fetchrow(
            tenant_id,
            """
            UPDATE platform.scans
            SET status = $3,
                error = COALESCE($4::jsonb, error),
                started_at = CASE WHEN $5 THEN COALESCE(started_at, now()) ELSE started_at END,
                completed_at = CASE WHEN $6 THEN now() ELSE completed_at END,
                updated_at = now()
            WHERE tenant_id = $1 AND id = $2
            RETURNING id, tenant_id, integration_id, status, trace_id, error,
                      started_at, completed_at, created_at, updated_at
            """,
            tenant_id,
            scan_id,
            status.value,
            json.dumps(error) if error else None,
            started,
            completed,
        )
        return dict(row) if row else None

    async def get(self, tenant_id: UUID, scan_id: UUID) -> dict[str, Any] | None:
        row = await self._db.fetchrow(
            tenant_id,
            """
            SELECT s.id, s.tenant_id, s.integration_id, s.status, s.trace_id, s.error,
                   s.started_at, s.completed_at, s.created_at, s.updated_at,
                   cr.account_id, cr.status AS collection_status,
                   i.provider
            FROM platform.scans s
            JOIN platform.collection_runs cr
              ON cr.scan_id = s.id AND cr.tenant_id = s.tenant_id
            JOIN platform.integrations i
              ON i.id = s.integration_id AND i.tenant_id = s.tenant_id
            WHERE s.tenant_id = $1 AND s.id = $2
            """,
            tenant_id,
            scan_id,
        )
        return dict(row) if row else None

    async def get_collection_run(
        self, tenant_id: UUID, scan_id: UUID
    ) -> dict[str, Any] | None:
        row = await self._db.fetchrow(
            tenant_id,
            """
            SELECT id, tenant_id, scan_id, integration_id, account_id, status,
                   manifest_s3_uri, resource_count, error, started_at, completed_at
            FROM platform.collection_runs
            WHERE tenant_id = $1 AND scan_id = $2
            """,
            tenant_id,
            scan_id,
        )
        return dict(row) if row else None

    async def update_collection_run(
        self,
        tenant_id: UUID,
        collection_run_id: UUID,
        *,
        status: str,
        manifest_s3_uri: str | None = None,
        resource_count: int | None = None,
        error: dict[str, Any] | None = None,
        started: bool = False,
        completed: bool = False,
    ) -> None:
        await self._db.execute(
            tenant_id,
            """
            UPDATE platform.collection_runs
            SET status = $3,
                manifest_s3_uri = COALESCE($4, manifest_s3_uri),
                resource_count = COALESCE($5, resource_count),
                error = COALESCE($6::jsonb, error),
                started_at = CASE WHEN $7 THEN COALESCE(started_at, now()) ELSE started_at END,
                completed_at = CASE WHEN $8 THEN now() ELSE completed_at END,
                updated_at = now()
            WHERE tenant_id = $1 AND id = $2
            """,
            tenant_id,
            collection_run_id,
            status,
            manifest_s3_uri,
            resource_count,
            json.dumps(error) if error else None,
            started,
            completed,
        )

    async def list_collection_events(
        self, tenant_id: UUID, scan_id: UUID
    ) -> list[dict[str, Any]]:
        rows = await self._db.fetch(
            tenant_id,
            """
            SELECT id, event_type, payload, created_at
            FROM assets.collection_events
            WHERE tenant_id = $1 AND scan_id = $2
            ORDER BY created_at ASC
            """,
            tenant_id,
            scan_id,
        )
        return [dict(r) for r in rows]

    async def list(
        self,
        tenant_id: UUID,
        *,
        limit: int = 50,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        rows = await self._db.fetch(
            tenant_id,
            """
            SELECT id, tenant_id, integration_id, status, trace_id,
                   started_at, completed_at, created_at, updated_at
            FROM platform.scans
            WHERE tenant_id = $1
            ORDER BY created_at DESC
            LIMIT $2 OFFSET $3
            """,
            tenant_id,
            limit,
            offset,
        )
        return [dict(r) for r in rows]
