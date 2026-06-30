from __future__ import annotations

import json
import logging
from typing import Any
from uuid import UUID, uuid4

import redis.asyncio as redis

from platform_backend.config.settings import Settings, get_settings
from platform_backend.db.pool import DatabasePool
from platform_backend.platform.models.scan import ScanStatus, assert_transition
from platform_backend.platform.repositories.integrations import IntegrationRepository, ScanRepository
from platform_backend.security.external_id import decrypt_external_id

logger = logging.getLogger(__name__)


class ScanService:
    def __init__(
        self,
        db: DatabasePool,
        redis_client: redis.Redis,
        settings: Settings | None = None,
    ) -> None:
        self._db = db
        self._redis = redis_client
        self._settings = settings or get_settings()
        self._integrations = IntegrationRepository(db)
        self._scans = ScanRepository(db)

    async def create_scan(self, tenant_id: UUID, integration_id: UUID) -> dict[str, Any]:
        integration = await self._integrations.get(tenant_id, integration_id)
        if not integration:
            raise LookupError("integration not found")
        if integration["status"] != "active":
            raise ValueError("integration is not active")

        scan = await self._scans.create(
            tenant_id,
            integration_id=integration_id,
            account_id=integration["account_id"],
        )
        scan_id = scan["id"]

        assert_transition(ScanStatus.CREATED, ScanStatus.QUEUED)
        queued = await self._scans.update_status(tenant_id, scan_id, ScanStatus.QUEUED, started=True)
        assert queued is not None

        job = self._build_collection_job(tenant_id, integration, scan)
        await self._redis.lpush(self._settings.collect_queue_key, json.dumps(job))

        logger.info(
            "scan queued",
            extra={
                "tenant_id": str(tenant_id),
                "scan_id": str(scan_id),
                "trace_id": str(queued["trace_id"]),
            },
        )
        return self._public_scan(queued)

    def _build_collection_job(
        self,
        tenant_id: UUID,
        integration: dict[str, Any],
        scan: dict[str, Any],
    ) -> dict[str, Any]:
        regions = integration["regions"]
        if isinstance(regions, str):
            regions = json.loads(regions)

        external_id = decrypt_external_id(integration["external_id"])
        scan_id = scan["id"]
        account_id = integration["account_id"]
        prefix = (
            f"{self._settings.s3_prefix}/tenants/{tenant_id}/scans/{scan_id}/aws/{account_id}"
        )

        return {
            "job_id": str(uuid4()),
            "scan_id": str(scan_id),
            "tenant_id": str(tenant_id),
            "integration_id": str(integration["id"]),
            "collection_run_id": str(scan["collection_run_id"]),
            "account_id": account_id,
            "role_arn": integration["role_arn"],
            "external_id": external_id,
            "regions": regions,
            "s3_bucket": self._settings.s3_bucket,
            "s3_prefix": prefix,
            "trace_id": str(scan["trace_id"]),
            "plugins": [
                "aws.iam",
                "aws.s3",
                "aws.ec2",
                "aws.database",
                "aws.efs",
                "aws.logging",
                "aws.network",
                "aws.lambda",
                "aws.guardduty",
                "aws.ebs",
                "aws.compute",
            ],
        }

    @staticmethod
    def _public_scan(row: dict[str, Any]) -> dict[str, Any]:
        return {
            "id": str(row["id"]),
            "tenant_id": str(row["tenant_id"]),
            "integration_id": str(row["integration_id"]),
            "status": row["status"],
            "trace_id": str(row["trace_id"]),
            "started_at": row["started_at"].isoformat() if row.get("started_at") else None,
            "completed_at": row["completed_at"].isoformat() if row.get("completed_at") else None,
            "created_at": row["created_at"].isoformat(),
            "updated_at": row["updated_at"].isoformat(),
        }

    async def get_scan(self, tenant_id: UUID, scan_id: UUID) -> dict[str, Any] | None:
        row = await self._scans.get(tenant_id, scan_id)
        if not row:
            return None
        return self._public_scan_detail(row)

    async def list_scans(self, tenant_id: UUID, *, limit: int = 50, offset: int = 0) -> list[dict[str, Any]]:
        rows = await self._scans.list(tenant_id, limit=limit, offset=offset)
        return [self._public_scan(r) for r in rows]

    async def get_scan_timeline(self, tenant_id: UUID, scan_id: UUID) -> list[dict[str, Any]] | None:
        scan = await self._scans.get(tenant_id, scan_id)
        if not scan:
            return None
        events = await self._scans.list_collection_events(tenant_id, scan_id)
        timeline = [
            {
                "stage": "scan",
                "status": scan["status"],
                "at": scan["updated_at"].isoformat() if scan.get("updated_at") else None,
            }
        ]
        for event in events:
            payload = event["payload"]
            if isinstance(payload, str):
                payload = json.loads(payload)
            timeline.append(
                {
                    "stage": event["event_type"],
                    "status": payload.get("status") if isinstance(payload, dict) else None,
                    "at": event["created_at"].isoformat(),
                    "payload": payload,
                }
            )
        return timeline

    @staticmethod
    def _public_scan_detail(row: dict[str, Any]) -> dict[str, Any]:
        base = ScanService._public_scan(row)
        base["account_id"] = row["account_id"]
        base["collection_status"] = row["collection_status"]
        if row.get("error"):
            err = row["error"]
            base["error"] = err if isinstance(err, dict) else json.loads(err)
        return base


class IntegrationService:
    def __init__(self, db: DatabasePool, settings: Settings | None = None) -> None:
        self._db = db
        self._settings = settings or get_settings()
        self._repo = IntegrationRepository(db)

    async def register_aws(
        self,
        tenant_id: UUID,
        *,
        account_id: str,
        role_arn: str,
        external_id: str,
        regions: list[str],
    ) -> dict[str, Any]:
        if not regions:
            raise ValueError("regions must not be empty")
        encrypted = encrypt_external_id_safe(external_id)
        row = await self._repo.create(
            tenant_id,
            account_id=account_id,
            role_arn=role_arn,
            external_id_encrypted=encrypted,
            regions=regions,
        )
        return self._public_integration(row)

    async def list(self, tenant_id: UUID) -> list[dict[str, Any]]:
        rows = await self._repo.list(tenant_id)
        return [self._public_integration(r) for r in rows]

    @staticmethod
    def _public_integration(row: dict[str, Any]) -> dict[str, Any]:
        regions = row["regions"]
        if isinstance(regions, str):
            regions = json.loads(regions)
        return {
            "id": str(row["id"]),
            "tenant_id": str(row["tenant_id"]),
            "provider": row["provider"],
            "account_id": row["account_id"],
            "role_arn": row["role_arn"],
            "regions": regions,
            "status": row["status"],
            "created_at": row["created_at"].isoformat(),
            "updated_at": row["updated_at"].isoformat(),
        }


def encrypt_external_id_safe(plaintext: str) -> str:
    from platform_backend.security.external_id import encrypt_external_id

    return encrypt_external_id(plaintext)
