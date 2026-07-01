from __future__ import annotations

import asyncio
import json
import logging
from typing import Any
from uuid import UUID

import redis.asyncio as redis

from platform_backend.assets.ingest.normalizer import normalize_bronze
from platform_backend.assets.ingest.s3_reader import SnapshotReader
from platform_backend.assets.ingest.writer import AssetWriter
from platform_backend.config.settings import Settings, get_settings
from platform_backend.db.pool import DatabasePool
from platform_backend.platform.models.scan import ScanStatus
from platform_backend.platform.repositories.integrations import ScanRepository
from platform_backend.platform.services.scan_service import IntegrationService
from platform_backend.queue.events import publish_policy_evaluate
from platform_backend.queue.redis_client import close_redis_client, create_redis_client

logger = logging.getLogger(__name__)


class IngestWorker:
    def __init__(
        self,
        db: DatabasePool,
        redis_client: redis.Redis,
        settings: Settings | None = None,
    ) -> None:
        self._db = db
        self._redis = redis_client
        self._settings = settings or get_settings()
        self._scans = ScanRepository(db)
        self._integrations = IntegrationService(db, self._settings)
        self._writer = AssetWriter(db)
        self._reader = SnapshotReader(self._settings)

    async def run_forever(self) -> None:
        logger.info("ingest worker listening on %s", self._settings.platform_events_key)
        while True:
            item = await self._redis.brpop(self._settings.platform_events_key, timeout=5)
            if not item:
                continue
            _, raw = item
            try:
                envelope = json.loads(raw)
                await self.handle_event(envelope)
            except Exception:
                logger.exception("failed to handle event")

    async def handle_event(self, envelope: dict[str, Any]) -> None:
        event_type = envelope["event_type"]
        tenant_id = UUID(envelope["tenant_id"])
        scan_id = UUID(envelope["scan_id"])
        payload = envelope.get("payload", {})

        await self._writer.append_event(tenant_id, scan_id, event_type, payload)

        if event_type == "collection.started":
            run_id = UUID(payload["collection_run_id"])
            await self._set_scan_status(tenant_id, scan_id, ScanStatus.COLLECTING)
            await self._scans.update_collection_run(
                tenant_id, run_id, status="running", started=True
            )
            return

        if event_type == "collection.failed":
            run_id = UUID(payload["collection_run_id"])
            await self._scans.update_status(
                tenant_id,
                scan_id,
                ScanStatus.FAILED,
                error=payload.get("error"),
                completed=True,
            )
            await self._scans.update_collection_run(
                tenant_id,
                run_id,
                status="failed",
                error=payload.get("error"),
                completed=True,
            )
            await self._maybe_mark_integration_invalid(tenant_id, scan_id, payload)
            await self._writer.append_event(
                tenant_id,
                scan_id,
                "scan.completed",
                {
                    "status": ScanStatus.FAILED.value,
                    "error": payload.get("error"),
                },
            )
            return

        if event_type == "collection.completed":
            try:
                await self._handle_collection_completed(tenant_id, scan_id, payload)
            except Exception:
                logger.exception(
                    "ingest failed",
                    extra={"tenant_id": str(tenant_id), "scan_id": str(scan_id)},
                )
                await self._set_scan_status(tenant_id, scan_id, ScanStatus.FAILED, completed=True)
            return

    async def _set_scan_status(
        self,
        tenant_id: UUID,
        scan_id: UUID,
        status: ScanStatus,
        *,
        completed: bool = False,
    ) -> None:
        await self._scans.update_status(tenant_id, scan_id, status, completed=completed)

    async def _handle_collection_completed(
        self, tenant_id: UUID, scan_id: UUID, payload: dict[str, Any]
    ) -> None:
        run_id = UUID(payload["collection_run_id"])
        collection_status = payload["status"]
        manifest_uri = payload["manifest_s3_uri"]

        await self._set_scan_status(tenant_id, scan_id, ScanStatus.COLLECTED)
        await self._scans.update_collection_run(
            tenant_id,
            run_id,
            status=collection_status,
            manifest_s3_uri=manifest_uri,
            resource_count=payload.get("resource_count"),
            completed=True,
        )

        await self._maybe_mark_integration_invalid(tenant_id, scan_id, payload)

        await self._set_scan_status(tenant_id, scan_id, ScanStatus.INGESTING)

        manifest = await asyncio.to_thread(self._reader.read_json, manifest_uri)
        bronze_files = await asyncio.to_thread(
            self._reader.read_manifest_and_bronze, manifest_uri, manifest
        )

        run = await self._scans.get_collection_run(tenant_id, scan_id)
        if not run:
            raise LookupError("collection run not found")

        integration_id = run["integration_id"]
        account_id = run["account_id"]
        all_resources: list[dict[str, Any]] = []
        all_relationships: list[dict[str, Any]] = []

        for bronze in bronze_files:
            resources, relationships = normalize_bronze(
                bronze,
                tenant_id=tenant_id,
                scan_id=scan_id,
                integration_id=integration_id,
                account_id=account_id,
            )
            all_resources.extend(resources)
            all_relationships.extend(relationships)

        await self._writer.insert_resources(tenant_id, all_resources)
        await self._writer.insert_relationships(tenant_id, scan_id, all_relationships)

        # Always hand off to policy evaluation as inventory_ready. Collection plugin
        # warnings live on collection_runs.status; final scan status is set by policy worker.
        await self._set_scan_status(tenant_id, scan_id, ScanStatus.INVENTORY_READY)

        resource_count = await self._writer.count_resources(tenant_id, scan_id)
        await self._writer.append_event(
            tenant_id,
            scan_id,
            "inventory.updated",
            {
                "resource_count": resource_count,
                "relationship_count": len(all_relationships),
                "collection_status": collection_status,
            },
        )

        await publish_policy_evaluate(
            self._redis,
            self._settings.policy_queue_key,
            tenant_id=tenant_id,
            scan_id=scan_id,
            payload={
                "resource_count": resource_count,
                "collection_status": collection_status,
            },
        )

        logger.info(
            "ingest complete",
            extra={
                "tenant_id": str(tenant_id),
                "scan_id": str(scan_id),
                "resources": resource_count,
            },
        )


    async def _maybe_mark_integration_invalid(
        self,
        tenant_id: UUID,
        scan_id: UUID,
        payload: dict[str, Any],
    ) -> None:
        run = await self._scans.get_collection_run(tenant_id, scan_id)
        if not run:
            return
        integration_id = run["integration_id"]
        error = payload.get("error")
        errors = payload.get("errors")
        if isinstance(errors, list):
            await self._integrations.mark_invalid_if_azure_auth_failure(
                tenant_id,
                integration_id,
                error=error if isinstance(error, dict) else None,
                errors=errors,
                resource_count=payload.get("resource_count"),
            )
        elif isinstance(error, dict):
            await self._integrations.mark_invalid_if_azure_auth_failure(
                tenant_id,
                integration_id,
                error=error,
            )


async def run_worker() -> None:
    settings = get_settings()
    logging.basicConfig(level=getattr(logging, settings.log_level.upper(), logging.INFO))
    db = await DatabasePool.create(settings)
    redis_client = await create_redis_client(settings)
    worker = IngestWorker(db, redis_client, settings)
    try:
        await worker.run_forever()
    finally:
        await close_redis_client(redis_client)
        await db.close()
