from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any
from uuid import UUID

import redis.asyncio as redis

from platform_backend.assets.ingest.writer import AssetWriter
from platform_backend.assets.repositories.resources import AssetRepository
from platform_backend.config.settings import Settings, get_settings
from platform_backend.db.pool import DatabasePool
from platform_backend.compliance.mapper import ComplianceMapper
from platform_backend.findings.repository import FindingsRepository, evaluate_scan
from platform_backend.platform.models.scan import ScanStatus
from platform_backend.platform.repositories.integrations import ScanRepository
from platform_backend.policy.catalog.loader import load_policies
from platform_backend.queue.redis_client import close_redis_client, create_redis_client

logger = logging.getLogger(__name__)


class PolicyWorker:
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
        self._assets = AssetRepository(db)
        self._findings = FindingsRepository(db)
        self._compliance = ComplianceMapper(db)
        self._writer = AssetWriter(db)
        catalog_path = Path(self._settings.policy_catalog_path)
        if not catalog_path.is_absolute():
            repo_root = Path(__file__).resolve().parents[3]
            catalog_path = repo_root / catalog_path
        self._policies = load_policies(catalog_path)

    async def run_forever(self) -> None:
        logger.info(
            "policy worker listening on %s (%d policies loaded)",
            self._settings.policy_queue_key,
            len(self._policies),
        )
        while True:
            item = await self._redis.brpop(self._settings.policy_queue_key, timeout=5)
            if not item:
                continue
            _, raw = item
            try:
                envelope = json.loads(raw)
                await self.handle_event(envelope)
            except Exception:
                logger.exception("failed to handle policy event")

    async def handle_event(self, envelope: dict[str, Any]) -> None:
        event_type = envelope.get("event_type")
        if event_type != "policy.evaluate":
            return

        tenant_id = UUID(envelope["tenant_id"])
        scan_id = UUID(envelope["scan_id"])
        payload = envelope.get("payload", {})

        await self._writer.append_event(tenant_id, scan_id, event_type, payload)

        scan = await self._scans.get(tenant_id, scan_id)
        if not scan:
            logger.warning("scan not found", extra={"scan_id": str(scan_id)})
            return

        current = ScanStatus(scan["status"])
        if current not in {ScanStatus.INVENTORY_READY, ScanStatus.COMPLETED_WITH_ERRORS}:
            logger.info(
                "skipping policy evaluation for scan in status %s",
                current,
                extra={"scan_id": str(scan_id)},
            )
            return

        await self._scans.update_status(tenant_id, scan_id, ScanStatus.EVALUATING)
        await self._findings.start_evaluation_run(tenant_id, scan_id)

        try:
            assets = await self._assets.list(tenant_id, scan_id, limit=5000, offset=0)
            policies_run, findings_count, fail_count = await evaluate_scan(
                assets,
                self._policies,
                self._findings,
                tenant_id,
                scan_id,
            )
            await self._findings.complete_evaluation_run(
                tenant_id,
                scan_id,
                policies_run=policies_run,
                findings_count=findings_count,
                fail_count=fail_count,
            )
            compliance_summary = await self._compliance.map_scan(tenant_id, scan_id)
            final_status = (
                ScanStatus.COMPLETED
                if current == ScanStatus.INVENTORY_READY
                else ScanStatus.COMPLETED_WITH_ERRORS
            )
            await self._scans.update_status(
                tenant_id,
                scan_id,
                final_status,
                completed=True,
            )
            await self._writer.append_event(
                tenant_id,
                scan_id,
                "policy.completed",
                {
                    "policies_run": policies_run,
                    "findings_count": findings_count,
                    "fail_count": fail_count,
                    "compliance_score": compliance_summary["score"],
                },
            )
            await self._writer.append_event(
                tenant_id,
                scan_id,
                "compliance.updated",
                compliance_summary,
            )
            await self._writer.append_event(
                tenant_id,
                scan_id,
                "scan.completed",
                {"status": final_status.value},
            )
            logger.info(
                "policy evaluation complete",
                extra={
                    "tenant_id": str(tenant_id),
                    "scan_id": str(scan_id),
                    "fail_count": fail_count,
                },
            )
        except Exception as exc:
            logger.exception("policy evaluation failed", extra={"scan_id": str(scan_id)})
            await self._findings.complete_evaluation_run(
                tenant_id,
                scan_id,
                policies_run=0,
                findings_count=0,
                fail_count=0,
                status="failed",
                error={"message": str(exc)},
            )
            await self._scans.update_status(
                tenant_id,
                scan_id,
                ScanStatus.FAILED,
                error={"message": str(exc)},
                completed=True,
            )
            await self._writer.append_event(
                tenant_id,
                scan_id,
                "scan.completed",
                {"status": ScanStatus.FAILED.value, "error": {"message": str(exc)}},
            )


async def run_worker() -> None:
    settings = get_settings()
    logging.basicConfig(level=getattr(logging, settings.log_level.upper(), logging.INFO))
    db = await DatabasePool.create(settings)
    redis_client = await create_redis_client(settings)
    worker = PolicyWorker(db, redis_client, settings)
    try:
        await worker.run_forever()
    finally:
        await close_redis_client(redis_client)
        await db.close()
