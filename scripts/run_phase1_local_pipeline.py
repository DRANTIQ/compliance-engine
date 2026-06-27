#!/usr/bin/env python3
"""Run Phase 1 pipeline in-process without competing Redis workers."""

from __future__ import annotations

import asyncio
import json
import os
import sys
from uuid import UUID

import redis.asyncio as redis

from platform_backend.assets.ingest.worker import IngestWorker
from platform_backend.config.settings import get_settings
from platform_backend.db.pool import DatabasePool
from platform_backend.platform.models.scan import ScanStatus
from platform_backend.platform.repositories.integrations import IntegrationRepository, ScanRepository
from platform_backend.platform.services.scan_service import ScanService
from platform_backend.queue.redis_client import close_redis_client, create_redis_client
from platform_backend.security.external_id import decrypt_external_id
from platform_collectors.config.settings import get_settings as collector_settings
from platform_collectors.storage.snapshot_writer import SnapshotWriter
from platform_collectors.worker.main import CollectionOrchestrator


async def main() -> int:
    tenant_id = UUID(os.environ.get("TENANT_ID", ""))
    integration_id = UUID(os.environ.get("INTEGRATION_ID", ""))
    if not tenant_id or not integration_id:
        print("Set TENANT_ID and INTEGRATION_ID", file=sys.stderr)
        return 1

    os.environ.setdefault("COLLECTOR_MOCK", "true")
    os.environ.setdefault("USE_LOCAL_STORAGE", "true")

    settings = get_settings()
    db = await DatabasePool.create(settings)
    redis_client = await create_redis_client(settings)

    integrations = IntegrationRepository(db)
    scans = ScanRepository(db)
    integration = await integrations.get(tenant_id, integration_id)
    if not integration:
        print("integration not found", file=sys.stderr)
        return 1

    scan_row = await scans.create(
        tenant_id,
        integration_id=integration_id,
        account_id=integration["account_id"],
    )
    scan_id = scan_row["id"]
    await scans.update_status(tenant_id, scan_id, ScanStatus.QUEUED, started=True)

    scan_service = ScanService(db, redis_client, settings)
    job = scan_service._build_collection_job(tenant_id, integration, scan_row)

    collector = CollectionOrchestrator(redis_client, collector_settings())
    await collector.run_job(json.dumps(job))
    print(f"scan {scan_id} collected (mock)")

    manifest_uri = SnapshotWriter(collector_settings()).manifest_uri(job["s3_prefix"])
    ingest = IngestWorker(db, redis_client, settings)
    await ingest._handle_collection_completed(
        tenant_id,
        scan_id,
        {
            "collection_run_id": str(scan_row["collection_run_id"]),
            "status": "completed",
            "manifest_s3_uri": manifest_uri,
            "account_id": integration["account_id"],
            "resource_count": 3,
            "errors": [],
        },
    )

    detail = await scan_service.get_scan(tenant_id, scan_id)
    print(f"final status: {detail['status']}")

    from platform_backend.assets.repositories.resources import AssetRepository

    assets = await AssetRepository(db).list(tenant_id, scan_id)
    print(f"assets: {len(assets)}")
    for asset in assets:
        print(f"  {asset['resource_type']} {asset['resource_id']}")

    await close_redis_client(redis_client)
    await db.close()

    if detail["status"] not in ("inventory_ready", "completed_with_errors") or len(assets) < 1:
        return 1
    print("Phase 1 local pipeline passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
