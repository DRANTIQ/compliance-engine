from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock
from uuid import UUID

import pytest

from platform_backend.assets.ingest.worker import IngestWorker
from platform_backend.platform.models.scan import ScanStatus

TENANT = UUID("00000000-0000-0000-0000-000000000001")
SCAN = UUID("00000000-0000-0000-0000-000000000002")
RUN = UUID("00000000-0000-0000-0000-000000000003")
INTEGRATION = UUID("00000000-0000-0000-0000-000000000004")


@pytest.mark.asyncio
async def test_collection_failed_marks_integration_invalid_on_auth() -> None:
    worker = IngestWorker(MagicMock(), MagicMock(), settings=MagicMock())
    worker._writer = MagicMock()
    worker._writer.append_event = AsyncMock()
    worker._scans = MagicMock()
    worker._scans.update_status = AsyncMock()
    worker._scans.update_collection_run = AsyncMock()
    worker._scans.get_collection_run = AsyncMock(
        return_value={"integration_id": INTEGRATION, "account_id": "sub-id"}
    )
    worker._integrations = MagicMock()
    worker._integrations.mark_invalid_if_azure_auth_failure = AsyncMock()

    await worker.handle_event(
        {
            "event_type": "collection.failed",
            "tenant_id": str(TENANT),
            "scan_id": str(SCAN),
            "payload": {
                "collection_run_id": str(RUN),
                "error": {
                    "message": "Authentication failed: invalid_client",
                    "type": "AzureCredentialError",
                    "auth_failure": True,
                },
            },
        }
    )

    worker._scans.update_status.assert_awaited_once()
    assert worker._scans.update_status.await_args.args[2] == ScanStatus.FAILED
    worker._integrations.mark_invalid_if_azure_auth_failure.assert_awaited_once()
    call_kwargs = worker._integrations.mark_invalid_if_azure_auth_failure.await_args.kwargs
    assert call_kwargs["error"]["auth_failure"] is True
