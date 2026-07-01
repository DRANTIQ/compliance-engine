from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock
from uuid import UUID, uuid4

import pytest

from platform_backend.api.routes.integrations import AzureIntegrationCreate
from platform_backend.platform.models.collection_job import AzureCollectionJob, parse_collection_job
from platform_backend.platform.services.scan_service import IntegrationService, ScanService
from platform_backend.security.external_id import decrypt_credential, encrypt_credential

SUBSCRIPTION_ID = "11111111-2222-3333-4444-555555555555"
TENANT_ID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
CLIENT_ID = "ffffffff-1111-2222-3333-444444444444"
SCAN_TENANT = UUID("00000000-0000-0000-0000-000000000001")
INTEGRATION_ID = UUID("00000000-0000-0000-0000-000000000002")


def test_azure_integration_create_normalizes_guids_and_locations() -> None:
    body = AzureIntegrationCreate(
        subscription_id=SUBSCRIPTION_ID.upper(),
        azure_tenant_id=TENANT_ID.upper(),
        azure_client_id=CLIENT_ID.upper(),
        client_secret="super-secret-value",
        locations=[" EastUS ", "westeurope"],
    )
    assert body.subscription_id == SUBSCRIPTION_ID.lower()
    assert body.locations == ["eastus", "westeurope"]


def test_azure_integration_create_rejects_bad_subscription_id() -> None:
    with pytest.raises(ValueError):
        AzureIntegrationCreate(
            subscription_id="not-a-guid",
            azure_tenant_id=TENANT_ID,
            azure_client_id=CLIENT_ID,
            client_secret="super-secret-value",
            locations=["eastus"],
        )


@pytest.mark.asyncio
async def test_register_azure_encrypts_client_secret() -> None:
    repo = MagicMock()
    repo.create_azure = AsyncMock(
        return_value={
            "id": INTEGRATION_ID,
            "tenant_id": SCAN_TENANT,
            "provider": "azure",
            "account_id": SUBSCRIPTION_ID,
            "role_arn": None,
            "regions": ["eastus"],
            "status": "active",
            "azure_tenant_id": TENANT_ID,
            "azure_client_id": CLIENT_ID,
            "created_at": MagicMock(isoformat=lambda: "2026-06-30T00:00:00+00:00"),
            "updated_at": MagicMock(isoformat=lambda: "2026-06-30T00:00:00+00:00"),
        }
    )
    service = IntegrationService(MagicMock(), settings=MagicMock())
    service._repo = repo

    result = await service.register_azure(
        SCAN_TENANT,
        subscription_id=SUBSCRIPTION_ID,
        azure_tenant_id=TENANT_ID,
        azure_client_id=CLIENT_ID,
        client_secret="plain-secret-12345678",
        locations=["eastus"],
    )

    assert result["provider"] == "azure"
    assert result["role_arn"] is None
    assert result["azure_client_id"] == CLIENT_ID
    assert "client_secret" not in result

    call_kwargs = repo.create_azure.await_args.kwargs
    encrypted = call_kwargs["azure_client_secret_encrypted"]
    assert encrypted != "plain-secret-12345678"
    assert decrypt_credential(encrypted) == "plain-secret-12345678"


def test_build_azure_collection_job() -> None:
    secret = encrypt_credential("job-secret-12345678")
    scan_service = ScanService(MagicMock(), MagicMock(), settings=MagicMock(s3_bucket="b", s3_prefix="pfx"))
    integration = {
        "id": INTEGRATION_ID,
        "provider": "azure",
        "account_id": SUBSCRIPTION_ID,
        "azure_tenant_id": TENANT_ID,
        "azure_client_id": CLIENT_ID,
        "azure_client_secret": secret,
        "regions": ["eastus", "westeurope"],
    }
    scan = {
        "id": uuid4(),
        "collection_run_id": uuid4(),
        "trace_id": uuid4(),
    }

    job = scan_service._build_azure_collection_job(SCAN_TENANT, integration, scan)
    parsed = parse_collection_job(job)

    assert isinstance(parsed, AzureCollectionJob)
    assert parsed.azure_client_secret == "job-secret-12345678"
    assert parsed.account_id == SUBSCRIPTION_ID
    assert "azure.storage" in parsed.plugins
    assert f"/azure/{SUBSCRIPTION_ID}" in job["s3_prefix"]


@pytest.mark.asyncio
async def test_verify_azure_maps_auth_failure() -> None:
    from platform_backend.platform.integrations import azure_verify

    repo = MagicMock()
    secret = encrypt_credential("bad-secret-12345678")
    repo.get = AsyncMock(
        return_value={
            "provider": "azure",
            "account_id": SUBSCRIPTION_ID,
            "azure_tenant_id": TENANT_ID,
            "azure_client_id": CLIENT_ID,
            "azure_client_secret": secret,
        }
    )
    service = IntegrationService(MagicMock())
    service._repo = repo

    original = azure_verify.verify_subscription_access

    def fail(**_kwargs):
        from platform_backend.platform.integrations.azure_verify import AzureVerificationError

        raise AzureVerificationError("invalid client secret", status_code=401)

    azure_verify.verify_subscription_access = fail
    try:
        result = await service.verify_azure(SCAN_TENANT, INTEGRATION_ID)
    finally:
        azure_verify.verify_subscription_access = original

    assert result["valid"] is False
    assert "invalid client secret" in result["message"]
