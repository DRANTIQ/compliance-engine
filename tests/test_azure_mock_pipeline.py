"""End-to-end mock Azure pipeline: collector bronze → normalizer → policy evaluation."""

from __future__ import annotations

from pathlib import Path
from uuid import uuid4

import pytest

from platform_backend.assets.ingest.normalizer import normalize_bronze
from platform_backend.policy.catalog.loader import load_policies
from platform_backend.policy.engine.evaluator import evaluate_policy_logic

pytest.importorskip("platform_collectors")

from platform_collectors.azure.auth import MOCK_SUBSCRIPTION_ID, mock_azure_session
from platform_collectors.models.collection_job import AzureCollectionJob
from platform_collectors.plugins.azure.plugins import AZURE_PLUGIN_REGISTRY

REPO_ROOT = Path(__file__).resolve().parents[1]
POLICIES_DIR = REPO_ROOT / "policy" / "catalog" / "policies"

TENANT = "54abf846-1d4c-49f9-9115-2f4f882a2cd2"
SCAN = "11111111-1111-1111-1111-111111111111"
INTEGRATION = "22222222-2222-2222-2222-222222222222"


def _azure_job() -> AzureCollectionJob:
    return AzureCollectionJob(
        job_id=uuid4(),
        scan_id=uuid4(),
        tenant_id=uuid4(),
        integration_id=uuid4(),
        collection_run_id=uuid4(),
        account_id=MOCK_SUBSCRIPTION_ID,
        azure_tenant_id="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        azure_client_id="ffffffff-1111-2222-3333-444444444444",
        azure_client_secret="mock-secret",
        regions=["eastus"],
        s3_bucket="test-bucket",
        s3_prefix="platform-v2/tenants/t/scans/s/azure/mock",
        plugins=list(AZURE_PLUGIN_REGISTRY.keys()),
    )


def _collect_mock_bronze() -> list[dict]:
    job = _azure_job()
    session = mock_azure_session()
    bronze_files: list[dict] = []
    for plugin_name in job.plugins:
        plugin = AZURE_PLUGIN_REGISTRY[plugin_name]
        result = plugin.collect(job, session)
        snapshots = result if isinstance(result, list) else [result]
        for snapshot in snapshots:
            bronze_files.append(
                {
                    "provider_type": snapshot.provider_type,
                    "resource_type": snapshot.resource_type,
                    "collected_at": "2026-06-30T00:00:00+00:00",
                    "items": snapshot.items,
                }
            )
    return bronze_files


def test_mock_azure_collector_to_normalizer_to_policy() -> None:
    policies = {p.policy_id: p for p in load_policies(POLICIES_DIR)}
    stg_policy = policies["AZURE_STG_001"]
    net_policy = policies["AZURE_NET_001"]

    all_resources = []
    for bronze in _collect_mock_bronze():
        resources, _relationships = normalize_bronze(
            bronze,
            tenant_id=TENANT,
            scan_id=SCAN,
            integration_id=INTEGRATION,
            account_id=MOCK_SUBSCRIPTION_ID,
        )
        all_resources.extend(resources)

    assert len(all_resources) >= 5

    storage_assets = [r for r in all_resources if r["resource_type"] == "storage.bucket"]
    assert storage_assets
    for asset in storage_assets:
        assert stg_policy.matches_asset(asset)
        assert evaluate_policy_logic(asset, stg_policy.logic) is False

    nsg_assets = [r for r in all_resources if r["resource_type"] == "network.security_group"]
    assert nsg_assets
    for asset in nsg_assets:
        assert net_policy.matches_asset(asset)
        assert evaluate_policy_logic(asset, net_policy.logic) is False

    # Inject a failing storage asset to prove policy engine catches misconfigurations.
    leaky = {
        "provider": "azure",
        "resource_type": "storage.bucket",
        "provider_type": "azure_storage_account",
        "properties": {"name": "leaky", "enable_https_traffic_only": False},
    }
    assert evaluate_policy_logic(leaky, stg_policy.logic) is True
