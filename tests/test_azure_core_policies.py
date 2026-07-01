"""Tests for Azure core policy pack (Phase 4)."""

from __future__ import annotations

from pathlib import Path

import yaml

from tests.migration_paths import migration_sql_path
from platform_backend.assets.ingest.normalizer import normalize_bronze
from platform_backend.policy.catalog.loader import load_policies, load_policy_packs
from platform_backend.policy.engine.evaluator import evaluate_policy_logic
from platform_backend.findings.experience import enrich_customer_finding, resource_type_label

REPO_ROOT = Path(__file__).resolve().parents[1]
POLICIES_DIR = REPO_ROOT / "policy" / "catalog" / "policies"
AZURE_MANIFEST = REPO_ROOT / "policy" / "catalog" / "azure_core.yaml"
AZURE_PACKS_PATH = REPO_ROOT / "policy" / "catalog" / "packs" / "azure.yaml"

TENANT = "54abf846-1d4c-49f9-9115-2f4f882a2cd2"
SCAN = "11111111-1111-1111-1111-111111111111"
INTEGRATION = "22222222-2222-2222-2222-222222222222"
SUBSCRIPTION = "11111111-2222-3333-4444-555555555555"


def _policy(policy_id: str):
    policies = {p.policy_id: p for p in load_policies(POLICIES_DIR)}
    return policies[policy_id]


def test_azure_manifest_has_13_policies() -> None:
    data = yaml.safe_load(AZURE_MANIFEST.read_text(encoding="utf-8"))
    assert data["pack_id"] == "pack_azure_core"
    assert len(data["policies"]) == 13


def test_azure_packs_yaml_loads() -> None:
    packs = load_policy_packs(AZURE_PACKS_PATH)
    pack_ids = {p["pack_id"] for p in packs}
    assert "pack_azure_core" in pack_ids
    assert "pack_azure_storage" in pack_ids
    core = next(p for p in packs if p["pack_id"] == "pack_azure_core")
    assert len(core["policy_ids"]) == 13


def test_storage_public_blob_fails() -> None:
    policy = _policy("AZURE_STG_003")
    asset = {
        "provider": "azure",
        "resource_type": "storage.bucket",
        "provider_type": "azure_storage_account",
        "properties": {"name": "leaky", "allow_blob_public_access": True},
    }
    assert evaluate_policy_logic(asset, policy.logic) is True


def test_nsg_ssh_from_internet_fails() -> None:
    policy = _policy("AZURE_NET_001")
    asset = {
        "provider": "azure",
        "resource_type": "network.security_group",
        "provider_type": "azure_network_security_group",
        "properties": {"name": "open-nsg", "allows_ssh_from_internet_ipv4": True},
    }
    assert evaluate_policy_logic(asset, policy.logic) is True


def test_azure_db_policy_does_not_match_aws_rds() -> None:
    policy = _policy("AZURE_DB_001")
    aws_asset = {
        "provider": "aws",
        "resource_type": "database.instance",
        "provider_type": "aws_rds_instance",
        "properties": {"publicly_accessible": True},
    }
    assert policy.matches_asset(aws_asset) is False


def test_normalize_and_evaluate_sql_public_access() -> None:
    sql_id = (
        f"/subscriptions/{SUBSCRIPTION}/resourceGroups/mock-rg/"
        "providers/Microsoft.Sql/servers/leaky-sql"
    )
    bronze = {
        "provider_type": "azure_sql_server",
        "resource_type": "database.instance",
        "collected_at": "2026-06-30T00:00:00+00:00",
        "items": [
            {
                "id": sql_id,
                "name": "leaky-sql",
                "location": "eastus",
                "resource_group": "mock-rg",
                "public_network_access": "Enabled",
                "minimal_tls_version": "1.2",
                "kind": "sql_server",
            }
        ],
    }
    resources, _ = normalize_bronze(
        bronze,
        tenant_id=TENANT,
        scan_id=SCAN,
        integration_id=INTEGRATION,
        account_id=SUBSCRIPTION,
    )
    policy = _policy("AZURE_DB_001")
    assert policy.matches_asset(resources[0]) is True
    assert evaluate_policy_logic(resources[0], policy.logic) is True


def test_customer_finding_azure_labels_and_remediation() -> None:
    finding = {
        "id": "00000000-0000-0000-0000-000000000099",
        "policy_id": "AZURE_STG_001",
        "resource_id": "/subscriptions/x/storageAccounts/acct",
        "resource_type": "storage.bucket",
        "result": "fail",
        "status": "open",
        "severity": "high",
        "title": "Storage account must require secure transfer (HTTPS)",
        "description": "test",
        "evidence": {"properties": {"name": "acct", "resource_group": "rg1"}},
        "evaluated_at": "2026-01-01T00:00:00+00:00",
        "created_at": "2026-01-01T00:00:00+00:00",
    }
    item = enrich_customer_finding(finding)
    assert item["resource_type_label"] == "Storage account"
    assert resource_type_label("storage.bucket", policy_id="AZURE_STG_001") == "Storage account"
    rem = item["remediation"]
    assert rem.get("azure_cli")
    assert rem.get("azure_portal_steps")


def test_migration_028_exists() -> None:
    migration = migration_sql_path("028_pack_azure_core.sql")
    assert migration.is_file()
    text = migration.read_text(encoding="utf-8")
    assert "AZURE_STG_001" in text
    assert "AZURE_CMP_002" in text
    assert "nist_800_53_rev5_azure" in text
    assert "soc2_azure" in text
