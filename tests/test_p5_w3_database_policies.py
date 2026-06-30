"""Tests for P5 Wave 3 CIS database services policies."""

from __future__ import annotations

from pathlib import Path

import yaml

from platform_backend.assets.ingest.normalizer import normalize_bronze
from platform_backend.policy.catalog.loader import load_policies
from platform_backend.policy.engine.evaluator import evaluate_policy_logic

REPO_ROOT = Path(__file__).resolve().parents[1]
POLICIES_DIR = REPO_ROOT / "policy" / "catalog" / "policies"
W3_MANIFEST = REPO_ROOT / "policy" / "catalog" / "p5_w3_data.yaml"


def _policy(policy_id: str):
    policies = {p.policy_id: p for p in load_policies(POLICIES_DIR)}
    return policies[policy_id]


def test_w3_manifest_has_15_policies() -> None:
    data = yaml.safe_load(W3_MANIFEST.read_text(encoding="utf-8"))
    assert data["pack_id"] == "pack_aws_data"
    assert len(data["policies"]) == 15


def test_rds_backup_retention_fails_below_7_days() -> None:
    policy = _policy("AWS_RDS_004")
    asset = {
        "resource_type": "database.instance",
        "provider_type": "aws_rds_instance",
        "properties": {"backup_retention_period": 1, "db_instance_identifier": "db-1"},
    }
    assert evaluate_policy_logic(asset, policy.logic) is True


def test_dynamodb_pitr_disabled_fails() -> None:
    policy = _policy("AWS_RDS_016")
    asset = {
        "resource_type": "database.table",
        "provider_type": "aws_dynamodb_table",
        "properties": {"point_in_time_recovery_enabled": False, "table_name": "orders"},
    }
    assert evaluate_policy_logic(asset, policy.logic) is True


def test_normalize_rds_instance_extended_fields() -> None:
    bronze = {
        "provider_type": "aws_rds_instance",
        "resource_type": "database.instance",
        "collected_at": "2026-06-26T00:00:00+00:00",
        "items": [
            {
                "DBInstanceIdentifier": "app-db",
                "DBInstanceArn": "arn:aws:rds:us-east-1:123456789012:db:app-db",
                "Region": "us-east-1",
                "StorageEncrypted": True,
                "AutoMinorVersionUpgrade": True,
                "PubliclyAccessible": False,
                "BackupRetentionPeriod": 3,
                "MultiAZ": False,
                "DeletionProtection": False,
                "IAMDatabaseAuthenticationEnabled": False,
                "EnabledCloudwatchLogsExports": [],
                "MonitoringInterval": 0,
                "PerformanceInsightsEnabled": False,
                "Engine": "postgres",
            }
        ],
    }
    resources, _ = normalize_bronze(
        bronze,
        tenant_id="00000000-0000-0000-0000-000000000001",
        scan_id="00000000-0000-0000-0000-000000000002",
        integration_id="00000000-0000-0000-0000-000000000003",
        account_id="123456789012",
    )
    props = resources[0]["properties"]
    assert props["backup_retention_period"] == 3
    assert props["has_cloudwatch_logs_exports"] is False


def test_migration_025_exists() -> None:
    migration = REPO_ROOT.parent / "platform-db" / "migrations" / "025_p5_database_services.sql"
    assert migration.is_file()
    text = migration.read_text(encoding="utf-8")
    assert "AWS_RDS_004" in text
    assert "AWS_RDS_018" in text
