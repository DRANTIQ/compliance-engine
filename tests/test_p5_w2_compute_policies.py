"""Tests for P5 Wave 2 CIS compute services policies."""

from __future__ import annotations

from pathlib import Path

import yaml

from tests.migration_paths import migration_sql_path
from platform_backend.assets.ingest.normalizer import normalize_bronze
from platform_backend.policy.catalog.loader import load_policies
from platform_backend.policy.engine.evaluator import evaluate_policy_logic

REPO_ROOT = Path(__file__).resolve().parents[1]
POLICIES_DIR = REPO_ROOT / "policy" / "catalog" / "policies"
W2_MANIFEST = REPO_ROOT / "policy" / "catalog" / "p5_w2_compute.yaml"


def _policy(policy_id: str):
    policies = {p.policy_id: p for p in load_policies(POLICIES_DIR)}
    return policies[policy_id]


def test_w2_manifest_has_20_policies() -> None:
    data = yaml.safe_load(W2_MANIFEST.read_text(encoding="utf-8"))
    assert data["pack_id"] == "pack_aws_compute"
    assert len(data["policies"]) == 20


def test_public_ami_fails() -> None:
    policy = _policy("AWS_EC2_005")
    asset = {
        "resource_type": "compute.image",
        "provider_type": "aws_ec2_ami",
        "properties": {"public": True, "image_id": "ami-123"},
    }
    assert evaluate_policy_logic(asset, policy.logic) is True


def test_termination_protection_fails_on_running_instance() -> None:
    policy = _policy("AWS_EC2_001")
    asset = {
        "resource_type": "compute.instance",
        "provider_type": "aws_ec2_instance",
        "properties": {
            "state": "running",
            "termination_protected": False,
            "instance_id": "i-1",
        },
    }
    assert evaluate_policy_logic(asset, policy.logic) is True


def test_sg_postgres_from_internet_fails() -> None:
    policy = _policy("AWS_EC2_013")
    asset = {
        "resource_type": "network.security_group",
        "provider_type": "aws_ec2_security_group",
        "properties": {
            "group_id": "sg-1",
            "allows_postgres_from_internet_ipv4": True,
        },
    }
    assert evaluate_policy_logic(asset, policy.logic) is True


def test_normalize_ebs_snapshot() -> None:
    bronze = {
        "provider_type": "aws_ebs_snapshot",
        "resource_type": "storage.snapshot",
        "collected_at": "2026-06-26T00:00:00+00:00",
        "items": [
            {
                "SnapshotId": "snap-abc",
                "Region": "us-east-1",
                "Encrypted": False,
                "Public": True,
                "State": "completed",
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
    assert resources[0]["properties"]["public"] is True
    assert resources[0]["properties"]["encrypted"] is False


def test_migration_024_exists() -> None:
    migration = migration_sql_path("024_p5_compute_services.sql")
    assert migration.is_file()
    text = migration.read_text(encoding="utf-8")
    assert "AWS_EC2_001" in text
    assert "AWS_EC2_020" in text
