"""Tests for P5 Wave 1 compute security policies."""

from __future__ import annotations

from pathlib import Path

import yaml

from tests.migration_paths import migration_sql_path
from platform_backend.assets.ingest.normalizer import normalize_bronze
from platform_backend.policy.catalog.loader import load_policies
from platform_backend.policy.engine.evaluator import evaluate_policy_logic

REPO_ROOT = Path(__file__).resolve().parents[1]
POLICIES_DIR = REPO_ROOT / "policy" / "catalog" / "policies"
P5_MANIFEST = REPO_ROOT / "policy" / "catalog" / "p5_w1_compute.yaml"


def _policy(policy_id: str):
    policies = {p.policy_id: p for p in load_policies(POLICIES_DIR)}
    return policies[policy_id]


def test_p5_manifest_has_15_policies() -> None:
    data = yaml.safe_load(P5_MANIFEST.read_text(encoding="utf-8"))
    assert len(data["policies"]) == 15


def test_lambda_public_invoke_fails() -> None:
    policy = _policy("AWS_CMP_001")
    asset = {
        "resource_type": "compute.function",
        "provider_type": "aws_lambda_function",
        "properties": {"publicly_accessible": True, "function_name": "fn"},
    }
    assert evaluate_policy_logic(asset, policy.logic) is True


def test_guardduty_disabled_fails() -> None:
    policy = _policy("AWS_CMP_006")
    asset = {
        "resource_type": "security.detector",
        "provider_type": "aws_guardduty_detector",
        "properties": {"enabled": False, "region": "us-east-1"},
    }
    assert evaluate_policy_logic(asset, policy.logic) is True


def test_ebs_unencrypted_fails() -> None:
    policy = _policy("AWS_CMP_011")
    asset = {
        "resource_type": "storage.volume",
        "provider_type": "aws_ebs_volume",
        "properties": {"encrypted": False, "volume_id": "vol-1"},
    }
    assert evaluate_policy_logic(asset, policy.logic) is True


def test_normalize_lambda_function_fields() -> None:
    bronze = {
        "provider_type": "aws_lambda_function",
        "resource_type": "compute.function",
        "collected_at": "2026-06-26T00:00:00+00:00",
        "items": [
            {
                "FunctionName": "demo",
                "FunctionArn": "arn:aws:lambda:us-east-1:123456789012:function:demo",
                "Region": "us-east-1",
                "Runtime": "python3.12",
                "RuntimeDeprecated": False,
                "TracingMode": "PassThrough",
                "HasDeadLetterQueue": False,
                "PubliclyAccessible": True,
                "FunctionUrlAuthNone": False,
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
    assert resources[0]["properties"]["publicly_accessible"] is True
    assert resources[0]["properties"]["has_dead_letter_queue"] is False


def test_migration_023_exists() -> None:
    migration = migration_sql_path("023_p5_compute_security.sql")
    assert migration.is_file()
    text = migration.read_text(encoding="utf-8")
    assert "AWS_CMP_001" in text
    assert "AWS_CMP_015" in text
    assert "drantiq_security_assessment_v1" in text
