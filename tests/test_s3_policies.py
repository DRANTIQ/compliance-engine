"""Unit tests for S3 policy parsing and evaluation."""

from __future__ import annotations

from uuid import UUID

from platform_backend.assets.ingest.normalizer import normalize_bronze
from platform_backend.policy.engine.evaluator import evaluate_policy_logic
from platform_collectors.plugins.aws.s3_collect import policy_denies_insecure_transport

TENANT = UUID("54abf846-1d4c-49f9-9115-2f4f882a2cd2")
SCAN = UUID("11111111-1111-1111-1111-111111111111")
INTEGRATION = UUID("22222222-2222-2222-2222-222222222222")
ACCOUNT = "123456789012"


def test_policy_denies_insecure_transport_detects_cis_pattern() -> None:
    policy = {
        "Statement": [
            {
                "Effect": "Deny",
                "Principal": {"AWS": "*"},
                "Action": "s3:*",
                "Resource": "arn:aws:s3:::example/*",
                "Condition": {"Bool": {"aws:SecureTransport": "false"}},
            }
        ]
    }
    assert policy_denies_insecure_transport(policy) is True


def test_policy_denies_insecure_transport_rejects_allow_only() -> None:
    policy = {
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": "*",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::example/*",
            }
        ]
    }
    assert policy_denies_insecure_transport(policy) is False


def test_s3_deny_http_fail_when_not_configured() -> None:
    asset = {"properties": {"name": "open-bucket", "denies_insecure_transport": False}}
    logic = {
        "type": "fail_when",
        "condition": {
            "type": "compound",
            "operator": "or",
            "conditions": [
                {
                    "type": "field_check",
                    "path": "properties.denies_insecure_transport",
                    "operator": "missing",
                },
                {
                    "type": "field_check",
                    "path": "properties.denies_insecure_transport",
                    "operator": "eq",
                    "expected": False,
                },
            ],
        },
    }
    assert evaluate_policy_logic(asset, logic) is True


def test_s3_write_logging_pass_when_enabled() -> None:
    asset = {"properties": {"name": "logged-bucket", "cloudtrail_s3_write_logging": True}}
    logic = {
        "type": "fail_when",
        "condition": {
            "type": "field_check",
            "path": "properties.cloudtrail_s3_write_logging",
            "operator": "eq",
            "expected": False,
        },
    }
    assert evaluate_policy_logic(asset, logic) is False


def test_normalize_s3_bucket_enriched_fields() -> None:
    bronze = {
        "provider_type": "aws_s3_bucket",
        "resource_type": "storage.bucket",
        "collected_at": "2026-06-26T00:00:00+00:00",
        "items": [
            {
                "Name": "mock-platform-bucket",
                "Region": "us-east-1",
                "PublicAccessBlock": {"BlockPublicAcls": True},
                "DeniesInsecureTransport": True,
                "CloudTrailS3WriteLogging": True,
                "CloudTrailS3ReadLogging": True,
            }
        ],
    }
    resources, _ = normalize_bronze(
        bronze,
        tenant_id=TENANT,
        scan_id=SCAN,
        integration_id=INTEGRATION,
        account_id=ACCOUNT,
    )
    props = resources[0]["properties"]
    assert props["denies_insecure_transport"] is True
    assert props["cloudtrail_s3_write_logging"] is True
    assert props["cloudtrail_s3_read_logging"] is True
