"""Unit tests for IAM bronze normalization."""

from __future__ import annotations

from uuid import UUID

from platform_backend.assets.ingest.normalizer import normalize_bronze

TENANT = UUID("54abf846-1d4c-49f9-9115-2f4f882a2cd2")
SCAN = UUID("11111111-1111-1111-1111-111111111111")
INTEGRATION = UUID("22222222-2222-2222-2222-222222222222")
ACCOUNT = "123456789012"


def test_normalize_iam_user_enriched_fields() -> None:
    bronze = {
        "provider_type": "aws_iam_user",
        "resource_type": "identity.user",
        "collected_at": "2026-06-26T00:00:00+00:00",
        "items": [
            {
                "UserName": "mock-admin",
                "UserId": "AIDAMOCK0001",
                "Arn": f"arn:aws:iam::{ACCOUNT}:user/mock-admin",
                "PasswordLastUsed": "2026-06-01T00:00:00+00:00",
                "MfaEnabled": False,
                "ActiveAccessKeyCount": 1,
                "HasUnusedActiveCredentials": False,
                "HasStaleActiveAccessKey": False,
                "HasDirectAttachedPoliciesWithoutGroups": False,
                "HasAdministratorAccess": False,
                "GroupCount": 1,
                "AttachedPolicyCount": 0,
                "Tags": [],
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
    assert len(resources) == 1
    props = resources[0]["properties"]
    assert props["user_name"] == "mock-admin"
    assert props["mfa_enabled"] is False
    assert props["password_last_used"] is not None
    assert props["active_access_key_count"] == 1


def test_normalize_iam_account_and_password_policy() -> None:
    account_bronze = {
        "provider_type": "aws_iam_account",
        "resource_type": "identity.account",
        "collected_at": "2026-06-26T00:00:00+00:00",
        "items": [
            {
                "AccountId": ACCOUNT,
                "RootAccessKeysPresent": 0,
                "RootMfaEnabled": True,
                "RootPasswordPresent": True,
                "SupportRoleExists": True,
            }
        ],
    }
    policy_bronze = {
        "provider_type": "aws_iam_account_password_policy",
        "resource_type": "identity.account",
        "collected_at": "2026-06-26T00:00:00+00:00",
        "items": [
            {
                "AccountId": ACCOUNT,
                "MinimumPasswordLength": 14,
                "PasswordReusePrevention": 24,
            }
        ],
    }
    account_resources, _ = normalize_bronze(
        account_bronze,
        tenant_id=TENANT,
        scan_id=SCAN,
        integration_id=INTEGRATION,
        account_id=ACCOUNT,
    )
    policy_resources, _ = normalize_bronze(
        policy_bronze,
        tenant_id=TENANT,
        scan_id=SCAN,
        integration_id=INTEGRATION,
        account_id=ACCOUNT,
    )
    assert account_resources[0]["properties"]["support_role_exists"] is True
    assert policy_resources[0]["properties"]["minimum_password_length"] == 14
