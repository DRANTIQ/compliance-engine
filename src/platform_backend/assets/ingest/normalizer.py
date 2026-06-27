from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any
from uuid import UUID


def _tags_from_aws(tag_list: list[dict[str, Any]] | None) -> dict[str, str]:
    if not tag_list:
        return {}
    return {t["Key"]: t["Value"] for t in tag_list if "Key" in t and "Value" in t}


def _parse_collected_at(value: str | None) -> datetime:
    if not value:
        return datetime.now(timezone.utc)
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _append_resource(
    resources: list[dict[str, Any]],
    *,
    tenant_id: UUID,
    scan_id: UUID,
    integration_id: UUID,
    account_id: str,
    resource_id: str,
    resource_type: str,
    provider_type: str,
    properties: dict[str, Any],
    tags: dict[str, str],
    region: str | None,
    collected_at: datetime,
) -> None:
    resources.append(
        {
            "tenant_id": tenant_id,
            "scan_id": scan_id,
            "resource_id": resource_id,
            "resource_type": resource_type,
            "provider": "aws",
            "provider_type": provider_type,
            "integration_id": integration_id,
            "account_id": account_id,
            "region": region,
            "properties": properties,
            "tags": tags,
            "collected_at": collected_at,
            "first_seen_at": collected_at,
            "last_seen_at": collected_at,
        }
    )


def normalize_bronze(
    bronze: dict[str, Any],
    *,
    tenant_id: UUID,
    scan_id: UUID,
    integration_id: UUID,
    account_id: str,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    provider_type = bronze["provider_type"]
    resource_type = bronze["resource_type"]
    collected_at = _parse_collected_at(bronze.get("collected_at"))
    resources: list[dict[str, Any]] = []
    relationships: list[dict[str, Any]] = []

    for item in bronze.get("items", []):
        if provider_type == "aws_iam_user":
            resource_id = item["Arn"]
            properties = {
                "user_name": item.get("UserName"),
                "user_id": item.get("UserId"),
                "password_last_used": item.get("PasswordLastUsed"),
                "mfa_enabled": item.get("MfaEnabled"),
                "active_access_key_count": item.get("ActiveAccessKeyCount", 0),
                "has_unused_active_credentials": item.get("HasUnusedActiveCredentials", False),
                "has_stale_active_access_key": item.get("HasStaleActiveAccessKey", False),
                "has_direct_attached_policies_without_groups": item.get(
                    "HasDirectAttachedPoliciesWithoutGroups", False
                ),
                "has_administrator_access": item.get("HasAdministratorAccess", False),
                "group_count": item.get("GroupCount", 0),
                "attached_policy_count": item.get("AttachedPolicyCount", 0),
            }
            tags = _tags_from_aws(item.get("Tags"))
            region = None
        elif provider_type == "aws_iam_account":
            acct = item.get("AccountId", account_id)
            resource_id = f"arn:aws:iam::{acct}:root"
            properties = {
                "account_id": acct,
                "root_access_keys_present": item.get("RootAccessKeysPresent", 0),
                "root_mfa_enabled": item.get("RootMfaEnabled", False),
                "root_password_present": item.get("RootPasswordPresent", False),
                "support_role_exists": item.get("SupportRoleExists", False),
            }
            tags = {}
            region = None
        elif provider_type == "aws_iam_account_password_policy":
            acct = item.get("AccountId", account_id)
            resource_id = f"arn:aws:iam::{acct}:password-policy"
            properties = {
                "account_id": acct,
                "minimum_password_length": item.get("MinimumPasswordLength"),
                "password_reuse_prevention": item.get("PasswordReusePrevention"),
            }
            tags = {}
            region = None
        elif provider_type == "aws_iam_server_certificate":
            resource_id = item["Arn"]
            properties = {
                "name": item.get("Name"),
                "server_certificate_id": item.get("ServerCertificateId"),
                "expiration": item.get("Expiration"),
                "is_expired": item.get("IsExpired", False),
            }
            tags = {}
            region = None
        elif provider_type == "aws_iam_access_analyzer":
            resource_id = item["Arn"]
            properties = {
                "name": item.get("Name"),
                "status": item.get("Status"),
                "region": item.get("Region"),
            }
            tags = {}
            region = item.get("Region")
        elif provider_type == "aws_s3_bucket":
            name = item["Name"]
            resource_id = f"arn:aws:s3:::{name}"
            properties = {
                "name": name,
                "public_access_block": item.get("PublicAccessBlock", {}),
                "denies_insecure_transport": item.get("DeniesInsecureTransport", False),
                "cloudtrail_s3_write_logging": item.get("CloudTrailS3WriteLogging", False),
                "cloudtrail_s3_read_logging": item.get("CloudTrailS3ReadLogging", False),
            }
            tags = {}
            region = item.get("Region")
        elif provider_type == "aws_ec2_instance":
            instance_id = item["InstanceId"]
            region = item.get("Region")
            resource_id = f"arn:aws:ec2:{region}:{account_id}:instance/{instance_id}"
            properties = {
                "instance_id": instance_id,
                "instance_type": item.get("InstanceType"),
                "state": item.get("State"),
                "vpc_id": item.get("VpcId"),
                "subnet_id": item.get("SubnetId"),
                "iam_instance_profile_arn": item.get("IamInstanceProfileArn"),
                "http_tokens": item.get("HttpTokens"),
            }
            tags = _tags_from_aws(item.get("Tags"))
            vpc_id = item.get("VpcId")
            if vpc_id:
                vpc_arn = f"arn:aws:ec2:{region}:{account_id}:vpc/{vpc_id}"
                relationships.append(
                    {
                        "from_resource_id": resource_id,
                        "to_resource_id": vpc_arn,
                        "relationship_type": "member_of",
                        "properties": {},
                    }
                )
        elif provider_type == "aws_rds_instance":
            resource_id = item["DBInstanceArn"]
            region = item.get("Region")
            properties = {
                "db_instance_identifier": item.get("DBInstanceIdentifier"),
                "storage_encrypted": item.get("StorageEncrypted", False),
                "auto_minor_version_upgrade": item.get("AutoMinorVersionUpgrade", False),
                "publicly_accessible": item.get("PubliclyAccessible", False),
            }
            tags = {}
        elif provider_type == "aws_efs_file_system":
            fs_id = item["FileSystemId"]
            region = item.get("Region")
            resource_id = f"arn:aws:elasticfilesystem:{region}:{account_id}:file-system/{fs_id}"
            properties = {
                "file_system_id": fs_id,
                "name": item.get("Name"),
                "encrypted": item.get("Encrypted", False),
            }
            tags = {}
        elif provider_type == "aws_cloudtrail_trail":
            resource_id = item["Arn"]
            region = item.get("Region")
            properties = {
                "name": item.get("Name"),
                "log_file_validation_enabled": item.get("LogFileValidationEnabled", False),
                "kms_key_id": item.get("KmsKeyId"),
            }
            tags = {}
        elif provider_type == "aws_config_configuration_recorder":
            region = item.get("Region")
            name = item.get("Name", "default")
            resource_id = f"arn:aws:config:{region}:{account_id}:config-recorder/{name}"
            properties = {
                "name": name,
                "status_recording": item.get("StatusRecording", False),
            }
            tags = {}
        elif provider_type == "aws_kms_key":
            resource_id = item["Arn"]
            region = item.get("Region")
            properties = {
                "key_id": item.get("KeyId"),
                "key_rotation_enabled": item.get("KeyRotationEnabled", False),
            }
            tags = {}
        elif provider_type == "aws_ec2_vpc":
            resource_id = item["Arn"]
            region = item.get("Region")
            properties = {
                "vpc_id": item.get("VpcId"),
                "flow_logs_enabled": item.get("FlowLogsEnabled", False),
            }
            tags = {}
        elif provider_type == "aws_securityhub_hub":
            resource_id = item["HubArn"]
            region = item.get("Region")
            properties = {
                "region": region,
                "enabled": item.get("Enabled", False),
            }
            tags = {}
        elif provider_type == "aws_account_ebs_encryption":
            region = item.get("Region")
            resource_id = f"arn:aws:ec2:{region}:{account_id}:ebs-encryption/default"
            properties = {
                "region": region,
                "default_ebs_encryption_enabled": item.get("DefaultEbsEncryptionEnabled", False),
            }
            tags = {}
        elif provider_type == "aws_ec2_security_group":
            region = item.get("Region")
            group_id = item["GroupId"]
            resource_id = f"arn:aws:ec2:{region}:{account_id}:security-group/{group_id}"
            properties = {
                "group_id": group_id,
                "group_name": item.get("GroupName"),
                "vpc_id": item.get("VpcId"),
                "is_default": item.get("IsDefault", False),
                "allows_unrestricted_cifs": item.get("AllowsUnrestrictedCifs", False),
                "allows_unrestricted_admin_ports_ipv4": item.get(
                    "AllowsUnrestrictedAdminPortsIpv4", False
                ),
                "allows_unrestricted_admin_ports_ipv6": item.get(
                    "AllowsUnrestrictedAdminPortsIpv6", False
                ),
                "default_allows_unrestricted_ingress": item.get(
                    "DefaultAllowsUnrestrictedIngress", False
                ),
            }
            tags = {}
        elif provider_type == "aws_ec2_network_acl":
            region = item.get("Region")
            nacl_id = item["NetworkAclId"]
            resource_id = f"arn:aws:ec2:{region}:{account_id}:network-acl/{nacl_id}"
            properties = {
                "network_acl_id": nacl_id,
                "vpc_id": item.get("VpcId"),
                "allows_unrestricted_admin_ports": item.get(
                    "AllowsUnrestrictedAdminPorts", False
                ),
            }
            tags = {}
        else:
            continue

        _append_resource(
            resources,
            tenant_id=tenant_id,
            scan_id=scan_id,
            integration_id=integration_id,
            account_id=account_id,
            resource_id=resource_id,
            resource_type=resource_type,
            provider_type=provider_type,
            properties=properties,
            tags=tags,
            region=region,
            collected_at=collected_at,
        )

    return resources, relationships
