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


def _cloud_provider(provider_type: str) -> str:
    return "azure" if provider_type.startswith("azure_") else "aws"


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
    provider: str | None = None,
) -> None:
    resources.append(
        {
            "tenant_id": tenant_id,
            "scan_id": scan_id,
            "resource_id": resource_id,
            "resource_type": resource_type,
            "provider": provider or _cloud_provider(provider_type),
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
                "has_public_ip": bool(item.get("PublicIpAddress")),
                "detailed_monitoring": item.get("MonitoringState") == "enabled",
                "termination_protected": item.get("TerminationProtected", False),
                "http_endpoint": item.get("HttpEndpoint", "enabled"),
                "http_put_response_hop_limit": item.get("HttpPutResponseHopLimit", 1),
                "source_dest_check": item.get("SourceDestCheck", True),
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
            logs_exports = item.get("EnabledCloudwatchLogsExports") or []
            properties = {
                "db_instance_identifier": item.get("DBInstanceIdentifier"),
                "storage_encrypted": item.get("StorageEncrypted", False),
                "auto_minor_version_upgrade": item.get("AutoMinorVersionUpgrade", False),
                "publicly_accessible": item.get("PubliclyAccessible", False),
                "backup_retention_period": item.get("BackupRetentionPeriod", 0),
                "multi_az": item.get("MultiAZ", False),
                "deletion_protection": item.get("DeletionProtection", False),
                "iam_database_authentication_enabled": item.get(
                    "IAMDatabaseAuthenticationEnabled", False
                ),
                "has_cloudwatch_logs_exports": len(logs_exports) > 0,
                "monitoring_interval": item.get("MonitoringInterval", 0),
                "performance_insights_enabled": item.get("PerformanceInsightsEnabled", False),
                "engine": item.get("Engine"),
            }
            tags = {}
        elif provider_type == "aws_rds_cluster":
            resource_id = item["DBClusterArn"]
            region = item.get("Region")
            properties = {
                "db_cluster_identifier": item.get("DBClusterIdentifier"),
                "storage_encrypted": item.get("StorageEncrypted", False),
                "deletion_protection": item.get("DeletionProtection", False),
                "backup_retention_period": item.get("BackupRetentionPeriod", 0),
                "iam_database_authentication_enabled": item.get(
                    "IAMDatabaseAuthenticationEnabled", False
                ),
            }
            tags = {}
        elif provider_type == "aws_rds_snapshot":
            region = item.get("Region")
            resource_id = item["DBSnapshotArn"]
            properties = {
                "db_snapshot_identifier": item.get("DBSnapshotIdentifier"),
                "encrypted": item.get("Encrypted", False),
                "public": item.get("Public", False),
                "status": item.get("Status"),
            }
            tags = {}
        elif provider_type == "aws_dynamodb_table":
            region = item.get("Region")
            resource_id = item["TableArn"]
            properties = {
                "table_name": item.get("TableName"),
                "sse_enabled": item.get("SseEnabled", False),
                "point_in_time_recovery_enabled": item.get("PointInTimeRecoveryEnabled", False),
                "deletion_protection_enabled": item.get("DeletionProtectionEnabled", False),
            }
            tags = {}
        elif provider_type == "aws_elasticache_replication_group":
            region = item.get("Region")
            resource_id = item.get("ARN") or item["ReplicationGroupId"]
            properties = {
                "replication_group_id": item.get("ReplicationGroupId"),
                "at_rest_encryption_enabled": item.get("AtRestEncryptionEnabled", False),
                "transit_encryption_enabled": item.get("TransitEncryptionEnabled", False),
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
                "allows_ssh_from_internet_ipv4": item.get("AllowsSshFromInternetIpv4", False),
                "allows_rdp_from_internet_ipv4": item.get("AllowsRdpFromInternetIpv4", False),
                "allows_all_traffic_from_internet_ipv4": item.get(
                    "AllowsAllTrafficFromInternetIpv4", False
                ),
                "allows_all_traffic_from_internet_ipv6": item.get(
                    "AllowsAllTrafficFromInternetIpv6", False
                ),
                "allows_postgres_from_internet_ipv4": item.get(
                    "AllowsPostgresFromInternetIpv4", False
                ),
                "allows_mysql_from_internet_ipv4": item.get("AllowsMysqlFromInternetIpv4", False),
                "allows_redis_from_internet_ipv4": item.get("AllowsRedisFromInternetIpv4", False),
                "allows_mongodb_from_internet_ipv4": item.get(
                    "AllowsMongodbFromInternetIpv4", False
                ),
                "allows_elasticsearch_from_internet_ipv4": item.get(
                    "AllowsElasticsearchFromInternetIpv4", False
                ),
                "allows_ftp_from_internet_ipv4": item.get("AllowsFtpFromInternetIpv4", False),
                "allows_telnet_from_internet_ipv4": item.get("AllowsTelnetFromInternetIpv4", False),
                "default_allows_unrestricted_ingress": item.get(
                    "DefaultAllowsUnrestrictedIngress", False
                ),
            }
            tags = {}
        elif provider_type == "aws_ec2_ami":
            region = item.get("Region")
            image_id = item["ImageId"]
            resource_id = f"arn:aws:ec2:{region}:{account_id}:image/{image_id}"
            properties = {
                "image_id": image_id,
                "name": item.get("Name"),
                "public": item.get("Public", False),
                "root_unencrypted": item.get("RootUnencrypted", False),
            }
            tags = {}
        elif provider_type == "aws_ebs_snapshot":
            region = item.get("Region")
            snapshot_id = item["SnapshotId"]
            resource_id = f"arn:aws:ec2:{region}:{account_id}:snapshot/{snapshot_id}"
            properties = {
                "snapshot_id": snapshot_id,
                "encrypted": item.get("Encrypted", False),
                "public": item.get("Public", False),
                "state": item.get("State"),
            }
            tags = {}
        elif provider_type == "aws_ec2_account_setting":
            region = item.get("Region")
            resource_id = f"arn:aws:ec2:{region}:{account_id}:account-settings/ec2"
            properties = {
                "region": region,
                "serial_console_access_enabled": item.get("SerialConsoleAccessEnabled", False),
                "has_default_vpc": item.get("HasDefaultVpc", False),
            }
            tags = {}
        elif provider_type == "aws_lambda_function":
            region = item.get("Region")
            function_name = item["FunctionName"]
            resource_id = item["FunctionArn"]
            properties = {
                "function_name": function_name,
                "runtime": item.get("Runtime"),
                "runtime_deprecated": item.get("RuntimeDeprecated", False),
                "tracing_mode": item.get("TracingMode"),
                "has_dead_letter_queue": item.get("HasDeadLetterQueue", False),
                "publicly_accessible": item.get("PubliclyAccessible", False),
                "function_url_auth_none": item.get("FunctionUrlAuthNone", False),
            }
            tags = {}
        elif provider_type == "aws_guardduty_detector":
            region = item.get("Region")
            detector_id = item.get("DetectorId") or "none"
            resource_id = f"arn:aws:guardduty:{region}:{account_id}:detector/{detector_id}"
            properties = {
                "region": region,
                "detector_id": item.get("DetectorId"),
                "enabled": item.get("Enabled", False),
                "s3_protection_enabled": item.get("S3ProtectionEnabled", False),
                "lambda_protection_enabled": item.get("LambdaProtectionEnabled", False),
                "eks_audit_logs_enabled": item.get("EksAuditLogsEnabled", False),
                "rds_login_events_enabled": item.get("RdsLoginEventsEnabled", False),
            }
            tags = {}
        elif provider_type == "aws_ebs_volume":
            region = item.get("Region")
            volume_id = item["VolumeId"]
            resource_id = f"arn:aws:ec2:{region}:{account_id}:volume/{volume_id}"
            properties = {
                "volume_id": volume_id,
                "encrypted": item.get("Encrypted", False),
                "state": item.get("State"),
                "size_gb": item.get("Size"),
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
        elif provider_type == "azure_storage_account":
            resource_id = item["id"]
            region = item.get("location")
            min_tls = item.get("minimum_tls_version") or ""
            properties = {
                "name": item.get("name"),
                "subscription_id": item.get("subscription_id", account_id),
                "enable_https_traffic_only": item.get("enable_https_traffic_only", False),
                "supports_https_traffic_only": item.get(
                    "supports_https_traffic_only",
                    item.get("enable_https_traffic_only", False),
                ),
                "minimum_tls_version": min_tls,
                "min_tls_1_2": "1.2" in str(min_tls) or "TLS1_2" in str(min_tls).upper(),
                "allow_blob_public_access": item.get("allow_blob_public_access"),
                "public_network_access": item.get("public_network_access"),
            }
            tags = {}
        elif provider_type == "azure_network_security_group":
            resource_id = item["id"]
            region = item.get("location")
            properties = {
                "name": item.get("name"),
                "resource_group": item.get("resource_group"),
                "allows_ssh_from_internet_ipv4": item.get("AllowsSshFromInternet", False),
                "allows_rdp_from_internet_ipv4": item.get("AllowsRdpFromInternet", False),
                "allows_unrestricted_admin_ports_ipv4": item.get(
                    "AllowsUnrestrictedAdminPorts", False
                ),
            }
            tags = {}
        elif provider_type == "azure_virtual_network":
            resource_id = item["id"]
            region = item.get("location")
            properties = {
                "name": item.get("name"),
                "resource_group": item.get("resource_group"),
                "address_space": item.get("address_space", []),
            }
            tags = {}
        elif provider_type == "azure_virtual_machine":
            resource_id = item["id"]
            region = item.get("location")
            properties = {
                "name": item.get("name"),
                "resource_group": item.get("resource_group"),
                "has_public_ip": item.get("has_public_ip", False),
                "os_disk_encrypted": item.get("os_disk_encrypted"),
                "provisioning_state": item.get("provisioning_state"),
            }
            tags = {}
            vnet_id = item.get("vnet_id")
            if vnet_id:
                relationships.append(
                    {
                        "from_resource_id": resource_id,
                        "to_resource_id": vnet_id,
                        "relationship_type": "member_of",
                        "properties": {},
                    }
                )
            for nsg_id in item.get("network_security_group_ids") or []:
                relationships.append(
                    {
                        "from_resource_id": resource_id,
                        "to_resource_id": nsg_id,
                        "relationship_type": "protected_by",
                        "properties": {},
                    }
                )
        elif provider_type == "azure_managed_disk":
            resource_id = item["id"]
            region = item.get("location")
            properties = {
                "name": item.get("name"),
                "resource_group": item.get("resource_group"),
                "encryption_type": item.get("encryption_type"),
                "disk_size_gb": item.get("disk_size_gb"),
            }
            tags = {}
        elif provider_type == "azure_subscription":
            resource_id = f"/subscriptions/{account_id}"
            properties = {
                "subscription_id": item.get("subscription_id", account_id),
                "owner_role_assignment_count": item.get("owner_role_assignment_count", 0),
                "too_many_owners": item.get("too_many_owners", False),
            }
            tags = {}
            region = None
        elif provider_type == "azure_key_vault":
            resource_id = item["id"]
            region = item.get("location")
            properties = {
                "name": item.get("name"),
                "resource_group": item.get("resource_group"),
                "enable_soft_delete": item.get("enable_soft_delete", False),
                "soft_delete_retention_in_days": item.get("soft_delete_retention_in_days"),
                "enable_purge_protection": item.get("enable_purge_protection", False),
                "public_network_access": item.get("public_network_access"),
            }
            tags = {}
        elif provider_type == "azure_defender":
            resource_id = f"/subscriptions/{account_id}/providers/Microsoft.Security/defender"
            properties = {
                "subscription_id": item.get("subscription_id", account_id),
                "defender_standard_enabled": item.get("defender_standard_enabled", False),
                "standard_plan_count": item.get("standard_plan_count", 0),
                "pricing_plans": item.get("pricing_plans", []),
            }
            tags = {}
            region = None
        elif provider_type == "azure_sql_server":
            resource_id = item["id"]
            region = item.get("location")
            public_access = str(item.get("public_network_access", "")).lower()
            properties = {
                "name": item.get("name"),
                "resource_group": item.get("resource_group"),
                "kind": item.get("kind", "sql_server"),
                "public_network_access": item.get("public_network_access"),
                "publicly_accessible": public_access in {"enabled", "true"},
                "minimal_tls_version": item.get("minimal_tls_version"),
                "tls_enforced": str(item.get("minimal_tls_version", "")) in {"1.2", "1.3"},
            }
            tags = {}
        elif provider_type == "azure_postgresql_server":
            resource_id = item["id"]
            region = item.get("location")
            public_access = str(item.get("public_network_access", "")).lower()
            properties = {
                "name": item.get("name"),
                "resource_group": item.get("resource_group"),
                "kind": item.get("kind", "postgresql_flexible"),
                "public_network_access": item.get("public_network_access"),
                "publicly_accessible": public_access in {"enabled", "true"},
                "version": item.get("version"),
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
