#!/usr/bin/env python3
"""Generate aws_cspm_v1.yaml, cis_aws_v6.yaml, and platform-db migration from CIS fixture."""

from __future__ import annotations

import json
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURE = (
    REPO_ROOT.parent
    / "infra-state-docs"
    / "new arch"
    / "tests"
    / "fixtures"
    / "cis_aws_v6_controls.json"
)

# policy_id assignment (fixed — do not renumber after Phase A)
POLICY_IDS: dict[str, str] = {
    "iam-root-access-keys": "AWS_IAM_001",
    "iam-root-mfa": "AWS_IAM_002",
    "iam-password-min-length": "AWS_IAM_003",
    "iam-password-reuse": "AWS_IAM_004",
    "iam-user-mfa": "AWS_IAM_005",
    "iam-credentials-unused": "AWS_IAM_006",
    "iam-single-access-key": "AWS_IAM_007",
    "iam-access-key-rotation": "AWS_IAM_008",
    "iam-permissions-via-groups": "AWS_IAM_009",
    "iam-admin-policies": "AWS_IAM_010",
    "iam-support-role": "AWS_IAM_011",
    "iam-instance-roles": "AWS_IAM_012",
    "iam-expired-certificates": "AWS_IAM_013",
    "iam-access-analyzer": "AWS_IAM_014",
    "s3-deny-http": "AWS_S3_001",
    "s3-public-access": "AWS_S3_002",
    "s3-write-logging": "AWS_S3_003",
    "s3-read-logging": "AWS_S3_004",
    "rds-encryption": "AWS_RDS_001",
    "rds-auto-upgrade": "AWS_RDS_002",
    "rds-public": "AWS_RDS_003",
    "efs-encryption": "AWS_EFS_001",
    "cloudtrail-validation": "AWS_LOG_001",
    "config-enabled": "AWS_LOG_002",
    "cloudtrail-kms": "AWS_LOG_003",
    "kms-rotation": "AWS_LOG_004",
    "vpc-flow-logs": "AWS_LOG_005",
    "security-hub-enabled": "AWS_LOG_006",
    "ebs-encryption-default": "AWS_NET_001",
    "cifs-restricted": "AWS_NET_002",
    "nacl-admin-ports": "AWS_NET_003",
    "sg-admin-ports-ipv4": "AWS_NET_004",
    "sg-admin-ports-ipv6": "AWS_NET_005",
    "default-sg-restricts-traffic": "AWS_NET_006",
    "ec2-imdsv2": "AWS_NET_007",
}

RESOURCE_TYPES: dict[str, tuple[str, str, str]] = {
    "iam-root-access-keys": ("identity.account", "aws_iam_account", "iam"),
    "iam-root-mfa": ("identity.account", "aws_iam_account", "iam"),
    "iam-password-min-length": ("identity.account", "aws_iam_account_password_policy", "iam"),
    "iam-password-reuse": ("identity.account", "aws_iam_account_password_policy", "iam"),
    "iam-user-mfa": ("identity.user", "aws_iam_user", "iam"),
    "iam-credentials-unused": ("identity.user", "aws_iam_user", "iam"),
    "iam-single-access-key": ("identity.user", "aws_iam_user", "iam"),
    "iam-access-key-rotation": ("identity.user", "aws_iam_user", "iam"),
    "iam-permissions-via-groups": ("identity.user", "aws_iam_user", "iam"),
    "iam-admin-policies": ("identity.user", "aws_iam_user", "iam"),
    "iam-support-role": ("identity.account", "aws_iam_account", "iam"),
    "iam-instance-roles": ("compute.instance", "aws_ec2_instance", "iam"),
    "iam-expired-certificates": ("identity.certificate", "aws_iam_server_certificate", "iam"),
    "iam-access-analyzer": ("identity.account", "aws_iam_access_analyzer", "iam"),
    "s3-deny-http": ("storage.bucket", "aws_s3_bucket", "s3"),
    "s3-public-access": ("storage.bucket", "aws_s3_bucket", "s3"),
    "s3-write-logging": ("storage.bucket", "aws_s3_bucket", "s3"),
    "s3-read-logging": ("storage.bucket", "aws_s3_bucket", "s3"),
    "rds-encryption": ("database.instance", "aws_rds_instance", "rds"),
    "rds-auto-upgrade": ("database.instance", "aws_rds_instance", "rds"),
    "rds-public": ("database.instance", "aws_rds_instance", "rds"),
    "efs-encryption": ("storage.filesystem", "aws_efs_file_system", "efs"),
    "cloudtrail-validation": ("governance.trail", "aws_cloudtrail_trail", "logging"),
    "config-enabled": ("governance.config", "aws_config_configuration_recorder", "logging"),
    "cloudtrail-kms": ("governance.trail", "aws_cloudtrail_trail", "logging"),
    "kms-rotation": ("security.key", "aws_kms_key", "logging"),
    "vpc-flow-logs": ("network.vpc", "aws_ec2_vpc", "logging"),
    "security-hub-enabled": ("governance.hub", "aws_securityhub_hub", "logging"),
    "ebs-encryption-default": ("identity.account", "aws_account_ebs_encryption", "network"),
    "cifs-restricted": ("network.security_group", "aws_ec2_security_group", "network"),
    "nacl-admin-ports": ("network.nacl", "aws_ec2_network_acl", "network"),
    "sg-admin-ports-ipv4": ("network.security_group", "aws_ec2_security_group", "network"),
    "sg-admin-ports-ipv6": ("network.security_group", "aws_ec2_security_group", "network"),
    "default-sg-restricts-traffic": ("network.security_group", "aws_ec2_security_group", "network"),
    "ec2-imdsv2": ("compute.instance", "aws_ec2_instance", "network"),
}

SEVERITY: dict[str, str] = {
    "iam-root-access-keys": "critical",
    "iam-root-mfa": "critical",
    "iam-password-min-length": "medium",
    "iam-password-reuse": "medium",
    "iam-user-mfa": "high",
    "iam-credentials-unused": "medium",
    "iam-single-access-key": "medium",
    "iam-access-key-rotation": "medium",
    "iam-permissions-via-groups": "medium",
    "iam-admin-policies": "high",
    "iam-support-role": "low",
    "iam-instance-roles": "medium",
    "iam-expired-certificates": "medium",
    "iam-access-analyzer": "medium",
    "s3-deny-http": "high",
    "s3-public-access": "critical",
    "s3-write-logging": "medium",
    "s3-read-logging": "medium",
    "rds-encryption": "high",
    "rds-auto-upgrade": "medium",
    "rds-public": "critical",
    "efs-encryption": "high",
    "cloudtrail-validation": "medium",
    "config-enabled": "medium",
    "cloudtrail-kms": "medium",
    "kms-rotation": "medium",
    "vpc-flow-logs": "medium",
    "security-hub-enabled": "medium",
    "ebs-encryption-default": "high",
    "cifs-restricted": "medium",
    "nacl-admin-ports": "high",
    "sg-admin-ports-ipv4": "high",
    "sg-admin-ports-ipv6": "high",
    "default-sg-restricts-traffic": "medium",
    "ec2-imdsv2": "high",
}

TITLES: dict[str, str] = {
    "iam-root-access-keys": "Root user must not have access keys",
    "iam-root-mfa": "Root user must have MFA enabled",
    "iam-password-min-length": "IAM password policy minimum length",
    "iam-password-reuse": "IAM password policy prevents reuse",
    "iam-user-mfa": "IAM user must have MFA enabled",
    "iam-credentials-unused": "Unused IAM credentials must be disabled",
    "iam-single-access-key": "IAM user must have at most one active access key",
    "iam-access-key-rotation": "IAM access keys must be rotated within 90 days",
    "iam-permissions-via-groups": "IAM users must receive permissions via groups",
    "iam-admin-policies": "IAM users must not have full admin policies attached",
    "iam-support-role": "AWS Support role must exist",
    "iam-instance-roles": "EC2 instances must use IAM instance roles",
    "iam-expired-certificates": "Expired IAM SSL/TLS certificates must be removed",
    "iam-access-analyzer": "IAM Access Analyzer must be enabled",
    "s3-deny-http": "S3 bucket policy must deny HTTP requests",
    "s3-public-access": "S3 bucket must block public access",
    "s3-write-logging": "S3 bucket write events must be logged",
    "s3-read-logging": "S3 bucket read events must be logged",
    "rds-encryption": "RDS instance encryption at rest must be enabled",
    "rds-auto-upgrade": "RDS auto minor version upgrade must be enabled",
    "rds-public": "RDS instances must not be publicly accessible",
    "efs-encryption": "EFS file systems must be encrypted",
    "cloudtrail-validation": "CloudTrail log file validation must be enabled",
    "config-enabled": "AWS Config must be enabled",
    "cloudtrail-kms": "CloudTrail logs must use KMS encryption",
    "kms-rotation": "KMS key rotation must be enabled",
    "vpc-flow-logs": "VPC flow logging must be enabled",
    "security-hub-enabled": "AWS Security Hub must be enabled",
    "ebs-encryption-default": "EBS default encryption must be enabled",
    "cifs-restricted": "CIFS access must be restricted",
    "nacl-admin-ports": "NACLs must not allow unrestricted admin ports",
    "sg-admin-ports-ipv4": "Security groups must not allow unrestricted admin ports (IPv4)",
    "sg-admin-ports-ipv6": "Security groups must not allow unrestricted admin ports (IPv6)",
    "default-sg-restricts-traffic": "Default security group must restrict all traffic",
    "ec2-imdsv2": "EC2 instances must require IMDSv2",
}

IMPLEMENTED = frozenset(POLICY_IDS.values())


def load_controls() -> list[dict]:
    data = json.loads(FIXTURE.read_text(encoding="utf-8"))
    for row in data:
        ref = row["control_ref"]
        if ref not in POLICY_IDS:
            raise KeyError(f"missing policy_id for control_ref {ref}")
    return data


def write_aws_cspm_v1(controls: list[dict], path: Path) -> None:
    lines = [
        "# Unified AWS CSPM policy catalog — CIS AWS v6 automated subset (35 policies)",
        "# Source: infra-state-docs/new arch/tests/fixtures/cis_aws_v6_controls.json",
        "version: '1.0.0'",
        "pack_id: pack_aws_cis_v6",
        "framework_id: cis_aws_v6",
        "policies:",
    ]
    for row in controls:
        ref = row["control_ref"]
        policy_id = POLICY_IDS[ref]
        resource_type, provider_type, collector = RESOURCE_TYPES[ref]
        status = "implemented" if policy_id in IMPLEMENTED else "planned"
        lines.extend(
            [
                f"  - policy_id: {policy_id}",
                f"    control_ref: {ref}",
                f"    cis_control_id: '{row['control_id']}'",
                f"    domain: {row['domain']}",
                f"    title: {TITLES[ref]}",
                f"    severity: {SEVERITY[ref]}",
                f"    resource_type: {resource_type}",
                f"    provider_type: {provider_type}",
                f"    collector: {collector}",
                f"    status: {status}",
            ]
        )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_cis_mappings(controls: list[dict], path: Path) -> None:
    lines = [
        "# CIS AWS v6 — policy_id to control_id mappings (one policy per control)",
        "framework_id: cis_aws_v6",
        "mappings:",
    ]
    for row in controls:
        ref = row["control_ref"]
        policy_id = POLICY_IDS[ref]
        lines.append(f"  - policy_id: {policy_id}")
        lines.append(f"    control_id: '{row['control_id']}'")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_migration(controls: list[dict], path: Path) -> None:
    values = []
    for row in controls:
        ref = row["control_ref"]
        policy_id = POLICY_IDS[ref]
        control_id = row["control_id"].replace("'", "''")
        values.append(f"  ('cis_aws_v6', '{control_id}', '{policy_id}')")
    sql = f"""-- platform-db migration 010
-- Full CIS AWS v6 policy mappings (35 policies -> 35 controls)
-- Generated by compliance-engine/scripts/build_policy_catalog.py

DELETE FROM compliance_v2.policy_mappings WHERE framework_id = 'cis_aws_v6';

INSERT INTO compliance_v2.policy_mappings (framework_id, control_id, policy_id)
VALUES
{",\n".join(values)}
ON CONFLICT (framework_id, control_id, policy_id) DO NOTHING;
"""
    path.write_text(sql, encoding="utf-8")


def main() -> None:
    controls = load_controls()
    assert len(controls) == 35, f"expected 35 controls, got {len(controls)}"
    write_aws_cspm_v1(controls, REPO_ROOT / "policy" / "catalog" / "aws_cspm_v1.yaml")
    write_cis_mappings(
        controls, REPO_ROOT / "policy" / "catalog" / "mappings" / "cis_aws_v6.yaml"
    )
    write_migration(
        controls,
        REPO_ROOT.parent / "platform-db" / "migrations" / "010_cis_policy_mappings.sql",
    )
    print("Wrote aws_cspm_v1.yaml, cis_aws_v6.yaml, 010_cis_policy_mappings.sql")


if __name__ == "__main__":
    main()
