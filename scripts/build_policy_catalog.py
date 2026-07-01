#!/usr/bin/env python3
"""Generate aws_cspm_v1.yaml, cis_aws_v6.yaml, sync policy YAMLs, and platform-db migration."""

from __future__ import annotations

import json
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
GENERATED_MIGRATIONS_DIR = REPO_ROOT / "generated" / "migrations"
PLATFORM_DB_MIGRATIONS_DIR = REPO_ROOT.parent / "platform-db" / "migrations"
POLICIES_DIR = REPO_ROOT / "policy" / "catalog" / "policies"


def write_migration_sql(filename: str, sql: str) -> None:
    """Write migration SQL for CI (generated/) and platform-db sibling when checked out."""
    GENERATED_MIGRATIONS_DIR.mkdir(parents=True, exist_ok=True)
    (GENERATED_MIGRATIONS_DIR / filename).write_text(sql, encoding="utf-8")
    if PLATFORM_DB_MIGRATIONS_DIR.is_dir():
        (PLATFORM_DB_MIGRATIONS_DIR / filename).write_text(sql, encoding="utf-8")


PACKS_DIR = REPO_ROOT / "policy" / "catalog" / "packs"
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

# Customer-facing titles (ADR-015) — paraphrased, not verbatim CIS wording
DISPLAY_TITLES: dict[str, str] = {
    "AWS_IAM_001": "Root account has active access keys",
    "AWS_IAM_002": "Root account missing MFA",
    "AWS_IAM_003": "Weak IAM password length policy",
    "AWS_IAM_004": "IAM password reuse not restricted",
    "AWS_IAM_005": "IAM user without MFA",
    "AWS_IAM_006": "Unused IAM credentials still active",
    "AWS_IAM_007": "IAM user has multiple active access keys",
    "AWS_IAM_008": "Stale IAM access key detected",
    "AWS_IAM_009": "IAM user has direct policy attachments",
    "AWS_IAM_010": "IAM user has administrator access",
    "AWS_IAM_011": "AWS Support access role missing",
    "AWS_IAM_012": "EC2 instance missing IAM role",
    "AWS_IAM_013": "Expired IAM server certificate",
    "AWS_IAM_014": "IAM Access Analyzer disabled",
    "AWS_S3_001": "S3 bucket allows insecure HTTP",
    "AWS_S3_002": "Public S3 bucket detected",
    "AWS_S3_003": "S3 write activity not logged",
    "AWS_S3_004": "S3 read activity not logged",
    "AWS_RDS_001": "RDS storage encryption disabled",
    "AWS_RDS_002": "RDS auto minor version upgrade disabled",
    "AWS_RDS_003": "RDS instance publicly accessible",
    "AWS_EFS_001": "EFS encryption disabled",
    "AWS_LOG_001": "CloudTrail log validation disabled",
    "AWS_LOG_002": "AWS Config not enabled",
    "AWS_LOG_003": "CloudTrail logs not KMS encrypted",
    "AWS_LOG_004": "KMS key rotation disabled",
    "AWS_LOG_005": "VPC flow logs disabled",
    "AWS_LOG_006": "Security Hub not enabled",
    "AWS_NET_001": "Default EBS encryption disabled",
    "AWS_NET_002": "Unrestricted CIFS in security group",
    "AWS_NET_003": "NACL allows unrestricted admin ports",
    "AWS_NET_004": "Security group allows admin ports (IPv4)",
    "AWS_NET_005": "Security group allows admin ports (IPv6)",
    "AWS_NET_006": "Default security group not restrictive",
    "AWS_NET_007": "EC2 instance not requiring IMDSv2",
}

PACK_BY_POLICY_ID: dict[str, str] = {
    "AWS_IAM_001": "pack_aws_identity",
    "AWS_IAM_002": "pack_aws_identity",
    "AWS_IAM_003": "pack_aws_identity",
    "AWS_IAM_004": "pack_aws_identity",
    "AWS_IAM_005": "pack_aws_identity",
    "AWS_IAM_006": "pack_aws_identity",
    "AWS_IAM_007": "pack_aws_identity",
    "AWS_IAM_008": "pack_aws_identity",
    "AWS_IAM_009": "pack_aws_identity",
    "AWS_IAM_010": "pack_aws_identity",
    "AWS_IAM_011": "pack_aws_identity",
    "AWS_IAM_012": "pack_aws_identity",
    "AWS_IAM_013": "pack_aws_identity",
    "AWS_IAM_014": "pack_aws_identity",
    "AWS_S3_001": "pack_aws_storage",
    "AWS_S3_002": "pack_aws_storage",
    "AWS_S3_003": "pack_aws_storage",
    "AWS_S3_004": "pack_aws_storage",
    "AWS_EFS_001": "pack_aws_storage",
    "AWS_RDS_001": "pack_aws_data",
    "AWS_RDS_002": "pack_aws_data",
    "AWS_RDS_003": "pack_aws_data",
    "AWS_LOG_001": "pack_aws_logging",
    "AWS_LOG_002": "pack_aws_logging",
    "AWS_LOG_003": "pack_aws_logging",
    "AWS_LOG_004": "pack_aws_logging",
    "AWS_LOG_005": "pack_aws_logging",
    "AWS_LOG_006": "pack_aws_logging",
    "AWS_NET_001": "pack_aws_network",
    "AWS_NET_002": "pack_aws_network",
    "AWS_NET_003": "pack_aws_network",
    "AWS_NET_004": "pack_aws_network",
    "AWS_NET_005": "pack_aws_network",
    "AWS_NET_006": "pack_aws_network",
    "AWS_NET_007": "pack_aws_network",
}


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
        "pack_id: pack_aws_core",
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
                f"    display_title: {DISPLAY_TITLES[policy_id]}",
                f"    title: {TITLES[ref]}",
                f"    pack_id: {PACK_BY_POLICY_ID[policy_id]}",
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


DEFAULT_POLICY_VERSION = "1.0.0"


def ensure_policy_versions() -> None:
    """Ensure every policy YAML has a semver for control versioning."""
    for path in sorted(POLICIES_DIR.glob("AWS_*.yaml")):
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        if data.get("version"):
            continue
        data["version"] = DEFAULT_POLICY_VERSION
        path.write_text(
            yaml.dump(data, sort_keys=False, allow_unicode=True, default_flow_style=False),
            encoding="utf-8",
        )


def sync_policy_yaml_files(controls: list[dict]) -> None:
    """Merge display_title and pack_id into policies/*.yaml (runtime fields only)."""
    for ref, policy_id in POLICY_IDS.items():
        path = POLICIES_DIR / f"{policy_id}.yaml"
        if not path.is_file():
            continue
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        data["display_title"] = DISPLAY_TITLES[policy_id]
        data["pack_id"] = PACK_BY_POLICY_ID[policy_id]
        data.setdefault("version", DEFAULT_POLICY_VERSION)
        data.pop("internal_reference", None)
        data.pop("cis_control_id", None)
        rem = data.get("remediation")
        if isinstance(rem, dict) and rem.get("headline") == TITLES[ref]:
            rem["headline"] = DISPLAY_TITLES[policy_id]
        path.write_text(
            yaml.dump(data, sort_keys=False, allow_unicode=True, default_flow_style=False),
            encoding="utf-8",
        )


def write_packs_yaml(
    w1_policies: list[dict] | None = None,
    w2_policies: list[dict] | None = None,
    w3_policies: list[dict] | None = None,
) -> None:
    w1_policies = w1_policies or []
    w2_policies = w2_policies or []
    w3_policies = w3_policies or []
    w1_ids = [p["policy_id"] for p in w1_policies]
    w2_ids = [p["policy_id"] for p in w2_policies]
    w3_ids = [p["policy_id"] for p in w3_policies]
    expansion_ids = sorted(w1_ids + w2_ids + w3_ids)
    all_core_ids = sorted(DISPLAY_TITLES.keys()) + expansion_ids
    PACKS_DIR.mkdir(parents=True, exist_ok=True)
    packs: dict[str, dict[str, object]] = {
        "pack_aws_identity": {
            "display_title": "Identity & access",
            "description": "IAM users, credentials, password policy, and access analyzer",
            "policy_ids": [],
        },
        "pack_aws_storage": {
            "display_title": "Storage",
            "description": "S3 buckets and EFS file systems",
            "policy_ids": [],
        },
        "pack_aws_data": {
            "display_title": "Data services",
            "description": "RDS, Aurora, DynamoDB, ElastiCache, and database snapshots",
            "policy_ids": sorted(w3_ids),
        },
        "pack_aws_logging": {
            "display_title": "Logging & monitoring",
            "description": "CloudTrail, Config, KMS, VPC flow logs, Security Hub",
            "policy_ids": [],
        },
        "pack_aws_network": {
            "display_title": "Network",
            "description": "Security groups, NACLs, EBS encryption, EC2 metadata",
            "policy_ids": [],
        },
        "pack_aws_compute_security": {
            "display_title": "Compute security",
            "description": "Lambda, GuardDuty, EC2 exposure, EBS encryption, remote access",
            "policy_ids": sorted(w1_ids),
        },
        "pack_aws_compute": {
            "display_title": "Compute services",
            "description": "EC2 hardening, AMIs, EBS snapshots, and compute network exposure",
            "policy_ids": sorted(w2_ids),
        },
        "pack_aws_core": {
            "display_title": "AWS core security",
            "description": "All Drantiq AWS security controls (default bundle)",
            "policy_ids": all_core_ids,
        },
    }
    for policy_id, pack_id in PACK_BY_POLICY_ID.items():
        if pack_id != "pack_aws_core":
            packs[pack_id]["policy_ids"].append(policy_id)  # type: ignore[union-attr]
    for pid, body in packs.items():
        if pid != "pack_aws_core":
            body["policy_ids"] = sorted(body["policy_ids"])  # type: ignore[arg-type]
    out = {
        "version": "1.0.0",
        "packs": [{"pack_id": pid, **{k: v for k, v in body.items() if k != "policy_ids"}, "policy_ids": body["policy_ids"]} for pid, body in packs.items()],
    }
    (PACKS_DIR / "aws.yaml").write_text(
        yaml.dump(out, sort_keys=False, allow_unicode=True, default_flow_style=False),
        encoding="utf-8",
    )


def _sql_str(value: str) -> str:
    return value.replace("'", "''")


def load_nist_policy_mappings() -> dict[str, list[str]]:
    """Map NIST 800-53 control id -> policy_ids from policy YAML framework_mappings."""
    grouped: dict[str, set[str]] = {}
    for policy_id in DISPLAY_TITLES:
        path = POLICIES_DIR / f"{policy_id}.yaml"
        if not path.is_file():
            continue
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        rem = data.get("remediation") or {}
        for mapping in rem.get("framework_mappings") or []:
            text = str(mapping).strip()
            if not text.upper().startswith("NIST "):
                continue
            nist_id = text.split(" ", 1)[1].strip()
            grouped.setdefault(nist_id, set()).add(policy_id)
    return {nist_id: sorted(policies) for nist_id, policies in sorted(grouped.items())}


def write_commercial_compliance_migration(controls: list[dict]) -> None:
    """Generate platform-db migration 017 — commercial framework visibility + seeds."""
    nist_by_control = load_nist_policy_mappings()
    drantiq_controls: list[str] = []
    drantiq_mappings: list[str] = []
    for policy_id in sorted(DISPLAY_TITLES):
        row = next((r for r in controls if POLICY_IDS[r["control_ref"]] == policy_id), None)
        if not row:
            continue
        ref = row["control_ref"]
        display = _sql_str(DISPLAY_TITLES[policy_id])
        title = _sql_str(TITLES[ref])
        domain = row["domain"]
        severity = SEVERITY[ref]
        drantiq_controls.append(
            f"  ('drantiq_security_assessment_v1', '{policy_id}', '{ref}', "
            f"'{title}', '{display}', '{domain}', '{severity}', 'automated', true)"
        )
        drantiq_mappings.append(
            f"  ('drantiq_security_assessment_v1', '{policy_id}', '{policy_id}')"
        )

    nist_controls: list[str] = []
    nist_mapping_rows: list[str] = []
    for nist_id, policy_ids in nist_by_control.items():
        titles = [DISPLAY_TITLES[pid] for pid in policy_ids if pid in DISPLAY_TITLES]
        display = _sql_str(titles[0] if titles else f"NIST {nist_id}")
        title = _sql_str(f"NIST 800-53 {nist_id}")
        nist_controls.append(
            f"  ('nist_800_53_rev5_aws', '{nist_id}', '{nist_id}', "
            f"'{title}', '{display}', 'nist', 'medium', 'automated', true)"
        )
        for policy_id in policy_ids:
            nist_mapping_rows.append(
                f"  ('nist_800_53_rev5_aws', '{nist_id}', '{policy_id}')"
            )

    sql = f"""-- platform-db migration 017
-- Commercial compliance: customer_visible frameworks, Drantiq assessment seed (ADR-015)
-- Generated by compliance-engine/scripts/build_policy_catalog.py

ALTER TABLE compliance_v2.frameworks
  ADD COLUMN IF NOT EXISTS customer_visible BOOLEAN NOT NULL DEFAULT false,
  ADD COLUMN IF NOT EXISTS requires_license BOOLEAN NOT NULL DEFAULT false,
  ADD COLUMN IF NOT EXISTS display_title TEXT;

ALTER TABLE compliance_v2.controls
  ADD COLUMN IF NOT EXISTS display_title TEXT;

ALTER TABLE policy.policies
  ADD COLUMN IF NOT EXISTS display_title TEXT;

-- Hide licensed CIS framework from customer API
UPDATE compliance_v2.frameworks
SET customer_visible = false,
    requires_license = true,
    display_title = title
WHERE framework_id = 'cis_aws_v6';

-- Drantiq brand framework (customer primary)
INSERT INTO compliance_v2.frameworks (
  framework_id, title, provider, version_label, enabled, customer_visible, requires_license, display_title
)
VALUES (
  'drantiq_security_assessment_v1',
  'Drantiq Security Assessment',
  'aws',
  'v1.0.0',
  true,
  true,
  false,
  'Drantiq Security Assessment'
)
ON CONFLICT (framework_id) DO UPDATE
  SET title = EXCLUDED.title,
      display_title = EXCLUDED.display_title,
      customer_visible = true,
      requires_license = false,
      enabled = true;

INSERT INTO compliance_v2.framework_versions (framework_id, version_name, published_at)
VALUES ('drantiq_security_assessment_v1', 'v1.0.0', now())
ON CONFLICT (framework_id, version_name) DO NOTHING;

INSERT INTO compliance_v2.controls (
  framework_id, control_id, control_ref, title, display_title, domain, severity, assessment_type, enabled
)
VALUES
{",\n".join(drantiq_controls)}
ON CONFLICT (framework_id, control_id) DO UPDATE
  SET control_ref = EXCLUDED.control_ref,
      title = EXCLUDED.title,
      display_title = EXCLUDED.display_title,
      domain = EXCLUDED.domain,
      severity = EXCLUDED.severity;

INSERT INTO compliance_v2.policy_mappings (framework_id, control_id, policy_id)
VALUES
{",\n".join(drantiq_mappings)}
ON CONFLICT (framework_id, control_id, policy_id) DO NOTHING;

-- NIST 800-53 lens (subset mapped from policy catalog; expanded in P4)
INSERT INTO compliance_v2.frameworks (
  framework_id, title, provider, version_label, enabled, customer_visible, requires_license, display_title
)
VALUES (
  'nist_800_53_rev5_aws',
  'NIST SP 800-53 Rev. 5 (AWS)',
  'aws',
  'rev5',
  true,
  true,
  false,
  'NIST 800-53 (AWS)'
)
ON CONFLICT (framework_id) DO UPDATE
  SET title = EXCLUDED.title,
      display_title = EXCLUDED.display_title,
      customer_visible = true,
      requires_license = false,
      enabled = true;

INSERT INTO compliance_v2.framework_versions (framework_id, version_name, published_at)
VALUES ('nist_800_53_rev5_aws', 'rev5', now())
ON CONFLICT (framework_id, version_name) DO NOTHING;

INSERT INTO compliance_v2.controls (
  framework_id, control_id, control_ref, title, display_title, domain, severity, assessment_type, enabled
)
VALUES
{",\n".join(nist_controls) if nist_controls else "  ('nist_800_53_rev5_aws', 'AC-3', 'AC-3', 'NIST 800-53 AC-3', 'Access enforcement', 'nist', 'medium', 'automated', true)"}
ON CONFLICT (framework_id, control_id) DO UPDATE
  SET title = EXCLUDED.title,
      display_title = EXCLUDED.display_title;

INSERT INTO compliance_v2.policy_mappings (framework_id, control_id, policy_id)
VALUES
{",\n".join(nist_mapping_rows) if nist_mapping_rows else "  ('nist_800_53_rev5_aws', 'AC-3', 'AWS_S3_002')"}
ON CONFLICT (framework_id, control_id, policy_id) DO NOTHING;

-- Sync policy display_title from catalog (best-effort for existing rows)
"""
    for policy_id in sorted(DISPLAY_TITLES):
        sql += (
            f"UPDATE policy.policies SET display_title = '{_sql_str(DISPLAY_TITLES[policy_id])}' "
            f"WHERE policy_id = '{policy_id}';\n"
        )

    write_migration_sql("017_commercial_compliance.sql", sql)

    # Regenerated seed artifact for review — never overwrites applied migrations.
    generated = REPO_ROOT / "generated" / "compliance_framework_seed.sql"
    generated.parent.mkdir(parents=True, exist_ok=True)
    generated.write_text(
        "-- Generated compliance framework seed (review / manual apply only).\n"
        "-- Applied migrations in platform-db/migrations/ are immutable once shipped.\n\n"
        + sql,
        encoding="utf-8",
    )


NIST_BASELINE_YAML = REPO_ROOT / "policy" / "catalog" / "mappings" / "nist_800_53_rev5.yaml"


def load_nist_baseline() -> dict:
    return yaml.safe_load(NIST_BASELINE_YAML.read_text(encoding="utf-8"))


def write_nist_baseline_migration() -> None:
    """Write platform-db migration 022 — expanded NIST Moderate baseline (P4)."""
    data = load_nist_baseline()
    framework_id = data["framework_id"]
    control_rows: list[str] = []
    mapping_rows: list[str] = []
    control_ids: list[str] = []

    for control in data["controls"]:
        cid = control["control_id"]
        control_ids.append(cid)
        display = _sql_str(control["display_title"])
        title = _sql_str(control["title"])
        domain = _sql_str(control["domain"])
        severity = control["severity"]
        assessment_type = control["assessment_type"]
        control_rows.append(
            f"  ('{framework_id}', '{cid}', '{cid}', "
            f"'{title}', '{display}', '{domain}', '{severity}', "
            f"'{assessment_type}', true)"
        )
        for policy_id in control.get("policy_ids") or []:
            mapping_rows.append(f"  ('{framework_id}', '{cid}', '{policy_id}')")

    id_list = ", ".join(f"'{cid}'" for cid in control_ids)
    sql = f"""-- platform-db migration 022
-- Expand NIST SP 800-53 Rev. 5 AWS baseline (P4)
-- Generated by compliance-engine/scripts/build_policy_catalog.py

DELETE FROM compliance_v2.policy_mappings
WHERE framework_id = '{framework_id}';

UPDATE compliance_v2.controls
SET enabled = false
WHERE framework_id = '{framework_id}';

INSERT INTO compliance_v2.controls (
  framework_id, control_id, control_ref, title, display_title, domain, severity, assessment_type, enabled
)
VALUES
{",\n".join(control_rows)}
ON CONFLICT (framework_id, control_id) DO UPDATE
  SET control_ref = EXCLUDED.control_ref,
      title = EXCLUDED.title,
      display_title = EXCLUDED.display_title,
      domain = EXCLUDED.domain,
      severity = EXCLUDED.severity,
      assessment_type = EXCLUDED.assessment_type,
      enabled = true;

UPDATE compliance_v2.controls
SET enabled = false
WHERE framework_id = '{framework_id}'
  AND control_id NOT IN ({id_list});

INSERT INTO compliance_v2.policy_mappings (framework_id, control_id, policy_id)
VALUES
{",\n".join(mapping_rows) if mapping_rows else f"  ('{framework_id}', 'AC-3', 'AWS_S3_002')"}
ON CONFLICT (framework_id, control_id, policy_id) DO NOTHING;
"""
    write_migration_sql("022_nist_moderate_baseline.sql", sql)


SOC2_BASELINE_YAML = REPO_ROOT / "policy" / "catalog" / "mappings" / "soc2_aws.yaml"


def load_soc2_baseline() -> dict:
    return yaml.safe_load(SOC2_BASELINE_YAML.read_text(encoding="utf-8"))


def sync_soc2_remediation_mappings() -> None:
    """Merge SOC2 CC tags into policy remediation.framework_mappings (P5 W4)."""
    data = load_soc2_baseline()
    policy_to_soc2: dict[str, list[str]] = {}
    for control in data["controls"]:
        cid = control["control_id"]
        for policy_id in control.get("policy_ids") or []:
            tag = f"SOC2 {cid}"
            policy_to_soc2.setdefault(policy_id, [])
            if tag not in policy_to_soc2[policy_id]:
                policy_to_soc2[policy_id].append(tag)

    for path in sorted(POLICIES_DIR.glob("AWS_*.yaml")):
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
        policy_id = doc.get("policy_id")
        if not policy_id or policy_id not in policy_to_soc2:
            continue
        remediation = doc.setdefault("remediation", {})
        existing = list(remediation.get("framework_mappings") or [])
        for tag in policy_to_soc2[policy_id]:
            if tag not in existing:
                existing.append(tag)
        remediation["framework_mappings"] = existing
        path.write_text(yaml.safe_dump(doc, sort_keys=False, default_flow_style=False), encoding="utf-8")


def write_soc2_baseline_migration() -> None:
    """Write platform-db migration 026 — SOC 2 TSC AWS mapping (P5 W4)."""
    data = load_soc2_baseline()
    framework_id = data["framework_id"]
    version = data.get("version", "2017")
    control_rows: list[str] = []
    mapping_rows: list[str] = []
    control_ids: list[str] = []

    for control in data["controls"]:
        cid = control["control_id"]
        control_ids.append(cid)
        display = _sql_str(control["display_title"])
        title = _sql_str(control["title"])
        domain = _sql_str(control["domain"])
        severity = control["severity"]
        assessment_type = control["assessment_type"]
        control_rows.append(
            f"  ('{framework_id}', '{cid}', '{cid}', "
            f"'{title}', '{display}', '{domain}', '{severity}', "
            f"'{assessment_type}', true)"
        )
        for policy_id in control.get("policy_ids") or []:
            mapping_rows.append(f"  ('{framework_id}', '{cid}', '{policy_id}')")

    id_list = ", ".join(f"'{cid}'" for cid in control_ids)
    sql = f"""-- platform-db migration 026
-- SOC 2 Trust Services Criteria AWS mapping (P5 W4)
-- Generated by compliance-engine/scripts/build_policy_catalog.py

INSERT INTO compliance_v2.frameworks (
  framework_id, title, provider, version_label, enabled, customer_visible, requires_license, display_title
)
VALUES (
  '{framework_id}',
  'SOC 2 Trust Services Criteria (AWS technical)',
  'aws',
  '{version}',
  true,
  true,
  false,
  'SOC 2 (AWS)'
)
ON CONFLICT (framework_id) DO UPDATE
  SET title = EXCLUDED.title,
      display_title = EXCLUDED.display_title,
      customer_visible = true,
      requires_license = false,
      enabled = true;

INSERT INTO compliance_v2.framework_versions (framework_id, version_name, published_at)
VALUES ('{framework_id}', '{version}', now())
ON CONFLICT (framework_id, version_name) DO NOTHING;

DELETE FROM compliance_v2.policy_mappings
WHERE framework_id = '{framework_id}';

UPDATE compliance_v2.controls
SET enabled = false
WHERE framework_id = '{framework_id}';

INSERT INTO compliance_v2.controls (
  framework_id, control_id, control_ref, title, display_title, domain, severity, assessment_type, enabled
)
VALUES
{",\n".join(control_rows)}
ON CONFLICT (framework_id, control_id) DO UPDATE
  SET control_ref = EXCLUDED.control_ref,
      title = EXCLUDED.title,
      display_title = EXCLUDED.display_title,
      domain = EXCLUDED.domain,
      severity = EXCLUDED.severity,
      assessment_type = EXCLUDED.assessment_type,
      enabled = true;

UPDATE compliance_v2.controls
SET enabled = false
WHERE framework_id = '{framework_id}'
  AND control_id NOT IN ({id_list});

INSERT INTO compliance_v2.policy_mappings (framework_id, control_id, policy_id)
VALUES
{",\n".join(mapping_rows) if mapping_rows else f"  ('{framework_id}', 'CC6.1', 'AWS_IAM_002')"}
ON CONFLICT (framework_id, control_id, policy_id) DO NOTHING;
"""
    write_migration_sql("026_p5_soc2_mapping.sql", sql)


P5_W1_MANIFEST = REPO_ROOT / "policy" / "catalog" / "p5_w1_compute.yaml"
P5_W2_MANIFEST = REPO_ROOT / "policy" / "catalog" / "p5_w2_compute.yaml"
P5_W3_MANIFEST = REPO_ROOT / "policy" / "catalog" / "p5_w3_data.yaml"


def load_wave_manifest(path: Path) -> list[dict]:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    policies = list(data.get("policies") or [])
    pack_id = data.get("pack_id", "pack_aws_core")
    for policy in policies:
        policy["pack_id"] = pack_id
    return policies


def load_p5_w1_policies() -> list[dict]:
    return load_wave_manifest(P5_W1_MANIFEST)


def load_p5_w2_policies() -> list[dict]:
    return load_wave_manifest(P5_W2_MANIFEST)


def load_p5_w3_policies() -> list[dict]:
    return load_wave_manifest(P5_W3_MANIFEST)


def write_wave_policy_yamls(policies: list[dict]) -> None:
    minutes_by_severity = {"critical": 10, "high": 5, "medium": 3, "low": 2}
    for policy in policies:
        policy_id = policy["policy_id"]
        display_title = policy["display_title"]
        title = policy["title"]
        severity = policy["severity"]
        nist = policy.get("nist_mappings") or []
        body = {
            "policy_id": policy_id,
            "version": DEFAULT_POLICY_VERSION,
            "title": title,
            "provider": "aws",
            "resource_type": policy["resource_type"],
            "provider_type": policy["provider_type"],
            "severity": severity,
            "description": title,
            "logic": policy["logic"],
            "evidence_fields": list(policy.get("evidence_fields") or []),
            "remediation": {
                "headline": display_title,
                "risk_summary": title,
                "business_impact": "This misconfiguration may increase attack surface or reduce threat detection coverage.",
                "fix_summary": f"Remediate in AWS: {title}",
                "estimated_fix_minutes": minutes_by_severity.get(severity, 3),
                "framework_mappings": [f"NIST {control_id}" for control_id in nist],
            },
            "display_title": display_title,
            "pack_id": policy["pack_id"],
        }
        path = POLICIES_DIR / f"{policy_id}.yaml"
        path.write_text(
            yaml.dump(body, sort_keys=False, allow_unicode=True, default_flow_style=False),
            encoding="utf-8",
        )


def write_aws_cspm_wave_append(wave_policies: list[dict], path: Path) -> None:
    lines = path.read_text(encoding="utf-8").rstrip().splitlines()
    for policy in wave_policies:
        lines.extend(
            [
                f"  - policy_id: {policy['policy_id']}",
                f"    control_ref: {policy['control_ref']}",
                f"    domain: {policy['domain']}",
                f"    display_title: {policy['display_title']}",
                f"    title: {policy['title']}",
                f"    pack_id: {policy['pack_id']}",
                f"    severity: {policy['severity']}",
                f"    resource_type: {policy['resource_type']}",
                f"    provider_type: {policy['provider_type']}",
                f"    collector: {policy['collector']}",
                "    status: implemented",
            ]
        )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_expansion_migration(
    wave_policies: list[dict],
    *,
    migration_stem: str,
    comment: str,
) -> None:
    nist_baseline_ids = {c["control_id"] for c in load_nist_baseline()["controls"]}
    drantiq_controls: list[str] = []
    drantiq_mappings: list[str] = []
    nist_mappings: list[str] = []

    for policy in wave_policies:
        policy_id = policy["policy_id"]
        ref = policy["control_ref"]
        display = _sql_str(policy["display_title"])
        title = _sql_str(policy["title"])
        domain = _sql_str(policy["domain"])
        severity = policy["severity"]
        drantiq_controls.append(
            f"  ('drantiq_security_assessment_v1', '{policy_id}', '{ref}', "
            f"'{title}', '{display}', '{domain}', '{severity}', 'automated', true)"
        )
        drantiq_mappings.append(
            f"  ('drantiq_security_assessment_v1', '{policy_id}', '{policy_id}')"
        )
        for nist_id in policy.get("nist_mappings") or []:
            if nist_id not in nist_baseline_ids:
                continue
            nist_mappings.append(
                f"  ('nist_800_53_rev5_aws', '{nist_id}', '{policy_id}')"
            )

    sql = f"""-- platform-db migration {migration_stem.split('_')[0]}
-- {comment}
-- Generated by compliance-engine/scripts/build_policy_catalog.py

INSERT INTO compliance_v2.controls (
  framework_id, control_id, control_ref, title, display_title, domain, severity, assessment_type, enabled
)
VALUES
{",\n".join(drantiq_controls)}
ON CONFLICT (framework_id, control_id) DO UPDATE
  SET control_ref = EXCLUDED.control_ref,
      title = EXCLUDED.title,
      display_title = EXCLUDED.display_title,
      domain = EXCLUDED.domain,
      severity = EXCLUDED.severity,
      assessment_type = EXCLUDED.assessment_type,
      enabled = true;

INSERT INTO compliance_v2.policy_mappings (framework_id, control_id, policy_id)
VALUES
{",\n".join(drantiq_mappings)}
ON CONFLICT (framework_id, control_id, policy_id) DO NOTHING;

INSERT INTO compliance_v2.policy_mappings (framework_id, control_id, policy_id)
VALUES
{",\n".join(nist_mappings)}
ON CONFLICT (framework_id, control_id, policy_id) DO NOTHING;
"""
    write_migration_sql(f"{migration_stem}.sql", sql)


def main() -> None:
    controls = load_controls()
    w1_policies = load_p5_w1_policies()
    w2_policies = load_p5_w2_policies()
    w3_policies = load_p5_w3_policies()
    expansion_policies = w1_policies + w2_policies + w3_policies
    assert len(controls) == 35, f"expected 35 CIS controls, got {len(controls)}"
    assert len(w1_policies) == 15, f"expected 15 P5 W1 policies, got {len(w1_policies)}"
    assert len(w2_policies) == 20, f"expected 20 P5 W2 policies, got {len(w2_policies)}"
    assert len(w3_policies) == 15, f"expected 15 P5 W3 policies, got {len(w3_policies)}"
    sync_policy_yaml_files(controls)
    write_wave_policy_yamls(w1_policies)
    write_wave_policy_yamls(w2_policies)
    write_wave_policy_yamls(w3_policies)
    write_packs_yaml(w1_policies, w2_policies, w3_policies)
    ensure_policy_versions()
    write_commercial_compliance_migration(controls)
    write_nist_baseline_migration()
    sync_soc2_remediation_mappings()
    write_soc2_baseline_migration()
    cspm_path = REPO_ROOT / "policy" / "catalog" / "aws_cspm_v1.yaml"
    write_aws_cspm_v1(controls, cspm_path)
    write_aws_cspm_wave_append(expansion_policies, cspm_path)
    write_expansion_migration(
        w1_policies,
        migration_stem="023_p5_compute_security",
        comment="P5 Wave 1: compute security checks (Lambda, GuardDuty, EC2, EBS)",
    )
    write_expansion_migration(
        w2_policies,
        migration_stem="024_p5_compute_services",
        comment="P5 Wave 2: CIS compute services checks (EC2, AMI, EBS, SG)",
    )
    write_expansion_migration(
        w3_policies,
        migration_stem="025_p5_database_services",
        comment="P5 Wave 3: CIS database services checks (RDS, DynamoDB, ElastiCache)",
    )
    write_cis_mappings(
        controls, REPO_ROOT / "policy" / "catalog" / "mappings" / "cis_aws_v6.yaml"
    )
    cis_migration = GENERATED_MIGRATIONS_DIR / "010_cis_policy_mappings.sql"
    write_migration(controls, cis_migration)
    if PLATFORM_DB_MIGRATIONS_DIR.is_dir():
        write_migration(controls, PLATFORM_DB_MIGRATIONS_DIR / "010_cis_policy_mappings.sql")
    print(
        "Wrote policy YAMLs, packs/aws.yaml, 017/022/026/023/024/025 migrations, "
        f"aws_cspm_v1.yaml (+{len(expansion_policies)} expansion), cis_aws_v6.yaml, soc2_aws.yaml"
    )


if __name__ == "__main__":
    main()
