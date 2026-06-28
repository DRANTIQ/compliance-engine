#!/usr/bin/env python3
"""Merge remediation metadata into policy YAML files from catalog + overrides."""

from __future__ import annotations

import sys
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[1]
POLICIES_DIR = REPO / "policy" / "catalog" / "policies"
CATALOG = REPO / "policy" / "catalog" / "aws_cspm_v1.yaml"

# Customer-facing remediation — keyed by policy_id
REMEDIATION: dict[str, dict] = {
    "AWS_S3_002": {
        "headline": "Public S3 bucket detected",
        "risk_summary": "Anyone on the internet may be able to access data in this bucket.",
        "business_impact": "Sensitive data could be exposed to the public internet.",
        "fix_summary": "Enable S3 Block Public Access on the bucket.",
        "estimated_fix_minutes": 2,
        "framework_mappings": ["CIS 3.1.4", "SOC2 CC6.6", "NIST AC-3"],
        "aws_cli": (
            "aws s3api put-public-access-block --bucket {bucket_name} "
            "--public-access-block-configuration "
            "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"
        ),
        "terraform": (
            'resource "aws_s3_bucket_public_access_block" "this" {\n'
            '  bucket = "{bucket_name}"\n'
            "  block_public_acls       = true\n"
            "  block_public_policy     = true\n"
            "  ignore_public_acls      = true\n"
            "  restrict_public_buckets = true\n"
            "}"
        ),
        "cloudformation": (
            "Type: AWS::S3::BucketPublicAccessBlock\n"
            "Properties:\n"
            "  Bucket: {bucket_name}\n"
            "  BlockPublicAcls: true\n"
            "  BlockPublicPolicy: true\n"
            "  IgnorePublicAcls: true\n"
            "  RestrictPublicBuckets: true"
        ),
    },
    "AWS_S3_001": {
        "headline": "S3 bucket allows insecure HTTP access",
        "risk_summary": "Data in transit to this bucket may be intercepted over unencrypted HTTP.",
        "business_impact": "Compliance violations and data interception risk.",
        "fix_summary": "Add a bucket policy that denies requests over HTTP.",
        "estimated_fix_minutes": 5,
        "framework_mappings": ["CIS 3.1.1", "SOC2 CC6.1"],
    },
    "AWS_S3_003": {
        "headline": "S3 write events not logged",
        "risk_summary": "Object uploads and modifications may go unrecorded.",
        "business_impact": "You cannot investigate unauthorized data changes.",
        "fix_summary": "Enable S3 server access logging or CloudTrail data events for the bucket.",
        "estimated_fix_minutes": 10,
        "framework_mappings": ["CIS 4.8"],
    },
    "AWS_S3_004": {
        "headline": "S3 read events not logged",
        "risk_summary": "Object downloads may go unrecorded.",
        "business_impact": "Data exfiltration may go undetected.",
        "fix_summary": "Enable CloudTrail data events for S3 object-level read activity.",
        "estimated_fix_minutes": 10,
        "framework_mappings": ["CIS 4.9"],
    },
    "AWS_LOG_001": {
        "headline": "CloudTrail log validation disabled",
        "risk_summary": "CloudTrail logs cannot be verified for tampering.",
        "business_impact": "Audit trail integrity cannot be guaranteed.",
        "fix_summary": "Enable log file validation on the CloudTrail trail.",
        "estimated_fix_minutes": 3,
        "framework_mappings": ["CIS 4.2", "SOC2 CC7.2", "NIST AU-9"],
        "aws_cli": "aws cloudtrail update-trail --name {trail_name} --enable-log-file-validation",
    },
    "AWS_LOG_002": {
        "headline": "AWS Config disabled",
        "risk_summary": "Configuration changes are not being recorded for audit.",
        "business_impact": "You cannot prove who changed what in your AWS account.",
        "fix_summary": "Enable the AWS Config recorder and delivery channel in the region.",
        "estimated_fix_minutes": 5,
        "framework_mappings": ["CIS 4.3", "SOC2 CC8.1", "NIST CM-2"],
    },
    "AWS_LOG_005": {
        "headline": "VPC flow logging disabled",
        "risk_summary": "Network traffic is not logged — blind to lateral movement.",
        "business_impact": "Attackers could move undetected inside your network.",
        "fix_summary": "Enable VPC Flow Logs on the VPC.",
        "estimated_fix_minutes": 5,
        "framework_mappings": ["CIS 4.7", "NIST AU-12"],
    },
    "AWS_LOG_006": {
        "headline": "AWS Security Hub disabled",
        "risk_summary": "Centralized security findings are not aggregated.",
        "business_impact": "Security gaps may go unnoticed across services.",
        "fix_summary": "Enable AWS Security Hub in the account and region.",
        "estimated_fix_minutes": 3,
        "framework_mappings": ["CIS 5.16", "NIST SI-4"],
    },
    "AWS_NET_001": {
        "headline": "EBS encryption not enabled by default",
        "risk_summary": "New EBS volumes may be created without encryption.",
        "business_impact": "Unencrypted disks increase data breach impact.",
        "fix_summary": "Enable EBS encryption by default for the region.",
        "estimated_fix_minutes": 2,
        "framework_mappings": ["CIS 6.1.1", "NIST SC-28"],
        "aws_cli": "aws ec2 enable-ebs-encryption-by-default --region {region}",
    },
    "AWS_NET_003": {
        "headline": "Network ACL allows unrestricted admin ports",
        "risk_summary": "Administrative ports may be reachable from the internet.",
        "business_impact": "Remote administration ports exposed to attackers.",
        "fix_summary": "Restrict NACL rules that allow 0.0.0.0/0 on admin ports.",
        "estimated_fix_minutes": 15,
        "framework_mappings": ["CIS 6.2", "NIST SC-7"],
    },
    "AWS_IAM_011": {
        "headline": "AWS Support role missing",
        "risk_summary": "AWS Support case management role is not configured.",
        "business_impact": "Incident response with AWS Support may be delayed.",
        "fix_summary": "Create the AWS Support access IAM role.",
        "estimated_fix_minutes": 5,
        "framework_mappings": ["CIS 2.16"],
    },
    "AWS_IAM_014": {
        "headline": "IAM Access Analyzer disabled",
        "risk_summary": "Unused access paths may go undetected.",
        "business_impact": "Over-permissive IAM policies may persist unnoticed.",
        "fix_summary": "Create and enable IAM Access Analyzer.",
        "estimated_fix_minutes": 3,
        "framework_mappings": ["CIS 2.19", "NIST AC-2"],
    },
}


def default_remediation(entry: dict) -> dict:
    cis = entry.get("cis_control_id")
    severity = entry.get("severity", "medium")
    minutes = {"critical": 5, "high": 5, "medium": 3, "low": 2}.get(severity, 3)
    title = entry.get("title", "")
    return {
        "headline": title,
        "risk_summary": entry.get("description") or f"This control checks: {title}.",
        "business_impact": "This misconfiguration may lead to unauthorized access or compliance failure.",
        "fix_summary": f"Remediate in AWS: {title}",
        "estimated_fix_minutes": minutes,
        "framework_mappings": [f"CIS {cis}"] if cis else [],
    }


def main() -> int:
    catalog = yaml.safe_load(CATALOG.read_text(encoding="utf-8"))
    cis_by_policy = {p["policy_id"]: p for p in catalog["policies"]}

    updated = 0
    for path in sorted(POLICIES_DIR.glob("*.yaml")):
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        if not data:
            continue
        pid = data["policy_id"]
        entry = cis_by_policy.get(pid, {})
        if entry.get("cis_control_id"):
            data["cis_control_id"] = entry["cis_control_id"]

        rem = REMEDIATION.get(pid) or default_remediation({**entry, **data})
        data["remediation"] = rem

        path.write_text(
            yaml.safe_dump(data, sort_keys=False, allow_unicode=True, default_flow_style=False),
            encoding="utf-8",
        )
        updated += 1
        print(f"updated {path.name}")

    print(f"Done — {updated} policy files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
