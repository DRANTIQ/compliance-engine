"""Tests for finding remediation enrichment from policy catalog."""

from __future__ import annotations

from platform_backend.findings.presentation import enrich_finding, render_template
from platform_backend.policy.catalog.registry import get_policy_definition


def test_s3_public_access_remediation_from_catalog() -> None:
    policy = get_policy_definition("AWS_S3_002")
    assert policy is not None
    assert policy.remediation is not None
    assert policy.remediation.headline == "Public S3 bucket detected"

    finding = {
        "id": "00000000-0000-0000-0000-000000000001",
        "policy_id": "AWS_S3_002",
        "resource_id": "arn:aws:s3:::steampipe-drantiq-test",
        "resource_type": "storage.bucket",
        "result": "fail",
        "status": "open",
        "severity": "critical",
        "title": "S3 bucket must block public access",
        "description": "S3 Block Public Access must be fully enabled (CIS 3.1.4).",
        "evidence": {"properties": {"name": "steampipe-drantiq-test"}},
        "evaluated_at": "2026-01-01T00:00:00+00:00",
        "created_at": "2026-01-01T00:00:00+00:00",
    }
    enriched = enrich_finding(finding)
    rem = enriched["remediation"]
    assert rem["headline"] == "Public S3 bucket detected"
    assert rem["estimated_fix_minutes"] == 2
    assert "CIS 3.1.4" in rem["framework_mappings"]
    assert "steampipe-drantiq-test" in rem["aws_cli"]
    assert "{bucket_name}" not in rem["aws_cli"]


def test_render_template_substitutes_placeholders() -> None:
    out = render_template(
        "aws ec2 enable-ebs-encryption-by-default --region {region}",
        {"region": "us-west-2"},
    )
    assert out == "aws ec2 enable-ebs-encryption-by-default --region us-west-2"
