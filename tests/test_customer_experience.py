"""Tests for customer experience API helpers."""

from __future__ import annotations

from platform_backend.findings.experience import (
    build_affected_resources,
    build_fix_priorities,
    build_resource_inventory_stats,
    build_resource_risk,
    build_risk_summary,
    enrich_customer_finding,
    parse_framework_mappings,
)
from platform_backend.policy.catalog.registry import get_policy_definition


def _s3_finding(**overrides: object) -> dict:
    base = {
        "id": "00000000-0000-0000-0000-000000000001",
        "policy_id": "AWS_S3_002",
        "resource_id": "arn:aws:s3:::steampipe-drantiq-test",
        "resource_type": "storage.bucket",
        "result": "fail",
        "status": "open",
        "severity": "critical",
        "title": "S3 bucket must block public access",
        "description": "S3 Block Public Access must be fully enabled (CIS 3.1.4).",
        "evidence": {
            "properties": {
                "name": "steampipe-drantiq-test",
                "block_public_acls": False,
            }
        },
        "evaluated_at": "2026-01-01T00:00:00+00:00",
        "created_at": "2026-01-01T00:00:00+00:00",
    }
    base.update(overrides)
    return base


def test_enrich_customer_finding_has_display_and_remediation() -> None:
    item = enrich_customer_finding(_s3_finding())
    assert item["display_title"] == "Public S3 bucket detected"
    assert item["technical_title"] == "S3 bucket must block public access"
    assert item["affected_resource"] == "steampipe-drantiq-test"
    assert item["resource_type_label"] == "S3 bucket"
    assert item["remediation"]["summary"]
    assert item["remediation"]["aws_cli"]
    assert "CIS" not in str(item["frameworks"])
    assert item["remediation"]["framework_mappings"] == ["SOC2 CC6.6", "NIST AC-3"]
    assert item.get("policy_version") == "1.0.0"
    assert item["risk_signals"]["risk_score"] >= 90
    assert item["risk_signals"]["internet_exposed"] is True
    assert item["risk_signals"]["publicly_accessible"] is True
    assert any(b["id"] == "internet_exposed" for b in item["risk_signals"]["why_badges"])
    assert item["risk_signals"]["assessed"]["business_critical"] is False
    framework_names = {f["framework"] for f in item["frameworks"]}
    assert "SOC 2" in framework_names
    assert "NIST 800-53" in framework_names


def test_parse_framework_mappings_internal_includes_cis() -> None:
    out = parse_framework_mappings(["CIS 3.1.4", "SOC2 CC6.1"], customer_visible=False)
    assert out[0] == {"framework": "CIS AWS v6", "control": "3.1.4"}
    assert out[1] == {"framework": "SOC 2", "control": "CC6.1"}


def test_parse_framework_mappings_customer_hides_cis() -> None:
    out = parse_framework_mappings(["CIS 3.1.4", "SOC2 CC6.1", "NIST AC-3"], customer_visible=True)
    assert out == [
        {"framework": "SOC 2", "control": "CC6.1"},
        {"framework": "NIST 800-53", "control": "AC-3"},
    ]


def test_build_risk_summary() -> None:
    findings = [
        _s3_finding(),
        _s3_finding(
            id="00000000-0000-0000-0000-000000000002",
            policy_id="AWS_S3_003",
            severity="high",
            title="S3 bucket policy must deny HTTP requests",
        ),
    ]
    summary = build_risk_summary(findings, compliance_score=38.1, top_n=5)
    assert summary["score"] == 38.1
    assert summary["total_findings"] == 2
    assert summary["critical"] == 1
    assert summary["high"] == 1
    assert len(summary["top_risks"]) == 2
    assert summary["top_risks"][0]["severity"] == "critical"
    assert summary["top_risks"][0]["affected_resource"] == "steampipe-drantiq-test"
    assert summary["top_risks"][0]["risk_score"] >= 90


def test_build_resource_inventory_stats() -> None:
    findings = [
        _s3_finding(),
        _s3_finding(
            id="00000000-0000-0000-0000-000000000002",
            resource_id="arn:aws:s3:::other-bucket",
            policy_id="AWS_S3_003",
            severity="high",
        ),
    ]
    stats = build_resource_inventory_stats(findings, resource_total=10)
    assert stats["cloud_resources"] == 10
    assert stats["resources_at_risk"] == 2
    assert stats["resources_protected"] == 8

    summary = build_risk_summary(findings, compliance_score=72.0, top_n=5, resource_total=10)
    assert summary["resources_at_risk"] == 2
    assert summary["resources_protected"] == 8


def test_build_fix_priorities_orders_critical_first() -> None:
    findings = [
        _s3_finding(
            id="00000000-0000-0000-0000-000000000002",
            policy_id="AWS_S3_003",
            severity="high",
            title="S3 bucket policy must deny HTTP requests",
        ),
        _s3_finding(),
    ]
    priorities = build_fix_priorities(findings, limit=10)
    assert priorities[0]["severity"] == "critical"
    assert priorities[0]["rank"] == 1
    assert priorities[0]["internet_exposed"] is True
    assert priorities[0]["risk_score"] >= 90


def test_build_resource_risk() -> None:
    findings = [
        _s3_finding(),
        _s3_finding(
            id="00000000-0000-0000-0000-000000000002",
            policy_id="AWS_S3_003",
            severity="high",
            title="S3 bucket policy must deny HTTP requests",
        ),
    ]
    risk = build_resource_risk(findings, "arn:aws:s3:::steampipe-drantiq-test")
    assert risk["risk_level"] == "critical"
    assert risk["finding_count"] == 2
    assert len(risk["display_titles"]) == 2


def test_build_affected_resources() -> None:
    policy = get_policy_definition("AWS_S3_002")
    assert policy is not None
    findings = [
        _s3_finding(),
        _s3_finding(
            id="00000000-0000-0000-0000-000000000002",
            resource_id="arn:aws:s3:::other-bucket",
            evidence={"properties": {"name": "other-bucket"}},
        ),
    ]
    out = build_affected_resources(findings, "AWS_S3_002")
    assert out["policy_id"] == "AWS_S3_002"
    assert out["affected_count"] == 2
    assert out["display_title"] == "Public S3 bucket detected"
