"""Unit tests for compliance mapping engine."""

from __future__ import annotations

from platform_backend.compliance.mapper import _aggregate_control, _compute_score


def test_control_pass_when_all_mapped_policies_pass() -> None:
    control = {
        "framework_id": "cis_aws_v6",
        "control_id": "3.1.4",
        "title": "S3 public access",
        "domain": "s3",
        "severity": "critical",
        "assessment_type": "automated",
        "mapped_policy_ids": ["AWS_S3_002"],
    }
    findings = {
        "AWS_S3_002": [{"id": "1", "result": "pass", "resource_id": "a", "severity": "critical", "title": "t", "evidence": {}}],
    }
    agg = _aggregate_control(control, findings)
    assert agg.status == "pass"
    assert agg.fail_count == 0


def test_control_fail_when_any_mapped_policy_fails() -> None:
    control = {
        "framework_id": "cis_aws_v6",
        "control_id": "2.9",
        "title": "IAM MFA",
        "domain": "iam",
        "severity": "high",
        "assessment_type": "automated",
        "mapped_policy_ids": ["AWS_IAM_005"],
    }
    findings = {
        "AWS_IAM_005": [
            {
                "id": "f1",
                "result": "fail",
                "resource_id": "arn:aws:iam::123:user/mock-admin",
                "severity": "high",
                "title": "IAM MFA",
                "evidence": {},
            }
        ],
    }
    agg = _aggregate_control(control, findings)
    assert agg.status == "fail"
    assert agg.fail_count == 1
    assert agg.finding_ids == ["f1"]


def test_control_not_assessed_without_mapping() -> None:
    control = {
        "framework_id": "cis_aws_v6",
        "control_id": "2.3",
        "title": "Root access keys",
        "domain": "iam",
        "severity": "critical",
        "assessment_type": "automated",
        "mapped_policy_ids": [],
    }
    agg = _aggregate_control(control, {})
    assert agg.status == "not_assessed"


def test_score_only_counts_assessed_controls() -> None:
    aggregates = [
        _aggregate_control(
            {
                "framework_id": "cis_aws_v6",
                "control_id": "3.1.4",
                "title": "S3",
                "domain": "s3",
                "severity": "critical",
                "assessment_type": "automated",
                "mapped_policy_ids": ["AWS_S3_002"],
            },
            {"AWS_S3_002": [{"id": "1", "result": "pass", "resource_id": "a", "severity": "c", "title": "t", "evidence": {}}]},
        ),
        _aggregate_control(
            {
                "framework_id": "cis_aws_v6",
                "control_id": "2.9",
                "title": "IAM MFA",
                "domain": "iam",
                "severity": "high",
                "assessment_type": "automated",
                "mapped_policy_ids": ["AWS_IAM_005"],
            },
            {"AWS_IAM_005": [{"id": "2", "result": "fail", "resource_id": "b", "severity": "h", "title": "t", "evidence": {}}]},
        ),
        _aggregate_control(
            {
                "framework_id": "cis_aws_v6",
                "control_id": "2.3",
                "title": "Root keys",
                "domain": "iam",
                "severity": "critical",
                "assessment_type": "automated",
                "mapped_policy_ids": [],
            },
            {},
        ),
    ]
    score, summary = _compute_score(aggregates)
    assert float(score) == 50.0
    assert summary["pass"] == 1
    assert summary["fail"] == 1
    assert summary["not_assessed"] == 1
