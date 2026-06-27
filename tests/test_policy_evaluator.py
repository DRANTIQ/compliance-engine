"""Unit tests for the policy DSL evaluator."""

from __future__ import annotations

from platform_backend.policy.engine.evaluator import evaluate_policy_logic


def test_s3_public_acl_fail_when_not_blocked() -> None:
    asset = {
        "resource_type": "storage.bucket",
        "provider_type": "aws_s3_bucket",
        "properties": {
            "name": "public-bucket",
            "public_access_block": {"BlockPublicAcls": False, "BlockPublicPolicy": True},
        },
    }
    logic = {
        "type": "fail_when",
        "condition": {
            "type": "field_check",
            "path": "properties.public_access_block.BlockPublicAcls",
            "operator": "ne",
            "expected": True,
        },
    }
    assert evaluate_policy_logic(asset, logic) is True


def test_s3_public_acl_pass_when_blocked() -> None:
    asset = {
        "properties": {
            "public_access_block": {"BlockPublicAcls": True, "BlockPublicPolicy": True},
        },
    }
    logic = {
        "type": "fail_when",
        "condition": {
            "type": "field_check",
            "path": "properties.public_access_block.BlockPublicAcls",
            "operator": "ne",
            "expected": True,
        },
    }
    assert evaluate_policy_logic(asset, logic) is False


def test_iam_mfa_fail_when_console_user_without_mfa() -> None:
    asset = {
        "properties": {
            "user_name": "mock-admin",
            "password_last_used": "2026-01-01T00:00:00+00:00",
        }
    }
    logic = {
        "type": "fail_when",
        "condition": {
            "type": "compound",
            "operator": "and",
            "conditions": [
                {"type": "field_check", "path": "properties.password_last_used", "operator": "exists"},
                {
                    "type": "compound",
                    "operator": "or",
                    "conditions": [
                        {"type": "field_check", "path": "properties.mfa_enabled", "operator": "missing"},
                        {
                            "type": "field_check",
                            "path": "properties.mfa_enabled",
                            "operator": "eq",
                            "expected": False,
                        },
                    ],
                },
            ],
        },
    }
    assert evaluate_policy_logic(asset, logic) is True


def test_iam_mfa_pass_when_no_console_access() -> None:
    asset = {"properties": {"user_name": "service-user"}}
    logic = {
        "type": "fail_when",
        "condition": {
            "type": "compound",
            "operator": "and",
            "conditions": [
                {"type": "field_check", "path": "properties.password_last_used", "operator": "exists"},
                {
                    "type": "compound",
                    "operator": "or",
                    "conditions": [
                        {"type": "field_check", "path": "properties.mfa_enabled", "operator": "missing"},
                    ],
                },
            ],
        },
    }
    assert evaluate_policy_logic(asset, logic) is False


def test_compound_and_requires_all_conditions() -> None:
    asset = {"properties": {"state": "running", "instance_type": "t3.micro"}}
    logic = {
        "type": "compound",
        "operator": "and",
        "conditions": [
            {"type": "field_check", "path": "properties.state", "operator": "eq", "expected": "running"},
            {"type": "field_check", "path": "properties.instance_type", "operator": "eq", "expected": "m5.large"},
        ],
    }
    assert evaluate_policy_logic(asset, logic) is False
