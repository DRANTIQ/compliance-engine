"""Unit tests for PR4 network rules and remaining policy coverage."""

from __future__ import annotations

from pathlib import Path

import yaml

from platform_backend.policy.engine.evaluator import evaluate_policy_logic
from platform_collectors.plugins.aws.network_rules import (
    analyze_security_group,
    network_acl_allows_unrestricted_admin_ports,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
POLICIES_DIR = REPO_ROOT / "policy" / "catalog" / "policies"


def test_sg_detects_unrestricted_ssh_ipv4() -> None:
    sg = {
        "GroupName": "web",
        "IpPermissions": [
            {
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                "Ipv6Ranges": [],
            }
        ],
    }
    flags = analyze_security_group(sg)
    assert flags["AllowsUnrestrictedAdminPortsIpv4"] is True
    assert flags["AllowsUnrestrictedAdminPortsIpv6"] is False


def test_nacl_detects_unrestricted_all_protocols() -> None:
    nacl = {
        "Entries": [
            {
                "Egress": False,
                "RuleAction": "allow",
                "CidrBlock": "0.0.0.0/0",
                "Protocol": "-1",
            }
        ]
    }
    assert network_acl_allows_unrestricted_admin_ports(nacl) is True


def test_rds_encryption_fail_when_not_encrypted() -> None:
    asset = {"properties": {"db_instance_identifier": "db1", "storage_encrypted": False}}
    logic = {
        "type": "fail_when",
        "condition": {
            "type": "field_check",
            "path": "properties.storage_encrypted",
            "operator": "eq",
            "expected": False,
        },
    }
    assert evaluate_policy_logic(asset, logic) is True


def test_catalog_has_all_35_policy_yamls() -> None:
    catalog = yaml.safe_load((REPO_ROOT / "policy" / "catalog" / "aws_cspm_v1.yaml").read_text(encoding="utf-8"))
    for entry in catalog["policies"]:
        path = POLICIES_DIR / f"{entry['policy_id']}.yaml"
        assert path.is_file(), f"missing policy yaml for {entry['policy_id']}"
