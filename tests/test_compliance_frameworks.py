"""Tests for commercial compliance framework constants and presentation."""

from __future__ import annotations

from pathlib import Path

from tests.migration_paths import migration_sql_path
from platform_backend.compliance.frameworks import (
    CUSTOMER_PRIMARY_FRAMEWORK,
    INTERNAL_PARITY_FRAMEWORK,
    NIST_AWS_FRAMEWORK,
    NIST_AZURE_FRAMEWORK,
    SOC2_AWS_FRAMEWORK,
    SOC2_AZURE_FRAMEWORK,
    SCAN_FRAMEWORK_IDS,
)
from platform_backend.findings.presentation import enrich_finding
from platform_backend.policy.catalog.loader import load_policy_packs


REPO_ROOT = Path(__file__).resolve().parents[1]
PACKS_PATH = REPO_ROOT / "policy" / "catalog" / "packs" / "aws.yaml"


def test_scan_framework_ids_include_customer_and_internal() -> None:
    assert CUSTOMER_PRIMARY_FRAMEWORK == "drantiq_security_assessment_v1"
    assert INTERNAL_PARITY_FRAMEWORK == "cis_aws_v6"
    assert NIST_AWS_FRAMEWORK == "nist_800_53_rev5_aws"
    assert NIST_AZURE_FRAMEWORK == "nist_800_53_rev5_azure"
    assert SOC2_AWS_FRAMEWORK == "soc2_aws"
    assert SOC2_AZURE_FRAMEWORK == "soc2_azure"
    assert CUSTOMER_PRIMARY_FRAMEWORK in SCAN_FRAMEWORK_IDS
    assert INTERNAL_PARITY_FRAMEWORK in SCAN_FRAMEWORK_IDS
    assert SOC2_AWS_FRAMEWORK in SCAN_FRAMEWORK_IDS
    assert NIST_AZURE_FRAMEWORK in SCAN_FRAMEWORK_IDS
    assert SOC2_AZURE_FRAMEWORK in SCAN_FRAMEWORK_IDS


def test_policy_packs_yaml_loads_domain_packs() -> None:
    packs = load_policy_packs(PACKS_PATH)
    pack_ids = {p["pack_id"] for p in packs}
    assert "pack_aws_identity" in pack_ids
    assert "pack_aws_storage" in pack_ids
    assert "pack_aws_core" in pack_ids
    assert "pack_aws_compute_security" in pack_ids
    compute = next(p for p in packs if p["pack_id"] == "pack_aws_compute_security")
    assert len(compute["policy_ids"]) == 15
    compute_services = next(p for p in packs if p["pack_id"] == "pack_aws_compute")
    assert len(compute_services["policy_ids"]) == 20
    data = next(p for p in packs if p["pack_id"] == "pack_aws_data")
    assert len(data["policy_ids"]) == 18
    core = next(p for p in packs if p["pack_id"] == "pack_aws_core")
    assert len(core["policy_ids"]) == 85


def test_list_findings_enrich_hides_cis_mappings() -> None:
    finding = {
        "id": "00000000-0000-0000-0000-000000000001",
        "policy_id": "AWS_S3_002",
        "resource_id": "arn:aws:s3:::bucket",
        "resource_type": "storage.bucket",
        "result": "fail",
        "status": "open",
        "severity": "critical",
        "title": "S3 bucket must block public access",
        "description": "test",
        "evidence": {},
        "evaluated_at": "2026-01-01T00:00:00+00:00",
        "created_at": "2026-01-01T00:00:00+00:00",
    }
    customer = enrich_finding(finding, customer_visible=True)
    assert "CIS" not in str(customer["remediation"]["framework_mappings"])
    internal = enrich_finding(finding, customer_visible=False)
    assert any("CIS" in m for m in internal["remediation"]["framework_mappings"])


def test_migration_017_seed_file_exists() -> None:
    migration = migration_sql_path("017_commercial_compliance.sql")
    assert migration.is_file()
    text = migration.read_text(encoding="utf-8")
    assert "drantiq_security_assessment_v1" in text
    assert "customer_visible" in text
    assert "nist_800_53_rev5_aws" in text


def test_migration_022_nist_baseline_expanded() -> None:
    migration = migration_sql_path("022_nist_moderate_baseline.sql")
    assert migration.is_file()
    text = migration.read_text(encoding="utf-8")
    assert "nist_800_53_rev5_aws" in text
    assert "assessment_type" in text or "manual" in text
    assert text.count("'AC-") >= 30


def test_nist_baseline_yaml_loads() -> None:
    import yaml

    path = REPO_ROOT / "policy" / "catalog" / "mappings" / "nist_800_53_rev5.yaml"
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert data["framework_id"] == "nist_800_53_rev5_aws"
    controls = data["controls"]
    assert len(controls) >= 35
    manual = [c for c in controls if c["assessment_type"] == "manual"]
    automated = [c for c in controls if c["assessment_type"] == "automated"]
    assert len(manual) >= 10
    assert len(automated) >= 15
