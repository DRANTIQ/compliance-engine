"""P5 Wave 4 — SOC 2 TSC mapping (mappings only, no new checks)."""

from __future__ import annotations

from pathlib import Path

import yaml

from platform_backend.compliance.frameworks import SOC2_AWS_FRAMEWORK, SCAN_FRAMEWORK_IDS


REPO_ROOT = Path(__file__).resolve().parents[1]
SOC2_YAML = REPO_ROOT / "policy" / "catalog" / "mappings" / "soc2_aws.yaml"
CSPM = REPO_ROOT / "policy" / "catalog" / "aws_cspm_v1.yaml"


def test_soc2_framework_in_scan_ids() -> None:
    assert SOC2_AWS_FRAMEWORK == "soc2_aws"
    assert SOC2_AWS_FRAMEWORK in SCAN_FRAMEWORK_IDS


def test_soc2_baseline_covers_all_policies() -> None:
    soc2 = yaml.safe_load(SOC2_YAML.read_text(encoding="utf-8"))
    cspm = yaml.safe_load(CSPM.read_text(encoding="utf-8"))
    catalog_ids = {p["policy_id"] for p in cspm["policies"]}
    mapped: set[str] = set()
    for control in soc2["controls"]:
        mapped.update(control.get("policy_ids") or [])
    assert catalog_ids == mapped, f"missing {sorted(catalog_ids - mapped)}"


def test_soc2_baseline_has_manual_and_automated_controls() -> None:
    soc2 = yaml.safe_load(SOC2_YAML.read_text(encoding="utf-8"))
    controls = soc2["controls"]
    assert len(controls) >= 15
    manual = [c for c in controls if c["assessment_type"] == "manual"]
    automated = [c for c in controls if c["assessment_type"] == "automated"]
    assert len(manual) >= 3
    assert len(automated) >= 10
    assert any(c["control_id"] == "CC6.1" for c in controls)
    assert any(c["control_id"] == "CC7.2" for c in controls)


def test_migration_026_soc2_seed_exists() -> None:
    migration = REPO_ROOT.parent / "platform-db" / "migrations" / "026_p5_soc2_mapping.sql"
    assert migration.is_file()
    text = migration.read_text(encoding="utf-8")
    assert "soc2_aws" in text
    assert "CC6.1" in text
    assert "customer_visible" in text
    assert text.count("'AWS_") >= 80


def test_policy_yamls_include_soc2_remediation_tags() -> None:
    policies_dir = REPO_ROOT / "policy" / "catalog" / "policies"
    with_soc2 = 0
    for path in sorted(policies_dir.glob("AWS_*.yaml")):
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
        mappings = (doc.get("remediation") or {}).get("framework_mappings") or []
        if any(str(m).startswith("SOC2 ") for m in mappings):
            with_soc2 += 1
    assert with_soc2 >= 80
