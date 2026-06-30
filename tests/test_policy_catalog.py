"""Validate locked policy catalog and CIS mappings."""

from __future__ import annotations

from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
CATALOG = REPO_ROOT / "policy" / "catalog" / "aws_cspm_v1.yaml"
MAPPINGS = REPO_ROOT / "policy" / "catalog" / "mappings" / "cis_aws_v6.yaml"
POLICIES_DIR = REPO_ROOT / "policy" / "catalog" / "policies"


def test_catalog_has_core_policies() -> None:
    catalog = yaml.safe_load(CATALOG.read_text(encoding="utf-8"))
    assert len(catalog["policies"]) == 85


def test_cis_mappings_still_35() -> None:
    mappings = yaml.safe_load(MAPPINGS.read_text(encoding="utf-8"))
    assert len(mappings["mappings"]) == 35


def test_mappings_match_cis_catalog_subset() -> None:
    catalog = yaml.safe_load(CATALOG.read_text(encoding="utf-8"))
    mappings = yaml.safe_load(MAPPINGS.read_text(encoding="utf-8"))
    cis_ids = {m["policy_id"] for m in mappings["mappings"]}
    catalog_ids = {p["policy_id"] for p in catalog["policies"]}
    assert cis_ids.issubset(catalog_ids)


def test_implemented_policies_have_yaml_files() -> None:
    catalog = yaml.safe_load(CATALOG.read_text(encoding="utf-8"))
    for entry in catalog["policies"]:
        if entry["status"] != "implemented":
            continue
        path = POLICIES_DIR / f"{entry['policy_id']}.yaml"
        assert path.is_file(), f"missing policy yaml for {entry['policy_id']}"


def test_policy_ids_are_unique_and_stable_prefix() -> None:
    catalog = yaml.safe_load(CATALOG.read_text(encoding="utf-8"))
    ids = [p["policy_id"] for p in catalog["policies"]]
    assert len(ids) == len(set(ids))
    for policy_id in ids:
        assert policy_id.startswith("AWS_")


def test_all_policies_have_display_title_and_pack() -> None:
    for path in sorted(POLICIES_DIR.glob("AWS_*.yaml")):
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        assert data.get("display_title"), f"missing display_title in {path.name}"
        assert data.get("pack_id"), f"missing pack_id in {path.name}"
