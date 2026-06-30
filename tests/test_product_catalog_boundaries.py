"""Product catalog must not contain vendor provenance metadata."""

from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
POLICIES_DIR = REPO_ROOT / "policy" / "catalog" / "policies"


def test_sources_yaml_not_in_product_repo() -> None:
    assert not (REPO_ROOT / "policy" / "catalog" / "sources.yaml").exists()


def test_policy_yamls_have_no_provenance_fields() -> None:
    for path in sorted(POLICIES_DIR.glob("AWS_*.yaml")):
        text = path.read_text(encoding="utf-8")
        assert "internal_reference:" not in text, path.name
        assert "reference_type:" not in text, path.name
        assert "prowler_check" not in text.lower(), path.name
        assert "steampipe_query" not in text.lower(), path.name
