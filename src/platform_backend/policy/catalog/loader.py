from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import yaml

from platform_backend.policy.catalog.models import PolicyDefinition, PolicyRemediation


def _parse_remediation(raw: dict[str, Any] | None) -> PolicyRemediation | None:
    if not raw:
        return None
    mappings = raw.get("framework_mappings") or []
    return PolicyRemediation(
        headline=raw.get("headline"),
        risk_summary=raw.get("risk_summary"),
        business_impact=raw.get("business_impact"),
        fix_summary=raw.get("fix_summary"),
        estimated_fix_minutes=raw.get("estimated_fix_minutes"),
        framework_mappings=tuple(str(m) for m in mappings),
        aws_cli=raw.get("aws_cli"),
        azure_cli=raw.get("azure_cli"),
        azure_portal_steps=tuple(str(s) for s in (raw.get("azure_portal_steps") or [])),
        terraform=raw.get("terraform"),
        cloudformation=raw.get("cloudformation"),
    )


def _parse_policy(data: dict[str, Any]) -> PolicyDefinition:
    return PolicyDefinition(
        policy_id=data["policy_id"],
        title=data["title"],
        provider=data.get("provider", "aws"),
        resource_type=data["resource_type"],
        provider_type=data.get("provider_type"),
        severity=data.get("severity", "medium"),
        description=data.get("description"),
        logic=data["logic"],
        evidence_fields=list(data.get("evidence_fields", [])),
        remediation=_parse_remediation(data.get("remediation")),
        cis_control_id=data.get("cis_control_id"),
        display_title=data.get("display_title"),
        pack_id=data.get("pack_id"),
        version=str(data.get("version") or "1.0.0"),
    )


def load_policies(catalog_path: Path) -> list[PolicyDefinition]:
    if not catalog_path.is_dir():
        raise FileNotFoundError(f"policy catalog directory not found: {catalog_path}")

    policies: list[PolicyDefinition] = []
    for path in sorted(catalog_path.glob("*.yaml")):
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        if not raw:
            continue
        policies.append(_parse_policy(raw))
    return policies


def load_policy_index(catalog_path: Path) -> dict[str, PolicyDefinition]:
    return {p.policy_id: p for p in load_policies(catalog_path)}


def load_policy_packs(packs_path: Path) -> list[dict[str, Any]]:
    if not packs_path.is_file():
        return []
    raw = yaml.safe_load(packs_path.read_text(encoding="utf-8")) or {}
    return list(raw.get("packs") or [])


def policy_definition_hash(logic: dict[str, Any]) -> str:
    payload = json.dumps(logic, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()
