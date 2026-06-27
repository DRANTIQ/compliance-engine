from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import yaml

from platform_backend.policy.catalog.models import PolicyDefinition


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


def policy_definition_hash(logic: dict[str, Any]) -> str:
    payload = json.dumps(logic, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()
