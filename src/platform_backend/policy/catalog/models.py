from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class PolicyDefinition:
    policy_id: str
    title: str
    provider: str
    resource_type: str
    provider_type: str | None
    severity: str
    description: str | None
    logic: dict[str, Any]
    evidence_fields: list[str]

    def matches_asset(self, asset: dict[str, Any]) -> bool:
        if asset.get("resource_type") != self.resource_type:
            return False
        if self.provider_type and asset.get("provider_type") != self.provider_type:
            return False
        return True
