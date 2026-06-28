from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class PolicyRemediation:
    headline: str | None = None
    risk_summary: str | None = None
    business_impact: str | None = None
    fix_summary: str | None = None
    estimated_fix_minutes: int | None = None
    framework_mappings: tuple[str, ...] = ()
    aws_cli: str | None = None
    terraform: str | None = None
    cloudformation: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "headline": self.headline,
            "risk_summary": self.risk_summary,
            "business_impact": self.business_impact,
            "fix_summary": self.fix_summary,
            "estimated_fix_minutes": self.estimated_fix_minutes,
            "framework_mappings": list(self.framework_mappings),
            "aws_cli": self.aws_cli,
            "terraform": self.terraform,
            "cloudformation": self.cloudformation,
        }


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
    remediation: PolicyRemediation | None = None
    cis_control_id: str | None = None

    def matches_asset(self, asset: dict[str, Any]) -> bool:
        if asset.get("resource_type") != self.resource_type:
            return False
        if self.provider_type and asset.get("provider_type") != self.provider_type:
            return False
        return True

    def effective_remediation(self) -> PolicyRemediation:
        if self.remediation:
            return self.remediation
        cis_tag = f"CIS {self.cis_control_id}" if self.cis_control_id else None
        mappings = (cis_tag,) if cis_tag else ()
        minutes = {"critical": 5, "high": 5, "medium": 3, "low": 2}.get(self.severity, 3)
        return PolicyRemediation(
            headline=self.title,
            risk_summary=self.description,
            business_impact="This misconfiguration may lead to unauthorized access or compliance failure.",
            fix_summary=f"Review the affected resource and remediate: {self.title}",
            estimated_fix_minutes=minutes,
            framework_mappings=mappings,
        )
