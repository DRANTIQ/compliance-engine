"""Customer experience API response models."""

from __future__ import annotations

from pydantic import BaseModel, Field


class CustomerRemediationResponse(BaseModel):
    summary: str | None = Field(default=None, description="Plain-language fix summary")
    headline: str | None = None
    risk_summary: str | None = None
    business_impact: str | None = None
    estimated_minutes: int | None = None
    estimated_fix_minutes: int | None = None
    aws_console_steps: list[str] = Field(default_factory=list)
    aws_cli: str | None = None
    terraform: str | None = None
    cloudformation: str | None = None
    framework_mappings: list[str] = Field(default_factory=list)


class FrameworkRef(BaseModel):
    framework: str
    control: str


class TopRiskItem(BaseModel):
    finding_id: str
    policy_id: str
    title: str
    technical_title: str
    severity: str
    affected_resource: str
    resource_type: str
    why_it_matters: str | None = None
    business_impact: str | None = None
    estimated_fix_minutes: int | None = None


class ScanRiskSummaryResponse(BaseModel):
    score: float | None = Field(default=None, description="CIS compliance score when available")
    total_findings: int
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0
    top_risks: list[TopRiskItem]


class FixPriorityItem(BaseModel):
    rank: int
    finding_id: str
    policy_id: str
    display_title: str
    technical_title: str
    severity: str
    affected_resource: str
    resource_id: str
    resource_type: str
    why_it_matters: str | None = None
    business_impact: str | None = None
    estimated_fix_minutes: int | None = None
    frameworks: list[FrameworkRef] = Field(default_factory=list)
    internet_exposed: bool = False
    data_sensitive: bool = False


class ResourceFindingSummary(BaseModel):
    finding_id: str
    policy_id: str
    display_title: str
    technical_title: str
    severity: str
    remediation_summary: str | None = None


class ResourceRiskResponse(BaseModel):
    resource_id: str
    risk_level: str
    finding_count: int
    findings: list[ResourceFindingSummary]
    display_titles: list[str]


class AffectedResourceItem(BaseModel):
    finding_id: str
    resource_id: str
    affected_resource: str
    resource_type: str
    severity: str
    display_title: str


class AffectedResourcesResponse(BaseModel):
    policy_id: str
    policy_title: str
    display_title: str
    affected_count: int
    resources: list[AffectedResourceItem]


class FindingDetailResponse(BaseModel):
    id: str
    policy_id: str
    resource_id: str
    resource_type: str
    resource_type_label: str
    result: str
    status: str
    severity: str
    title: str
    display_title: str
    plain_language_title: str
    technical_title: str
    affected_resource: str
    description: str | None = None
    risk: str | None = None
    business_impact: str | None = None
    evidence: dict
    remediation: CustomerRemediationResponse
    frameworks: list[FrameworkRef] = Field(default_factory=list)
    evaluated_at: str
    created_at: str
