from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field

from platform_backend.api.deps import get_db_pool, get_tenant_id
from platform_backend.api.schemas.customer_experience import (
    AffectedResourcesResponse,
    FindingDetailResponse,
)
from platform_backend.db.pool import DatabasePool
from platform_backend.assets.repositories.resources import AssetRepository
from platform_backend.findings.experience import (
    build_affected_resources,
    build_related_resources,
    enrich_customer_finding,
    parse_framework_mappings,
)
from platform_backend.findings.presentation import enrich_finding
from platform_backend.findings.repository import FindingsRepository
from platform_backend.identity.deps import get_principal
from platform_backend.identity.models import PlatformPrincipal

router = APIRouter(prefix="/v1/findings", tags=["findings"])


class RemediationResponse(BaseModel):
    headline: str | None = Field(default=None, description="Short risk headline for UI")
    risk_summary: str | None = None
    business_impact: str | None = None
    fix_summary: str | None = None
    estimated_fix_minutes: int | None = None
    framework_mappings: list[str] = Field(default_factory=list, description="SOC2 / NIST control refs")
    aws_cli: str | None = Field(default=None, description="Suggested AWS CLI remediation")
    terraform: str | None = None
    cloudformation: str | None = None


class FindingResponse(BaseModel):
    id: str
    policy_id: str | None = Field(default=None, description="Internal control ID e.g. AWS_S3_001")
    resource_id: str
    resource_type: str
    result: str = Field(description="pass | fail | error")
    status: str = Field(description="open | resolved | suppressed")
    severity: str
    title: str
    display_title: str | None = Field(default=None, description="Customer-facing headline")
    technical_title: str | None = Field(default=None, description="Policy technical title")
    description: str | None = None
    evidence: dict = Field(description="Fields that triggered the policy")
    remediation: RemediationResponse
    evaluated_at: str
    created_at: str


async def get_findings_repo(db: DatabasePool = Depends(get_db_pool)) -> FindingsRepository:
    return FindingsRepository(db)


async def get_assets_repo(db: DatabasePool = Depends(get_db_pool)) -> AssetRepository:
    return AssetRepository(db)


@router.get(
    "",
    response_model=list[FindingResponse],
    summary="List findings for scan",
    description=(
        "Policy evaluation results for a scan. Filter by `result=fail` for issues only. "
        "Includes remediation copy from policy YAML catalog."
    ),
    responses={200: {"description": "Finding list"}},
)
async def list_findings(
    scan_id: UUID = Query(..., description="Scan UUID"),
    tenant_id: UUID = Depends(get_tenant_id),
    repo: FindingsRepository = Depends(get_findings_repo),
    result: str | None = Query(default=None, description="pass | fail | error"),
    policy_id: str | None = Query(default=None, description="Filter e.g. AWS_S3_001"),
    status: str | None = Query(default=None, description="open | resolved | suppressed"),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> list[FindingResponse]:
    rows = await repo.list_findings(
        tenant_id,
        scan_id,
        result=result,
        policy_id=policy_id,
        status=status,
        limit=limit,
        offset=offset,
    )
    return [FindingResponse(**enrich_finding(r, customer_visible=True)) for r in rows]


@router.get(
    "/{finding_id}/affected-resources",
    response_model=AffectedResourcesResponse,
    summary="Affected resources for finding policy",
    description=(
        "All resources that failed the same policy as this finding in the scan. "
        "Useful when one finding represents a policy with many failing resources."
    ),
    responses={200: {"description": "Affected resources"}, 404: {"description": "Finding not found"}},
)
async def get_finding_affected_resources(
    finding_id: UUID,
    scan_id: UUID = Query(..., description="Scan UUID"),
    tenant_id: UUID = Depends(get_tenant_id),
    repo: FindingsRepository = Depends(get_findings_repo),
) -> AffectedResourcesResponse:
    row = await repo.get_finding(tenant_id, scan_id, finding_id)
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="finding not found")
    rows = await repo.list_by_policy(tenant_id, scan_id, row["policy_id"], result="fail")
    return AffectedResourcesResponse(**build_affected_resources(rows, row["policy_id"]))


@router.get(
    "/{finding_id}",
    response_model=FindingDetailResponse,
    summary="Get finding by ID",
    description=(
        "Customer-oriented finding detail: plain-language title, business impact, "
        "framework mappings, and full remediation (CLI, Terraform). Requires `scan_id`."
    ),
    responses={200: {"description": "Finding detail"}, 404: {"description": "Finding not found"}},
)
async def get_finding(
    finding_id: UUID,
    scan_id: UUID = Query(..., description="Scan UUID"),
    tenant_id: UUID = Depends(get_tenant_id),
    principal: PlatformPrincipal = Depends(get_principal),
    repo: FindingsRepository = Depends(get_findings_repo),
    assets_repo: AssetRepository = Depends(get_assets_repo),
    expand: str | None = Query(
        default=None,
        description="super_admin only: expand=framework_mappings for full internal mappings",
    ),
) -> FindingDetailResponse:
    row = await repo.get_finding(tenant_id, scan_id, finding_id)
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="finding not found")
    item = enrich_customer_finding(row)
    relationships = await assets_repo.list_relationships(tenant_id, scan_id, row["resource_id"])
    peer_ids = {
        rel["to_resource_id"] if rel["from_resource_id"] == row["resource_id"] else rel["from_resource_id"]
        for rel in relationships
    }
    assets_by_id: dict[str, dict] = {}
    for peer_id in peer_ids:
        asset = await assets_repo.get(tenant_id, scan_id, peer_id)
        if asset:
            assets_by_id[peer_id] = asset
    item["related_resources"] = build_related_resources(
        row["resource_id"],
        relationships,
        assets_by_id=assets_by_id,
    )
    if expand == "framework_mappings" and principal.role == "super_admin":
        internal = enrich_finding(row, customer_visible=False)
        rem = item.get("remediation") or {}
        rem["framework_mappings"] = internal["remediation"].get("framework_mappings") or []
        item["remediation"] = rem
        item["frameworks"] = parse_framework_mappings(
            rem["framework_mappings"],
            customer_visible=False,
        )
    return FindingDetailResponse(**item)
