from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict, Field

from platform_backend.api.deps import get_db_pool, get_tenant_id
from platform_backend.compliance.repository import ComplianceRepository
from platform_backend.db.pool import DatabasePool
from platform_backend.identity.deps import get_principal
from platform_backend.identity.models import PlatformPrincipal

router = APIRouter(prefix="/v1/compliance", tags=["compliance"])


class FrameworkSummary(BaseModel):
    framework_id: str = Field(description="e.g. drantiq_security_assessment_v1")
    title: str = Field(description="Customer display title")
    display_title: str | None = None
    provider: str
    version_label: str
    customer_visible: bool = True
    requires_license: bool = False


class ControlResultResponse(BaseModel):
    control_id: str
    status: str = Field(description="pass | fail | not_assessed | manual | error")
    severity: str | None = None
    title: str
    display_title: str | None = None
    domain: str | None = None
    mapped_policy_ids: list[str]
    fail_count: int
    pass_count: int
    finding_ids: list[str]
    evidence: dict
    evaluated_at: str


class CoverageSummary(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    assessed: int
    automated: int
    not_assessed: int
    manual: int
    pass_: int = Field(alias="pass", serialization_alias="pass")
    fail_: int = Field(alias="fail", serialization_alias="fail")
    pass_rate: float


class ScanComplianceResponse(BaseModel):
    framework_id: str
    framework_title: str
    display_title: str | None = None
    version_label: str
    scan_id: str
    score: float = Field(description="Weighted security assessment score 0–100")
    summary: dict = Field(description="pass/fail/not_assessed counts")
    coverage: CoverageSummary
    evaluated_at: str
    controls: list[ControlResultResponse]


async def get_compliance_repo(db: DatabasePool = Depends(get_db_pool)) -> ComplianceRepository:
    return ComplianceRepository(db)


@router.get(
    "/frameworks",
    response_model=list[FrameworkSummary],
    summary="List security assessment frameworks",
    description=(
        "Customer-visible frameworks only (Drantiq Security Assessment, NIST 800-53). "
        "Licensed reference frameworks are excluded from this list."
    ),
    responses={200: {"description": "Framework list"}},
)
async def list_frameworks(
    _principal: PlatformPrincipal = Depends(get_principal),
    repo: ComplianceRepository = Depends(get_compliance_repo),
) -> list[FrameworkSummary]:
    rows = await repo.list_frameworks(customer_visible_only=True)
    return [
        FrameworkSummary(
            framework_id=row["framework_id"],
            title=row.get("display_title") or row["title"],
            display_title=row.get("display_title") or row["title"],
            provider=row["provider"],
            version_label=row["version_label"],
            customer_visible=row.get("customer_visible", True),
            requires_license=row.get("requires_license", False),
        )
        for row in rows
    ]


@router.get(
    "/frameworks/{framework_id}/scans/{scan_id}",
    response_model=ScanComplianceResponse,
    summary="Security assessment matrix for scan",
    description=(
        "Full assessment result: score, coverage by assessment type, linked findings. "
        "Used by platform-ui compliance lens tab."
    ),
    responses={200: {"description": "Assessment matrix"}, 404: {"description": "Results not found"}},
)
async def get_scan_compliance(
    framework_id: str,
    scan_id: UUID,
    tenant_id: UUID = Depends(get_tenant_id),
    principal: PlatformPrincipal = Depends(get_principal),
    repo: ComplianceRepository = Depends(get_compliance_repo),
) -> ScanComplianceResponse:
    customer_only = principal.role != "super_admin"
    result = await repo.get_scan_compliance(
        tenant_id,
        scan_id,
        framework_id,
        customer_visible_only=customer_only,
    )
    if not result:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="compliance results not found for scan",
        )
    if customer_only and isinstance(result.get("coverage"), dict):
        coverage = dict(result["coverage"])
        coverage.pop("total_checks", None)
        result["coverage"] = coverage
    return ScanComplianceResponse(**result)
