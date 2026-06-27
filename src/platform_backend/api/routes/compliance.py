from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from platform_backend.api.deps import get_db_pool, get_tenant_id
from platform_backend.identity.deps import get_principal
from platform_backend.identity.models import PlatformPrincipal
from platform_backend.compliance.repository import ComplianceRepository
from platform_backend.db.pool import DatabasePool

router = APIRouter(prefix="/v1/compliance", tags=["compliance"])


class FrameworkSummary(BaseModel):
    framework_id: str
    title: str
    provider: str
    version_label: str


class ControlResultResponse(BaseModel):
    control_id: str
    status: str
    severity: str | None = None
    title: str
    domain: str | None = None
    mapped_policy_ids: list[str]
    fail_count: int
    pass_count: int
    finding_ids: list[str]
    evidence: dict
    evaluated_at: str


class ScanComplianceResponse(BaseModel):
    framework_id: str
    framework_title: str
    version_label: str
    scan_id: str
    score: float
    summary: dict
    evaluated_at: str
    controls: list[ControlResultResponse]


async def get_compliance_repo(db: DatabasePool = Depends(get_db_pool)) -> ComplianceRepository:
    return ComplianceRepository(db)


@router.get("/frameworks", response_model=list[FrameworkSummary])
async def list_frameworks(
    _principal: PlatformPrincipal = Depends(get_principal),
    repo: ComplianceRepository = Depends(get_compliance_repo),
) -> list[FrameworkSummary]:
    rows = await repo.list_frameworks()
    return [FrameworkSummary(**row) for row in rows]


@router.get(
    "/frameworks/{framework_id}/scans/{scan_id}",
    response_model=ScanComplianceResponse,
)
async def get_scan_compliance(
    framework_id: str,
    scan_id: UUID,
    tenant_id: UUID = Depends(get_tenant_id),
    repo: ComplianceRepository = Depends(get_compliance_repo),
) -> ScanComplianceResponse:
    result = await repo.get_scan_compliance(tenant_id, scan_id, framework_id)
    if not result:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="compliance results not found for scan",
        )
    return ScanComplianceResponse(**result)
