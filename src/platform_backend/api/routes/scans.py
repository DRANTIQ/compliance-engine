from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel

from platform_backend.api.deps import get_db_pool, get_scan_service, get_tenant_id, require_write_access
from platform_backend.identity.models import PlatformPrincipal
from platform_backend.compliance.repository import ComplianceRepository
from platform_backend.db.pool import DatabasePool
from platform_backend.platform.repositories.scan_insights import ScanInsightsRepository
from platform_backend.platform.services.scan_service import ScanService

router = APIRouter(prefix="/v1/scans", tags=["scans"])


class ScanCreate(BaseModel):
    integration_id: UUID


class ScanResponse(BaseModel):
    id: str
    tenant_id: str
    integration_id: str
    status: str
    trace_id: str
    started_at: str | None = None
    completed_at: str | None = None
    created_at: str
    updated_at: str


class ScanDetailResponse(ScanResponse):
    account_id: str | None = None
    collection_status: str | None = None
    error: dict | None = None


@router.post("", response_model=ScanResponse, status_code=status.HTTP_201_CREATED)
async def create_scan(
    body: ScanCreate,
    principal: PlatformPrincipal = Depends(require_write_access),
    service: ScanService = Depends(get_scan_service),
) -> ScanResponse:
    tenant_id = principal.tenant_id
    try:
        row = await service.create_scan(tenant_id, body.integration_id)
    except LookupError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    return ScanResponse(**row)


@router.get("/{scan_id}/timeline")
async def get_scan_timeline(
    scan_id: UUID,
    tenant_id: UUID = Depends(get_tenant_id),
    service: ScanService = Depends(get_scan_service),
) -> list[dict]:
    timeline = await service.get_scan_timeline(tenant_id, scan_id)
    if timeline is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="scan not found")
    return timeline


@router.get("/{scan_id}", response_model=ScanDetailResponse)
async def get_scan(
    scan_id: UUID,
    tenant_id: UUID = Depends(get_tenant_id),
    service: ScanService = Depends(get_scan_service),
) -> ScanDetailResponse:
    row = await service.get_scan(tenant_id, scan_id)
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="scan not found")
    return ScanDetailResponse(**row)


@router.get("", response_model=list[ScanResponse])
async def list_scans(
    tenant_id: UUID = Depends(get_tenant_id),
    service: ScanService = Depends(get_scan_service),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
) -> list[ScanResponse]:
    rows = await service.list_scans(tenant_id, limit=limit, offset=offset)
    return [ScanResponse(**r) for r in rows]


async def get_scan_insights_repo(db: DatabasePool = Depends(get_db_pool)) -> ScanInsightsRepository:
    return ScanInsightsRepository(db)


async def get_compliance_repo(db: DatabasePool = Depends(get_db_pool)) -> ComplianceRepository:
    return ComplianceRepository(db)


@router.get("/{scan_id}/compliance")
async def get_scan_compliance_summary(
    scan_id: UUID,
    tenant_id: UUID = Depends(get_tenant_id),
    service: ScanService = Depends(get_scan_service),
    compliance: ComplianceRepository = Depends(get_compliance_repo),
    framework_id: str = Query(default="cis_aws_v6"),
) -> dict:
    scan = await service.get_scan(tenant_id, scan_id)
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="scan not found")
    result = await compliance.get_scan_compliance(tenant_id, scan_id, framework_id)
    if not result:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="compliance results not found for scan",
        )
    return result


@router.get("/{scan_id}/inventory-completeness")
async def get_inventory_completeness(
    scan_id: UUID,
    tenant_id: UUID = Depends(get_tenant_id),
    service: ScanService = Depends(get_scan_service),
    insights: ScanInsightsRepository = Depends(get_scan_insights_repo),
) -> dict:
    scan = await service.get_scan(tenant_id, scan_id)
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="scan not found")
    return await insights.inventory_completeness(tenant_id, scan_id)


@router.get("/{scan_id}/policy-coverage")
async def get_policy_coverage(
    scan_id: UUID,
    tenant_id: UUID = Depends(get_tenant_id),
    service: ScanService = Depends(get_scan_service),
    insights: ScanInsightsRepository = Depends(get_scan_insights_repo),
) -> dict:
    scan = await service.get_scan(tenant_id, scan_id)
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="scan not found")
    return await insights.policy_coverage(tenant_id, scan_id)
