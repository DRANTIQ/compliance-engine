from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel

from platform_backend.api.deps import get_db_pool, get_tenant_id
from platform_backend.db.pool import DatabasePool
from platform_backend.findings.repository import FindingsRepository

router = APIRouter(prefix="/v1/findings", tags=["findings"])


class FindingResponse(BaseModel):
    id: str
    policy_id: str
    resource_id: str
    resource_type: str
    result: str
    status: str
    severity: str
    title: str
    description: str | None = None
    evidence: dict
    evaluated_at: str
    created_at: str


async def get_findings_repo(db: DatabasePool = Depends(get_db_pool)) -> FindingsRepository:
    return FindingsRepository(db)


@router.get("", response_model=list[FindingResponse])
async def list_findings(
    scan_id: UUID = Query(...),
    tenant_id: UUID = Depends(get_tenant_id),
    repo: FindingsRepository = Depends(get_findings_repo),
    result: str | None = Query(default=None),
    policy_id: str | None = Query(default=None),
    status: str | None = Query(default=None),
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
    return [FindingResponse(**r) for r in rows]


@router.get("/{finding_id}", response_model=FindingResponse)
async def get_finding(
    finding_id: UUID,
    scan_id: UUID = Query(...),
    tenant_id: UUID = Depends(get_tenant_id),
    repo: FindingsRepository = Depends(get_findings_repo),
) -> FindingResponse:
    row = await repo.get_finding(tenant_id, scan_id, finding_id)
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="finding not found")
    return FindingResponse(**row)
