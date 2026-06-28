from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status

from platform_backend.api.deps import get_db_pool, get_tenant_id
from platform_backend.api.schemas.customer_experience import AffectedResourcesResponse
from platform_backend.db.pool import DatabasePool
from platform_backend.findings.experience import build_affected_resources
from platform_backend.findings.repository import FindingsRepository

router = APIRouter(prefix="/v1/policies", tags=["policies"])


async def get_findings_repo(db: DatabasePool = Depends(get_db_pool)) -> FindingsRepository:
    return FindingsRepository(db)


@router.get(
    "/{policy_id}/affected-resources",
    response_model=AffectedResourcesResponse,
    summary="Affected resources for policy",
    description=(
        "Lists every resource that failed a policy in the given scan. "
        "Answers: which resources are affected by this control?"
    ),
    responses={200: {"description": "Affected resources"}, 404: {"description": "Scan has no failures for policy"}},
)
async def get_policy_affected_resources(
    policy_id: str,
    scan_id: UUID = Query(..., description="Scan UUID"),
    tenant_id: UUID = Depends(get_tenant_id),
    repo: FindingsRepository = Depends(get_findings_repo),
) -> AffectedResourcesResponse:
    rows = await repo.list_by_policy(tenant_id, scan_id, policy_id, result="fail")
    if not rows:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="no failing findings for policy in scan",
        )
    return AffectedResourcesResponse(**build_affected_resources(rows, policy_id))
