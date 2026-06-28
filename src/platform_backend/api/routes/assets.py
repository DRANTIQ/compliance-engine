from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field

from platform_backend.api.deps import get_db_pool, get_tenant_id
from platform_backend.api.schemas.customer_experience import ResourceRiskResponse
from platform_backend.assets.repositories.resources import AssetRepository
from platform_backend.db.pool import DatabasePool
from platform_backend.findings.experience import build_resource_risk
from platform_backend.findings.repository import FindingsRepository

router = APIRouter(prefix="/v1/assets", tags=["assets"])


class AssetResponse(BaseModel):
    resource_id: str = Field(description="Stable resource identifier (often ARN)")
    resource_type: str = Field(description="Normalized type, e.g. aws_s3_bucket")
    provider: str
    provider_type: str
    account_id: str
    region: str | None = None
    properties: dict = Field(description="Bronze-normalized resource properties")
    tags: dict
    collected_at: str
    ingested_at: str


class RelationshipResponse(BaseModel):
    from_resource_id: str
    to_resource_id: str
    relationship_type: str
    properties: dict
    created_at: str


async def get_asset_repo(db: DatabasePool = Depends(get_db_pool)) -> AssetRepository:
    return AssetRepository(db)


async def get_findings_repo(db: DatabasePool = Depends(get_db_pool)) -> FindingsRepository:
    return FindingsRepository(db)


@router.get(
    "",
    response_model=list[AssetResponse],
    summary="List assets for scan",
    description="Paginated inventory for a completed scan. Filter by `resource_type` optionally.",
    responses={200: {"description": "Asset page"}},
)
async def list_assets(
    scan_id: UUID = Query(..., description="Scan UUID"),
    tenant_id: UUID = Depends(get_tenant_id),
    repo: AssetRepository = Depends(get_asset_repo),
    resource_type: str | None = Query(default=None, description="Filter e.g. aws_iam_user"),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> list[AssetResponse]:
    rows = await repo.list(
        tenant_id, scan_id, resource_type=resource_type, limit=limit, offset=offset
    )
    return [AssetResponse(**r) for r in rows]


@router.get(
    "/search",
    response_model=list[AssetResponse],
    summary="Search assets",
    description="Full-text search over resource properties and tags for a scan. Requires `q` and/or `type` and/or `tag`.",
    responses={200: {"description": "Matching assets"}},
)
async def search_assets(
    scan_id: UUID = Query(..., description="Scan UUID"),
    tenant_id: UUID = Depends(get_tenant_id),
    repo: AssetRepository = Depends(get_asset_repo),
    q: str | None = Query(default=None, min_length=1, description="Free-text search"),
    type: str | None = Query(default=None, alias="type", description="Resource type filter"),
    tag: str | None = Query(default=None, description="Tag filter as key or key=value"),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> list[AssetResponse]:
    tag_key: str | None = None
    tag_value: str | None = None
    if tag:
        if "=" in tag:
            tag_key, tag_value = tag.split("=", 1)
        else:
            tag_key = tag

    rows = await repo.search(
        tenant_id,
        scan_id,
        q=q,
        resource_type=type,
        tag_key=tag_key,
        tag_value=tag_value,
        limit=limit,
        offset=offset,
    )
    return [AssetResponse(**r) for r in rows]


@router.get(
    "/{resource_id}/risk",
    response_model=ResourceRiskResponse,
    summary="Resource risk detail",
    description="All failing findings affecting a resource in the scan, with risk level and remediation summaries.",
    responses={200: {"description": "Resource risk"}, 404: {"description": "Asset not found"}},
)
async def get_asset_risk(
    resource_id: str,
    scan_id: UUID = Query(..., description="Scan UUID"),
    tenant_id: UUID = Depends(get_tenant_id),
    assets: AssetRepository = Depends(get_asset_repo),
    findings: FindingsRepository = Depends(get_findings_repo),
) -> ResourceRiskResponse:
    asset = await assets.get(tenant_id, scan_id, resource_id)
    if not asset:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="asset not found")
    rows = await findings.list_by_resource(tenant_id, scan_id, resource_id, result="fail")
    return ResourceRiskResponse(**build_resource_risk(rows, resource_id))


@router.get(
    "/{resource_id}",
    response_model=AssetResponse,
    summary="Get single asset",
    description="One resource by `resource_id` for the given scan.",
    responses={200: {"description": "Asset"}, 404: {"description": "Asset not found"}},
)
async def get_asset(
    resource_id: str,
    scan_id: UUID = Query(..., description="Scan UUID"),
    tenant_id: UUID = Depends(get_tenant_id),
    repo: AssetRepository = Depends(get_asset_repo),
) -> AssetResponse:
    row = await repo.get(tenant_id, scan_id, resource_id)
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="asset not found")
    return AssetResponse(**row)


@router.get(
    "/{resource_id}/relationships",
    response_model=list[RelationshipResponse],
    summary="Asset relationships",
    description="IAM graph edges (e.g. role → policy attachment) for a resource in the scan.",
    responses={200: {"description": "Relationship list"}},
)
async def get_asset_relationships(
    resource_id: str,
    scan_id: UUID = Query(..., description="Scan UUID"),
    tenant_id: UUID = Depends(get_tenant_id),
    repo: AssetRepository = Depends(get_asset_repo),
) -> list[RelationshipResponse]:
    rows = await repo.list_relationships(tenant_id, scan_id, resource_id)
    return [RelationshipResponse(**r) for r in rows]
