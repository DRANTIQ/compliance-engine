from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel

from platform_backend.api.deps import get_db_pool, get_scan_service, get_tenant_id
from platform_backend.assets.repositories.resources import AssetRepository
from platform_backend.db.pool import DatabasePool
from platform_backend.platform.services.scan_service import ScanService

router = APIRouter(prefix="/v1/assets", tags=["assets"])


class AssetResponse(BaseModel):
    resource_id: str
    resource_type: str
    provider: str
    provider_type: str
    account_id: str
    region: str | None = None
    properties: dict
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


@router.get("", response_model=list[AssetResponse])
async def list_assets(
    scan_id: UUID = Query(...),
    tenant_id: UUID = Depends(get_tenant_id),
    repo: AssetRepository = Depends(get_asset_repo),
    resource_type: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> list[AssetResponse]:
    rows = await repo.list(
        tenant_id, scan_id, resource_type=resource_type, limit=limit, offset=offset
    )
    return [AssetResponse(**r) for r in rows]


@router.get("/search", response_model=list[AssetResponse])
async def search_assets(
    scan_id: UUID = Query(...),
    tenant_id: UUID = Depends(get_tenant_id),
    repo: AssetRepository = Depends(get_asset_repo),
    q: str | None = Query(default=None, min_length=1),
    type: str | None = Query(default=None, alias="type"),
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


@router.get("/{resource_id}", response_model=AssetResponse)
async def get_asset(
    resource_id: str,
    scan_id: UUID = Query(...),
    tenant_id: UUID = Depends(get_tenant_id),
    repo: AssetRepository = Depends(get_asset_repo),
) -> AssetResponse:
    row = await repo.get(tenant_id, scan_id, resource_id)
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="asset not found")
    return AssetResponse(**row)


@router.get("/{resource_id}/relationships", response_model=list[RelationshipResponse])
async def get_asset_relationships(
    resource_id: str,
    scan_id: UUID = Query(...),
    tenant_id: UUID = Depends(get_tenant_id),
    repo: AssetRepository = Depends(get_asset_repo),
) -> list[RelationshipResponse]:
    rows = await repo.list_relationships(tenant_id, scan_id, resource_id)
    return [RelationshipResponse(**r) for r in rows]
