from __future__ import annotations

import re
from datetime import datetime
from typing import Any
from uuid import UUID

import redis.asyncio as redis
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field, field_validator

from platform_backend.api.deps import get_db_pool, get_redis, get_settings_dep
from platform_backend.config.settings import Settings
from platform_backend.db.pool import DatabasePool
from platform_backend.identity.deps import require_super_admin
from platform_backend.identity.models import PlatformPrincipal
from platform_backend.platform.repositories.admin import AdminRepository

router = APIRouter(prefix="/v1/admin", tags=["admin"])

SLUG_PATTERN = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")


def _serialize_row(row: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in row.items():
        if isinstance(value, UUID):
            out[key] = str(value)
        elif isinstance(value, datetime):
            out[key] = value.isoformat()
        else:
            out[key] = value
    return out


async def get_admin_repo(db: DatabasePool = Depends(get_db_pool)) -> AdminRepository:
    return AdminRepository(db)


class TenantResponse(BaseModel):
    id: str
    name: str
    slug: str
    status: str
    created_at: str
    updated_at: str


class TenantCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    slug: str = Field(min_length=1, max_length=64)

    @field_validator("slug")
    @classmethod
    def validate_slug(cls, value: str) -> str:
        slug = value.strip().lower()
        if not SLUG_PATTERN.match(slug):
            raise ValueError("slug must be lowercase alphanumeric with optional hyphens")
        return slug


class TenantUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=255)
    status: str | None = Field(default=None, pattern="^(active|suspended)$")


class MembershipCreate(BaseModel):
    auth_issuer: str = Field(min_length=8)
    auth_subject: str = Field(min_length=8)
    email: str | None = None
    role: str = Field(default="tenant_admin", pattern="^(tenant_admin|viewer|super_admin)$")


class MembershipResponse(BaseModel):
    id: str
    user_id: str
    tenant_id: str
    role: str
    auth_issuer: str
    auth_subject: str
    status: str
    email: str | None = None
    display_name: str | None = None
    created_at: str
    updated_at: str


class AdminScanResponse(BaseModel):
    id: str
    tenant_id: str
    tenant_name: str
    tenant_slug: str
    integration_id: str
    status: str
    trace_id: str
    started_at: str | None
    completed_at: str | None
    created_at: str
    updated_at: str


class AdminOverviewResponse(BaseModel):
    tenant_count: int
    failed_scan_count: int
    active_scan_count: int
    collect_queue_depth: int
    events_queue_depth: int
    api_status: str


@router.get("/overview", response_model=AdminOverviewResponse)
async def admin_overview(
    _principal: PlatformPrincipal = Depends(require_super_admin),
    repo: AdminRepository = Depends(get_admin_repo),
    redis_client: redis.Redis = Depends(get_redis),
    settings: Settings = Depends(get_settings_dep),
) -> AdminOverviewResponse:
    tenant_count = await repo.count_tenants()
    failed_scan_count = await repo.count_scans_by_status("failed")
    active = 0
    for st in ("queued", "collecting", "ingesting", "evaluating"):
        active += await repo.count_scans_by_status(st)
    collect_depth = int(await redis_client.llen(settings.collect_queue_key))
    events_depth = int(await redis_client.llen(settings.platform_events_key))
    return AdminOverviewResponse(
        tenant_count=tenant_count,
        failed_scan_count=failed_scan_count,
        active_scan_count=active,
        collect_queue_depth=collect_depth,
        events_queue_depth=events_depth,
        api_status="healthy",
    )


@router.get("/tenants", response_model=list[TenantResponse])
async def list_tenants(
    _principal: PlatformPrincipal = Depends(require_super_admin),
    repo: AdminRepository = Depends(get_admin_repo),
) -> list[TenantResponse]:
    rows = await repo.list_tenants()
    return [TenantResponse(**_serialize_row(r)) for r in rows]


@router.post("/tenants", response_model=TenantResponse, status_code=status.HTTP_201_CREATED)
async def create_tenant(
    body: TenantCreate,
    _principal: PlatformPrincipal = Depends(require_super_admin),
    repo: AdminRepository = Depends(get_admin_repo),
) -> TenantResponse:
    try:
        row = await repo.create_tenant(name=body.name.strip(), slug=body.slug)
    except Exception as exc:
        if "unique" in str(exc).lower():
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="tenant slug already exists",
            ) from exc
        raise
    return TenantResponse(**_serialize_row(row))


@router.get("/tenants/{tenant_id}", response_model=TenantResponse)
async def get_tenant(
    tenant_id: UUID,
    _principal: PlatformPrincipal = Depends(require_super_admin),
    repo: AdminRepository = Depends(get_admin_repo),
) -> TenantResponse:
    row = await repo.get_tenant(tenant_id)
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="tenant not found")
    return TenantResponse(**_serialize_row(row))


@router.patch("/tenants/{tenant_id}", response_model=TenantResponse)
async def update_tenant(
    tenant_id: UUID,
    body: TenantUpdate,
    _principal: PlatformPrincipal = Depends(require_super_admin),
    repo: AdminRepository = Depends(get_admin_repo),
) -> TenantResponse:
    if body.name is None and body.status is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="no fields to update")
    row = await repo.update_tenant(tenant_id, name=body.name, status=body.status)
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="tenant not found")
    return TenantResponse(**_serialize_row(row))


@router.get("/tenants/{tenant_id}/memberships", response_model=list[MembershipResponse])
async def list_memberships(
    tenant_id: UUID,
    _principal: PlatformPrincipal = Depends(require_super_admin),
    repo: AdminRepository = Depends(get_admin_repo),
) -> list[MembershipResponse]:
    if not await repo.get_tenant(tenant_id):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="tenant not found")
    rows = await repo.list_memberships(tenant_id)
    return [MembershipResponse(**_serialize_row(r)) for r in rows]


@router.post(
    "/tenants/{tenant_id}/memberships",
    response_model=MembershipResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_membership(
    tenant_id: UUID,
    body: MembershipCreate,
    _principal: PlatformPrincipal = Depends(require_super_admin),
    repo: AdminRepository = Depends(get_admin_repo),
) -> MembershipResponse:
    if not await repo.get_tenant(tenant_id):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="tenant not found")
    row = await repo.create_membership(
        tenant_id,
        auth_issuer=body.auth_issuer.strip(),
        auth_subject=body.auth_subject.strip(),
        email=body.email,
        role=body.role,
    )
    return MembershipResponse(**_serialize_row(row))


@router.get("/scans", response_model=list[AdminScanResponse])
async def list_admin_scans(
    status_filter: str | None = Query(default=None, alias="status"),
    limit: int = Query(default=50, ge=1, le=200),
    _principal: PlatformPrincipal = Depends(require_super_admin),
    repo: AdminRepository = Depends(get_admin_repo),
) -> list[AdminScanResponse]:
    rows = await repo.list_scans(status=status_filter, limit=limit)
    return [AdminScanResponse(**_serialize_row(r)) for r in rows]
