from __future__ import annotations

import re
from datetime import datetime
from typing import Any
from uuid import UUID

import redis.asyncio as redis
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field, field_validator

from platform_backend.api.deps import get_db_pool, get_integration_service, get_redis, get_scan_service, get_settings_dep
from platform_backend.config.settings import Settings
from platform_backend.db.pool import DatabasePool
from platform_backend.identity.deps import require_super_admin
from platform_backend.identity.models import PlatformPrincipal
from platform_backend.platform.repositories.admin import AdminRepository
from platform_backend.platform.services.scan_service import IntegrationService, ScanService

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
    policy_queue_depth: int
    api_status: str


class AdminIntegrationResponse(BaseModel):
    id: str
    tenant_id: str
    provider: str
    account_id: str
    role_arn: str
    regions: list[str]
    status: str
    created_at: str
    updated_at: str


class AdminScanCreate(BaseModel):
    integration_id: UUID


class AdminScanCreateResponse(BaseModel):
    id: str
    tenant_id: str
    integration_id: str
    status: str
    trace_id: str
    started_at: str | None = None
    completed_at: str | None = None
    created_at: str
    updated_at: str


@router.get(
    "/overview",
    response_model=AdminOverviewResponse,
    summary="Platform ops overview",
    description="Cross-tenant counts: tenants, failed/active scans, Redis queue depths. **super_admin only.** Login as ops@drantiq.local.",
    responses={200: {"description": "Overview metrics"}, 403: {"description": "Not super_admin"}},
)
async def admin_overview(
    _principal: PlatformPrincipal = Depends(require_super_admin),
    repo: AdminRepository = Depends(get_admin_repo),
    redis_client: redis.Redis = Depends(get_redis),
    db: DatabasePool = Depends(get_db_pool),
    settings: Settings = Depends(get_settings_dep),
) -> AdminOverviewResponse:
    tenant_count = await repo.count_tenants()
    failed_scan_count = await repo.count_scans_by_status("failed")
    active = 0
    for st in ("queued", "collecting", "ingesting", "evaluating"):
        active += await repo.count_scans_by_status(st)
    collect_depth = int(await redis_client.llen(settings.collect_queue_key))
    events_depth = int(await redis_client.llen(settings.platform_events_key))
    policy_depth = int(await redis_client.llen(settings.policy_queue_key))
    try:
        await db.ping()
        await redis_client.ping()
        api_status = "ready"
    except Exception:
        api_status = "degraded"
    return AdminOverviewResponse(
        tenant_count=tenant_count,
        failed_scan_count=failed_scan_count,
        active_scan_count=active,
        collect_queue_depth=collect_depth,
        events_queue_depth=events_depth,
        policy_queue_depth=policy_depth,
        api_status=api_status,
    )


@router.get(
    "/tenants",
    response_model=list[TenantResponse],
    summary="List all tenants",
    description="Cross-tenant list for admin-ui. **super_admin only.**",
)
async def list_tenants(
    _principal: PlatformPrincipal = Depends(require_super_admin),
    repo: AdminRepository = Depends(get_admin_repo),
) -> list[TenantResponse]:
    rows = await repo.list_tenants()
    return [TenantResponse(**_serialize_row(r)) for r in rows]


@router.post(
    "/tenants",
    response_model=TenantResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create tenant",
    description="Provision a new customer tenant. Slug must be unique lowercase alphanumeric with hyphens.",
    responses={201: {"description": "Created"}, 409: {"description": "Slug exists"}},
)
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


@router.get(
    "/tenants/{tenant_id}",
    response_model=TenantResponse,
    summary="Get tenant",
    description="Single tenant by UUID.",
    responses={404: {"description": "Tenant not found"}},
)
async def get_tenant(
    tenant_id: UUID,
    _principal: PlatformPrincipal = Depends(require_super_admin),
    repo: AdminRepository = Depends(get_admin_repo),
) -> TenantResponse:
    row = await repo.get_tenant(tenant_id)
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="tenant not found")
    return TenantResponse(**_serialize_row(row))


@router.patch(
    "/tenants/{tenant_id}",
    response_model=TenantResponse,
    summary="Update tenant",
    description="Rename or suspend/activate tenant.",
    responses={400: {"description": "No fields"}, 404: {"description": "Not found"}},
)
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


@router.get(
    "/tenants/{tenant_id}/memberships",
    response_model=list[MembershipResponse],
    summary="List tenant memberships",
    description="Supabase/OIDC users linked to tenant with roles.",
)
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
    summary="Provision user membership",
    description=(
        "Link Supabase user (`auth_issuer` + `auth_subject` from JWT) to tenant. "
        "Issuer is typically `https://<project>.supabase.co/auth/v1`."
    ),
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


@router.get(
    "/scans",
    response_model=list[AdminScanResponse],
    summary="List scans (cross-tenant)",
    description="Recent scans across all tenants. Filter `?status=failed` for ops triage.",
)
async def list_admin_scans(
    status_filter: str | None = Query(default=None, alias="status"),
    limit: int = Query(default=50, ge=1, le=200),
    _principal: PlatformPrincipal = Depends(require_super_admin),
    repo: AdminRepository = Depends(get_admin_repo),
) -> list[AdminScanResponse]:
    rows = await repo.list_scans(status=status_filter, limit=limit)
    return [AdminScanResponse(**_serialize_row(r)) for r in rows]


@router.get(
    "/tenants/{tenant_id}/integrations",
    response_model=list[AdminIntegrationResponse],
    summary="List tenant integrations (admin)",
    description="Same as tenant-scoped integrations list but callable by super_admin for any tenant.",
)
async def list_tenant_integrations(
    tenant_id: UUID,
    _principal: PlatformPrincipal = Depends(require_super_admin),
    repo: AdminRepository = Depends(get_admin_repo),
    integration_service: IntegrationService = Depends(get_integration_service),
) -> list[AdminIntegrationResponse]:
    if not await repo.get_tenant(tenant_id):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="tenant not found")
    rows = await integration_service.list(tenant_id)
    return [AdminIntegrationResponse(**r) for r in rows]


@router.get(
    "/tenants/{tenant_id}/scans",
    response_model=list[AdminScanResponse],
    summary="List scans for tenant (admin)",
    description="Recent scans for one tenant from admin-ui tenant detail.",
)
async def list_tenant_scans(
    tenant_id: UUID,
    limit: int = Query(default=20, ge=1, le=100),
    _principal: PlatformPrincipal = Depends(require_super_admin),
    repo: AdminRepository = Depends(get_admin_repo),
) -> list[AdminScanResponse]:
    if not await repo.get_tenant(tenant_id):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="tenant not found")
    rows = await repo.list_scans_for_tenant(tenant_id, limit=limit)
    return [AdminScanResponse(**_serialize_row(r)) for r in rows]


@router.post(
    "/tenants/{tenant_id}/scans",
    response_model=AdminScanCreateResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Trigger scan for tenant (admin)",
    description="Ops-initiated scan from admin-ui tenant detail. Same pipeline as POST /v1/scans.",
    responses={201: {"description": "Scan queued"}, 404: {"description": "Tenant or integration not found"}},
)
async def create_tenant_scan(
    tenant_id: UUID,
    body: AdminScanCreate,
    _principal: PlatformPrincipal = Depends(require_super_admin),
    repo: AdminRepository = Depends(get_admin_repo),
    service: ScanService = Depends(get_scan_service),
) -> AdminScanCreateResponse:
    if not await repo.get_tenant(tenant_id):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="tenant not found")
    try:
        row = await service.create_scan(tenant_id, body.integration_id)
    except LookupError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    return AdminScanCreateResponse(**row)
