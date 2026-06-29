from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends, Header, HTTPException, status
from pydantic import BaseModel, Field

from platform_backend.identity.deps import get_principal
from platform_backend.identity.models import PlatformPrincipal

router = APIRouter(prefix="/v1/me", tags=["identity"])


class WorkspaceSummary(BaseModel):
    id: str
    name: str
    slug: str
    status: str
    onboarding_state: str
    plan: str
    trial_end: str | None = None


class MeResponse(BaseModel):
    tenant_id: str = Field(description="Tenant UUID from membership")
    role: str = Field(description="tenant_admin | viewer | super_admin")
    subject: str = Field(description="JWT `sub` claim (Supabase user UID)")
    email: str | None = Field(default=None, description="Email from JWT or users table")
    user_id: str | None = Field(default=None, description="Internal platform.users id")
    issuer: str | None = Field(default=None, description="JWT `iss` (Supabase auth issuer URL)")
    auth_mode: str = Field(description="jwt or dev_header")
    workspace: WorkspaceSummary | None = None


@router.get(
    "",
    response_model=MeResponse,
    summary="Current user profile",
    description=(
        "Returns the authenticated principal resolved from Supabase JWT or dev headers. "
        "**Use this first** after Authorize in Swagger to confirm token and membership.\n\n"
        "- **401** — missing or invalid Bearer token\n"
        "- **403** — JWT valid but no row in `platform.tenant_memberships`"
    ),
    responses={
        200: {"description": "Membership resolved"},
        401: {"description": "Missing or invalid Authorization header"},
        403: {"description": "User not provisioned for any tenant"},
    },
)
async def get_me(principal: PlatformPrincipal = Depends(get_principal)) -> MeResponse:
    workspace = None
    if principal.workspace_name and principal.onboarding_state:
        trial_end = principal.trial_end
        workspace = WorkspaceSummary(
            id=str(principal.tenant_id),
            name=principal.workspace_name,
            slug=principal.workspace_slug or "",
            status=principal.workspace_status or "active",
            onboarding_state=principal.onboarding_state,
            plan=principal.plan or "trial",
            trial_end=trial_end.isoformat() if isinstance(trial_end, datetime) else None,
        )
    return MeResponse(
        tenant_id=str(principal.tenant_id),
        role=principal.role,
        subject=principal.subject,
        email=principal.email,
        user_id=str(principal.user_id) if principal.user_id else None,
        issuer=principal.issuer,
        auth_mode=principal.auth_mode,
        workspace=workspace,
    )
