from __future__ import annotations

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from platform_backend.identity.deps import get_principal
from platform_backend.identity.models import PlatformPrincipal

router = APIRouter(prefix="/v1/me", tags=["identity"])


class MeResponse(BaseModel):
    tenant_id: str = Field(description="Tenant UUID from membership")
    role: str = Field(description="tenant_admin | viewer | super_admin")
    subject: str = Field(description="JWT `sub` claim (Supabase user UID)")
    email: str | None = Field(default=None, description="Email from JWT or users table")
    user_id: str | None = Field(default=None, description="Internal platform.users id")
    issuer: str | None = Field(default=None, description="JWT `iss` (Supabase auth issuer URL)")
    auth_mode: str = Field(description="jwt or dev_header")


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
    return MeResponse(
        tenant_id=str(principal.tenant_id),
        role=principal.role,
        subject=principal.subject,
        email=principal.email,
        user_id=str(principal.user_id) if principal.user_id else None,
        issuer=principal.issuer,
        auth_mode=principal.auth_mode,
    )
