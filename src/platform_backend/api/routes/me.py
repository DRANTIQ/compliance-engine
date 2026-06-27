from __future__ import annotations

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from platform_backend.identity.deps import get_principal
from platform_backend.identity.models import PlatformPrincipal

router = APIRouter(prefix="/v1/me", tags=["identity"])


class MeResponse(BaseModel):
    tenant_id: str
    role: str
    subject: str
    email: str | None = None
    user_id: str | None = None
    issuer: str | None = None
    auth_mode: str


@router.get("", response_model=MeResponse)
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
