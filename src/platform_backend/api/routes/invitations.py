from __future__ import annotations

import logging
from datetime import datetime
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from platform_backend.api.deps import get_db_pool
from platform_backend.config.settings import Settings, get_settings
from platform_backend.db.pool import DatabasePool
from platform_backend.identity.deps import get_jwt_claims, get_principal, require_write_access
from platform_backend.identity.models import PlatformPrincipal, TokenClaims
from platform_backend.platform.repositories.invitations import InvitationError, InvitationRepository

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/v1/invitations", tags=["invitations"])


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


async def get_invitation_repo(db: DatabasePool = Depends(get_db_pool)) -> InvitationRepository:
    return InvitationRepository(db)


class InvitationCreate(BaseModel):
    email: str = Field(min_length=3, max_length=320)
    role: str = Field(default="viewer", pattern="^(tenant_admin|viewer)$")


class InvitationResponse(BaseModel):
    id: str
    tenant_id: str
    email: str
    role: str
    status: str
    expires_at: str
    created_at: str
    invite_url: str | None = None


class InvitationPreview(BaseModel):
    email: str
    role: str
    status: str
    workspace_name: str
    expires_at: str


class InvitationAccept(BaseModel):
    token: str = Field(min_length=16)


class InvitationAcceptResponse(BaseModel):
    workspace: dict[str, Any]
    membership: dict[str, Any]
    next_path: str = "/welcome"


@router.post(
    "",
    response_model=InvitationResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Invite teammate",
    description="Send a workspace invitation. **tenant_admin only.** Returns invite URL for sharing.",
)
async def create_invitation(
    body: InvitationCreate,
    principal: PlatformPrincipal = Depends(require_write_access),
    repo: InvitationRepository = Depends(get_invitation_repo),
    settings: Settings = Depends(get_settings),
) -> InvitationResponse:
    row, token = await repo.create_invitation(
        tenant_id=principal.tenant_id,
        email=str(body.email),
        role=body.role,
        invited_by=principal.user_id,
    )
    app_url = settings.app_public_url.rstrip("/")
    result = _serialize_row(row)
    result["invite_url"] = f"{app_url}/accept-invite?token={token}"
    logger.info(
        "invitation.created tenant_id=%s email=%s",
        principal.tenant_id,
        body.email,
        extra={"audit": True, "event": "invitation.created"},
    )
    return InvitationResponse(**result)


@router.get(
    "/preview",
    response_model=InvitationPreview,
    summary="Preview invitation",
    description="Validate an invite token before signup or accept.",
)
async def preview_invitation(
    token: str,
    repo: InvitationRepository = Depends(get_invitation_repo),
) -> InvitationPreview:
    invite = await repo.get_by_token(token)
    if not invite:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="invitation not found")
    return InvitationPreview(
        email=invite["email"],
        role=invite["role"],
        status=invite["status"],
        workspace_name=invite["tenant_name"],
        expires_at=invite["expires_at"].isoformat()
        if isinstance(invite["expires_at"], datetime)
        else str(invite["expires_at"]),
    )


@router.post(
    "/accept",
    response_model=InvitationAcceptResponse,
    summary="Accept invitation",
    description="Join an existing workspace using an invite token. Requires JWT with no existing membership.",
)
async def accept_invitation(
    body: InvitationAccept,
    claims: TokenClaims = Depends(get_jwt_claims),
    repo: InvitationRepository = Depends(get_invitation_repo),
) -> InvitationAcceptResponse:
    try:
        result = await repo.accept_invitation(
            token=body.token,
            auth_issuer=claims.issuer,
            auth_subject=claims.subject,
            email=claims.email,
        )
    except InvitationError as exc:
        raise HTTPException(status_code=exc.status_code, detail=str(exc)) from exc

    tenant = _serialize_row(result["tenant"])
    membership = _serialize_row(result["membership"])
    logger.info(
        "invitation.accepted tenant_id=%s subject=%s",
        tenant["id"],
        claims.subject,
        extra={"audit": True, "event": "invitation.accepted"},
    )
    return InvitationAcceptResponse(
        workspace=tenant,
        membership=membership,
        next_path="/welcome",
    )


@router.get(
    "",
    response_model=list[InvitationResponse],
    summary="List workspace invitations",
)
async def list_invitations(
    principal: PlatformPrincipal = Depends(require_write_access),
    repo: InvitationRepository = Depends(get_invitation_repo),
) -> list[InvitationResponse]:
    rows = await repo.list_for_tenant(principal.tenant_id)
    return [InvitationResponse(**_serialize_row(r)) for r in rows]


@router.delete(
    "/{invitation_id}",
    response_model=InvitationResponse,
    summary="Revoke invitation",
)
async def revoke_invitation(
    invitation_id: UUID,
    principal: PlatformPrincipal = Depends(require_write_access),
    repo: InvitationRepository = Depends(get_invitation_repo),
) -> InvitationResponse:
    row = await repo.revoke(principal.tenant_id, invitation_id)
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="invitation not found")
    return InvitationResponse(**_serialize_row(row))
