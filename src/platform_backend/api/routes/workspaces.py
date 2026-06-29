from __future__ import annotations

import logging
from datetime import datetime
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from platform_backend.api.deps import get_db_pool
from platform_backend.db.pool import DatabasePool
from platform_backend.identity.deps import get_jwt_claims, get_principal, require_write_access
from platform_backend.identity.models import PlatformPrincipal, TokenClaims
from platform_backend.identity.slug import validate_workspace_name
from platform_backend.platform.repositories.workspace import (
    ONBOARDING_STATES,
    SlugUnavailableError,
    WorkspaceRepository,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/v1/workspaces", tags=["workspaces"])


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


async def get_workspace_repo(db: DatabasePool = Depends(get_db_pool)) -> WorkspaceRepository:
    return WorkspaceRepository(db)


class WorkspaceCreate(BaseModel):
    workspace_name: str = Field(min_length=2, max_length=100, description="Customer-facing workspace name")


class WorkspaceResponse(BaseModel):
    id: str
    name: str
    slug: str
    status: str
    onboarding_state: str
    plan: str
    trial_end: str | None = None
    created_at: str | None = None
    updated_at: str | None = None


class WorkspaceCreateResponse(BaseModel):
    workspace: WorkspaceResponse
    membership: dict[str, str]
    next_path: str = "/welcome"


class OnboardingUpdate(BaseModel):
    onboarding_state: str = Field(description="Target onboarding state")


@router.post(
    "",
    response_model=WorkspaceCreateResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create workspace",
    description=(
        "Create a new workspace for the authenticated user. Requires a valid JWT with "
        "**no existing membership**. Slug is generated server-side."
    ),
    responses={
        201: {"description": "Workspace created"},
        401: {"description": "Missing or invalid JWT"},
        403: {"description": "User already belongs to a workspace"},
        409: {"description": "Workspace name unavailable"},
        422: {"description": "Invalid workspace name"},
    },
)
async def create_workspace(
    body: WorkspaceCreate,
    claims: TokenClaims = Depends(get_jwt_claims),
    repo: WorkspaceRepository = Depends(get_workspace_repo),
) -> WorkspaceCreateResponse:
    if err := validate_workspace_name(body.workspace_name):
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=err)

    if await repo.has_membership(auth_issuer=claims.issuer, auth_subject=claims.subject):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="account already belongs to a workspace",
        )

    try:
        result = await repo.create_workspace(
            workspace_name=body.workspace_name,
            auth_issuer=claims.issuer,
            auth_subject=claims.subject,
            email=claims.email,
        )
    except SlugUnavailableError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        ) from exc

    tenant = _serialize_row(result["tenant"])
    logger.info(
        "tenant.registered tenant_id=%s slug=%s subject=%s",
        tenant["id"],
        tenant["slug"],
        claims.subject,
        extra={"audit": True, "event": "tenant.registered"},
    )

    return WorkspaceCreateResponse(
        workspace=WorkspaceResponse(**tenant),
        membership={
            "id": str(result["membership"]["id"]),
            "role": result["membership"]["role"],
            "status": result["membership"]["status"],
        },
        next_path="/welcome",
    )


@router.get(
    "/current",
    response_model=WorkspaceResponse,
    summary="Current workspace",
    description="Returns the workspace for the authenticated membership.",
)
async def get_current_workspace(
    principal: PlatformPrincipal = Depends(get_principal),
    repo: WorkspaceRepository = Depends(get_workspace_repo),
) -> WorkspaceResponse:
    row = await repo.get_workspace(principal.tenant_id)
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="workspace not found")
    return WorkspaceResponse(**_serialize_row(row))


@router.patch(
    "/current/onboarding",
    response_model=WorkspaceResponse,
    summary="Update onboarding state",
    description="Advance workspace onboarding. Sets status to `active` when onboarding completes.",
)
async def update_onboarding(
    body: OnboardingUpdate,
    principal: PlatformPrincipal = Depends(require_write_access),
    repo: WorkspaceRepository = Depends(get_workspace_repo),
) -> WorkspaceResponse:
    if body.onboarding_state not in ONBOARDING_STATES:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="invalid onboarding_state",
        )
    row = await repo.update_onboarding_state(principal.tenant_id, body.onboarding_state)
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="workspace not found")
    logger.info(
        "onboarding.updated tenant_id=%s state=%s",
        principal.tenant_id,
        body.onboarding_state,
        extra={"audit": True, "event": "onboarding.updated"},
    )
    return WorkspaceResponse(**_serialize_row(row))
