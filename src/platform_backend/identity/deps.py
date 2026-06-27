from __future__ import annotations

from typing import Callable

from fastapi import Depends, HTTPException, Request, status

from platform_backend.config.settings import Settings, get_settings
from platform_backend.db.pool import DatabasePool
from platform_backend.identity.models import PlatformPrincipal, PlatformRole, READ_ROLES, WRITE_ROLES
from platform_backend.identity.repository import IdentityRepository
from platform_backend.identity.jwt_factory import build_jwt_verifier
from platform_backend.identity.service import IdentityService

_oidc_verifier = None


def _get_jwt_verifier(settings: Settings):
    global _oidc_verifier
    if _oidc_verifier is None and settings.jwt_auth_enabled:
        _oidc_verifier = build_jwt_verifier(settings)
    return _oidc_verifier


async def get_identity_service(
    request: Request,
    settings: Settings = Depends(get_settings),
) -> IdentityService:
    db: DatabasePool = request.app.state.db_pool
    return IdentityService(
        IdentityRepository(db),
        settings,
        oidc_verifier=_get_jwt_verifier(settings),
    )


async def get_principal(
    request: Request,
    service: IdentityService = Depends(get_identity_service),
) -> PlatformPrincipal:
    principal = await service.authenticate(request)
    request.state.tenant_id = principal.tenant_id
    request.state.principal = principal
    return principal


async def get_tenant_id(principal: PlatformPrincipal = Depends(get_principal)):
    return principal.tenant_id


def require_roles(*roles: PlatformRole) -> Callable:
    allowed = frozenset(roles)

    async def _check(principal: PlatformPrincipal = Depends(get_principal)) -> PlatformPrincipal:
        if principal.role not in allowed:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"role '{principal.role}' is not permitted for this operation",
            )
        return principal

    return _check


require_read_access = require_roles(*sorted(READ_ROLES))
require_write_access = require_roles(*sorted(WRITE_ROLES))
require_super_admin = require_roles("super_admin")
