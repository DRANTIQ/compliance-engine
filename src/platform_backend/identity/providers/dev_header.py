from __future__ import annotations

from uuid import UUID

from fastapi import HTTPException, Request, status

from platform_backend.identity.models import PlatformPrincipal, PlatformRole

VALID_ROLES: frozenset[PlatformRole] = frozenset({"tenant_admin", "viewer", "super_admin"})


def resolve_dev_header_principal(request: Request) -> PlatformPrincipal:
    tenant_header = request.headers.get("X-Tenant-ID")
    if not tenant_header:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="X-Tenant-ID header is required",
        )
    try:
        tenant_id = UUID(tenant_header)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="X-Tenant-ID must be a valid UUID",
        ) from exc

    role_header = request.headers.get("X-Role", "tenant_admin")
    if role_header not in VALID_ROLES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"X-Role must be one of: {', '.join(sorted(VALID_ROLES))}",
        )

    subject = request.headers.get("X-Subject", f"dev:{tenant_id}")
    email = request.headers.get("X-Email")

    return PlatformPrincipal(
        tenant_id=tenant_id,
        role=role_header,
        subject=subject,
        email=email,
        user_id=None,
        issuer="dev-header",
        auth_mode="dev_header",
    )
