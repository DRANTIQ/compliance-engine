from __future__ import annotations

from fastapi import HTTPException, Request, status

from platform_backend.config.settings import Settings
from platform_backend.identity.models import PlatformPrincipal, TokenClaims
from platform_backend.identity.providers.dev_header import resolve_dev_header_principal
from platform_backend.identity.providers.hmac_jwt import JwtVerifier
from platform_backend.identity.repository import IdentityRepository


class IdentityService:
    def __init__(
        self,
        repo: IdentityRepository,
        settings: Settings,
        oidc_verifier: JwtVerifier | None = None,
    ) -> None:
        self._repo = repo
        self._settings = settings
        self._oidc = oidc_verifier

    async def authenticate(self, request: Request) -> PlatformPrincipal:
        authorization = request.headers.get("Authorization")
        if authorization and authorization.lower().startswith("bearer "):
            if not self._oidc:
                raise HTTPException(
                    status_code=status.HTTP_501_NOT_IMPLEMENTED,
                    detail="OIDC authentication is not configured",
                )
            token = authorization.split(" ", 1)[1].strip()
            if not token:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Bearer token is required",
                )
            claims = self._oidc.verify(token)
            principal = await self._repo.resolve_membership(
                auth_issuer=claims.issuer,
                auth_subject=claims.subject,
            )
            if not principal:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="user is not provisioned for any tenant",
                )
            if claims.email and not principal.email:
                return PlatformPrincipal(
                    tenant_id=principal.tenant_id,
                    role=principal.role,
                    subject=principal.subject,
                    email=claims.email,
                    user_id=principal.user_id,
                    issuer=claims.issuer,
                    auth_mode="jwt",
                    workspace_name=principal.workspace_name,
                    workspace_slug=principal.workspace_slug,
                    workspace_status=principal.workspace_status,
                    onboarding_state=principal.onboarding_state,
                    plan=principal.plan,
                    trial_end=principal.trial_end,
                )
            return principal

        if self._settings.dev_tenant_header_auth:
            return resolve_dev_header_principal(request)

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authorization required",
        )

    def verify_bearer_token(self, request: Request) -> TokenClaims:
        authorization = request.headers.get("Authorization")
        if not authorization or not authorization.lower().startswith("bearer "):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Bearer token is required",
            )
        if not self._oidc:
            raise HTTPException(
                status_code=status.HTTP_501_NOT_IMPLEMENTED,
                detail="OIDC authentication is not configured",
            )
        token = authorization.split(" ", 1)[1].strip()
        if not token:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Bearer token is required",
            )
        return self._oidc.verify(token)
