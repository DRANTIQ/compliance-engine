from __future__ import annotations

from platform_backend.config.settings import Settings
from platform_backend.identity.providers.hmac_jwt import HmacJwtVerifier, JwtVerifier
from platform_backend.identity.providers.oidc_jwt import OidcJwtVerifier


def _legacy_hs256_secret(settings: Settings) -> str:
    secret = (settings.oidc_jwt_secret or "").strip()
    if not secret or secret.startswith("your-"):
        return ""
    return secret


def build_jwt_verifier(settings: Settings) -> JwtVerifier | None:
    if not settings.jwt_auth_enabled:
        return None

    issuer = settings.effective_oidc_issuer
    audience = settings.oidc_audience or "authenticated"

    if not issuer:
        raise RuntimeError(
            "JWT auth requires OIDC_ISSUER or SUPABASE_URL "
            "(e.g. https://<project>.supabase.co)"
        )

    legacy_secret = _legacy_hs256_secret(settings)
    if legacy_secret:
        return HmacJwtVerifier(
            issuer=issuer,
            audience=audience,
            secret=legacy_secret,
        )

    jwks_uri = settings.oidc_jwks_uri
    if not jwks_uri:
        jwks_uri = f"{issuer}/.well-known/jwks.json"
    return OidcJwtVerifier(
        issuer=issuer,
        audience=audience,
        jwks_uri=jwks_uri,
    )
