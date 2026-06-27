from __future__ import annotations

import logging

from fastapi import HTTPException, status
from jwt import PyJWKClient, decode
from jwt.exceptions import InvalidTokenError

from platform_backend.identity.models import TokenClaims

logger = logging.getLogger(__name__)


class OidcJwtVerifier:
    def __init__(
        self,
        *,
        issuer: str,
        audience: str,
        jwks_uri: str,
    ) -> None:
        self._issuer = issuer.rstrip("/")
        self._audience = audience
        self._jwks_client = PyJWKClient(jwks_uri)

    def verify(self, token: str) -> TokenClaims:
        try:
            signing_key = self._jwks_client.get_signing_key_from_jwt(token)
            payload = decode(
                token,
                signing_key.key,
                algorithms=["RS256", "RS384", "RS512", "ES256", "ES384", "ES512"],
                audience=self._audience,
                issuer=self._issuer,
                options={"require": ["exp", "iss", "sub"]},
            )
        except InvalidTokenError as exc:
            logger.info("jwt verification failed", extra={"error": str(exc)})
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="invalid or expired token",
            ) from exc

        email = payload.get("email")
        if email is not None:
            email = str(email)

        return TokenClaims(
            subject=str(payload["sub"]),
            issuer=str(payload["iss"]),
            email=email,
            raw=dict(payload),
        )
