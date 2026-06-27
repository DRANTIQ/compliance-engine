from __future__ import annotations

import logging
from typing import Protocol

from fastapi import HTTPException, status
from jwt import decode
from jwt.exceptions import InvalidTokenError

from platform_backend.identity.models import TokenClaims

logger = logging.getLogger(__name__)


class JwtVerifier(Protocol):
    def verify(self, token: str) -> TokenClaims: ...


class HmacJwtVerifier:
    """HS256 JWT verification (Supabase Auth and similar IdPs)."""

    def __init__(
        self,
        *,
        issuer: str,
        audience: str,
        secret: str,
    ) -> None:
        self._issuer = issuer.rstrip("/")
        self._audience = audience
        self._secret = secret

    def verify(self, token: str) -> TokenClaims:
        try:
            payload = decode(
                token,
                self._secret,
                algorithms=["HS256"],
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
