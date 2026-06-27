"""Tests for HS256 JWT verification (Supabase Auth)."""

from __future__ import annotations

import time

import jwt
import pytest
from fastapi import HTTPException

from platform_backend.identity.providers.hmac_jwt import HmacJwtVerifier

ISSUER = "https://testproject.supabase.co/auth/v1"
AUDIENCE = "authenticated"
SECRET = "test-jwt-secret-for-unit-tests-only"


def _make_token(**overrides: object) -> str:
    now = int(time.time())
    payload = {
        "iss": ISSUER,
        "sub": "11111111-2222-3333-4444-555555555555",
        "aud": AUDIENCE,
        "exp": now + 3600,
        "iat": now,
        "email": "partner@example.com",
        "role": "authenticated",
    }
    payload.update(overrides)
    return jwt.encode(payload, SECRET, algorithm="HS256")


def test_hmac_jwt_verifier_accepts_valid_token() -> None:
    verifier = HmacJwtVerifier(issuer=ISSUER, audience=AUDIENCE, secret=SECRET)
    claims = verifier.verify(_make_token())
    assert claims.subject == "11111111-2222-3333-4444-555555555555"
    assert claims.issuer == ISSUER
    assert claims.email == "partner@example.com"


def test_hmac_jwt_verifier_rejects_expired_token() -> None:
    verifier = HmacJwtVerifier(issuer=ISSUER, audience=AUDIENCE, secret=SECRET)
    token = _make_token(exp=int(time.time()) - 10)
    with pytest.raises(HTTPException) as exc:
        verifier.verify(token)
    assert exc.value.status_code == 401
