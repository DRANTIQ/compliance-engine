from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal
from uuid import UUID

PlatformRole = Literal["tenant_admin", "viewer", "super_admin"]
READ_ROLES: frozenset[PlatformRole] = frozenset({"tenant_admin", "viewer", "super_admin"})
WRITE_ROLES: frozenset[PlatformRole] = frozenset({"tenant_admin", "super_admin"})


@dataclass(frozen=True)
class TokenClaims:
    subject: str
    issuer: str
    email: str | None = None
    raw: dict[str, Any] | None = None


@dataclass(frozen=True)
class PlatformPrincipal:
    tenant_id: UUID
    role: PlatformRole
    subject: str
    email: str | None = None
    user_id: UUID | None = None
    issuer: str | None = None
    auth_mode: str = "unknown"
