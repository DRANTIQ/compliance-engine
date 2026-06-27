from __future__ import annotations

from uuid import UUID

from platform_backend.db.pool import DatabasePool
from platform_backend.identity.models import PlatformPrincipal, PlatformRole


class IdentityRepository:
    def __init__(self, db: DatabasePool) -> None:
        self._db = db

    async def resolve_membership(
        self,
        *,
        auth_issuer: str,
        auth_subject: str,
    ) -> PlatformPrincipal | None:
        row = await self._db.fetchrow_global(
            """
            SELECT u.id AS user_id,
                   u.email,
                   m.tenant_id,
                   m.role
            FROM platform.tenant_memberships m
            JOIN platform.users u ON u.id = m.user_id
            WHERE m.auth_issuer = $1
              AND m.auth_subject = $2
              AND m.status = 'active'
            """,
            auth_issuer,
            auth_subject,
        )
        if not row:
            return None
        return PlatformPrincipal(
            tenant_id=row["tenant_id"],
            role=row["role"],
            subject=auth_subject,
            email=row["email"],
            user_id=row["user_id"],
            issuer=auth_issuer,
            auth_mode="jwt",
        )
