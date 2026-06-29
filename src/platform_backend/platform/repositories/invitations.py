from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import UUID

import asyncpg

from platform_backend.db.pool import DatabasePool

INVITE_TTL_DAYS = 7
INVITE_ROLES = frozenset({"tenant_admin", "viewer"})


def hash_invite_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def generate_invite_token() -> str:
    return secrets.token_urlsafe(32)


class InvitationRepository:
    def __init__(self, db: DatabasePool) -> None:
        self._db = db

    async def create_invitation(
        self,
        *,
        tenant_id: UUID,
        email: str,
        role: str,
        invited_by: UUID | None,
    ) -> tuple[dict[str, Any], str]:
        if role not in INVITE_ROLES:
            raise ValueError(f"invalid invite role: {role}")

        token = generate_invite_token()
        token_hash = hash_invite_token(token)
        expires_at = datetime.now(timezone.utc) + timedelta(days=INVITE_TTL_DAYS)

        row = await self._db.fetchrow_global(
            """
            INSERT INTO platform.invitations (
                tenant_id, email, role, token_hash, invited_by, expires_at
            )
            VALUES ($1, lower($2), $3, $4, $5, $6)
            RETURNING id, tenant_id, email, role, status, expires_at, created_at
            """,
            tenant_id,
            email.strip(),
            role,
            token_hash,
            invited_by,
            expires_at,
        )
        assert row is not None
        return dict(row), token

    async def get_by_token(self, token: str) -> dict[str, Any] | None:
        token_hash = hash_invite_token(token)
        row = await self._db.fetchrow_global(
            """
            SELECT i.id, i.tenant_id, i.email, i.role, i.status, i.expires_at,
                   i.accepted_at, i.created_at,
                   t.name AS tenant_name
            FROM platform.invitations i
            JOIN platform.tenants t ON t.id = i.tenant_id
            WHERE i.token_hash = $1
            """,
            token_hash,
        )
        if not row:
            return None
        result = dict(row)
        if result["status"] == "pending" and result["expires_at"] < datetime.now(timezone.utc):
            await self._db.fetchrow_global(
                """
                UPDATE platform.invitations
                SET status = 'expired', updated_at = now()
                WHERE id = $1 AND status = 'pending'
                RETURNING id
                """,
                result["id"],
            )
            result["status"] = "expired"
        return result

    async def list_for_tenant(self, tenant_id: UUID) -> list[dict[str, Any]]:
        rows = await self._db.fetch_global(
            """
            SELECT id, tenant_id, email, role, status, expires_at, accepted_at, created_at
            FROM platform.invitations
            WHERE tenant_id = $1
            ORDER BY created_at DESC
            """,
            tenant_id,
        )
        return [dict(r) for r in rows]

    async def revoke(self, tenant_id: UUID, invitation_id: UUID) -> dict[str, Any] | None:
        row = await self._db.fetchrow_global(
            """
            UPDATE platform.invitations
            SET status = 'revoked', updated_at = now()
            WHERE id = $1 AND tenant_id = $2 AND status = 'pending'
            RETURNING id, tenant_id, email, role, status, expires_at, accepted_at, created_at
            """,
            invitation_id,
            tenant_id,
        )
        return dict(row) if row else None

    async def accept_invitation(
        self,
        *,
        token: str,
        auth_issuer: str,
        auth_subject: str,
        email: str | None,
    ) -> dict[str, Any]:
        invite = await self.get_by_token(token)
        if not invite:
            raise InvitationError("invitation not found", status_code=404)
        if invite["status"] == "revoked":
            raise InvitationError("invitation was revoked", status_code=410)
        if invite["status"] == "expired":
            raise InvitationError("invitation has expired", status_code=410)
        if invite["status"] == "accepted":
            raise InvitationError("invitation already accepted", status_code=409)
        if invite["status"] != "pending":
            raise InvitationError("invitation is not valid", status_code=400)

        if email and invite["email"].lower() != email.lower():
            raise InvitationError("invitation email does not match your account", status_code=403)

        async with self._db.acquire() as conn:
            async with conn.transaction():
                existing = await conn.fetchrow(
                    """
                    SELECT tenant_id FROM platform.tenant_memberships
                    WHERE auth_issuer = $1 AND auth_subject = $2 AND status = 'active'
                    """,
                    auth_issuer,
                    auth_subject,
                )
                if existing:
                    raise InvitationError("account already belongs to a workspace", status_code=403)

                user_row = await conn.fetchrow(
                    """
                    INSERT INTO platform.users (email, onboarding_state)
                    VALUES ($1, 'WORKSPACE_CREATED')
                    RETURNING id
                    """,
                    email or invite["email"],
                )
                assert user_row is not None

                membership_row = await conn.fetchrow(
                    """
                    INSERT INTO platform.tenant_memberships (
                        user_id, tenant_id, role, auth_issuer, auth_subject
                    )
                    VALUES ($1, $2, $3, $4, $5)
                    RETURNING id, tenant_id, role, status
                    """,
                    user_row["id"],
                    invite["tenant_id"],
                    invite["role"],
                    auth_issuer,
                    auth_subject,
                )
                assert membership_row is not None

                await conn.execute(
                    """
                    UPDATE platform.invitations
                    SET status = 'accepted', accepted_at = now(), updated_at = now()
                    WHERE id = $1
                    """,
                    invite["id"],
                )

                tenant_row = await conn.fetchrow(
                    """
                    SELECT id, name, slug, status, onboarding_state, plan, trial_end
                    FROM platform.tenants WHERE id = $1
                    """,
                    invite["tenant_id"],
                )
                assert tenant_row is not None

                return {
                    "tenant": dict(tenant_row),
                    "membership": dict(membership_row),
                }


class InvitationError(Exception):
    def __init__(self, message: str, *, status_code: int = 400) -> None:
        super().__init__(message)
        self.status_code = status_code
