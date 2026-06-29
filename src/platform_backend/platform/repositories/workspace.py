from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import UUID

import asyncpg

from platform_backend.db.pool import DatabasePool
from platform_backend.identity.slug import slug_candidates, slugify_workspace_name, validate_slug

ONBOARDING_STATES = frozenset({
    "WORKSPACE_CREATED",
    "AWS_CONNECTED",
    "FIRST_SCAN_STARTED",
    "FIRST_SCAN_COMPLETE",
    "ONBOARDING_COMPLETE",
})

TRIAL_DAYS = 14


class WorkspaceRepository:
    def __init__(self, db: DatabasePool) -> None:
        self._db = db

    async def has_membership(self, *, auth_issuer: str, auth_subject: str) -> bool:
        row = await self._db.fetchrow_global(
            """
            SELECT 1
            FROM platform.tenant_memberships
            WHERE auth_issuer = $1
              AND auth_subject = $2
              AND status = 'active'
            """,
            auth_issuer,
            auth_subject,
        )
        return row is not None

    async def slug_exists(self, conn: asyncpg.Connection, slug: str) -> bool:
        row = await conn.fetchrow(
            "SELECT 1 FROM platform.tenants WHERE slug = $1",
            slug,
        )
        return row is not None

    async def resolve_unique_slug(self, conn: asyncpg.Connection, workspace_name: str) -> str | None:
        base = slugify_workspace_name(workspace_name)
        if err := validate_slug(base):
            return None
        for candidate in slug_candidates(base):
            if candidate in {"admin", "api", "app", "drantiq"}:
                continue
            if not await self.slug_exists(conn, candidate):
                return candidate
        return None

    async def create_workspace(
        self,
        *,
        workspace_name: str,
        auth_issuer: str,
        auth_subject: str,
        email: str | None,
    ) -> dict[str, Any]:
        async with self._db.acquire() as conn:
            async with conn.transaction():
                slug = await self.resolve_unique_slug(conn, workspace_name.strip())
                if not slug:
                    raise SlugUnavailableError("workspace name unavailable")

                trial_end = datetime.now(timezone.utc) + timedelta(days=TRIAL_DAYS)
                tenant_row = await conn.fetchrow(
                    """
                    INSERT INTO platform.tenants (
                        name, slug, status, onboarding_state, plan, trial_end
                    )
                    VALUES ($1, $2, 'provisioning', 'WORKSPACE_CREATED', 'trial', $3)
                    RETURNING id, name, slug, status, onboarding_state, plan, trial_end,
                              created_at, updated_at
                    """,
                    workspace_name.strip(),
                    slug,
                    trial_end,
                )
                assert tenant_row is not None

                user_row = await conn.fetchrow(
                    """
                    INSERT INTO platform.users (email, onboarding_state)
                    VALUES ($1, 'WORKSPACE_CREATED')
                    RETURNING id, email, onboarding_state
                    """,
                    email,
                )
                assert user_row is not None

                membership_row = await conn.fetchrow(
                    """
                    INSERT INTO platform.tenant_memberships (
                        user_id, tenant_id, role, auth_issuer, auth_subject
                    )
                    VALUES ($1, $2, 'tenant_admin', $3, $4)
                    RETURNING id, role, status
                    """,
                    user_row["id"],
                    tenant_row["id"],
                    auth_issuer,
                    auth_subject,
                )
                assert membership_row is not None

                return {
                    "tenant": dict(tenant_row),
                    "user": dict(user_row),
                    "membership": dict(membership_row),
                }

    async def get_workspace(self, tenant_id: UUID) -> dict[str, Any] | None:
        row = await self._db.fetchrow_global(
            """
            SELECT id, name, slug, status, onboarding_state, plan, trial_end,
                   created_at, updated_at
            FROM platform.tenants
            WHERE id = $1
            """,
            tenant_id,
        )
        return dict(row) if row else None

    async def update_onboarding_state(
        self,
        tenant_id: UUID,
        onboarding_state: str,
    ) -> dict[str, Any] | None:
        if onboarding_state not in ONBOARDING_STATES:
            raise ValueError(f"invalid onboarding_state: {onboarding_state}")

        status = "active" if onboarding_state == "ONBOARDING_COMPLETE" else None
        row = await self._db.fetchrow_global(
            """
            UPDATE platform.tenants
            SET onboarding_state = $2,
                status = COALESCE($3, status),
                updated_at = now()
            WHERE id = $1
            RETURNING id, name, slug, status, onboarding_state, plan, trial_end,
                      created_at, updated_at
            """,
            tenant_id,
            onboarding_state,
            status,
        )
        return dict(row) if row else None

    async def update_plan(
        self,
        tenant_id: UUID,
        *,
        plan: str,
        trial_end: datetime | None = None,
    ) -> dict[str, Any] | None:
        row = await self._db.fetchrow_global(
            """
            UPDATE platform.tenants
            SET plan = $2,
                trial_end = COALESCE($3, trial_end),
                updated_at = now()
            WHERE id = $1
            RETURNING id, name, slug, status, onboarding_state, plan, trial_end,
                      created_at, updated_at
            """,
            tenant_id,
            plan,
            trial_end,
        )
        return dict(row) if row else None


class SlugUnavailableError(Exception):
    pass
