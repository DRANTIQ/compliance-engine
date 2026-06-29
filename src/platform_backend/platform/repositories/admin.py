from __future__ import annotations

from typing import Any
from uuid import UUID

from platform_backend.db.pool import DatabasePool


class AdminRepository:
    def __init__(self, db: DatabasePool) -> None:
        self._db = db

    async def list_tenants(self) -> list[dict[str, Any]]:
        rows = await self._db.fetch_global(
            """
            SELECT id, name, slug, status, created_at, updated_at
            FROM platform.tenants
            ORDER BY created_at DESC
            """
        )
        return [dict(r) for r in rows]

    async def get_tenant(self, tenant_id: UUID) -> dict[str, Any] | None:
        row = await self._db.fetchrow_global(
            """
            SELECT id, name, slug, status, created_at, updated_at
            FROM platform.tenants
            WHERE id = $1
            """,
            tenant_id,
        )
        return dict(row) if row else None

    async def create_tenant(self, *, name: str, slug: str) -> dict[str, Any]:
        row = await self._db.fetchrow_global(
            """
            INSERT INTO platform.tenants (name, slug, status, onboarding_state, plan)
            VALUES ($1, $2, 'active', 'ONBOARDING_COMPLETE', 'trial')
            RETURNING id, name, slug, status, created_at, updated_at
            """,
            name,
            slug,
        )
        assert row is not None
        return dict(row)

    async def update_tenant(
        self,
        tenant_id: UUID,
        *,
        name: str | None = None,
        status: str | None = None,
    ) -> dict[str, Any] | None:
        row = await self._db.fetchrow_global(
            """
            UPDATE platform.tenants
            SET name = COALESCE($2, name),
                status = COALESCE($3, status),
                updated_at = now()
            WHERE id = $1
            RETURNING id, name, slug, status, created_at, updated_at
            """,
            tenant_id,
            name,
            status,
        )
        return dict(row) if row else None

    async def list_memberships(self, tenant_id: UUID) -> list[dict[str, Any]]:
        rows = await self._db.fetch_global(
            """
            SELECT m.id,
                   m.user_id,
                   m.tenant_id,
                   m.role,
                   m.auth_issuer,
                   m.auth_subject,
                   m.status,
                   m.created_at,
                   m.updated_at,
                   u.email,
                   u.display_name
            FROM platform.tenant_memberships m
            JOIN platform.users u ON u.id = m.user_id
            WHERE m.tenant_id = $1
            ORDER BY m.created_at DESC
            """,
            tenant_id,
        )
        return [dict(r) for r in rows]

    async def create_membership(
        self,
        tenant_id: UUID,
        *,
        auth_issuer: str,
        auth_subject: str,
        email: str | None,
        role: str,
    ) -> dict[str, Any]:
        user_row = await self._db.fetchrow_global(
            """
            INSERT INTO platform.users (email)
            VALUES ($1)
            RETURNING id
            """,
            email,
        )
        assert user_row is not None
        row = await self._db.fetchrow_global(
            """
            INSERT INTO platform.tenant_memberships (
                user_id, tenant_id, role, auth_issuer, auth_subject
            )
            VALUES ($1, $2, $3, $4, $5)
            ON CONFLICT (auth_issuer, auth_subject) DO UPDATE
              SET tenant_id = EXCLUDED.tenant_id,
                  role = EXCLUDED.role,
                  user_id = EXCLUDED.user_id,
                  status = 'active',
                  updated_at = now()
            RETURNING id, user_id, tenant_id, role, auth_issuer, auth_subject,
                      status, created_at, updated_at
            """,
            user_row["id"],
            tenant_id,
            role,
            auth_issuer,
            auth_subject,
        )
        assert row is not None
        result = dict(row)
        result["email"] = email
        return result

    async def list_scans(
        self,
        *,
        status: str | None = None,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        tenants = await self.list_tenants()
        results: list[dict[str, Any]] = []
        for tenant in tenants:
            tenant_id = tenant["id"]
            if status:
                rows = await self._db.fetch(
                    tenant_id,
                    """
                    SELECT s.id, s.tenant_id, s.integration_id, s.status, s.trace_id,
                           s.started_at, s.completed_at, s.created_at, s.updated_at
                    FROM platform.scans s
                    WHERE s.tenant_id = $1 AND s.status = $2
                    ORDER BY s.updated_at DESC
                    LIMIT $3
                    """,
                    tenant_id,
                    status,
                    limit,
                )
            else:
                rows = await self._db.fetch(
                    tenant_id,
                    """
                    SELECT s.id, s.tenant_id, s.integration_id, s.status, s.trace_id,
                           s.started_at, s.completed_at, s.created_at, s.updated_at
                    FROM platform.scans s
                    WHERE s.tenant_id = $1
                    ORDER BY s.updated_at DESC
                    LIMIT $2
                    """,
                    tenant_id,
                    limit,
                )
            for row in rows:
                item = dict(row)
                item["tenant_name"] = tenant["name"]
                item["tenant_slug"] = tenant["slug"]
                results.append(item)
        results.sort(key=lambda r: r["updated_at"], reverse=True)
        return results[:limit]

    async def list_scans_for_tenant(
        self,
        tenant_id: UUID,
        *,
        limit: int = 20,
    ) -> list[dict[str, Any]]:
        tenant = await self.get_tenant(tenant_id)
        if not tenant:
            return []
        rows = await self._db.fetch(
            tenant_id,
            """
            SELECT s.id, s.tenant_id, s.integration_id, s.status, s.trace_id,
                   s.started_at, s.completed_at, s.created_at, s.updated_at
            FROM platform.scans s
            WHERE s.tenant_id = $1
            ORDER BY s.updated_at DESC
            LIMIT $2
            """,
            tenant_id,
            limit,
        )
        return [
            {
                **dict(row),
                "tenant_name": tenant["name"],
                "tenant_slug": tenant["slug"],
            }
            for row in rows
        ]

    async def count_tenants(self) -> int:
        value = await self._db.fetchrow_global("SELECT COUNT(*)::int AS n FROM platform.tenants")
        return int(value["n"]) if value else 0

    async def count_scans_by_status(self, status: str) -> int:
        total = 0
        for tenant in await self.list_tenants():
            row = await self._db.fetchrow(
                tenant["id"],
                """
                SELECT COUNT(*)::int AS n
                FROM platform.scans
                WHERE tenant_id = $1 AND status = $2
                """,
                tenant["id"],
                status,
            )
            if row:
                total += int(row["n"])
        return total
