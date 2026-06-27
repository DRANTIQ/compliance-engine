#!/usr/bin/env python3
"""Provision a tenant membership for OIDC login (Cognito/Entra/Okta/Auth0)."""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
from pathlib import Path
from uuid import UUID

import asyncpg


async def main() -> int:
    parser = argparse.ArgumentParser(description="Seed platform identity membership")
    parser.add_argument("--tenant-id", required=True, help="Platform tenant UUID")
    parser.add_argument("--auth-issuer", required=True, help="JWT iss claim (IdP issuer URL)")
    parser.add_argument("--auth-subject", required=True, help="JWT sub claim (IdP user id)")
    parser.add_argument("--email", default=None, help="User email")
    parser.add_argument("--role", default="tenant_admin", choices=["tenant_admin", "viewer", "super_admin"])
    args = parser.parse_args()

    database_url = os.environ.get("DATABASE_URL")
    if not database_url:
        env_path = Path(__file__).resolve().parents[2] / "platform-db" / ".env"
        if env_path.is_file():
            for line in env_path.read_text(encoding="utf-8").splitlines():
                if line.startswith("DATABASE_URL="):
                    database_url = line.split("=", 1)[1].strip().strip('"')
                    break
    if not database_url:
        print("DATABASE_URL is required", file=sys.stderr)
        return 1
    if "sslmode=" not in database_url:
        sep = "&" if "?" in database_url else "?"
        database_url = f"{database_url}{sep}sslmode=require"

    tenant_id = UUID(args.tenant_id)
    conn = await asyncpg.connect(database_url, statement_cache_size=0)
    try:
        tenant = await conn.fetchrow("SELECT id FROM platform.tenants WHERE id = $1", tenant_id)
        if not tenant:
            print(f"tenant not found: {tenant_id}", file=sys.stderr)
            return 1

        user_id = await conn.fetchval(
            """
            INSERT INTO platform.users (email)
            VALUES ($1)
            RETURNING id
            """,
            args.email,
        )

        await conn.execute(
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
            """,
            user_id,
            tenant_id,
            args.role,
            args.auth_issuer,
            args.auth_subject,
        )
        print(f"membership provisioned for subject={args.auth_subject} tenant={tenant_id} role={args.role}")
    finally:
        await conn.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
