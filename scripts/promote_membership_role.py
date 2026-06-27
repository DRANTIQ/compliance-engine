#!/usr/bin/env python3
"""Update role on an existing platform.tenant_memberships row."""

from __future__ import annotations

import argparse
import asyncio
import os
import sys

import asyncpg


async def main() -> int:
    parser = argparse.ArgumentParser(description="Promote or change membership role")
    parser.add_argument("--auth-subject", required=True, help="JWT sub claim (IdP user id)")
    parser.add_argument(
        "--auth-issuer",
        default=None,
        help="JWT iss claim (defaults from SUPABASE_URL env)",
    )
    parser.add_argument(
        "--role",
        required=True,
        choices=["tenant_admin", "viewer", "super_admin"],
    )
    args = parser.parse_args()

    database_url = os.environ.get("DATABASE_URL")
    if not database_url:
        print("DATABASE_URL is required", file=sys.stderr)
        return 1
    if "sslmode=" not in database_url:
        sep = "&" if "?" in database_url else "?"
        database_url = f"{database_url}{sep}sslmode=require"

    issuer = args.auth_issuer
    if not issuer:
        supabase_url = os.environ.get("SUPABASE_URL", "").rstrip("/")
        if not supabase_url:
            print("auth-issuer or SUPABASE_URL is required", file=sys.stderr)
            return 1
        issuer = f"{supabase_url}/auth/v1"

    conn = await asyncpg.connect(database_url, statement_cache_size=0)
    try:
        row = await conn.fetchrow(
            """
            UPDATE platform.tenant_memberships
            SET role = $3, updated_at = now()
            WHERE auth_issuer = $1 AND auth_subject = $2
            RETURNING id, tenant_id, role
            """,
            issuer,
            args.auth_subject,
            args.role,
        )
        if not row:
            print("membership not found", file=sys.stderr)
            return 1
        print(f"updated membership {row['id']} tenant={row['tenant_id']} role={row['role']}")
    finally:
        await conn.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
