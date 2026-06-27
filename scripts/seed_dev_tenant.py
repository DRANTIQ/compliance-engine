#!/usr/bin/env python3
"""Create a dev tenant in platform.tenants (no RLS). Prints tenant UUID."""

from __future__ import annotations

import argparse
import os
import sys

import psycopg


def main() -> int:
    parser = argparse.ArgumentParser(description="Seed Platform V2 dev tenant")
    parser.add_argument("--name", default="Drantiq Sandbox")
    parser.add_argument("--slug", default="drantiq-sandbox")
    args = parser.parse_args()

    database_url = os.environ.get("DATABASE_URL")
    if not database_url:
        print("ERROR: DATABASE_URL is not set", file=sys.stderr)
        return 1

    with psycopg.connect(database_url) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO platform.tenants (name, slug)
                VALUES (%s, %s)
                ON CONFLICT (slug) DO UPDATE
                  SET name = EXCLUDED.name, updated_at = now()
                RETURNING id
                """,
                (args.name, args.slug),
            )
            tenant_id = cur.fetchone()[0]
        conn.commit()

    print(str(tenant_id))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
