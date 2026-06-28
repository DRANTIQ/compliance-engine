#!/usr/bin/env python3
"""Verify STS AssumeRole into sandbox integration before a real scan."""

from __future__ import annotations

import asyncio
import os
import sys

import asyncpg
import boto3


async def main() -> int:
    sys.path.insert(0, os.path.join(os.path.dirname(__file__)))
    from load_repo_dotenv import load_collectors_dotenv, load_repo_dotenv

    load_repo_dotenv()
    load_collectors_dotenv()
    load_collectors_dotenv()
    database_url = os.environ.get("DATABASE_URL")
    if not database_url:
        print("DATABASE_URL required (compliance-engine/.env)", file=sys.stderr)
        return 1
    if "sslmode=" not in database_url:
        database_url += ("&" if "?" in database_url else "?") + "sslmode=require"

    tenant_id = os.environ.get("TENANT_ID", "54abf846-1d4c-49f9-9115-2f4f882a2cd2")
    account_id = os.environ.get("AWS_ACCOUNT_ID", "387957186076")

    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
    from platform_backend.security.external_id import decrypt_external_id

    conn = await asyncpg.connect(database_url, statement_cache_size=0)
    try:
        row = await conn.fetchrow(
            """
            SELECT role_arn, external_id
            FROM platform.integrations
            WHERE tenant_id = $1::uuid AND account_id = $2
            """,
            tenant_id,
            account_id,
        )
    finally:
        await conn.close()

    if not row:
        print(f"No integration for tenant={tenant_id} account={account_id}", file=sys.stderr)
        return 1

    role_arn = row["role_arn"]
    external_id = decrypt_external_id(row["external_id"])
    print(f"integration role_arn={role_arn}")

    hub = boto3.client("sts").get_caller_identity()
    print(f"hub caller: {hub.get('Account')} {hub.get('Arn')}")

    assumed = boto3.client("sts").assume_role(
        RoleArn=role_arn,
        RoleSessionName="platform-v2-preflight",
        ExternalId=external_id,
    )
    creds = assumed["Credentials"]
    sandbox = boto3.client(
        "sts",
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
    ).get_caller_identity()
    print(f"sandbox caller: {sandbox.get('Account')} {sandbox.get('Arn')}")
    print("AssumeRole OK — ready for real scan")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
