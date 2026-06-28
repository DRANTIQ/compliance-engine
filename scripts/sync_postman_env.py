#!/usr/bin/env python3
"""Sync Postman environment from repo .env files and refresh Supabase tokens."""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ENV_OUT = ROOT / "postman" / "environments" / "Platform-V2-Local.postman_environment.json"


def load_dotenv(path: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    if not path.is_file():
        return out
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        out[key.strip()] = value.strip()
    return out


def supabase_login(url: str, anon_key: str, email: str, password: str) -> str:
    endpoint = f"{url.rstrip('/')}/auth/v1/token?grant_type=password"
    payload = json.dumps({"email": email, "password": password}).encode("utf-8")
    req = urllib.request.Request(
        endpoint,
        data=payload,
        headers={
            "apikey": anon_key,
            "Content-Type": "application/json",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        body = json.loads(resp.read().decode("utf-8"))
    token = body.get("access_token")
    if not token:
        raise RuntimeError(f"No access_token for {email}")
    return token


def main() -> int:
    ui_env = load_dotenv(ROOT.parent / "platform-ui" / ".env")
    be_env = load_dotenv(ROOT / ".env")

    supabase_url = ui_env.get("VITE_SUPABASE_URL") or be_env.get("SUPABASE_URL", "")
    anon_key = ui_env.get("VITE_SUPABASE_ANON_KEY", "")
    base_url = ui_env.get("VITE_API_URL") or f"http://localhost:{be_env.get('API_PORT', '8090')}"

    if not supabase_url or not anon_key:
        print("Missing VITE_SUPABASE_URL or VITE_SUPABASE_ANON_KEY in platform-ui/.env", file=sys.stderr)
        return 1

    user_email = "admin@drantiq.local"
    admin_email = "ops@drantiq.local"
    viewer_email = "user@drantiq.local"
    password = os.environ.get("DRANTIQ_DEV_PASSWORD", "password123")

    tokens: dict[str, str] = {}
    for label, email, key in [
        ("tenant_admin", user_email, "supabaseToken"),
        ("super_admin", admin_email, "adminSupabaseToken"),
        ("viewer", viewer_email, "viewerSupabaseToken"),
    ]:
        try:
            tokens[key] = supabase_login(supabase_url, anon_key, email, password)
            print(f"Logged in {label} ({email})")
        except urllib.error.HTTPError as exc:
            print(f"WARN: login failed for {email}: HTTP {exc.code}", file=sys.stderr)
        except Exception as exc:
            print(f"WARN: login failed for {email}: {exc}", file=sys.stderr)

    values = [
        ("baseUrl", base_url),
        ("authMode", "supabase"),
        ("supabaseUrl", supabase_url),
        ("supabaseAnonKey", anon_key),
        ("tenantId", "54abf846-1d4c-49f9-9115-2f4f882a2cd2"),
        ("role", "tenant_admin"),
        ("adminRole", "super_admin"),
        ("userEmail", user_email),
        ("userPassword", password),
        ("adminEmail", admin_email),
        ("adminPassword", password),
        ("viewerEmail", viewer_email),
        ("viewerPassword", password),
        ("supabaseToken", tokens.get("supabaseToken", "")),
        ("adminSupabaseToken", tokens.get("adminSupabaseToken", "")),
        ("viewerSupabaseToken", tokens.get("viewerSupabaseToken", "")),
        ("integrationId", "57d0d584-fe04-49bc-8c87-a8163772fa5c"),
        ("scanId", ""),
        ("findingId", ""),
        ("resourceId", ""),
        ("frameworkId", "cis_aws_v6"),
        ("awsAccountId", "387957186076"),
        ("awsRoleArn", "arn:aws:iam::387957186076:role/SteampipeReadRole"),
        ("awsExternalId", "deva-external"),
        ("authIssuer", f"{supabase_url.rstrip('/')}/auth/v1"),
    ]

    secret_keys = {
        "supabaseAnonKey",
        "supabaseToken",
        "adminSupabaseToken",
        "viewerSupabaseToken",
        "userPassword",
        "adminPassword",
        "viewerPassword",
    }

    env_doc = {
        "id": "p2v2-local-env-001",
        "name": "Platform V2 — Local",
        "values": [
            {
                "key": key,
                "value": value,
                "type": "secret" if key in secret_keys else "default",
                "enabled": True,
            }
            for key, value in values
        ],
        "_postman_variable_scope": "environment",
        "_postman_exported_at": "2026-06-27T00:00:00.000Z",
        "_postman_exported_using": "Postman/11.0.0",
    }

    ENV_OUT.write_text(json.dumps(env_doc, indent=2), encoding="utf-8")
    print(f"Wrote {ENV_OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
