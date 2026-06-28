# Platform V2 — Postman

Import these into Postman for end-to-end API testing with **Supabase JWT auth**.

| File | Purpose |
|------|---------|
| `Platform-V2-API.postman_collection.json` | All routes + login + E2E workflows |
| `environments/Platform-V2-Local.postman_environment.json` | Supabase URL, anon key, tokens, test users |

## Refresh environment from `.env`

Pulls Supabase config from `platform-ui/.env`, logs in test users, saves JWT tokens:

```powershell
cd compliance-engine
python scripts/sync_postman_env.py
python scripts/generate_postman_collection.py
```

Re-import the environment in Postman after syncing (or click refresh if linked).

## Quick start

1. Start stack: `scripts/start_platform_v2.ps1`
2. Run `python scripts/sync_postman_env.py`
3. Postman → **Import** → collection + environment
4. Select **Platform V2 — Local**
5. Run **E2E Read Workflow** (includes login steps)

## Auth (default: Supabase)

| Step | Action |
|------|--------|
| 1 | **Authentication → Login (tenant_admin)** → sets `supabaseToken` |
| 2 | Customer API calls use Bearer `supabaseToken` |
| 3 | **Login (super_admin)** → sets `adminSupabaseToken` for `/v1/admin/*` |

Test users (dev password `password123`):

| Email | Role | Token variable |
|-------|------|----------------|
| `admin@drantiq.local` | tenant_admin | `supabaseToken` |
| `ops@drantiq.local` | super_admin | `adminSupabaseToken` |
| `user@drantiq.local` | viewer | `viewerSupabaseToken` |

Tokens expire (~1 hour). Re-run login or `sync_postman_env.py`.

## Dev headers fallback

Set `authMode=dev_headers` in environment to use `X-Tenant-ID` + `X-Role` instead (requires `DEV_TENANT_HEADER_AUTH=true` on API).

## Newman

```bash
python scripts/sync_postman_env.py
newman run postman/Platform-V2-API.postman_collection.json \
  -e postman/environments/Platform-V2-Local.postman_environment.json \
  --folder "E2E Read Workflow"
```

OpenAPI: http://localhost:8090/docs (Swagger) · http://localhost:8090/redoc · import `contracts/openapi.json`
