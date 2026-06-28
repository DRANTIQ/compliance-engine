# Platform V2 API

HTTP API for inventory, scans, findings, and compliance.

## Interactive documentation

| URL | Format |
|-----|--------|
| http://localhost:8090/docs | **Swagger UI** (try requests in browser) |
| http://localhost:8090/swagger | Redirect → `/docs` |
| http://localhost:8090/redoc | ReDoc (readable reference) |
| http://localhost:8090/openapi.json | OpenAPI 3.1 JSON (import to Postman) |

Start the API: `scripts/start_platform_v2.ps1`

## Supabase auth in Swagger

1. Get a token (Postman **Authentication** folder, or curl):

```bash
curl -X POST "https://<project>.supabase.co/auth/v1/token?grant_type=password" \
  -H "apikey: <SUPABASE_ANON_KEY>" \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@drantiq.local","password":"password123"}'
```

2. Open http://localhost:8090/docs
3. Click **Authorize** → **SupabaseJWT** → paste `access_token` (no `Bearer` prefix)
4. Call **GET /v1/me** to verify

Admin routes need `ops@drantiq.local` (`super_admin` membership).

## Postman

See `postman/README.md` — collection includes auto-login and E2E workflows.

Export fresh OpenAPI after code changes:

```bash
python scripts/export_openapi.py
```

## Route map

| Prefix | Tag | Auth |
|--------|-----|------|
| `/health`, `/ready` | health | None |
| `/v1/me` | identity | JWT |
| `/v1/integrations` | integrations | JWT (write: tenant_admin+) |
| `/v1/scans` | scans | JWT |
| `/v1/assets` | assets | JWT |
| `/v1/findings` | findings | JWT |
| `/v1/compliance` | compliance | JWT |
| `/v1/admin` | admin | JWT (**super_admin**) |

Dev headers (`X-Tenant-ID`, `X-Role`) work when `DEV_TENANT_HEADER_AUTH=true`.
