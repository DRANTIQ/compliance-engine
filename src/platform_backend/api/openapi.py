"""OpenAPI / Swagger configuration for Platform V2 API."""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.openapi.utils import get_openapi

API_DESCRIPTION = """
# Platform V2 API

Multi-tenant cloud security platform: AWS inventory collection, policy evaluation,
findings, and security assessment scoring.

**Interactive docs:** `/docs` (Swagger UI) · `/redoc` (ReDoc) · `/openapi.json`

---

## Authentication

Production and local dev (default) use **Supabase JWT**. The API validates the
`Authorization: Bearer <access_token>` header via Supabase JWKS (ES256).

### Step 1 — Get a Supabase access token

```http
POST https://<project-ref>.supabase.co/auth/v1/token?grant_type=password
apikey: <SUPABASE_ANON_KEY>
Content-Type: application/json

{
  "email": "admin@drantiq.local",
  "password": "password123"
}
```

Response field: `access_token` (JWT, ~1 hour TTL).

### Step 2 — Call Platform API

```http
GET http://localhost:8090/v1/me
Authorization: Bearer <access_token>
```

The API resolves `sub` + `iss` from the JWT against `platform.tenant_memberships`
and applies Postgres RLS for the tenant.

### Test users (dev)

| Email | Role | Use for |
|-------|------|---------|
| `admin@drantiq.local` | `tenant_admin` | platform-ui — scans, integrations |
| `user@drantiq.local` | `viewer` | Read-only |
| `ops@drantiq.local` | `super_admin` | admin-ui — `/v1/admin/*` |

Membership must exist in `platform.tenant_memberships` (seed via
`scripts/seed_identity_membership.py`).

### Swagger UI

1. Open **Authorize** (top right)
2. **SupabaseJWT** → paste `access_token` only (no `Bearer` prefix)
3. Try **GET /v1/me** to confirm

### Dev header auth (optional)

When `DEV_TENANT_HEADER_AUTH=true` on the backend, you may skip JWT and send:

| Header | Example |
|--------|---------|
| `X-Tenant-ID` | Tenant UUID |
| `X-Role` | `tenant_admin` · `viewer` · `super_admin` |

Use **DevHeaders** scheme in Authorize for local testing without Supabase.

---

## Scan lifecycle

```
POST /v1/scans → Redis collect queue → collector → S3 bronze → ingest → policy → findings → CIS
```

Statuses: `created` → `queued` → `collecting` → `ingesting` → `inventory_ready` →
`evaluating` → `completed` | `completed_with_errors` | `failed`

Poll **GET /v1/scans/{id}** until terminal state before reading findings/assets.

---

## Roles

| Role | Access |
|------|--------|
| `viewer` | Read scans, assets, findings, compliance |
| `tenant_admin` | + create integrations, trigger scans |
| `super_admin` | + `/v1/admin/*` cross-tenant ops |

---

## Postman

Import `postman/Platform-V2-API.postman_collection.json` and run
`python scripts/sync_postman_env.py` to refresh tokens from `.env`.
"""

OPENAPI_TAGS = [
    {
        "name": "health",
        "description": "Liveness and readiness probes. No authentication required.",
    },
    {
        "name": "identity",
        "description": "Current user profile from JWT or dev headers. Use to verify auth setup.",
    },
    {
        "name": "integrations",
        "description": (
            "AWS account connections (AssumeRole + external ID). "
            "Requires `tenant_admin` or `super_admin` to register."
        ),
    },
    {
        "name": "scans",
        "description": (
            "Scan orchestration: trigger collection, poll status, timeline, "
            "CIS summary, inventory completeness, policy coverage, "
            "risk summary, and fix priorities."
        ),
    },
    {
        "name": "assets",
        "description": "Versioned inventory per scan. Resources and IAM relationships from bronze ingest.",
    },
    {
        "name": "findings",
        "description": (
            "Policy evaluation results with remediation metadata (AWS CLI, Terraform, "
            "risk copy). Customer detail includes display titles and fix steps. "
            "Keyed by `policy_id` (e.g. AWS_S3_001)."
        ),
    },
    {
        "name": "policies",
        "description": "Policy-centric views — affected resources per control in a scan.",
    },
    {
        "name": "compliance",
        "description": "CIS AWS v6 framework mapping — control matrix and weighted score per scan.",
    },
    {
        "name": "admin",
        "description": (
            "Internal ops (`super_admin` only): tenants, memberships, cross-tenant scans, "
            "queue depth overview."
        ),
    },
]

SECURITY_SCHEMES = {
    "SupabaseJWT": {
        "type": "http",
        "scheme": "bearer",
        "bearerFormat": "JWT",
        "description": (
            "Supabase `access_token` from POST .../auth/v1/token?grant_type=password. "
            "Paste token only in Authorize dialog."
        ),
    },
    "DevTenantId": {
        "type": "apiKey",
        "in": "header",
        "name": "X-Tenant-ID",
        "description": "Tenant UUID. Only when DEV_TENANT_HEADER_AUTH=true.",
    },
    "DevRole": {
        "type": "apiKey",
        "in": "header",
        "name": "X-Role",
        "description": "tenant_admin | viewer | super_admin. Pair with DevTenantId.",
    },
}

# Paths that do not require authentication
PUBLIC_PATHS = {"/health", "/ready"}


def configure_openapi(app: FastAPI) -> None:
    def custom_openapi():
        if app.openapi_schema:
            return app.openapi_schema

        schema = get_openapi(
            title=app.title,
            version=app.version,
            description=API_DESCRIPTION,
            routes=app.routes,
            tags=OPENAPI_TAGS,
        )

        schema.setdefault("components", {})["securitySchemes"] = SECURITY_SCHEMES

        default_security = [{"SupabaseJWT": []}]

        for path, methods in schema.get("paths", {}).items():
            if path in PUBLIC_PATHS:
                continue
            for op in methods.values():
                if not isinstance(op, dict):
                    continue
                # Prefer JWT; document dev headers as alternate in description
                op["security"] = default_security
                existing = op.get("description") or ""
                if existing and "**Auth:**" not in existing:
                    op["description"] = existing

        schema["servers"] = [
            {"url": "http://localhost:8090", "description": "Local dev"},
            {"url": "https://api.example.com", "description": "Staging / production"},
        ]

        app.openapi_schema = schema
        return app.openapi_schema

    app.openapi = custom_openapi  # type: ignore[method-assign]
