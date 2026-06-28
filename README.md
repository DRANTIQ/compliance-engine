# Platform V2 backend (compliance-engine → platform-backend)

Modular monolith: inventory ingest, policy (later), findings (later), compliance (later), API.

## Phase 1 scope (current)

Full inventory pipeline:

```
POST /v1/scans → Redis → aws-collector → S3/local bronze → ingest worker → assets DB
GET  /v1/assets?scan_id=...
```

### API routes

| Method | Path |
|--------|------|
| GET | `/health`, `/ready` |
| POST/GET | `/v1/integrations`, `/v1/integrations/aws` |
| POST/GET | `/v1/scans`, `/v1/scans/{id}`, `/v1/scans/{id}/timeline` |
| GET | `/v1/assets`, `/v1/assets/{id}`, `/v1/assets/{id}/relationships` |

Dev auth: `X-Tenant-ID` header.

## Quick start (local mock pipeline)

Each repo uses **`.env` only** (copy from `.env.example`; never commit `.env`).

```powershell
cd compliance-engine
cp .env.example .env
cd ..\platform-collectors
cp .env.example .env   # COLLECTOR_MOCK=true for mock

cd ..\compliance-engine
.\scripts\start_platform_v2.ps1
```

Or run processes manually:

Requires `platform-db` migrations applied and `EXTERNAL_ID_ENCRYPTION_KEY` set.

## Security

- Postgres RLS via `platform.set_tenant()` per request
- `external_id` encrypted at rest (never in API responses)
- `statement_cache_size=0` for Supabase pooler compatibility
- Parameterized SQL only

## Related repos

| Repo | Role |
|------|------|
| **platform-db** | DDL |
| **platform-collectors** | AWS collector worker |
| **compliance-engine** | **This repo** — API + ingest |

## EC2 production deploy

See **[deploy/ec2/README.md](deploy/ec2/README.md)** — GitHub Actions → Ubuntu EC2 → Docker Compose → nginx + Let's Encrypt (`api.drantiq.ai`).


Phase 1 inventory pipeline implemented. Policy/findings = Phase 2 (official plan).
