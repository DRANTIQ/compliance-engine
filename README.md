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

```powershell
# Terminal 1 — API (port 8084 if 8080/8082 busy)
$env:API_PORT = "8084"
python scripts/run_api.py

# Terminal 2 — ingest worker (one instance only)
python scripts/run_ingest_worker.py

# Terminal 3 — collector worker
cd ..\platform-collectors
$env:COLLECTOR_MOCK = "true"
$env:USE_LOCAL_STORAGE = "true"
python scripts/run_collector_worker.py

# Or run all in one process (dev):
python scripts/run_phase1_local_pipeline.py
```

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

## Status

Phase 1 inventory pipeline implemented. Policy/findings = Phase 2 (official plan).
