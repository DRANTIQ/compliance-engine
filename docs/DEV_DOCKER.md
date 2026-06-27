# Local dev — Platform V2 (Phase 1)

## Windows quick start (recommended)

```powershell
cd compliance-engine

# Stop stale duplicate workers (fixes port + ingest errors)
.\scripts\stop_platform_v2.ps1

# Start API + ingest + mock collector
.\scripts\start_platform_v2.ps1

# Swagger: http://localhost:8090/docs
```

Default API port: **8090** (avoids legacy 8080/8081/8082).

## E2E test

```powershell
$env:TENANT_ID = "<from seed_dev_tenant.py>"
$env:INTEGRATION_ID = "<integration uuid>"
$env:API_BASE = "http://localhost:8090"
python scripts/run_phase1_e2e.py
```

## Docker compose (optional)

- `platform-api` on port 8082 in compose (override with `API_PORT`)
- `ingest-worker` + `redis` on 6380
- Postgres = Supabase (`DATABASE_URL` in `.env`)

```bash
cp .env.example .env
docker compose up --build -d
```

Also run **one** collector worker from `platform-collectors` (or use `COLLECTOR_MOCK=true`).

## Bootstrap tenant

```powershell
python scripts/seed_dev_tenant.py
# Use printed UUID as X-Tenant-ID
```

## Common errors fixed

| Error | Cause | Fix |
|-------|-------|-----|
| Port 8080/8082 in use | Legacy or duplicate API | `.\scripts\stop_platform_v2.ps1` then start on 8090 |
| Multiple ingest ERRORs | Several ingest workers running | `stop_platform_v2.ps1` (only run one ingest) |
| Scan stuck at `ingesting` | Old worker + bad file URI | Pull latest + restart stack |
| asyncpg prepared statement | Supabase pooler | Fixed (`statement_cache_size=0`) |

## Port map

| Service | Port |
|---------|------|
| Platform V2 API | **8090** (dev default) |
| Legacy steampipe | 8000 |
| Legacy compliance-engine | 8001 / 8081 |
| Redis (steampipe compose) | 6379 |
