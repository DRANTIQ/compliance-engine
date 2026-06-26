# compliance-engine

Platform V2 **backend** — inventory, unified policy engine, findings, compliance mapping, and public API.

Modular monolith: one repo, separate K8s Deployments per worker type.

## Pipeline position

```
Redis events + S3 → inventory-ingest → assets DB
                  → policy-worker → findings
                  → compliance mapper → CIS matrix
platform-api ← platform-ui / admin-ui
```

## What lives here

| Module | K8s Deployment | Phase |
|--------|----------------|-------|
| `api/` | `platform-api` | 1+ |
| `inventory/` | `inventory-ingest` | 1 |
| `policy/` | `policy-worker` | 2 |
| `findings/` | (library + policy worker) | 2 |
| `compliance/` | (mapping engine) | 3 |
| `notifications/` | (design only v1) | 5+ |

| Path | Purpose |
|------|---------|
| `policy/catalog/policies/` | YAML unified policy library (`AWS_S3_001`, …) |
| `policy/catalog/mappings/` | Framework mappings (CIS, SOC2, …) |
| `contracts/` | API + event schemas |

## Database

**DDL lives in `platform-db`**, not here. This service connects via `DATABASE_URL` and uses schemas:

`platform` · `assets` · `policy` · `findings` · `compliance`

Run migrations from [platform-db](https://github.com/YOUR_ORG/platform-db) before deploy.

## Related repos

| Repo | Role |
|------|------|
| **platform-collectors** | Writes S3 + collection events |
| **compliance-engine** | **This repo** |
| **platform-ui** | Customer UI → `/v1/*` |
| **admin-ui** | Ops UI → `/v1/admin/*` |
| **platform-db** | Postgres migrations |

## Planning docs

**infra-state-docs/new arch/docs/** — see [docs/LINKS.md](docs/LINKS.md)

Key: `BUILD_GUIDE.md`, `POLICY_LIBRARY.md`, `PLATFORM_ARCHITECTURE.md`

## Configuration

```bash
cp .env.example .env   # never commit
```

## Phase 1 exit criteria

Ingest S3 snapshot → versioned assets + relationships in Postgres → list via API.

## Status

Initial repo scaffold — implementation after [PREREQUISITES](docs/LINKS.md) complete.
