# Pre-customer production checklist

Status key: **Done** | **Partial** | **Pending** (your action)

---

## Security

| Item | Status | Notes |
|------|--------|-------|
| HTTPS everywhere | **Partial** | Vercel + certbot/nginx for API. Update live nginx from `deploy/ec2/nginx/api.conf` (HTTP→HTTPS redirect + TLS). |
| CSP headers | **Done** | API middleware + Vercel `vercel.json` (platform-ui, admin-ui). Redeploy all three. |
| Security headers | **Done** | `X-Frame-Options`, `Referrer-Policy`, `nosniff`, HSTS on nginx template. |
| Rate limiting | **Done** | Redis-backed per-IP limit (`RATE_LIMIT_PER_MINUTE=120` prod default). Returns 429. |
| JWT expiration | **Done** | Supabase JWT `exp` validated; expired tokens rejected. |
| Refresh tokens | **Done** | Supabase JS client auto-refreshes; no backend refresh endpoint (by design). |
| Secure cookies | **Partial** | API uses Bearer tokens (no cookies). UIs use Supabase localStorage — acceptable for MVP; migrate to httpOnly cookies later if needed. |
| Secrets in Secrets Manager | **Pending** | Today: GitHub Secrets → EC2 `.env`. **Before scale:** AWS SSM Parameter Store or Secrets Manager + instance role. |
| No AWS keys in .env | **Done** | EC2 uses `InstanceRole` IAM; omit `AWS_*` from GitHub secrets. |
| Logging sanitization | **Done** | `SanitizeFilter` redacts tokens, DB URLs, Bearer headers. |
| Audit logging | **Partial** | Structured `audit` logs for mutating `/v1/*` requests. **Pending:** ship logs to CloudWatch/SIEM; immutable store. |
| Swagger disabled in prod | **Done** | `API_DOCS_ENABLED=false` in prod `.env`. |
| `/docs` public exposure | **Done** | Disabled when `API_DOCS_ENABLED=false`. |

---

## Reliability

| Item | Status | Notes |
|------|--------|-------|
| Health `/health` | **Done** | Liveness — process alive. |
| Readiness `/ready` | **Done** | Postgres + Redis ping; 503 if down. |
| Deploy waits on `/ready` | **Done** | `remote-deploy.sh` checks health + ready. |
| Docker healthcheck (API) | **Done** | `docker-compose.prod.yml` healthcheck on `platform-api`. |
| Crash recovery | **Partial** | `restart: unless-stopped` on all services. **Pending:** Redis persistence volume. |
| Retry logic (AWS) | **Pending** | Add boto3 retry config in collector. |
| Queue retry | **Pending** | Workers drop failed jobs today. **Next:** requeue + max attempts. |
| DLQ | **Pending** | Not implemented. Plan keys: `platform:collect.aws:dlq`, etc. |
| Timeouts | **Partial** | DB `command_timeout=30`, nginx `proxy_read_timeout 120s`. **Pending:** per-scan job timeout. |
| Circuit breakers | **Pending** | Not implemented (Postgres/Redis/STS). |

---

## Monitoring

| Item | Status | Notes |
|------|--------|-------|
| Error tracking (Sentry) | **Partial** | Set `SENTRY_DSN` GitHub secret + `pip install sentry-sdk` in image (optional dep). |
| Request timing logs | **Done** | `http_request` JSON logs with `duration_ms`; `X-Response-Time-Ms` header. |
| Admin queue depth | **Done** | `/v1/admin/overview`: collect, events, **policy** queue depths. |
| API latency metrics | **Partial** | Logs only. **Pending:** Prometheus/CloudWatch dashboards. |
| Collector duration | **Partial** | Timestamps in S3 manifest + DB. **Pending:** exported metric. |
| Scan duration | **Partial** | `started_at` / `completed_at` on scan API. **Pending:** p50/p95 dashboard. |
| Login failures | **Partial** | JWT failures logged. **Pending:** Supabase auth dashboard + alert on spike. |
| Log shipping | **Pending** | Install CloudWatch agent on EC2 or use Docker log driver. |

---

## IAM & scans (blocking customers)

| Item | Status |
|------|--------|
| Hub `InstanceRole` + `sts:AssumeRole` | **Pending** — add to IAM policy |
| Customer role trust + ExternalId | **Pending** — per integration |
| EC2 IMDS hop limit = 2 | **Pending** — verify in EC2 console |
| `POLICY_CATALOG_PATH=/app/policy/catalog/policies` | **Pending** — redeploy or add to `.env` |
| Successful end-to-end scan | **Pending** |

---

## Deploy checklist (run before first customer)

1. Push `compliance-engine` → run **Deploy to EC2**
2. Push `platform-ui` + `admin-ui` → Vercel redeploy
3. Update nginx on EC2 from `deploy/ec2/nginx/api.conf`; run certbot if needed
4. Confirm GitHub secrets: no `AWS_*`, prod `EXTERNAL_ID_ENCRYPTION_KEY`, `CORS_ORIGINS`
5. Add `sts:AssumeRole` to `InstanceRole`
6. Optional: `SENTRY_DSN` secret
7. Run test scan → verify CIS tab returns 200
8. Poll `GET /v1/admin/overview` as super_admin — queues near 0, `api_status: ready`

---

## Optional env vars (production)

| Variable | Default | Purpose |
|----------|---------|---------|
| `RATE_LIMIT_PER_MINUTE` | `120` | Per-IP API rate limit |
| `API_DOCS_ENABLED` | `false` | Disable Swagger in prod |
| `SENTRY_DSN` | (empty) | Error tracking |
| `POLICY_CATALOG_PATH` | `/app/policy/catalog/policies` | Policy YAML in Docker |
