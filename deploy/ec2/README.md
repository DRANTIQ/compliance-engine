# EC2 deploy — Docker Hub + GitHub Secrets

Production flow:

1. **GitHub Actions** builds `compliance-engine` + `platform-collectors` images  
2. **Pushes** to Docker Hub: `drantiq/drantiq:backend-<tag>`, `drantiq/drantiq:collector-<tag>`  
3. **Renders** `.env` from GitHub Secrets (nothing sensitive on EC2 long-term except last deploy copy)  
4. **SCP** compose + `.env` + script to EC2  
5. **SSH** → `docker pull` → `docker compose up -d`

EC2 does **not** build images or clone app source.

---

## Docker Hub setup

1. Create / use org **`drantiq`** on [hub.docker.com](https://hub.docker.com)  
2. Create repository **`drantiq/drantiq`** (public or private)  
3. **Access token:** Account Settings → **Security** → **New Access Token**  
   - Description: `github-actions-deploy`  
   - Permissions: **Read & Write** (or Read for EC2-only if you split tokens)  
4. Copy token once — it is shown only at creation.

### GitHub secrets for Docker Hub

| Secret | Value |
|--------|--------|
| `DOCKERHUB_USERNAME` | `drantiq` (or your Docker Hub username) |
| `DOCKERHUB_TOKEN` | Token from step 3 |

If `drantiq/drantiq` is **private**, the deploy step logs Docker Hub in on EC2 using the same secrets so `docker pull` works.

---

## Image tags

Each deploy pushes:

```
drantiq/drantiq:backend-<7-char-sha>    drantiq/drantiq:backend-latest
drantiq/drantiq:collector-<7-char-sha>  drantiq/drantiq:collector-latest
```

EC2 runs the SHA tag from that deploy. Override tag via workflow_dispatch **image_tag** input.

---

## GitHub Secrets (application)

Repository → **Settings → Secrets and variables → Actions → New repository secret**

### Required

| Secret | Example / notes |
|--------|-----------------|
| `DATABASE_URL` | Supabase session pooler URL with `?sslmode=require` |
| `EXTERNAL_ID_ENCRYPTION_KEY` | Same as local `.env` |
| `SUPABASE_URL` | `https://xxxx.supabase.co` |
| `DOCKERHUB_USERNAME` | Docker Hub user/org |
| `DOCKERHUB_TOKEN` | Docker Hub access token |
| `EC2_HOST` | Elastic IP e.g. `54.90.98.205` |
| `EC2_USER` | `ubuntu` |
| `EC2_SSH_PRIVATE_KEY` | Full private key PEM for deploy user |

### Optional (omit if using EC2 IAM role for AWS)

| Secret | Purpose |
|--------|---------|
| `OIDC_JWT_SECRET` | Supabase JWT secret (HS256 legacy) |
| `AWS_ACCESS_KEY_ID` | Hub account for collector STS + S3 |
| `AWS_SECRET_ACCESS_KEY` | |
| `AWS_SESSION_TOKEN` | If using temporary creds |
| `S3_BUCKET` | Default `steampipe-data-storage` if unset |
| `S3_REGION` | Default `us-east-1` |
| `S3_PREFIX` | Default `platform-v2` |
| `CORS_ORIGINS` | Default includes app + admin Vercel URLs |
| `COLLECTORS_REPO_PAT` | **Required if `platform-collectors` is private** — see below |

### `COLLECTORS_REPO_PAT` — fix “Not Found” on checkout

GitHub Actions’ default token can only access the **current** repo. If `DRANTIQ/platform-collectors` is private (or not visible to the workflow), checkout fails with:

`Not Found - https://docs.github.com/rest/repos/repos#get-a-repository`

**1. Confirm the repo exists on GitHub**

```bash
cd platform-collectors
git remote -v
git push -u origin main   # if not pushed yet
```

**2. Create a PAT with read access**

- GitHub → **Settings** → **Developer settings** → **Fine-grained personal access tokens**
- **Repository access:** only `platform-collectors`
- **Permissions:** Contents → **Read-only**
- Generate and copy the token

(Classic PAT: scope `repo` also works.)

**3. Add secret to `compliance-engine`**

| Secret | Value |
|--------|--------|
| `COLLECTORS_REPO_PAT` | the PAT from step 2 |

**Optional variable** if the repo path is not `DRANTIQ/platform-collectors`:

| Variable | Example |
|----------|---------|
| `COLLECTORS_REPO` | `DRANTIQ/platform-collectors` |

### Variables (optional)

| Variable | Example |
|----------|---------|
| `API_PUBLIC_URL` | `https://api.drantiq.ai` — post-deploy smoke test |

---

## How env reaches containers

```
GitHub Secrets
    ↓  render_production_env.py (in Actions runner)
deploy/ec2/.env.rendered
    ↓  SCP to EC2
/opt/platform/deploy/.env
    ↓  docker compose env_file: .env
platform-api | ingest-worker | policy-worker | aws-collector
```

Compose **overrides** `REDIS_URL=redis://redis:6379/0` for all app containers.

Defaults (CORS, queue keys, `OIDC_ENABLED=true`, etc.) live in `render_production_env.py` — override by setting matching GitHub secrets/vars if you extend the script.

---

## One-time EC2 bootstrap

```bash
ssh ubuntu@54.90.98.205
curl -fsSL https://get.docker.com | sudo sh
sudo usermod -aG docker ubuntu
sudo mkdir -p /opt/platform/deploy && sudo chown ubuntu:ubuntu /opt/platform/deploy

# nginx → 127.0.0.1:8090 (see nginx/api.conf)
sudo certbot --nginx -d api.drantiq.ai
```

Attach an **Elastic IP** and set `EC2_HOST` to it.

---

## Deploy SSH key

```bash
ssh-keygen -t ed25519 -f github-deploy -N ""
ssh-copy-id -i github-deploy.pub ubuntu@YOUR_EC2_IP
```

Put **`github-deploy`** contents (private key) in `EC2_SSH_PRIVATE_KEY`.

---

## Manual workflow run

**Actions → Deploy to EC2 → Run workflow**

- **host** — new IP if `EC2_HOST` secret is stale  
- **image_tag** — custom Docker tag suffix (default: git SHA)

---

## Local test of env render

```bash
export DATABASE_URL='postgresql://...?sslmode=require'
export EXTERNAL_ID_ENCRYPTION_KEY='...'
export SUPABASE_URL='https://....supabase.co'
python3 deploy/ec2/render_production_env.py
```

---

## Troubleshooting

| Issue | Fix |
|-------|-----|
| `denied: requested access to the resource is denied` | Check `DOCKERHUB_USERNAME` / `DOCKERHUB_TOKEN`; repo name `drantiq/drantiq` |
| Collector build fails checkout | Add `COLLECTORS_REPO_PAT` with read access to `platform-collectors` |
| `/ready` fails | `DATABASE_URL` or Redis |
| 502 nginx | `docker compose ps` — API container down |
| IP changed | Update `EC2_HOST` or use workflow **host** input |
