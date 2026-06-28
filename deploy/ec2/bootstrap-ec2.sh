#!/usr/bin/env bash
# One-time EC2 setup — Docker, nginx, deploy directory. No app git clones required.
set -euo pipefail

DEPLOY_DIR="/opt/platform/deploy"
API_DOMAIN="${API_DOMAIN:-api.drantiq.ai}"

log() { echo "[bootstrap] $*"; }

if [[ "$(id -u)" -ne 0 ]]; then
  SUDO=sudo
else
  SUDO=
fi

log "Install packages"
$SUDO apt-get update
$SUDO apt-get install -y ca-certificates curl nginx certbot python3-certbot-nginx

if ! command -v docker >/dev/null; then
  log "Install Docker"
  curl -fsSL https://get.docker.com | $SUDO sh
  $SUDO usermod -aG docker ubuntu
fi

log "Create ${DEPLOY_DIR}"
$SUDO mkdir -p "${DEPLOY_DIR}"
$SUDO chown -R ubuntu:ubuntu /opt/platform

NGINX_SITE="/etc/nginx/sites-available/${API_DOMAIN}"
if [[ ! -f "${NGINX_SITE}" ]]; then
  log "Install nginx site (copy api.conf from repo or paste manually)"
  log "  sudo certbot --nginx -d ${API_DOMAIN}"
fi

cat <<EOF

Bootstrap complete.

1. Attach an Elastic IP and point ${API_DOMAIN} → that IP
2. Configure nginx + certbot for ${API_DOMAIN} (proxy to 127.0.0.1:8090)
3. Add GitHub Actions secrets (see deploy/ec2/README.md)
4. Push to main — pipeline will SCP .env + compose and deploy

Deploy directory: ${DEPLOY_DIR}

EOF
