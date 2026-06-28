#!/usr/bin/env bash
# Pull Docker Hub images and restart stack on EC2.
set -euo pipefail

DEPLOY_DIR="${DEPLOY_DIR:-/opt/platform/deploy}"
IMAGE_TAG="${IMAGE_TAG:?set IMAGE_TAG}"
DOCKER_IMAGE="${DOCKER_IMAGE:-drantiq/drantiq}"

export BACKEND_IMAGE="${BACKEND_IMAGE:-${DOCKER_IMAGE}:backend-${IMAGE_TAG}}"
export COLLECTOR_IMAGE="${COLLECTOR_IMAGE:-${DOCKER_IMAGE}:collector-${IMAGE_TAG}}"

log() { echo "[deploy] $*"; }

if [[ ! -f "${DEPLOY_DIR}/.env" ]]; then
  echo "Missing ${DEPLOY_DIR}/.env — deploy step should SCP rendered env from GitHub Actions." >&2
  exit 1
fi

if [[ ! -f "${DEPLOY_DIR}/docker-compose.prod.yml" ]]; then
  echo "Missing ${DEPLOY_DIR}/docker-compose.prod.yml" >&2
  exit 1
fi

cd "${DEPLOY_DIR}"

if [[ -n "${DOCKERHUB_USERNAME:-}" && -n "${DOCKERHUB_TOKEN:-}" ]]; then
  log "Docker Hub login"
  echo "${DOCKERHUB_TOKEN}" | docker login -u "${DOCKERHUB_USERNAME}" --password-stdin
fi

COMPOSE=(docker compose)
if ! docker compose version >/dev/null 2>&1; then
  COMPOSE=(docker-compose)
fi

log "Pull ${BACKEND_IMAGE} and ${COLLECTOR_IMAGE}"
export BACKEND_IMAGE COLLECTOR_IMAGE
"${COMPOSE[@]}" -f docker-compose.prod.yml pull

log "Start stack"
"${COMPOSE[@]}" -f docker-compose.prod.yml up -d --remove-orphans

log "Wait for API health"
for _ in $(seq 1 30); do
  if curl -sf "http://127.0.0.1:8090/health" >/dev/null; then
    log "API healthy"
    curl -sf "http://127.0.0.1:8090/health"
    echo
    "${COMPOSE[@]}" -f docker-compose.prod.yml ps
    exit 0
  fi
  sleep 2
done

echo "API did not become healthy within 60s" >&2
"${COMPOSE[@]}" -f docker-compose.prod.yml logs --tail=100 platform-api
exit 1
