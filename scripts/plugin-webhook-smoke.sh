#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
control_api_dir="${repo_root}/services/control-api"
nats_url=${CDNCA_PLUGIN_WEBHOOK_SMOKE_NATS_URL:-}
database_url=${CDNCA_PLUGIN_WEBHOOK_SMOKE_DATABASE_URL:-${TEST_DATABASE_URL:-}}
container_name=""

cleanup() {
  if [[ -n "${container_name}" ]]; then
    docker rm -f "${container_name}" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT INT TERM

if [[ -z "${database_url}" ]]; then
  echo "CDNCA_PLUGIN_WEBHOOK_SMOKE_DATABASE_URL or TEST_DATABASE_URL is required for the v2 PostgreSQL/084 runtime smoke" >&2
  exit 1
fi

if [[ -z "${nats_url}" ]]; then
  if ! command -v docker >/dev/null 2>&1; then
    echo "docker is required when CDNCA_PLUGIN_WEBHOOK_SMOKE_NATS_URL is unset" >&2
    exit 1
  fi
  container_name="cdnca-plugin-webhook-smoke-${PPID}-$$"
  docker run -d --rm \
    --name "${container_name}" \
    --tmpfs /data \
    -p 127.0.0.1::4222 \
    nats:2.11.4-alpine -js -sd /data >/dev/null

  for _ in {1..50}; do
    if docker logs "${container_name}" 2>&1 | grep -q "Server is ready"; then
      break
    fi
    sleep 0.1
  done
  if ! docker logs "${container_name}" 2>&1 | grep -q "Server is ready"; then
    echo "temporary NATS server did not become ready" >&2
    exit 1
  fi
  published_address=$(docker port "${container_name}" 4222/tcp)
  nats_url="nats://${published_address}"
fi

cd "${control_api_dir}"
CDNCA_PLUGIN_WEBHOOK_SMOKE_NATS_URL="${nats_url}" \
  go test -count=1 -run '^TestPluginWebhookNATSTLSSmoke$' -v ./internal/pluginwebhook

CDNCA_PLUGIN_WEBHOOK_RUNTIME_DATABASE_URL="${database_url}" \
CDNCA_PLUGIN_WEBHOOK_RUNTIME_NATS_URL="${nats_url}" \
  go test -tags integration -count=1 -run '^TestRuntimePGSocketNATSFileLifecycle$' -v ./internal/pluginwebhookruntime
