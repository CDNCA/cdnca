#!/usr/bin/env bash
set -euo pipefail

umask 077

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(cd "${script_dir}/../.." && pwd)
clickhouse_image=clickhouse/clickhouse-server:25.3.6.56-alpine
nats_image=nats:2.11.4-alpine
suffix="${PPID}-$$-$(date +%s)"
clickhouse_container="cdnca-obs-chain-ch-${suffix}"
nats_container="cdnca-obs-chain-nats-${suffix}"
network="cdnca-obs-chain-${suffix}"
database="obs_chain_${PPID}_$$_$(date +%s)"
output=$(mktemp "${TMPDIR:-/tmp}/cdnca-obs-chain.XXXXXX")
ch_user=obs_chain
ch_password=obs_chain_local_only
nats_user=obs_chain
nats_password=obs_chain_local_only

obs_chain_cleanup() {
  docker rm -f -v "${clickhouse_container}" "${nats_container}" >/dev/null 2>&1 || true
  docker network rm "${network}" >/dev/null 2>&1 || true
  rm -f "${output}"
}

obs_chain_fail() {
  printf 'FAIL chain-smoke: %s\n' "$1" >&2
  if [[ -r "${output}" ]]; then
    sed -E 's/(query|cookie|authorization|old|storage)-secret/[REDACTED]/g' "${output}" | tail -n 240 >&2
  fi
  exit 1
}

trap obs_chain_cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

for dependency in docker go rg; do
  if ! command -v "${dependency}" >/dev/null 2>&1; then
    printf 'SKIP chain-smoke: %s is unavailable\n' "${dependency}" >&2
    exit 77
  fi
done
if ! docker info >/dev/null 2>&1; then
  printf '%s\n' 'SKIP chain-smoke: Docker daemon is unavailable' >&2
  exit 77
fi
for image in "${clickhouse_image}" "${nats_image}"; do
  if ! docker image inspect "${image}" >/dev/null 2>&1 && ! docker pull "${image}" >/dev/null; then
    printf 'SKIP chain-smoke: fixed image %s is unavailable\n' "${image}" >&2
    exit 77
  fi
done

docker network create "${network}" >/dev/null
docker run -d --name "${clickhouse_container}" --network "${network}" \
  --ulimit nofile=262144:262144 -p 127.0.0.1::8123 \
  -e CLICKHOUSE_DB=default -e CLICKHOUSE_USER="${ch_user}" -e CLICKHOUSE_PASSWORD="${ch_password}" \
  -e CLICKHOUSE_DEFAULT_ACCESS_MANAGEMENT=1 "${clickhouse_image}" >/dev/null
docker run -d --name "${nats_container}" --network "${network}" -p 127.0.0.1::4222 \
  "${nats_image}" -js -sd /data --user "${nats_user}" --pass "${nats_password}" >/dev/null

ready_streak=0
for _ in {1..300}; do
  if docker exec "${clickhouse_container}" clickhouse-client --user "${ch_user}" --password "${ch_password}" \
    --query 'SELECT 1' >/dev/null 2>&1 && docker logs "${nats_container}" 2>&1 | rg -q 'Server is ready'; then
    ready_streak=$((ready_streak + 1))
    if [[ ${ready_streak} -ge 3 ]]; then
      break
    fi
  else
    ready_streak=0
  fi
  sleep 0.2
done
[[ ${ready_streak} -ge 3 ]] || obs_chain_fail 'ClickHouse did not become stably ready'
docker logs "${nats_container}" 2>&1 | rg -q 'Server is ready' || obs_chain_fail 'NATS did not become ready'

docker exec "${clickhouse_container}" clickhouse-client --user "${ch_user}" --password "${ch_password}" \
  --query "CREATE DATABASE ${database}" >/dev/null
while IFS= read -r migration; do
  docker exec -i "${clickhouse_container}" clickhouse-client --user "${ch_user}" --password "${ch_password}" \
    --database "${database}" --multiquery <"${migration}" >/dev/null
done < <(find "${repo_root}/infra/clickhouse/migrations" -maxdepth 1 -type f \
  -name '[0-9][0-9][0-9]_*.up.sql' -print | LC_ALL=C sort)

ch_address=$(docker port "${clickhouse_container}" 8123/tcp | head -n 1)
nats_address=$(docker port "${nats_container}" 4222/tcp | head -n 1)
nats_plain_url="nats://${nats_address}"
nats_auth_url="nats://${nats_user}:${nats_password}@${nats_address}"

if ! (
  cd "${repo_root}/services/agent-gateway"
  GOWORK=off go run "${script_dir}/gateway_stream_fixture.go" "${nats_auth_url}"
) >"${output}" 2>&1; then
  obs_chain_fail 'authoritative Gateway support stream fixture failed'
fi

if ! CDNCA_EDGE_TELEMETRY_SMOKE_NATS_URL="${nats_auth_url}" \
  "${repo_root}/scripts/edge-telemetry-transport-smoke.sh" >>"${output}" 2>&1; then
  obs_chain_fail 'real Edge/Gateway/NATS transport smoke failed'
fi

if ! (
  cd "${repo_root}/services/control-api"
  ANALYTICS_INGEST_INTEGRATION=1 \
  ANALYTICS_INGEST_NATS_URL="${nats_plain_url}" \
  ANALYTICS_INGEST_NATS_USER="${nats_user}" \
  ANALYTICS_INGEST_NATS_PASSWORD="${nats_password}" \
  ANALYTICS_INGEST_CLICKHOUSE_URL="http://${ch_address}" \
  ANALYTICS_INGEST_CLICKHOUSE_DATABASE="${database}" \
  ANALYTICS_INGEST_CLICKHOUSE_USER="${ch_user}" \
  ANALYTICS_INGEST_CLICKHOUSE_PASSWORD="${ch_password}" \
  TEST_CLICKHOUSE_URL="http://${ch_address}" \
  TEST_CLICKHOUSE_USERNAME="${ch_user}" \
  TEST_CLICKHOUSE_PASSWORD="${ch_password}" \
    go test -race -count=1 -timeout=4m \
      -run '^(TestAuthorityNATSClickHouseReconciliation|TestNATSClickHouseIngestLifecycle)$' ./internal/analytics
  TEST_CLICKHOUSE_URL="http://${ch_address}" TEST_CLICKHOUSE_USERNAME="${ch_user}" TEST_CLICKHOUSE_PASSWORD="${ch_password}" \
    go test -race -count=1 -timeout=4m -run '^TestClickHouseAnalyticsLogIntegration$' ./internal/analyticslog
) >>"${output}" 2>&1; then
  obs_chain_fail 'real NATS/control/ClickHouse/API integration failed'
fi

if rg -q '(query|cookie|authorization|old|storage)-secret' "${output}"; then
  obs_chain_fail 'sensitive sentinel leaked into task output'
fi

printf '%s\n' 'chain-smoke partial pass: real Edge/Gateway/NATS and NATS/control/ClickHouse/API segments passed on shared service instances; single-message identity continuity remains unproven until capture wire audit passes'

docker exec "${clickhouse_container}" clickhouse-client --user "${ch_user}" --password "${ch_password}" \
  --query "DROP DATABASE IF EXISTS ${database} SYNC" >/dev/null
docker rm -f -v "${clickhouse_container}" "${nats_container}" >/dev/null
docker network rm "${network}" >/dev/null
if docker ps -a --format '{{.Names}}' | rg -q "^(${clickhouse_container}|${nats_container})$" || \
  docker network ls --format '{{.Name}}' | rg -q "^${network}$"; then
  obs_chain_fail 'task containers or network remained after cleanup'
fi
rm -f "${output}"
trap - EXIT HUP INT TERM
