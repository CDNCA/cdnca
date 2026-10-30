#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
control_api_dir="${repo_root}/services/control-api"
context_dir="${control_api_dir}/internal/accountrecoverycontext"
database_url=${TEST_DATABASE_URL:-}
container_name=""
published_address=""

cleanup() {
  if [[ -n "${container_name}" ]]; then
    docker rm -f "${container_name}" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT INT TERM

wait_for_postgres() {
  local consecutive_ready=0
  for _ in {1..100}; do
    if docker exec "${container_name}" \
      psql -U postgres -d postgres -Atc "SELECT 1" >/dev/null 2>&1; then
      consecutive_ready=$((consecutive_ready + 1))
      if ((consecutive_ready >= 5)); then
        return 0
      fi
    else
      consecutive_ready=0
    fi
    sleep 0.2
  done
  echo "temporary PostgreSQL 17 did not become ready" >&2
  return 1
}

wait_for_host_port() {
  local host=${published_address%:*}
  local port=${published_address##*:}
  for _ in {1..100}; do
    if (exec 3<>"/dev/tcp/${host}/${port}") 2>/dev/null; then
      exec 3>&-
      exec 3<&-
      return 0
    fi
    sleep 0.2
  done
  echo "temporary PostgreSQL host port did not become ready" >&2
  return 1
}

if [[ -z "${database_url}" ]]; then
  if ! command -v docker >/dev/null 2>&1; then
    echo "docker is required when TEST_DATABASE_URL is unset" >&2
    exit 1
  fi
  container_name="cdnca-account-recovery-context-smoke-${PPID}-$$"
  docker run -d --rm \
    --name "${container_name}" \
    -e POSTGRES_PASSWORD=account-recovery-context-smoke \
    -p 127.0.0.1::5432 \
    postgres:17-alpine >/dev/null
  published_address=$(docker port "${container_name}" 5432/tcp)
  wait_for_postgres
  wait_for_host_port
  server_version=$(docker exec "${container_name}" \
    psql -U postgres -d postgres -Atc "SHOW server_version_num")
  if [[ ! "${server_version}" =~ ^17[0-9]{4}$ ]]; then
    echo "expected PostgreSQL 17, got ${server_version}" >&2
    exit 1
  fi
  database_url="postgresql://postgres:account-recovery-context-smoke@${published_address}/postgres?sslmode=disable"
fi

cd "${control_api_dir}"
TEST_DATABASE_URL="${database_url}" go test -race -count=1 ./internal/accountrecoverycontext
go vet ./internal/accountrecoverycontext

if command -v shellcheck >/dev/null 2>&1; then
  shellcheck "${repo_root}/scripts/account-recovery-context-smoke.sh"
else
  echo "shellcheck is required" >&2
  exit 1
fi

if rg -n -i \
  '(slog|log|printf|errorf).*(username|hostname|tenant|scope|source.?ip|forwarded|authorization|cookie)|(username|hostname|source.?ip|forwarded).*(slog|log|printf|errorf)' \
  "${context_dir}" --glob '*.go' --glob '!**/*_test.go'; then
  echo "account recovery context source may log trusted routing data" >&2
  exit 1
fi
