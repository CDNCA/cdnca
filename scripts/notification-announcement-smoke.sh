#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
control_api_dir="${repo_root}/services/control-api"
database_url=${TEST_DATABASE_URL:-}
psql_bin=${PSQL_BIN:-psql}

if [[ -z "${database_url}" ]]; then
  echo "TEST_DATABASE_URL must reference the task-owned PostgreSQL 17.9 Unix socket" >&2
  exit 1
fi
if ! command -v "${psql_bin}" >/dev/null 2>&1; then
  echo "PSQL_BIN must identify a PostgreSQL 17 psql binary" >&2
  exit 1
fi

settings=$("${psql_bin}" "${database_url}" -AtX -F '|' -c \
  "SELECT current_setting('server_version'),current_setting('listen_addresses'),current_setting('max_connections'),current_setting('max_locks_per_transaction')")
IFS='|' read -r server_version listen_addresses max_connections max_locks <<<"${settings}"
if [[ "${server_version}" != 17.9* || -n "${listen_addresses}" ||
      "${max_connections}" != "20" || "${max_locks}" != "512" ]]; then
  echo "PostgreSQL must be 17.9 with listen_addresses='', max_connections=20, max_locks_per_transaction=512" >&2
  exit 1
fi

cd "${control_api_dir}"
TEST_DATABASE_URL="${database_url}" \
  go test -tags=integration -count=1 ./internal/notification ./internal/notificationruntime
go test -count=1 ./cmd/control-api -run '^TestAnnouncementNotificationAdapterStableContractErrors$'
TEST_DATABASE_URL="${database_url}" \
  go test -count=1 ./cmd/control-api -run '^TestAnnouncementNotification'

TEST_DATABASE_URL="${database_url}" \
  go test -race -tags=integration -count=1 ./internal/notification ./internal/notificationruntime
TEST_DATABASE_URL="${database_url}" \
  go test -race -count=1 ./cmd/control-api -run '^TestAnnouncementNotification'
go vet ./internal/notification ./internal/notificationruntime
go vet ./cmd/control-api

if command -v shellcheck >/dev/null 2>&1; then
  shellcheck "${repo_root}/scripts/notification-announcement-smoke.sh"
else
  echo "shellcheck is required" >&2
  exit 1
fi

if rg -n -i \
  '(slog|logger\.(debug|info|warn|error)).*(recipient|contact|subject|body|payload|credential|secret|token)|(recipient|contact|subject|body|payload|credential|secret|token).*(slog|logger\.(debug|info|warn|error))' \
  "${control_api_dir}/cmd/control-api/announcement_notification_runtime.go"; then
  echo "announcement notification adapter may log sensitive delivery data" >&2
  exit 1
fi

printf 'announcement notification smoke passed\n'
