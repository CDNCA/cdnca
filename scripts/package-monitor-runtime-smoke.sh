#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
control_api_dir="${repo_root}/services/control-api"
task_prefix="cdnca-package-monitor-runtime-${PPID}-$$"
temporary_base=${PACKAGE_MONITOR_RUNTIME_TMPDIR:-/tmp}
task_root=$(mktemp -d "${temporary_base%/}/${task_prefix}.XXXXXX")
data_dir="${task_root}/data"
socket_dir="${task_root}/socket"
postgres_log="${task_root}/postgres.log"
postgres_bin=${POSTGRES_17_BIN:-}

cleanup() {
  local status=$?
  local residual=0
  local orphan=0
  trap - EXIT INT TERM
  if [[ -n "${postgres_bin}" && -x "${postgres_bin}/pg_ctl" && -d "${data_dir}" ]] && \
    "${postgres_bin}/pg_ctl" -D "${data_dir}" status >/dev/null 2>&1; then
    "${postgres_bin}/pg_ctl" -D "${data_dir}" -m fast -w stop >/dev/null 2>&1 || status=1
  fi
  if pgrep -f "${data_dir}" >/dev/null 2>&1; then
    residual=$(pgrep -f "${data_dir}" | wc -l | tr -d ' ')
  fi
  orphan=$(ps -axo pid=,ppid=,command= | awk -v marker="${data_dir}" \
    '$2 == 1 && index($0, marker) > 0 { count++ } END { print count + 0 }')
  if [[ -n "${task_root}" && "${task_root}" == "${temporary_base%/}/${task_prefix}."* ]]; then
    if command -v trash >/dev/null 2>&1; then
      trash "${task_root}" || status=1
    elif command -v gio >/dev/null 2>&1; then
      gio trash "${task_root}" >/dev/null || status=1
    else
      printf 'recoverable trash command is required to clean %s\n' "${task_root}" >&2
      status=1
    fi
  else
    printf 'refusing to remove unsafe task root: %s\n' "${task_root}" >&2
    status=1
  fi
  printf 'package monitor runtime cleanup: task residual=%s, PPID=1 orphan=%s\n' \
    "${residual}" "${orphan}"
  if ((residual != 0 || orphan != 0)); then
    status=1
  fi
  exit "${status}"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

if [[ -z "${postgres_bin}" ]]; then
  if ! command -v brew >/dev/null 2>&1; then
    echo "Homebrew PostgreSQL 17.9 is required" >&2
    exit 1
  fi
  postgres_bin="$(brew --prefix postgresql@17)/bin"
fi
for command_name in initdb pg_ctl pg_isready postgres psql; do
  if [[ ! -x "${postgres_bin}/${command_name}" ]]; then
    printf 'missing PostgreSQL command: %s/%s\n' "${postgres_bin}" "${command_name}" >&2
    exit 1
  fi
done
postgres_version=$("${postgres_bin}/postgres" --version)
if [[ ! "${postgres_version}" =~ ^postgres\ \(PostgreSQL\)\ 17\.9([[:space:]].*)?$ ]]; then
  "${postgres_bin}/postgres" --version >&2
  echo "PostgreSQL 17.9 is required" >&2
  exit 1
fi

mkdir -p "${socket_dir}"
"${postgres_bin}/initdb" -D "${data_dir}" --auth=trust --encoding=UTF8 --no-locale >/dev/null
{
  printf "listen_addresses = ''\n"
  printf "unix_socket_directories = '%s'\n" "${socket_dir}"
  printf "max_connections = 20\n"
  printf "max_locks_per_transaction = 512\n"
} >>"${data_dir}/postgresql.conf"
if ! "${postgres_bin}/pg_ctl" -D "${data_dir}" -l "${postgres_log}" -w start >/dev/null; then
  cat "${postgres_log}" >&2
  exit 1
fi

database_user=$(id -un)
for _ in {1..100}; do
  if "${postgres_bin}/pg_isready" -h "${socket_dir}" -U "${database_user}" -d postgres \
    >/dev/null 2>&1; then
    break
  fi
  sleep 0.05
done
if ! "${postgres_bin}/pg_isready" -h "${socket_dir}" -U "${database_user}" -d postgres \
  >/dev/null 2>&1; then
  cat "${postgres_log}" >&2
  exit 1
fi

psql=("${postgres_bin}/psql" -h "${socket_dir}" -U "${database_user}" -d postgres -AtX)
"${psql[@]}" -v ON_ERROR_STOP=1 -c 'CREATE ROLE cdnca_control_app NOLOGIN'
"${psql[@]}" -v ON_ERROR_STOP=1 -c 'CREATE ROLE cdnca_plugin_webhook_runtime NOLOGIN'
server_version_num=$("${psql[@]}" -c 'SHOW server_version_num')
listen_addresses=$("${psql[@]}" -c 'SHOW listen_addresses')
max_connections=$("${psql[@]}" -c 'SHOW max_connections')
max_locks=$("${psql[@]}" -c 'SHOW max_locks_per_transaction')
socket_setting=$("${psql[@]}" -c 'SHOW unix_socket_directories')
if [[ "${server_version_num}" != "170009" ]] || [[ -n "${listen_addresses}" ]] || \
  [[ "${max_connections}" != "20" ]] || [[ "${max_locks}" != "512" ]] || \
  [[ "${socket_setting}" != "${socket_dir}" ]]; then
  printf 'version=%s listen=%q connections=%s locks=%s socket=%s\n' \
    "${server_version_num}" "${listen_addresses}" "${max_connections}" "${max_locks}" \
    "${socket_setting}" >&2
  echo "temporary PostgreSQL settings do not match the frozen runtime gate" >&2
  exit 1
fi

database_url="host=${socket_dir} user=${database_user} dbname=postgres sslmode=disable"
package_monitor_go_files=(
  "${control_api_dir}/internal/packagemonitor/runtime.go"
  "${control_api_dir}/internal/packagemonitor/runtime_test.go"
  "${control_api_dir}/internal/packagemonitor/runtime_integration_test.go"
  "${control_api_dir}/internal/packagemonitor/state.go"
  "${control_api_dir}/internal/packagemonitor/state_test.go"
  "${control_api_dir}/internal/packagemonitor/store.go"
  "${control_api_dir}/internal/packagemonitor/store_test.go"
  "${control_api_dir}/internal/packagemonitor/store_integration_test.go"
  "${control_api_dir}/migrations/package_monitor_078_integration_test.go"
)
if [[ -n "$(gofmt -l "${package_monitor_go_files[@]}")" ]]; then
  echo "package monitor Go files are not gofmt clean" >&2
  exit 1
fi

cd "${control_api_dir}"
go test -count=1 ./internal/packagemonitor
go test -race -count=1 ./internal/packagemonitor
go vet ./internal/packagemonitor

TEST_DATABASE_URL="${database_url}" \
  go test -tags=integration -count=1 ./internal/packagemonitor
TEST_DATABASE_URL="${database_url}" \
  go test -race -tags=integration -count=1 ./internal/packagemonitor
TEST_DATABASE_URL="${database_url}" \
  go test -tags=integration -count=1 -run '^TestPackageMonitor078' ./migrations
TEST_DATABASE_URL="${database_url}" \
  go test -race -tags=integration -count=1 -run '^TestPackageMonitor078' ./migrations
TEST_DATABASE_URL="${database_url}" go test -count=1 ./migrations
TEST_DATABASE_URL="${database_url}" go test -race -count=1 ./migrations
TEST_DATABASE_URL="${database_url}" go test -count=1 ./internal/database
TEST_DATABASE_URL="${database_url}" go test -race -count=1 ./internal/database

shellcheck "${repo_root}/scripts/package-monitor-runtime-smoke.sh"
printf 'package monitor runtime smoke passed\n'
