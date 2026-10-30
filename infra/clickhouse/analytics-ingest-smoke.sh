#!/bin/sh
set -eu

umask 077

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH='' cd -- "$script_dir/../.." && pwd)
env_file=${ENV_FILE:-$repo_root/infra/env/development.env}

if [ ! -r "$env_file" ]; then
    printf '%s\n' 'analytics ingest smoke environment file is not readable' >&2
    exit 2
fi

# shellcheck disable=SC1090
. "$env_file"

: "${NATS_USERNAME:?set NATS_USERNAME}"
: "${NATS_PASSWORD:?set NATS_PASSWORD}"
: "${NATS_CLIENT_PORT:?set NATS_CLIENT_PORT}"
: "${CLICKHOUSE_USER:?set CLICKHOUSE_USER}"
: "${CLICKHOUSE_PASSWORD:?set CLICKHOUSE_PASSWORD}"
: "${CLICKHOUSE_HTTP_PORT:?set CLICKHOUSE_HTTP_PORT}"

task_suffix="$(date +%Y%m%d%H%M%S)_$$"
task_database="cdnca_analytics_ingest_$task_suffix"
task_stream="ANALYTICS_INGEST_SMOKE_$task_suffix"
task_durable="analytics_ingest_smoke_$task_suffix"
task_isolation_stream="ANALYTICS_ISOLATION_SMOKE_$task_suffix"

clickhouse() {
    docker compose --env-file "$env_file" -f "$repo_root/compose.yaml" exec -T clickhouse \
        sh -c 'exec clickhouse-client --user "$CLICKHOUSE_USER" --password "$CLICKHOUSE_PASSWORD" "$@"' \
        analytics-ingest-smoke "$@"
}

cleanup() {
    clickhouse --param_database "$task_database" \
        --query 'DROP DATABASE IF EXISTS {database:Identifier} SYNC' >/dev/null 2>&1 || :
}

trap cleanup EXIT HUP INT TERM

clickhouse --param_database "$task_database" \
    --query 'CREATE DATABASE {database:Identifier}' >/dev/null
clickhouse --database "$task_database" --multiquery \
    < "$script_dir/migrations/001_analytics.up.sql" >/dev/null
clickhouse --database "$task_database" --multiquery \
    < "$script_dir/migrations/002_analytics_authority_capture.up.sql" >/dev/null
clickhouse --database "$task_database" --multiquery \
    < "$script_dir/migrations/003_analytics_hourly_rollup.up.sql" >/dev/null
clickhouse --database "$task_database" --multiquery \
    < "$script_dir/migrations/004_analytics_version_evidence.up.sql" >/dev/null

export ANALYTICS_INGEST_INTEGRATION=1
export ANALYTICS_INGEST_NATS_URL="nats://127.0.0.1:$NATS_CLIENT_PORT"
export ANALYTICS_INGEST_NATS_USER="$NATS_USERNAME"
export ANALYTICS_INGEST_NATS_PASSWORD="$NATS_PASSWORD"
export ANALYTICS_INGEST_CLICKHOUSE_URL="http://127.0.0.1:$CLICKHOUSE_HTTP_PORT"
export ANALYTICS_INGEST_CLICKHOUSE_DATABASE="$task_database"
export ANALYTICS_INGEST_CLICKHOUSE_USER="$CLICKHOUSE_USER"
export ANALYTICS_INGEST_CLICKHOUSE_PASSWORD="$CLICKHOUSE_PASSWORD"
export ANALYTICS_INGEST_STREAM="$task_stream"
export ANALYTICS_INGEST_DURABLE="$task_durable"
export ANALYTICS_INGEST_ISOLATION_STREAM="$task_isolation_stream"

(
    cd "$repo_root/services/control-api"
    go test -v -count=1 -run '^TestNATSClickHouseIngestLifecycle$' ./internal/analytics
)

clickhouse --param_database "$task_database" \
    --query 'DROP DATABASE {database:Identifier} SYNC' >/dev/null
remaining=$(clickhouse --param_database "$task_database" --format TSVRaw \
    --query 'SELECT count() FROM system.databases WHERE name = {database:String}')
if [ "$remaining" != 0 ]; then
    printf '%s\n' 'analytics ingest smoke failed to clean its ClickHouse database' >&2
    exit 1
fi
trap - EXIT HUP INT TERM

printf '%s\n' 'analytics ingest smoke passed: retry, restart, poison isolation, and bounded backlog verified'
