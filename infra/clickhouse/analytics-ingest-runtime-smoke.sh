#!/bin/sh
set -eu

umask 077

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH='' cd -- "$script_dir/../.." && pwd)
env_file=${ENV_FILE:-$repo_root/infra/env/development.env}

if [ ! -r "$env_file" ]; then
    printf '%s\n' 'analytics ingest runtime smoke environment file is not readable' >&2
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
task_database="cdnca_analytics_runtime_$task_suffix"

clickhouse() {
    docker compose --env-file "$env_file" -f "$repo_root/compose.yaml" exec -T clickhouse \
        sh -c 'exec clickhouse-client --user "$CLICKHOUSE_USER" --password "$CLICKHOUSE_PASSWORD" "$@"' \
        analytics-ingest-runtime-smoke "$@"
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

export ANALYTICS_INGEST_RUNTIME_INTEGRATION=1
export ANALYTICS_INGEST_ENABLED=true
export ANALYTICS_INGEST_NATS_URL="nats://127.0.0.1:$NATS_CLIENT_PORT"
export ANALYTICS_INGEST_NATS_USER="$NATS_USERNAME"
export ANALYTICS_INGEST_NATS_PASSWORD="$NATS_PASSWORD"
export ANALYTICS_INGEST_CLICKHOUSE_URL="http://127.0.0.1:$CLICKHOUSE_HTTP_PORT"
export ANALYTICS_INGEST_CLICKHOUSE_DATABASE="$task_database"
export ANALYTICS_INGEST_CLICKHOUSE_USER="$CLICKHOUSE_USER"
export ANALYTICS_INGEST_CLICKHOUSE_PASSWORD="$CLICKHOUSE_PASSWORD"
export ANALYTICS_INGEST_CONNECT_TIMEOUT=1s
export ANALYTICS_INGEST_WRITE_TIMEOUT=500ms
export ANALYTICS_INGEST_SUPERVISOR_BACKOFF_MIN=100ms
export ANALYTICS_INGEST_SUPERVISOR_BACKOFF_MAX=300ms
export ANALYTICS_INGEST_STREAM="ANALYTICS_INGEST_RUNTIME_$task_suffix"
export ANALYTICS_INGEST_DURABLE="analytics_ingest_runtime_$task_suffix"
export ANALYTICS_INGEST_ISOLATION_STREAM="ANALYTICS_ISOLATION_RUNTIME_$task_suffix"
export ANALYTICS_INGEST_ACK_WAIT=2s
export ANALYTICS_INGEST_FETCH_TIMEOUT=200ms
export ANALYTICS_INGEST_OPERATION_TIMEOUT=500ms
export ANALYTICS_INGEST_NAK_BASE_DELAY=100ms
export ANALYTICS_INGEST_NAK_MAX_DELAY=300ms
export ANALYTICS_INGEST_MAX_DELIVER=20
export ANALYTICS_INGEST_MAX_ACK_PENDING=8
export ANALYTICS_INGEST_MAX_WAITING=4
export ANALYTICS_INGEST_FETCH_BATCH=4
export ANALYTICS_INGEST_STREAM_MAX_AGE=0
export ANALYTICS_INGEST_STREAM_MAX_BYTES=67108864
export ANALYTICS_INGEST_STREAM_MAX_MESSAGES=1000
export ANALYTICS_INGEST_ISOLATION_MAX_AGE=1h
export ANALYTICS_INGEST_ISOLATION_MAX_BYTES=16777216
export ANALYTICS_INGEST_DUPLICATE_WINDOW=2m
export ANALYTICS_INGEST_REPLICAS=1

(
    cd "$repo_root/services/control-api"
    go test -v -count=1 -run '^TestAnalyticsIngestRuntimeProcessLifecycle$' ./cmd/control-api
)

clickhouse --param_database "$task_database" \
    --query 'DROP DATABASE {database:Identifier} SYNC' >/dev/null
remaining=$(clickhouse --param_database "$task_database" --format TSVRaw \
    --query 'SELECT count() FROM system.databases WHERE name = {database:String}')
if [ "$remaining" != 0 ]; then
    printf '%s\n' 'analytics ingest runtime smoke failed to clean its ClickHouse database' >&2
    exit 1
fi
trap - EXIT HUP INT TERM

printf '%s\n' 'analytics ingest runtime smoke passed: process wiring, restart, recovery, poison, shutdown, summary, and five rankings verified'
