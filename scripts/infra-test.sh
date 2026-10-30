#!/usr/bin/env bash

set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
ENV_FILE="${ENV_FILE:-infra/env/development.env}"

if [[ "$ENV_FILE" != /* ]]; then
  ENV_FILE="$REPO_ROOT/$ENV_FILE"
fi

for command_name in docker curl; do
  if ! command -v "$command_name" >/dev/null 2>&1; then
    printf 'missing required command: %s\n' "$command_name" >&2
    exit 1
  fi
done

if [[ ! -f "$ENV_FILE" ]]; then
  printf 'environment file not found: %s\n' "$ENV_FILE" >&2
  exit 1
fi

set -a
# shellcheck disable=SC1090
source "$ENV_FILE"
set +a

compose=(docker compose --env-file "$ENV_FILE" -f "$REPO_ROOT/compose.yaml")

printf 'Starting infrastructure...\n'
"${compose[@]}" up -d --wait

printf 'Checking PostgreSQL query path...\n'
postgres_result="$(
  "${compose[@]}" exec -T \
    -e PGPASSWORD="$POSTGRES_PASSWORD" \
    postgres psql -h 127.0.0.1 -U "$POSTGRES_USER" -d "$POSTGRES_DB" \
    -Atqc "SELECT current_database()"
)"
[[ "$postgres_result" == "$POSTGRES_DB" ]]

printf 'Checking Redis authenticated read/write path...\n'
redis_key="cdnca:infra-test:$$"
"${compose[@]}" exec -T redis \
  redis-cli --no-auth-warning -a "$REDIS_PASSWORD" SET "$redis_key" ready EX 30 >/dev/null
redis_result="$(
  "${compose[@]}" exec -T redis \
    redis-cli --no-auth-warning -a "$REDIS_PASSWORD" GET "$redis_key"
)"
[[ "$redis_result" == "ready" ]]
"${compose[@]}" exec -T redis \
  redis-cli --no-auth-warning -a "$REDIS_PASSWORD" DEL "$redis_key" >/dev/null

printf 'Checking ClickHouse authenticated query path...\n'
clickhouse_result="$(
  curl --fail --silent --show-error \
    --user "$CLICKHOUSE_USER:$CLICKHOUSE_PASSWORD" \
    --data-binary 'SELECT toUInt64(20) + 22' \
    "http://127.0.0.1:$CLICKHOUSE_HTTP_PORT/"
)"
[[ "$clickhouse_result" == "42" ]]

printf 'Checking NATS authenticated protocol and JetStream paths...\n'
exec 3<>"/dev/tcp/127.0.0.1/$NATS_CLIENT_PORT"
IFS= read -r -t 5 nats_info <&3
[[ "$nats_info" == INFO\ * ]]
printf 'CONNECT {"user":"%s","pass":"%s","verbose":false,"pedantic":true}\r\nPING\r\n' \
  "$NATS_USERNAME" "$NATS_PASSWORD" >&3
nats_response=''
for _ in 1 2 3; do
  IFS= read -r -t 5 nats_response <&3
  nats_response="${nats_response%$'\r'}"
  [[ "$nats_response" == PONG ]] && break
done
exec 3>&-
[[ "$nats_response" == PONG ]]

jetstream_health="$(
  curl --fail --silent --show-error \
    "http://127.0.0.1:$NATS_MONITOR_PORT/healthz?js-enabled-only=true"
)"
[[ "$jetstream_health" == *'"status":"ok"'* ]]

printf 'Infrastructure checks passed.\n'

