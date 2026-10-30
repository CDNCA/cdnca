#!/usr/bin/env bash
# Node telemetry end to end: real OpenResty (node runtime image) + edge-agent telemetry
# pipeline -> agent-gateway telemetry transport -> NATS -> control-api analytics ingest -> ClickHouse. Access
# events, security events (CC challenge / 429 aggregated lines with their count), and subscription minutes land in
# ClickHouse with the node's numbers; the gateway unreachable for 10 minutes while traffic continues, then back:
# nothing lost, nothing twice (counts do not double).
#
# The processes are tests/dynroute-e2e/run.sh's with DYNROUTE_E2E_TELEMETRY=1 and the control half
# TestTelemetryControlProcess (services/control-api/cmd/control-api/telemetry_e2e_test.go).
#
#   tests/telemetry-e2e/run.sh                       (~20 min)
#   TELEMETRY_E2E_OFFLINE=10m                        how long the gateway is unreachable (default 10m)
#   PG_NATIVE=<script>                               native PostgreSQL helper (else dynroute-e2e's container)
#   TELEMETRY_E2E_CH_PORT (18934)  TELEMETRY_E2E_PG_PORT (56134)
#   CDNCA_D13_IMAGE   node runtime image (default cdnca-native-runtime:edge-golden)
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CH_IMAGE=clickhouse/clickhouse-server:25.3.6.56-alpine
CH="cdnca-tele-e2e-ch-$$"
CH_PORT="${TELEMETRY_E2E_CH_PORT:-18934}"
PG_PORT="${TELEMETRY_E2E_PG_PORT:-56134}"
PG_NATIVE="${PG_NATIVE:-}"
PG_NAME="tele-e2e-$$"
export PATH="/opt/homebrew/opt/postgresql@17/bin:$PATH"
pg_started=
cleanup() {
  docker rm -f "$CH" >/dev/null 2>&1 || true
  [ -n "$pg_started" ] && "$PG_NATIVE" stop "$PG_NAME" >/dev/null 2>&1 || true
}
trap cleanup EXIT

docker image inspect "$CH_IMAGE" >/dev/null 2>&1 || { echo "BLOCKED: $CH_IMAGE missing" >&2; exit 69; }
echo "[telemetry-e2e] ClickHouse $CH_IMAGE"
docker run -d --rm --name "$CH" -p "127.0.0.1:${CH_PORT}:8123" -e CLICKHOUSE_SKIP_USER_SETUP=1 \
  -v "$ROOT/infra/clickhouse/migrations:/m:ro" "$CH_IMAGE" >/dev/null
for _ in $(seq 60); do curl -sf "http://127.0.0.1:${CH_PORT}/ping" >/dev/null && break; sleep 1; done
curl -sf "http://127.0.0.1:${CH_PORT}/ping" >/dev/null || { echo "ClickHouse did not start" >&2; exit 1; }
for file in $(ls "$ROOT"/infra/clickhouse/migrations/*.up.sql | sort); do
  docker exec "$CH" clickhouse-client --multiquery --queries-file "/m/$(basename "$file")" ||
    { echo "ClickHouse migration $(basename "$file") failed" >&2; exit 1; }
done

if [ -z "${DYNROUTE_E2E_DATABASE_URL:-}" ] && [ -x "$PG_NATIVE" ]; then
  url=$("$PG_NATIVE" start "$PG_NAME" "$PG_PORT" | grep -o 'postgres://[^ ]*' | head -1)
  pg_started=1
  base=${url%/*}
  psql -X -q "$base/postgres" -c 'CREATE DATABASE telemetry_e2e TEMPLATE template0' \
    -c 'REVOKE CREATE ON DATABASE telemetry_e2e FROM PUBLIC' \
    -c 'REVOKE ALL ON DATABASE telemetry_e2e FROM cdnca_control_app, cdnca_plugin_webhook_runtime, cdnca_control_runtime'
  export DYNROUTE_E2E_DATABASE_URL="$base/telemetry_e2e?sslmode=disable"
fi

export DYNROUTE_E2E_TELEMETRY=1 DYNROUTE_E2E_CONTROL_TEST=TestTelemetryControlProcess
export TELEMETRY_E2E_CLICKHOUSE_URL="http://127.0.0.1:${CH_PORT}" TELEMETRY_E2E_OFFLINE="${TELEMETRY_E2E_OFFLINE:-10m}"
bash "$ROOT/tests/dynroute-e2e/run.sh"
echo "[telemetry-e2e] passed"
