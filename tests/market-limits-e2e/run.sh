#!/usr/bin/env bash
# Node market supply limits end to end (ADR 0012 ML-14): market process <-> three controllers over mTLS.
#
#   tests/market-limits-e2e/run.sh        (about 12 minutes)
#   PG_NATIVE=<script>   native PostgreSQL helper (start <name> <port> / stop <name>); MARKET_LIMITS_E2E_PG_PORT (56251)
#   MARKET_LIMITS_E2E_KEEP=1   keep the work directory
#
# Process 1 (services/market-service internal/httpapi TestMarketLimitsMarketProcess): the production member API and
#   relay over mTLS (test CA), an injected clock, and a loopback control endpoint standing in for the operator,
#   direct top-up confirmations and the schedulers (limit evaluator, 5-minute meter, renewal, node load).
# Process 2 (services/control-api cmd/control-api TestMarketLimitsControlProcess, -tags integration): leaf seller A
#   (production marketclient + marketruntime grant/hold/usage loops + marketsupply on a migrated schema, the market
#   reached through CDNCA_MARKET_CA_FILE) and subscribers B and C (production marketclient, own certificates/leases).
#
# Scenarios: ① prepaid purchase, QPS at the cap 2 buckets → B paused, C serving; below 80% → B resumes;
#   ② traffic offer, prepaid exhausted → pause, overdraft at the credit line → still pause, top-up → released;
#   ③ prepaid_exhausted_action=stop, renewal unpaid → stop hold applied by the leaf (node share stopped), top-up →
#   restored; ④ node at 95% CPU two minutes → overloaded for every subscriber on it, five minutes below → restored.
# The node half (a real OpenResty node answering 503 for a stopped subscriber) is not wired (E2-B).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PG_NATIVE="${PG_NATIVE:?set PG_NATIVE to a native PostgreSQL helper (start <name> <port> / stop <name>)}"
PG_PORT="${MARKET_LIMITS_E2E_PG_PORT:-56251}"
PG_NAME="market-limits-e2e-$$"
export PATH="/opt/homebrew/opt/postgresql@17/bin:$PATH"
WORK="$(cd "$(mktemp -d "${TMPDIR:-/tmp}/market-limits-e2e.XXXXXX")" && pwd -P)"
pg_started=
MARKET_PID=
cleanup() {
  [ -n "$MARKET_PID" ] && kill "$MARKET_PID" 2>/dev/null || true
  [ -n "$pg_started" ] && "$PG_NATIVE" stop "$PG_NAME" >/dev/null 2>&1 || true
  if [ "${MARKET_LIMITS_E2E_KEEP:-}" = 1 ]; then echo "[market-limits-e2e] kept $WORK" >&2; else rm -rf "$WORK"; fi
}
trap cleanup EXIT

url=$("$PG_NATIVE" start "$PG_NAME" "$PG_PORT" | grep -o 'postgres://[^ ]*' | head -1)
pg_started=1
base=${url%/*}
psql -X -q "$base/postgres" -c 'CREATE DATABASE market_limits_control TEMPLATE template0' \
  -c 'REVOKE CREATE ON DATABASE market_limits_control FROM PUBLIC' \
  -c 'REVOKE ALL ON DATABASE market_limits_control FROM cdnca_control_app, cdnca_plugin_webhook_runtime, cdnca_control_runtime' \
  -c 'CREATE DATABASE market_limits_market TEMPLATE template0'

echo "[market-limits-e2e] building"
mkdir -p "$WORK/bin"
GOWORK=off go test -C "$ROOT/services/market-service" -c -o "$WORK/bin/market.test" ./internal/httpapi
go test -C "$ROOT/services/control-api" -tags integration -c -o "$WORK/bin/control.test" ./cmd/control-api

echo "[market-limits-e2e] market"
(cd "$ROOT/services/market-service/internal/httpapi" && MARKET_LIMITS_E2E_DIR="$WORK" \
  MARKET_TEST_DATABASE_URL="$base/market_limits_market?sslmode=disable" \
  exec "$WORK/bin/market.test" -test.run '^TestMarketLimitsMarketProcess$' -test.count=1 -test.v -test.timeout 45m) \
  >"$WORK/market.log" 2>&1 &
MARKET_PID=$!

echo "[market-limits-e2e] controllers"
set +e
(cd "$ROOT/services/control-api/cmd/control-api" && MARKET_LIMITS_E2E_DIR="$WORK" \
  TEST_DATABASE_URL="$base/market_limits_control?sslmode=disable" \
  exec "$WORK/bin/control.test" -test.run '^TestMarketLimitsControlProcess$' -test.count=1 -test.v -test.timeout 30m) \
  >"$WORK/control.log" 2>&1
control=$?
[ "$control" -ne 0 ] && kill "$MARKET_PID" 2>/dev/null
wait "$MARKET_PID"
market=$?
MARKET_PID=
set -e
grep -E 'PASS |^(--- |FAIL|ok)|_test.go:[0-9]+' "$WORK/control.log" | sed 's/^/[control] /'
grep -E '^(--- |FAIL|ok)|_test.go:[0-9]+' "$WORK/market.log" | sed 's/^/[market] /'
if [ "$control" -ne 0 ] || [ "$market" -ne 0 ]; then
  echo "[market-limits-e2e] FAILED control=$control market=$market (MARKET_LIMITS_E2E_KEEP=1 keeps $WORK)" >&2
  exit 1
fi
echo "[market-limits-e2e] passed"
