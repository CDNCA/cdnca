#!/usr/bin/env bash
# Node market three-level resale chain end to end (ADR 0012 ML-30 E1): market process <-> three controllers over mTLS.
#
#   tests/market-supplier-e2e/run.sh      (a few minutes)
#   PG_NATIVE=<script>   native PostgreSQL helper (start <name> <port> / stop <name>); MARKET_SUPPLIER_E2E_PG_PORT (56252)
#   MARKET_SUPPLIER_E2E_KEEP=1   keep the work directory
#
# Process 1: the same market process as tests/market-limits-e2e (TestMarketLimitsMarketProcess: production member
#   API, relay, operator API with an operator certificate, subscriber/complaint routes as cmd/market-service mounts them).
# Process 2 (services/control-api cmd/control-api TestMarketSupplierControlProcess, -tags integration): supplier A,
#   reseller B and root subscriber C, each its own migrated schema, lease and production marketruntime (grants, relay,
#   holds, notices into the notification center); A runs marketsupply with the real site service, C marketsubscribe.
#
# Scenarios: ① A lists, B buys by direct top-up and resells, C buys the resale (balances per seller); ② visibility a
#   (A sees C only as a downstream number via B); ③ C's site committed through the relay onto A's line group;
#   ④ attack digest of A's site (stand-in ClickHouse readers) reaches C bound to its site, B only gets
#   market.downstream.attacked; ⑤–⑦ A's stop complaint on the downstream number, operator see-through to C, stop
#   held on C's root and applied by A to C's share only, notices to A/B/C, release restores.
# Not here: a real OpenResty node answering 503 for the stopped share (deploy acceptance, docs/runbooks/deploy-1035.md).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PG_NATIVE="${PG_NATIVE:?set PG_NATIVE to a native PostgreSQL helper (start <name> <port> / stop <name>)}"
PG_PORT="${MARKET_SUPPLIER_E2E_PG_PORT:-56252}"
PG_NAME="market-supplier-e2e-$$"
export PATH="/opt/homebrew/opt/postgresql@17/bin:$PATH"
WORK="$(cd "$(mktemp -d "${TMPDIR:-/tmp}/market-supplier-e2e.XXXXXX")" && pwd -P)"
pg_started=
MARKET_PID=
cleanup() {
  [ -n "$MARKET_PID" ] && kill "$MARKET_PID" 2>/dev/null || true
  [ -n "$pg_started" ] && "$PG_NATIVE" stop "$PG_NAME" >/dev/null 2>&1 || true
  if [ "${MARKET_SUPPLIER_E2E_KEEP:-}" = 1 ]; then echo "[market-supplier-e2e] kept $WORK" >&2; else rm -rf "$WORK"; fi
}
trap cleanup EXIT

url=$("$PG_NATIVE" start "$PG_NAME" "$PG_PORT" | grep -o 'postgres://[^ ]*' | head -1)
pg_started=1
base=${url%/*}
psql -X -q "$base/postgres" -c 'CREATE DATABASE market_supplier_control TEMPLATE template0' \
  -c 'REVOKE CREATE ON DATABASE market_supplier_control FROM PUBLIC' \
  -c 'REVOKE ALL ON DATABASE market_supplier_control FROM cdnca_control_app, cdnca_plugin_webhook_runtime, cdnca_control_runtime' \
  -c 'CREATE DATABASE market_supplier_market TEMPLATE template0'

echo "[market-supplier-e2e] building"
mkdir -p "$WORK/bin"
GOWORK=off go test -C "$ROOT/services/market-service" -c -o "$WORK/bin/market.test" ./internal/httpapi
go test -C "$ROOT/services/control-api" -tags integration -c -o "$WORK/bin/control.test" ./cmd/control-api

echo "[market-supplier-e2e] market"
(cd "$ROOT/services/market-service/internal/httpapi" && MARKET_LIMITS_E2E_DIR="$WORK" \
  MARKET_TEST_DATABASE_URL="$base/market_supplier_market?sslmode=disable" \
  exec "$WORK/bin/market.test" -test.run '^TestMarketLimitsMarketProcess$' -test.count=1 -test.v -test.timeout 45m) \
  >"$WORK/market.log" 2>&1 &
MARKET_PID=$!

echo "[market-supplier-e2e] controllers"
set +e
(cd "$ROOT/services/control-api/cmd/control-api" && MARKET_LIMITS_E2E_DIR="$WORK" \
  TEST_DATABASE_URL="$base/market_supplier_control?sslmode=disable" \
  exec "$WORK/bin/control.test" -test.run '^TestMarketSupplierControlProcess$' -test.count=1 -test.v -test.timeout 30m) \
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
  echo "[market-supplier-e2e] FAILED control=$control market=$market (MARKET_SUPPLIER_E2E_KEEP=1 keeps $WORK)" >&2
  exit 1
fi
echo "[market-supplier-e2e] passed"
