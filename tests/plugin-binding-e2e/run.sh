#!/usr/bin/env bash
# Plugin purchase binding acceptance across license-service and market-service (two processes, real mTLS):
# market order → cashier capture → licence → push → license-side binding on installation A → portal rebind to B →
# A's lease loses the feature code and B's gains it → the market's buyer reads (licences, cancel, downloads) follow
# the license-side binding.
#
#   PLUGIN_BINDING_E2E_LICENSE_DATABASE_URL=postgres://... PLUGIN_BINDING_E2E_MARKET_DATABASE_URL=postgres://... \
#     tests/plugin-binding-e2e/run.sh
#
# Each half migrates its own isolated schema in the given database (use two databases, or the same one).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
: "${PLUGIN_BINDING_E2E_LICENSE_DATABASE_URL:?set PLUGIN_BINDING_E2E_LICENSE_DATABASE_URL}"
: "${PLUGIN_BINDING_E2E_MARKET_DATABASE_URL:?set PLUGIN_BINDING_E2E_MARKET_DATABASE_URL}"
WORK="$(cd "$(mktemp -d "${TMPDIR:-/tmp}/plugin-binding-e2e.XXXXXX")" && pwd -P)"
chmod 700 "$WORK"
LICENSE_PID=""
MARKET_PID=""
cleanup() {
  [ -n "$LICENSE_PID" ] && kill "$LICENSE_PID" 2>/dev/null || true
  [ -n "$MARKET_PID" ] && kill "$MARKET_PID" 2>/dev/null || true
  if [ "${PLUGIN_BINDING_E2E_KEEP:-}" = 1 ]; then echo "[binding-e2e] kept $WORK" >&2; else rm -rf "$WORK"; fi
}
trap cleanup EXIT

echo "[binding-e2e] building test binaries"
mkdir -p "$WORK/bin"
GOWORK=off go test -C "$ROOT/services/license-service" -c -o "$WORK/bin/license.test" ./internal/httpapi
GOWORK=off go test -C "$ROOT/services/market-service" -c -o "$WORK/bin/market.test" ./internal/httpapi

PLUGIN_BINDING_E2E_DIR="$WORK" LICENSE_TEST_DATABASE_URL="$PLUGIN_BINDING_E2E_LICENSE_DATABASE_URL" \
  "$WORK/bin/license.test" -test.run '^TestPluginBindingE2ELicense$' -test.count=1 -test.v -test.timeout 20m \
  >"$WORK/license.log" 2>&1 &
LICENSE_PID=$!
PLUGIN_BINDING_E2E_DIR="$WORK" MARKET_TEST_DATABASE_URL="$PLUGIN_BINDING_E2E_MARKET_DATABASE_URL" \
  "$WORK/bin/market.test" -test.run '^TestPluginBindingE2EMarket$' -test.count=1 -test.v -test.timeout 20m \
  >"$WORK/market.log" 2>&1 &
MARKET_PID=$!

set +e
# Either half failing early would leave the other waiting on a handoff file: stop it instead.
while kill -0 "$LICENSE_PID" 2>/dev/null && kill -0 "$MARKET_PID" 2>/dev/null; do sleep 1; done
if ! kill -0 "$MARKET_PID" 2>/dev/null; then
  wait "$MARKET_PID"; market=$?
  [ "$market" -ne 0 ] && kill "$LICENSE_PID" 2>/dev/null
  wait "$LICENSE_PID"; license=$?
else
  wait "$LICENSE_PID"; license=$?
  [ "$license" -ne 0 ] && kill "$MARKET_PID" 2>/dev/null
  wait "$MARKET_PID"; market=$?
fi
LICENSE_PID=""
MARKET_PID=""
set -e
grep -E '^(--- |PASS|FAIL|ok)|_test.go:[0-9]+' "$WORK/license.log" | sed 's/^/[license] /'
grep -E '^(--- |PASS|FAIL|ok)|_test.go:[0-9]+' "$WORK/market.log" | sed 's/^/[market] /'
if [ "$license" -ne 0 ] || [ "$market" -ne 0 ]; then
  echo "[binding-e2e] FAILED license=$license market=$market" >&2
  exit 1
fi
echo "[binding-e2e] PASS"
