#!/usr/bin/env bash
# Plugin distribution acceptance: license service <-> control-api (<-> market-service).
#
#   tests/plugin-distribution-e2e/run.sh            # starts a throwaway PostgreSQL 17 container
#   PLUGIN_E2E_DATABASE_URL=postgres://... PLUGIN_E2E_CONTROL_DATABASE_URL=postgres://... run.sh
#                                                   # reuse servers (schemas are isolated per run); the control
#                                                   # database must have the control-api role baseline
#   PLUGIN_E2E_MARKET=0                             # skip the market process (example plugin two published by the
#                                                   # operator)
#
# Node plugins were removed in 1.0.35 (ADR 0007 §4.6, PA-03): there is no agent-gateway or edge-agent process.
#
# Process 1 (license-service, internal/httpapi): production license API + plugin runtime mTLS listener on a real
#   PostgreSQL schema; publishes and authorizes the example management plugin through the operator routes.
# Process 2 (control-api, cmd/control-api): production plugin installation + authorized webhook wiring against
#   process 1 over mTLS; installs, pauses/resumes, upgrades and uninstalls the plugin and checks receipts on both
#   sides; then confirms, upgrades and uninstalls example plugin two and checks its license-side receipts.
# Process 3 (market-service, internal/httpapi; PLUGIN_E2E_MARKET=1, the default): the plugin market publishes
#   example plugin two instead of the operator: publisher key with possession proof (re-checked by process 1 over
#   the /service/v1 mTLS listener), signed upload, scan conclusion, first-version review, signed catalog served over
#   HTTPS and verified by process 1, paid plan bought from the prepaid balance, licence projection that makes process
#   1 create the pending_confirmation authorization (confirmed by the controller administrator in process 2), and
#   1.1.0 for the upgrade.
#   PA-18: it also sells a developer rule pack (entrypoint rule_pack, free plan): uploaded with its content file,
#   compiled by the production review worker (developer layer, cost budget), reviewed (plugin.listing.review.*
#   audit), listed and fetched/re-checked by process 1 (plugin_data_packs); process 2 confirms the installation,
#   runs the production artifact catalog consumer against process 1 (rule_pack/<plugin> entry), gets a developer
#   local pack, enables it at platform level and publishes a site's security.mounts. Node enforcement is not part
#   of this run (site object security.mounts producer pending).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# Physical path: the edge-agent refuses trust files below a symlinked directory (macOS /var -> /private/var).
WORK="$(cd "$(mktemp -d "${TMPDIR:-/tmp}/plugin-e2e.XXXXXX")" && pwd -P)"
chmod 700 "$WORK"
CONTAINER=""
LICENSE_PID=""
MARKET_PID=""

cleanup() {
  [ -n "$LICENSE_PID" ] && kill "$LICENSE_PID" 2>/dev/null || true
  [ -n "$MARKET_PID" ] && kill "$MARKET_PID" 2>/dev/null || true
  [ -n "$CONTAINER" ] && docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
  if [ "${PLUGIN_E2E_KEEP:-}" = 1 ]; then echo "[plugin-e2e] kept $WORK" >&2; else rm -rf "$WORK"; fi
}
trap cleanup EXIT

if [ -z "${PLUGIN_E2E_DATABASE_URL:-}" ]; then
  PORT="${PLUGIN_E2E_PG_PORT:-55681}"
  CONTAINER="plugin-e2e-pg-$$"
  docker run -d --rm --name "$CONTAINER" -e POSTGRES_PASSWORD=pw -p "127.0.0.1:${PORT}:5432" \
    postgres:17.5-bookworm -c max_locks_per_transaction=4096 -c max_connections=300 >/dev/null
  # Ready only once the server answers on the published port (the entrypoint restarts postgres after init).
  for _ in $(seq 1 60); do
    docker exec "$CONTAINER" pg_isready -U postgres -h 127.0.0.1 >/dev/null 2>&1 &&
      (exec 3<>"/dev/tcp/127.0.0.1/${PORT}") 2>/dev/null && break
    sleep 1
  done
  sleep 2
  PLUGIN_E2E_DATABASE_URL="postgres://postgres:pw@127.0.0.1:${PORT}/postgres?sslmode=disable"
  # control-api migrations require the installer's NOLOGIN roles and a database without PUBLIC CREATE
  # (same baseline as scripts/install-control.sh setup_postgres).
  docker exec -i "$CONTAINER" psql -X -q -v ON_ERROR_STOP=1 -U postgres -d postgres <<'SQL'
CREATE ROLE cdnca_control_app NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
CREATE ROLE cdnca_plugin_webhook_runtime NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
CREATE ROLE cdnca_control_runtime NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
CREATE DATABASE plugin_e2e_control TEMPLATE template0;
REVOKE CREATE ON DATABASE plugin_e2e_control FROM PUBLIC;
REVOKE ALL ON DATABASE plugin_e2e_control FROM cdnca_control_app, cdnca_plugin_webhook_runtime;
\connect plugin_e2e_control
REVOKE ALL ON SCHEMA public FROM PUBLIC;
SQL
  PLUGIN_E2E_CONTROL_DATABASE_URL="postgres://postgres:pw@127.0.0.1:${PORT}/plugin_e2e_control?sslmode=disable"
fi
PLUGIN_E2E_CONTROL_DATABASE_URL="${PLUGIN_E2E_CONTROL_DATABASE_URL:-$PLUGIN_E2E_DATABASE_URL}"

PLUGIN_E2E_MARKET="${PLUGIN_E2E_MARKET:-1}"
export PLUGIN_E2E_MARKET

# Build first: compiling modules in parallel starves the license half's 30 second migration budget.
echo "[plugin-e2e] building test binaries"
mkdir -p "$WORK/bin"
GOWORK=off go test -C "$ROOT/services/license-service" -c -o "$WORK/bin/license.test" ./internal/httpapi
go test -C "$ROOT/services/control-api" -c -o "$WORK/bin/control.test" ./cmd/control-api
if [ "$PLUGIN_E2E_MARKET" = 1 ]; then
  GOWORK=off go test -C "$ROOT/services/market-service" -c -o "$WORK/bin/market.test" ./internal/httpapi
fi

echo "[plugin-e2e] license process"
(cd "$ROOT/services/license-service/internal/httpapi" && PLUGIN_E2E_DIR="$WORK" \
  LICENSE_TEST_DATABASE_URL="$PLUGIN_E2E_DATABASE_URL" LICENSE_TEST_MIGRATION_TIMEOUT=5m "$WORK/bin/license.test" \
  -test.run '^TestPluginDistributionLicenseFixture$' -test.count=1 -test.v -test.timeout 40m) \
  >"$WORK/license.log" 2>&1 &
LICENSE_PID=$!
if [ "$PLUGIN_E2E_MARKET" = 1 ]; then
  echo "[plugin-e2e] market-service process"
  (cd "$ROOT/services/market-service/internal/httpapi" && PLUGIN_E2E_DIR="$WORK" \
    MARKET_TEST_DATABASE_URL="$PLUGIN_E2E_DATABASE_URL" "$WORK/bin/market.test" \
    -test.run '^TestPluginMarketE2EProcess$' -test.count=1 -test.v -test.timeout 60m) \
    >"$WORK/market.log" 2>&1 &
  MARKET_PID=$!
fi
# The license half migrates its schema under a 30 second budget; start the control half after it is ready.
for _ in $(seq 1 1200); do
  [ -f "$WORK/license.json" ] && break
  kill -0 "$LICENSE_PID" 2>/dev/null || break
  sleep 1
done
if [ ! -f "$WORK/license.json" ]; then
  grep -E '^(--- |FAIL|ok)|_test.go:[0-9]+' "$WORK/license.log" | sed 's/^/[license] /' >&2
  [ -f "$WORK/market.log" ] && grep -E '^(--- |FAIL|ok)|_test.go:[0-9]+' "$WORK/market.log" | sed 's/^/[market] /' >&2
  echo "[plugin-e2e] license process did not become ready" >&2
  exit 1
fi

echo "[plugin-e2e] control-api process"
set +e
(cd "$ROOT/services/control-api/cmd/control-api" && PLUGIN_E2E_DIR="$WORK" \
  TEST_DATABASE_URL="$PLUGIN_E2E_CONTROL_DATABASE_URL" "$WORK/bin/control.test" \
  -test.run '^TestPluginDistributionControlAgainstLicenseProcess$' -test.count=1 -test.v -test.timeout 40m) \
  2>&1 | tee "$WORK/control.log" | grep -E '^(=== RUN|--- |PASS|FAIL|ok)|_test.go:[0-9]+'
control=${PIPESTATUS[0]}
# The control half signals its peers on success; on failure it may not, so stop them instead of waiting.
if [ "$control" -ne 0 ]; then
  kill "$LICENSE_PID" $MARKET_PID 2>/dev/null || true
fi
wait "$LICENSE_PID"
license=$?
LICENSE_PID=""
market=0
if [ -n "$MARKET_PID" ]; then
  wait "$MARKET_PID"
  market=$?
  MARKET_PID=""
fi
set -e
grep -E '^(--- |PASS|FAIL|ok)|_test.go:[0-9]+' "$WORK/license.log" | sed 's/^/[license] /'
[ -f "$WORK/market.log" ] && grep -E '^(--- |PASS|FAIL|ok)|_test.go:[0-9]+' "$WORK/market.log" | sed 's/^/[market] /'
if [ "$control" -ne 0 ] || [ "$license" -ne 0 ] || [ "$market" -ne 0 ]; then
  echo "[plugin-e2e] FAILED control=$control license=$license market=$market" >&2
  exit 1
fi
echo "[plugin-e2e] PASS"
