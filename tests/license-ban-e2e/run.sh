#!/usr/bin/env bash
# Installation ban end to end (ADR 0014 LIC-BAN-07): license service -> control-api -> NATS -> agent-gateway ->
# edge-agent in the node runtime image (real OpenResty, dynamic routing runtime).
#
#   tests/license-ban-e2e/run.sh        (about 10 minutes)
#   PG_NATIVE=<script>   native PostgreSQL helper (start <name> <port> / stop <name>); LICENSE_BAN_E2E_PG_PORT (56241)
#   CDNCA_D13_IMAGE   node runtime image (default cdnca-native-runtime:edge-golden)
#
# The processes are tests/dynroute-e2e/run.sh's (control half TestLicenseBanControlProcess) plus the license
# process (services/license-service/internal/httpapi TestLicenseBanLicenseProcess), started through
# DYNROUTE_E2E_PRESTART. One clock offset file ($WORK/clock-offset) is the injected clock of the license service,
# the control plane's installation ban runtime and the node's installation ban runtime.
#
# Scenarios (control half): ① ticket on the node, site 200; ② permanent ban: console writes 423
# installation_locked, node 503 fixed page; ③ lift: unlocked, node 200; ④ control plane offline, clock +30 days:
# node freezes (service_ticket_expired) and keeps serving 200; ⑤ back online: fresh ticket, node 200; ⑥ timed ban: Retry-After,
# clock past until: expiry worker lifts, node 200; ⑦ the node refuses a ban twice with persistence_failed: control
# keeps it retryable, redelivers the same revision after the backoff and records it applied, node 503 (adds
# about 3 minutes); ⑧ deposit loss automatic ban:
# the license seller default ban worker against a market stand-in bans the installation as the system (small-1035f F1).
#
# ADR 0014 §8 asks for two nodes (one online, one cut off). The gateway fixture has one node identity, so the cut
# off node is the same node with the control plane offline (④): the node path that decides is the same.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PG_NATIVE="${PG_NATIVE:-}"
PG_PORT="${LICENSE_BAN_E2E_PG_PORT:-56241}"
PG_NAME="license-ban-e2e-$$"
export PATH="/opt/homebrew/opt/postgresql@17/bin:$PATH"
pg_started=
cleanup() {
  [ -n "${LICENSE_BAN_E2E_LICENSE_PID:-}" ] && kill "$LICENSE_BAN_E2E_LICENSE_PID" 2>/dev/null || true
  [ -n "$pg_started" ] && "$PG_NATIVE" stop "$PG_NAME" >/dev/null 2>&1 || true
}
trap cleanup EXIT

if [ -z "${DYNROUTE_E2E_DATABASE_URL:-}" ] && [ -x "$PG_NATIVE" ]; then
  url=$("$PG_NATIVE" start "$PG_NAME" "$PG_PORT" | grep -o 'postgres://[^ ]*' | head -1)
  pg_started=1
  base=${url%/*}
  psql -X -q "$base/postgres" -c 'CREATE DATABASE license_ban_control TEMPLATE template0' \
    -c 'REVOKE CREATE ON DATABASE license_ban_control FROM PUBLIC' \
    -c 'REVOKE ALL ON DATABASE license_ban_control FROM cdnca_control_app, cdnca_plugin_webhook_runtime, cdnca_control_runtime' \
    -c 'CREATE DATABASE license_ban_license TEMPLATE template0'
  export DYNROUTE_E2E_DATABASE_URL="$base/license_ban_control?sslmode=disable"
  export LICENSE_BAN_E2E_LICENSE_DATABASE_URL="$base/license_ban_license?sslmode=disable"
fi
[ -n "${LICENSE_BAN_E2E_LICENSE_DATABASE_URL:-}" ] || { echo "LICENSE_BAN_E2E_LICENSE_DATABASE_URL is required" >&2; exit 2; }

export LICENSE_BAN_E2E=1 DYNROUTE_E2E_CONTROL_TEST=TestLicenseBanControlProcess
export DYNROUTE_E2E_PRESTART="$ROOT/tests/license-ban-e2e/prestart.sh" LICENSE_BAN_E2E_ROOT="$ROOT"
set +e
bash "$ROOT/tests/dynroute-e2e/run.sh"
status=$?
set -e
exit "$status"
