#!/usr/bin/env bash
# Two-process signer revocation (签名密钥泄露吊销) acceptance: license-service <-> control-api.
#
#   tests/signer-revocation-e2e/run.sh              # starts a throwaway PostgreSQL 17 container
#   SIGNER_E2E_DATABASE_URL=postgres://.../db SIGNER_E2E_CONTROL_DATABASE_URL=postgres://.../db run.sh
#                                                   # reuse servers; the control database needs the
#                                                   # control-api role baseline (see pg-control-test.sh)
#
# Process 1 (license-service, internal/signercheckpointhttp): production draft -> approval -> publication of a
#   revocation for one lineage signing key (lease, policy, release), an offline-root-signed v2 checkpoint imported
#   through the production store, and the production installation checkpoint route over TLS. A mode file switches
#   it to "legacy" (404, no checkpoint route) or "outage" (503).
# Process 2 (control-api, internal/signerrevocationconsumer): production consumer with the gate installed on the
#   shared trust store. Asserts: legacy center -> startup ok and nothing rejected; checkpoint -> lease/policy/release
#   from the revoked key rejected while another key is accepted; outage -> LKG retained and audited; restart during
#   outage -> LKG restored from PostgreSQL and still enforced.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORK="$(cd "$(mktemp -d "${TMPDIR:-/tmp}/signer-e2e.XXXXXX")" && pwd -P)"
chmod 700 "$WORK"
CONTAINER=""
LICENSE_PID=""

cleanup() {
  [ -n "$LICENSE_PID" ] && kill "$LICENSE_PID" 2>/dev/null || true
  [ -n "$CONTAINER" ] && docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
  if [ "${SIGNER_E2E_KEEP:-}" = 1 ]; then echo "[signer-e2e] kept $WORK" >&2; else rm -rf "$WORK"; fi
}
trap cleanup EXIT

if [ -z "${SIGNER_E2E_DATABASE_URL:-}" ]; then
  PORT="${SIGNER_E2E_PG_PORT:-55691}"
  CONTAINER="signer-e2e-pg-$$"
  docker run -d --name "$CONTAINER" -e POSTGRES_USER=cdnca -e POSTGRES_PASSWORD=pw -e POSTGRES_DB=postgres \
    -p "127.0.0.1:${PORT}:5432" postgres:17.5-bookworm -c max_locks_per_transaction=1024 -c max_connections=300 >/dev/null
  for _ in $(seq 1 90); do
    docker exec "$CONTAINER" pg_isready -h 127.0.0.1 -U cdnca -d postgres >/dev/null 2>&1 &&
      (exec 3<>"/dev/tcp/127.0.0.1/${PORT}") 2>/dev/null && break
    sleep 1
  done
  sleep 2
  docker exec -i "$CONTAINER" psql -X -q -v ON_ERROR_STOP=1 -U cdnca -d postgres <<'SQL'
CREATE ROLE cdnca_control_app NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
CREATE ROLE cdnca_plugin_webhook_runtime NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
CREATE ROLE cdnca_control_runtime NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
CREATE DATABASE signer_e2e_license TEMPLATE template0;
CREATE DATABASE signer_e2e_control OWNER cdnca TEMPLATE template0;
REVOKE CREATE ON DATABASE signer_e2e_control FROM PUBLIC;
REVOKE ALL ON DATABASE signer_e2e_control FROM cdnca_control_app, cdnca_plugin_webhook_runtime, cdnca_control_runtime;
SQL
  SIGNER_E2E_DATABASE_URL="postgres://cdnca:pw@127.0.0.1:${PORT}/signer_e2e_license?sslmode=disable"
  SIGNER_E2E_CONTROL_DATABASE_URL="postgres://cdnca:pw@127.0.0.1:${PORT}/signer_e2e_control?sslmode=disable"
fi
SIGNER_E2E_CONTROL_DATABASE_URL="${SIGNER_E2E_CONTROL_DATABASE_URL:-$SIGNER_E2E_DATABASE_URL}"

echo "[signer-e2e] building test binaries"
mkdir -p "$WORK/bin"
GOWORK=off go test -C "$ROOT/services/license-service" -tags=integration -c -o "$WORK/bin/license.test" \
  ./internal/signercheckpointhttp
GOWORK=off go test -C "$ROOT/services/control-api" -tags=integration -c -o "$WORK/bin/control.test" \
  ./internal/signerrevocationconsumer

echo "[signer-e2e] license process"
(cd "$ROOT/services/license-service/internal/signercheckpointhttp" && SIGNER_REVOCATION_E2E_DIR="$WORK" \
  LICENSE_TEST_DATABASE_URL="$SIGNER_E2E_DATABASE_URL" "$WORK/bin/license.test" \
  -test.run '^TestSignerRevocationE2ELicenseFixture$' -test.count=1 -test.v -test.timeout 45m) \
  >"$WORK/license.log" 2>&1 &
LICENSE_PID=$!
for _ in $(seq 1 1200); do
  [ -f "$WORK/license.json" ] && break
  kill -0 "$LICENSE_PID" 2>/dev/null || break
  sleep 1
done
if [ ! -f "$WORK/license.json" ]; then
  grep -E '^(--- |FAIL|ok)|_test.go:[0-9]+' "$WORK/license.log" | sed 's/^/[license] /' >&2
  echo "[signer-e2e] license process did not become ready" >&2
  exit 1
fi

echo "[signer-e2e] control process"
control_status=0
(cd "$ROOT/services/control-api/internal/signerrevocationconsumer" && SIGNER_REVOCATION_E2E_DIR="$WORK" \
  TEST_DATABASE_URL="$SIGNER_E2E_CONTROL_DATABASE_URL" "$WORK/bin/control.test" \
  -test.run '^TestSignerRevocationE2EControlAgainstLicense$' -test.count=1 -test.v -test.timeout 45m) \
  >"$WORK/control.log" 2>&1 || control_status=$?
license_status=0
wait "$LICENSE_PID" || license_status=$?
LICENSE_PID=""

grep -E 'PASS |^(--- |FAIL|ok)|_test.go:[0-9]+' "$WORK/control.log" | sed 's/^/[control] /'
grep -E '^(--- |FAIL|ok)|_test.go:[0-9]+' "$WORK/license.log" | sed 's/^/[license] /'
if [ "$control_status" -ne 0 ] || [ "$license_status" -ne 0 ]; then
  echo "[signer-e2e] FAILED (control=$control_status license=$license_status)" >&2
  exit 1
fi
echo "[signer-e2e] passed"
