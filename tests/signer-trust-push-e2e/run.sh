#!/usr/bin/env bash
# Node signer trust push acceptance (签名密钥泄露吊销·节点侧推送):
#   authorization download origin -> control-api -> NATS -> agent-gateway -> edge-agent.
#
#   SIGNER_PUSH_E2E_DATABASE_URL=postgres://.../db tests/signer-trust-push-e2e/run.sh
#       the database needs the control-api role baseline (tests/postgres-integration/run.sh); without the
#       variable a throwaway PostgreSQL 17 container is started
#   SIGNER_PUSH_E2E_NATS_URL=nats://...   reuse a JetStream server; otherwise SIGNER_PUSH_E2E_NATS_SERVER (default
#       nats-server on PATH) is started locally, else a throwaway NATS container
#
# Operator: `signer-offline-root keygen` here, `sign-edge-trust` from the control half (production CLI).
# Process 1 (authority.go): stand-in for the license publication endpoint GET /public/v1/edge-signer-trust.
# Process 2 (control-api cmd/control-api TestSignerTrustPushControlProcess): production buildEdgeSignerTrustRuntime
#   (fetcher, PostgreSQL store, download refresh, capability-gated distributor over NATS).
# Process 3 (agent-gateway TestSignerTrustGatewayProcess): production Connect service + NATS signer trust bus.
# Process 4 (edge-agent cmd/edge-agent TestSignerTrustAgentAgainstControlProcess): production gateway client,
#   artifact trust store and persisted SignerTrustRuntime.
# Asserts: revoke -> pushed/applied/receipted and control download trust refreshed; no bundle for a node without
#   EDGE_SIGNER_TRUST; agent restart restores the revocation; push still arrives with deployments paused; rotation
#   with fingerprint revocation; origin rollback rejected by control and never reaches the node.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# Physical path: the edge-agent refuses trust files below a symlinked directory (macOS /var -> /private/var).
WORK="$(cd "$(mktemp -d "${TMPDIR:-/tmp}/signer-push-e2e.XXXXXX")" && pwd -P)"
chmod 700 "$WORK"
PIDS=()
CONTAINERS=()

cleanup() {
  for pid in ${PIDS[@]+"${PIDS[@]}"}; do kill "$pid" 2>/dev/null || true; done
  for container in ${CONTAINERS[@]+"${CONTAINERS[@]}"}; do docker rm -f "$container" >/dev/null 2>&1 || true; done
  if [ "${SIGNER_PUSH_E2E_KEEP:-}" = 1 ]; then echo "[signer-push-e2e] kept $WORK" >&2; else rm -rf "$WORK"; fi
}
trap cleanup EXIT

if [ -z "${SIGNER_PUSH_E2E_DATABASE_URL:-}" ]; then
  PORT="${SIGNER_PUSH_E2E_PG_PORT:-55692}"
  CONTAINERS+=("signer-push-e2e-pg-$$")
  docker run -d --rm --name "signer-push-e2e-pg-$$" -e POSTGRES_PASSWORD=pw -p "127.0.0.1:${PORT}:5432" \
    postgres:17.5-bookworm -c max_locks_per_transaction=4096 -c max_connections=300 >/dev/null
  for _ in $(seq 1 60); do
    docker exec "signer-push-e2e-pg-$$" pg_isready -U postgres -h 127.0.0.1 >/dev/null 2>&1 &&
      (exec 3<>"/dev/tcp/127.0.0.1/${PORT}") 2>/dev/null && break
    sleep 1
  done
  sleep 2
  docker exec -i "signer-push-e2e-pg-$$" psql -X -q -v ON_ERROR_STOP=1 -U postgres -d postgres <<'SQL'
CREATE ROLE cdnca_control_app NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
CREATE ROLE cdnca_plugin_webhook_runtime NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
CREATE ROLE cdnca_control_runtime NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
CREATE DATABASE signer_push_e2e TEMPLATE template0;
REVOKE CREATE ON DATABASE signer_push_e2e FROM PUBLIC;
REVOKE ALL ON DATABASE signer_push_e2e FROM cdnca_control_app, cdnca_plugin_webhook_runtime, cdnca_control_runtime;
SQL
  SIGNER_PUSH_E2E_DATABASE_URL="postgres://postgres:pw@127.0.0.1:${PORT}/signer_push_e2e?sslmode=disable"
fi

if [ -z "${SIGNER_PUSH_E2E_NATS_URL:-}" ]; then
  NATS_PORT="${SIGNER_PUSH_E2E_NATS_PORT:-54283}"
  NATS_SERVER="${SIGNER_PUSH_E2E_NATS_SERVER:-$(command -v nats-server || true)}"
  if [ -n "$NATS_SERVER" ]; then
    mkdir -p "$WORK/nats"
    "$NATS_SERVER" -js -sd "$WORK/nats" -a 127.0.0.1 -p "$NATS_PORT" >"$WORK/nats.log" 2>&1 &
    PIDS+=("$!")
  else
    CONTAINERS+=("signer-push-e2e-nats-$$")
    docker run -d --rm --name "signer-push-e2e-nats-$$" -p "127.0.0.1:${NATS_PORT}:4222" nats:2.11.9-alpine -js >/dev/null
  fi
  for _ in $(seq 1 30); do
    (exec 3<>"/dev/tcp/127.0.0.1/${NATS_PORT}") 2>/dev/null && break
    sleep 1
  done
  SIGNER_PUSH_E2E_NATS_URL="nats://127.0.0.1:${NATS_PORT}"
fi
export SIGNER_PUSH_E2E_DIR="$WORK" SIGNER_PUSH_E2E_NATS_URL

echo "[signer-push-e2e] building"
mkdir -p "$WORK/bin" "$WORK/root" "$WORK/downloads/edge-agent"
chmod 700 "$WORK/root"
GOWORK=off go build -C "$ROOT/services/license-service" -o "$WORK/bin/signer-offline-root" ./cmd/signer-offline-root
go test -C "$ROOT/services/control-api" -c -o "$WORK/bin/control.test" ./cmd/control-api
go test -C "$ROOT/services/agent-gateway" -c -o "$WORK/bin/gateway.test" .
go test -C "$ROOT/agents/edge-agent" -c -o "$WORK/bin/agent.test" ./cmd/edge-agent
go build -o "$WORK/bin/authority" "$ROOT/tests/signer-trust-push-e2e/authority.go"

echo "[signer-push-e2e] offline root keygen"
"$WORK/bin/signer-offline-root" keygen -key-id e2e-offline-root -generation 1 -out-dir "$WORK/root" >"$WORK/keygen.log"

echo "[signer-push-e2e] authority, gateway, agent"
"$WORK/bin/authority" "$WORK" >"$WORK/authority.log" 2>&1 &
PIDS+=("$!")
(cd "$ROOT/services/agent-gateway" && exec "$WORK/bin/gateway.test" -test.run '^TestSignerTrustGatewayProcess$' \
  -test.count=1 -test.v -test.timeout 30m) >"$WORK/gateway.log" 2>&1 &
GATEWAY_PID=$!
PIDS+=("$GATEWAY_PID")
(cd "$ROOT/agents/edge-agent/cmd/edge-agent" && exec "$WORK/bin/agent.test" -test.run '^TestSignerTrustAgentAgainstControlProcess$' \
  -test.count=1 -test.v -test.timeout 30m) >"$WORK/agent.log" 2>&1 &
AGENT_PID=$!
PIDS+=("$AGENT_PID")

echo "[signer-push-e2e] control-api"
set +e
(cd "$ROOT/services/control-api/cmd/control-api" && TEST_DATABASE_URL="$SIGNER_PUSH_E2E_DATABASE_URL" \
  SIGNER_PUSH_E2E_OFFLINE_TOOL="$WORK/bin/signer-offline-root" SIGNER_PUSH_E2E_ROOT_DIR="$WORK/root" \
  "$WORK/bin/control.test" -test.run '^TestSignerTrustPushControlProcess$' -test.count=1 -test.v -test.timeout 30m) \
  >"$WORK/control.log" 2>&1
control=$?
[ "$control" -ne 0 ] && kill "$AGENT_PID" "$GATEWAY_PID" 2>/dev/null
wait "$GATEWAY_PID"
gateway=$?
wait "$AGENT_PID"
agent=$?
set -e
grep -E 'PASS |^(--- |FAIL|ok)|_test.go:[0-9]+' "$WORK/control.log" | sed 's/^/[control] /'
grep -E '^(--- |FAIL|ok)|_test.go:[0-9]+' "$WORK/gateway.log" | sed 's/^/[gateway] /'
grep -E '^(--- |FAIL|ok)|_test.go:[0-9]+' "$WORK/agent.log" | sed 's/^/[agent] /'
grep -c 'GET /public/v1/edge-signer-trust' "$WORK/authority.log" | sed 's/^/[authority] document requests: /'
if [ "$control" -ne 0 ] || [ "$gateway" -ne 0 ] || [ "$agent" -ne 0 ]; then
  echo "[signer-push-e2e] FAILED control=$control gateway=$gateway agent=$agent" >&2
  exit 1
fi
echo "[signer-push-e2e] passed"
