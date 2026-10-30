#!/usr/bin/env bash
# Node artifact set acceptance (PA-01, ADR 0007 section 4.3): control-api -> NATS -> agent-gateway -> edge-agent.
#
#   ARTIFACT_SET_E2E_DATABASE_URL=postgres://.../db tests/artifact-set-e2e/run.sh
#       the database needs the control-api role baseline (tests/postgres-integration/run.sh); without the
#       variable a throwaway PostgreSQL 17 container is started
#   ARTIFACT_SET_E2E_NATS_URL=nats://...   reuse a JetStream server; otherwise ARTIFACT_SET_E2E_NATS_SERVER (default
#       nats-server on PATH) is started locally, else a throwaway NATS container
#
# Process 1 (control-api cmd/control-api TestArtifactSetControlProcess): production artifactsetdist distributor fed
#   by the verified IP library (ipintelsync store), edge outbox -> NATS, NATS -> edgestatus (receipts, applied items,
#   audit), production ControlInternal service with the production artifact store over mTLS, publication gate.
# Process 2 (agent-gateway TestArtifactSetGatewayProcess): production Connect service, NATS command bus and generated
#   ControlInternal client over mTLS.
# Process 3 (edge-agent cmd/edge-agent TestArtifactSetAgentAgainstControlProcess): production gateway client, trust
#   store and node artifact set runtime (object store, executor, IP library installer, wafengine module installer).
# Asserts: a node without a library is refused carrier rules naming it; library 1 is delivered, installed, IP_INTEL v2
#   declared and the gate opens; library 2 with a segment altered on the node is rejected (segment_mismatch) and the
#   node keeps library 1; after RetryAfter the segments are resent and library 2 applies; an OWASP CRS engine module
#   signed by an untrusted key is refused by the agent's wafengine installer (signature_invalid, nothing installed),
#   the platform-signed build of the node's platform (not the arm64 one) is installed; audit events recorded
#   (node.artifact_set.*, node.engine_module.install_reject / install).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# Physical path: the edge-agent refuses trust files below a symlinked directory (macOS /var -> /private/var).
WORK="$(cd "$(mktemp -d "${TMPDIR:-/tmp}/artifact-set-e2e.XXXXXX")" && pwd -P)"
chmod 700 "$WORK"
PIDS=()
CONTAINERS=()

cleanup() {
  for pid in ${PIDS[@]+"${PIDS[@]}"}; do kill "$pid" 2>/dev/null || true; done
  for container in ${CONTAINERS[@]+"${CONTAINERS[@]}"}; do docker rm -f "$container" >/dev/null 2>&1 || true; done
  if [ "${ARTIFACT_SET_E2E_KEEP:-}" = 1 ]; then echo "[artifact-set-e2e] kept $WORK" >&2; else rm -rf "$WORK"; fi
}
trap cleanup EXIT

if [ -z "${ARTIFACT_SET_E2E_DATABASE_URL:-}" ]; then
  PORT="${ARTIFACT_SET_E2E_PG_PORT:-55693}"
  CONTAINERS+=("artifact-set-e2e-pg-$$")
  docker run -d --rm --name "artifact-set-e2e-pg-$$" -e POSTGRES_PASSWORD=pw -p "127.0.0.1:${PORT}:5432" \
    postgres:17.5-bookworm -c max_locks_per_transaction=4096 -c max_connections=300 >/dev/null
  for _ in $(seq 1 60); do
    docker exec "artifact-set-e2e-pg-$$" pg_isready -U postgres -h 127.0.0.1 >/dev/null 2>&1 &&
      (exec 3<>"/dev/tcp/127.0.0.1/${PORT}") 2>/dev/null && break
    sleep 1
  done
  sleep 2
  docker exec -i "artifact-set-e2e-pg-$$" psql -X -q -v ON_ERROR_STOP=1 -U postgres -d postgres <<'SQL'
CREATE ROLE cdnca_control_app NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
CREATE ROLE cdnca_plugin_webhook_runtime NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
CREATE ROLE cdnca_control_runtime NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
CREATE DATABASE artifact_set_e2e TEMPLATE template0;
REVOKE CREATE ON DATABASE artifact_set_e2e FROM PUBLIC;
REVOKE ALL ON DATABASE artifact_set_e2e FROM cdnca_control_app, cdnca_plugin_webhook_runtime, cdnca_control_runtime;
SQL
  ARTIFACT_SET_E2E_DATABASE_URL="postgres://postgres:pw@127.0.0.1:${PORT}/artifact_set_e2e?sslmode=disable"
fi

if [ -z "${ARTIFACT_SET_E2E_NATS_URL:-}" ]; then
  NATS_PORT="${ARTIFACT_SET_E2E_NATS_PORT:-54284}"
  NATS_SERVER="${ARTIFACT_SET_E2E_NATS_SERVER:-$(command -v nats-server || true)}"
  if [ -n "$NATS_SERVER" ]; then
    mkdir -p "$WORK/nats"
    "$NATS_SERVER" -js -sd "$WORK/nats" -a 127.0.0.1 -p "$NATS_PORT" >"$WORK/nats.log" 2>&1 &
    PIDS+=("$!")
  else
    CONTAINERS+=("artifact-set-e2e-nats-$$")
    docker run -d --rm --name "artifact-set-e2e-nats-$$" -p "127.0.0.1:${NATS_PORT}:4222" nats:2.11.9-alpine -js >/dev/null
  fi
  for _ in $(seq 1 30); do
    (exec 3<>"/dev/tcp/127.0.0.1/${NATS_PORT}") 2>/dev/null && break
    sleep 1
  done
  ARTIFACT_SET_E2E_NATS_URL="nats://127.0.0.1:${NATS_PORT}"
fi
export ARTIFACT_SET_E2E_DIR="$WORK" ARTIFACT_SET_E2E_NATS_URL

echo "[artifact-set-e2e] building"
mkdir -p "$WORK/bin"
go test -C "$ROOT/services/control-api" -c -o "$WORK/bin/control.test" ./cmd/control-api
go test -C "$ROOT/services/agent-gateway" -c -o "$WORK/bin/gateway.test" .
go test -C "$ROOT/agents/edge-agent" -c -o "$WORK/bin/agent.test" ./cmd/edge-agent

echo "[artifact-set-e2e] gateway, agent"
(cd "$ROOT/services/agent-gateway" && exec "$WORK/bin/gateway.test" -test.run '^TestArtifactSetGatewayProcess$' \
  -test.count=1 -test.v -test.timeout 30m) >"$WORK/gateway.log" 2>&1 &
GATEWAY_PID=$!
PIDS+=("$GATEWAY_PID")
(cd "$ROOT/agents/edge-agent/cmd/edge-agent" && exec "$WORK/bin/agent.test" -test.run '^TestArtifactSetAgentAgainstControlProcess$' \
  -test.count=1 -test.v -test.timeout 30m) >"$WORK/agent.log" 2>&1 &
AGENT_PID=$!
PIDS+=("$AGENT_PID")

echo "[artifact-set-e2e] control-api"
set +e
(cd "$ROOT/services/control-api/cmd/control-api" && TEST_DATABASE_URL="$ARTIFACT_SET_E2E_DATABASE_URL" \
  "$WORK/bin/control.test" -test.run '^TestArtifactSetControlProcess$' -test.count=1 -test.v -test.timeout 30m) \
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
if [ "$control" -ne 0 ] || [ "$gateway" -ne 0 ] || [ "$agent" -ne 0 ]; then
  echo "[artifact-set-e2e] FAILED control=$control gateway=$gateway agent=$agent" >&2
  exit 1
fi
echo "[artifact-set-e2e] passed"
