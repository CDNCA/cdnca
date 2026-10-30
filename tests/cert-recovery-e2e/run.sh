#!/usr/bin/env bash
# Expired node certificate self-recovery, three processes (ADR 0013 GW-02):
# control-api (ControlInternal, 2-minute node certificates) -> agent-gateway (Redis session coordinator, started,
# killed and restarted by the control half) -> edge-agent (node runtime image, OpenResty probed all along).
#
#   CERT_RECOVERY_E2E_DATABASE_URL=postgres://.../db tests/cert-recovery-e2e/run.sh
#       the database needs the control-api role baseline (tests/postgres-integration/run.sh);
#       without it a throwaway PostgreSQL 17 container is started
#   CERT_RECOVERY_E2E_REDIS=host:port   reuse a Redis server; otherwise redis-server on PATH is started locally
#   CDNCA_D13_IMAGE   node runtime image (default cdnca-native-runtime:edge-golden)
#
# Process 1 (control-api cmd/control-api TestCertRecoveryControlProcess, -tags integration,cdnca_e2e_short_cert_ttl,
#   CDNCA_E2E_NODE_CERTIFICATE_TTL=2m): openControlInternalRuntime, a pending platform node with an enrollment token.
# Process 2 (agent-gateway TestCertRecoveryGatewayProcess): enrollment + mTLS listeners, ControlInternal over mTLS,
#   NewRedisSessionCoordinator; a child of process 1.
# Process 3 (edge-agent cmd/edge-agent TestCertRecoveryAgentProcess, linux test binary in the node runtime image,
#   --rm --init, no privileges): enrollment.Run, switching mTLS dialer, renewer + recoverer, OpenResty.
# Asserts: ① gateway away until the certificate expired, back -> the node recovers with its own key and reconnects;
#   ② a recovery signed by another key is refused; ③ a revoked certificate is not recovered, the node keeps running;
#   OpenResty answers every probe. About 8 minutes.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
IMAGE="${CDNCA_D13_IMAGE:-cdnca-native-runtime:edge-golden}"
# Physical path: the agent refuses security files below a symlinked directory (macOS /var -> /private/var).
WORK="$(cd "$(mktemp -d "${TMPDIR:-/tmp}/cert-recovery-e2e.XXXXXX")" && pwd -P)"
chmod 755 "$WORK"
PIDS=()
CONTAINERS=()
AGENT_CONTAINER="cert-recovery-e2e-agent-$$"
ENROLLMENT_PORT="${CERT_RECOVERY_E2E_ENROLLMENT_PORT:-54391}"
MTLS_PORT="${CERT_RECOVERY_E2E_MTLS_PORT:-54392}"
AGENT_PORT="${CERT_RECOVERY_E2E_AGENT_PORT:-54393}"

cleanup() {
  for pid in ${PIDS[@]+"${PIDS[@]}"}; do kill "$pid" 2>/dev/null || true; done
  for container in ${CONTAINERS[@]+"${CONTAINERS[@]}"}; do docker rm -f "$container" >/dev/null 2>&1 || true; done
  # The gateway is the control half's child; kill a leftover one if the control half died.
  pkill -f "$WORK/bin/gateway.test" 2>/dev/null || true
  if [ "${CERT_RECOVERY_E2E_KEEP:-}" = 1 ]; then echo "[cert-recovery-e2e] kept $WORK" >&2; else rm -rf "$WORK"; fi
}
trap cleanup EXIT

docker image inspect "$IMAGE" >/dev/null 2>&1 || { echo "BLOCKED: $IMAGE missing" >&2; exit 69; }
case "$(docker image inspect "$IMAGE" --format '{{.Architecture}}')" in
  arm64|aarch64) GO_ARCH=arm64 ;;
  *) GO_ARCH=amd64 ;;
esac

if [ -z "${CERT_RECOVERY_E2E_DATABASE_URL:-}" ]; then
  PORT="${CERT_RECOVERY_E2E_PG_PORT:-55394}"
  CONTAINERS+=("cert-recovery-e2e-pg-$$")
  docker run -d --rm --name "cert-recovery-e2e-pg-$$" -e POSTGRES_PASSWORD=pw -p "127.0.0.1:${PORT}:5432" \
    postgres:17.5-bookworm -c max_locks_per_transaction=4096 -c max_connections=300 >/dev/null
  for _ in $(seq 1 60); do
    docker exec "cert-recovery-e2e-pg-$$" pg_isready -U postgres -h 127.0.0.1 >/dev/null 2>&1 &&
      (exec 3<>"/dev/tcp/127.0.0.1/${PORT}") 2>/dev/null && break
    sleep 1
  done
  sleep 2
  docker exec -i "cert-recovery-e2e-pg-$$" psql -X -q -v ON_ERROR_STOP=1 -U postgres -d postgres <<'SQL'
CREATE ROLE cdnca_control_app NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
CREATE ROLE cdnca_plugin_webhook_runtime NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
CREATE ROLE cdnca_control_runtime NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
CREATE DATABASE cert_recovery_e2e TEMPLATE template0;
REVOKE CREATE ON DATABASE cert_recovery_e2e FROM PUBLIC;
REVOKE ALL ON DATABASE cert_recovery_e2e FROM cdnca_control_app, cdnca_plugin_webhook_runtime, cdnca_control_runtime;
SQL
  CERT_RECOVERY_E2E_DATABASE_URL="postgres://postgres:pw@127.0.0.1:${PORT}/cert_recovery_e2e?sslmode=disable"
fi

if [ -z "${CERT_RECOVERY_E2E_REDIS:-}" ]; then
  REDIS_PORT="${CERT_RECOVERY_E2E_REDIS_PORT:-54394}"
  REDIS_SERVER="$(command -v redis-server || true)"
  [ -n "$REDIS_SERVER" ] || { echo "BLOCKED: redis-server not on PATH (or set CERT_RECOVERY_E2E_REDIS)" >&2; exit 69; }
  "$REDIS_SERVER" --port "$REDIS_PORT" --bind 127.0.0.1 --save '' --appendonly no >"$WORK/redis.log" 2>&1 &
  PIDS+=("$!")
  for _ in $(seq 1 30); do
    (exec 3<>"/dev/tcp/127.0.0.1/${REDIS_PORT}") 2>/dev/null && break
    sleep 0.2
  done
  CERT_RECOVERY_E2E_REDIS="127.0.0.1:${REDIS_PORT}"
fi

echo "[cert-recovery-e2e] building"
mkdir -p "$WORK/bin"
go test -C "$ROOT/services/control-api" -tags integration,cdnca_e2e_short_cert_ttl -c -o "$WORK/bin/control.test" ./cmd/control-api
GOWORK=off go test -C "$ROOT/services/agent-gateway" -c -o "$WORK/bin/gateway.test" .
GOWORK=off CGO_ENABLED=0 GOOS=linux GOARCH="$GO_ARCH" go test -C "$ROOT/agents/edge-agent" -c -o "$WORK/bin/agent.test" ./cmd/edge-agent
chmod -R a+rX "$WORK/bin"

echo "[cert-recovery-e2e] agent (container $IMAGE)"
# The work directory is mounted at the same path so the JSON files' paths resolve inside the container.
CONTAINERS+=("$AGENT_CONTAINER")
docker run --rm --init --name "$AGENT_CONTAINER" --add-host host.docker.internal:host-gateway \
  -p "127.0.0.1:${AGENT_PORT}:${AGENT_PORT}" -v "$WORK:$WORK" \
  -e CERT_RECOVERY_E2E_DIR="$WORK" -e CERT_RECOVERY_E2E_OPENRESTY=/usr/local/openresty/bin/openresty \
  -e CERT_RECOVERY_E2E_AGENT_LISTEN="0.0.0.0:${AGENT_PORT}" -e CERT_RECOVERY_E2E_GATEWAY_HOST=host.docker.internal \
  --entrypoint "$WORK/bin/agent.test" "$IMAGE" \
  -test.run '^TestCertRecoveryAgentProcess$' -test.count=1 -test.v -test.timeout 58m >"$WORK/agent.log" 2>&1 &
AGENT_PID=$!
PIDS+=("$AGENT_PID")

echo "[cert-recovery-e2e] control-api (starts the gateway)"
set +e
(cd "$ROOT/services/control-api/cmd/control-api" && TEST_DATABASE_URL="$CERT_RECOVERY_E2E_DATABASE_URL" \
  CDNCA_E2E_NODE_CERTIFICATE_TTL=2m CERT_RECOVERY_E2E_DIR="$WORK" CERT_RECOVERY_E2E_AGENT_URL="http://127.0.0.1:${AGENT_PORT}" \
  CERT_RECOVERY_E2E_GATEWAY_BIN="$WORK/bin/gateway.test" CERT_RECOVERY_E2E_REDIS="$CERT_RECOVERY_E2E_REDIS" \
  CERT_RECOVERY_E2E_ENROLLMENT_PORT="$ENROLLMENT_PORT" CERT_RECOVERY_E2E_MTLS_PORT="$MTLS_PORT" \
  "$WORK/bin/control.test" -test.run '^TestCertRecoveryControlProcess$' -test.count=1 -test.v -test.timeout 55m) \
  >"$WORK/control.log" 2>&1
control=$?
[ "$control" -ne 0 ] && docker stop -t 5 "$AGENT_CONTAINER" >/dev/null 2>&1
wait "$AGENT_PID"
agent=$?
set -e
grep -E 'PASS |^(--- |FAIL|ok)|_test.go:[0-9]+' "$WORK/control.log" | sed 's/^/[control] /'
for log in "$WORK"/gateway-*.log; do
  [ -f "$log" ] && grep -E '^(--- |FAIL|ok)|_test.go:[0-9]+|stream failed' "$log" | tail -5 | sed "s/^/[$(basename "$log" .log)] /"
done
grep -E '^(--- |FAIL|ok)|_test.go:[0-9]+|recover' "$WORK/agent.log" | tail -20 | sed 's/^/[agent] /'
if [ "$control" -ne 0 ] || [ "$agent" -ne 0 ]; then
  echo "[cert-recovery-e2e] FAILED control=$control agent=$agent (CERT_RECOVERY_E2E_KEEP=1 keeps $WORK)" >&2
  exit 1
fi
echo "[cert-recovery-e2e] passed"
