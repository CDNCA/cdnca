#!/usr/bin/env bash
# Dynamic routing three-process acceptance (D13-a3b ③, F1 S2): control-api -> NATS -> agent-gateway -> edge-agent
# (in the node runtime image) -> dynamic routing runtime serving requests.
#
#   DYNROUTE_E2E_DATABASE_URL=postgres://.../db tests/dynroute-e2e/run.sh
#       the database needs the control-api role baseline (tests/postgres-integration/run.sh);
#       without it a throwaway PostgreSQL 17 container is started
#   DYNROUTE_E2E_NATS_URL=nats://...   reuse a JetStream server; otherwise DYNROUTE_E2E_NATS_SERVER (default
#       nats-server on PATH) is started locally, else a throwaway NATS container
#   CDNCA_D13_IMAGE   node runtime image (default cdnca-native-runtime:edge-golden)
#   DYNROUTE_E2E_AGENT_OVERLAY / DYNROUTE_E2E_GATEWAY_OVERLAY  go build -overlay file for the agent / gateway test
#       binary (diagnosing or verifying a fix without editing the tree)
#   DYNROUTE_E2E_CONTROL_TEST   control half test (default TestDynRouteControlProcess; tests/telemetry-e2e runs
#       TestTelemetryControlProcess with DYNROUTE_E2E_TELEMETRY=1: node telemetry and gateway telemetry transport on)
#   DYNROUTE_E2E_SITE_DROP=1  攻击自动升级 D 级 step ④ after ①: control signs level D for shop (blackhole route) ->
#       NATS -> gateway site drop bus -> agent (daemon executor, OpenResty control socket) -> shop 444, blog 200,
#       receipt applied=true in escalate_site_drop_node_states; lifting restores shop
#   DYNROUTE_E2E_PRESTART   script sourced once the work directory and binaries exist, before the gateway and agent
#       start (tests/license-ban-e2e starts the license process there and exports DYNROUTE_E2E_INSTALLATION_ID; the
#       gateway then enables the installation ban bus and the agent the installation ban runtime)
#
# Process 1 (control-api cmd/control-api TestDynRouteControlProcess, -tags integration): production edgepublish
#   with a real node enrollment declaring site_runtime 9, rulepackcontrol mounts, artifactsetdist over artifactsync
#   (rule packs), edge outbox -> NATS, NATS -> edgestatus, ControlInternal over mTLS.
# Process 2 (agent-gateway TestDynRouteGatewayProcess): production Connect service and NATS command bus, listening
#   on every address for the container.
# Process 3 (edge-agent cmd/edge-agent TestDynRouteAgentProcess, linux test binary in the node runtime image,
#   --rm --init, no privileges): the daemon's dynamic routing wiring and the production gateway client.
# Asserts: ① two v9 sites 200, unknown host refused; ② a mount whose pack is not on the node is refused by the agent
#   precheck and the previous release keeps serving; ③ the pack arrives in the node artifact set, the release
#   applies, rule r020 blocks /wp-admin/ on the mounted site only, and switching the mount off lets it through.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
IMAGE="${CDNCA_D13_IMAGE:-cdnca-native-runtime:edge-golden}"
# Physical path: the edge-agent refuses trust files below a symlinked directory (macOS /var -> /private/var).
WORK="$(cd "$(mktemp -d "${TMPDIR:-/tmp}/dynroute-e2e.XXXXXX")" && pwd -P)"
chmod 755 "$WORK"
PIDS=()
CONTAINERS=()
AGENT_CONTAINER="dynroute-e2e-agent-$$"

cleanup() {
  for pid in ${PIDS[@]+"${PIDS[@]}"}; do kill "$pid" 2>/dev/null || true; done
  for container in ${CONTAINERS[@]+"${CONTAINERS[@]}"}; do docker rm -f "$container" >/dev/null 2>&1 || true; done
  if [ "${DYNROUTE_E2E_KEEP:-}" = 1 ]; then echo "[dynroute-e2e] kept $WORK" >&2; else rm -rf "$WORK"; fi
}
trap cleanup EXIT

docker image inspect "$IMAGE" >/dev/null 2>&1 || { echo "BLOCKED: $IMAGE missing" >&2; exit 69; }
case "$(docker image inspect "$IMAGE" --format '{{.Architecture}}')" in
  arm64|aarch64) GO_ARCH=arm64 ;;
  *) GO_ARCH=amd64 ;;
esac

if [ -z "${DYNROUTE_E2E_DATABASE_URL:-}" ]; then
  PORT="${DYNROUTE_E2E_PG_PORT:-55694}"
  CONTAINERS+=("dynroute-e2e-pg-$$")
  docker run -d --rm --name "dynroute-e2e-pg-$$" -e POSTGRES_PASSWORD=pw -p "127.0.0.1:${PORT}:5432" \
    postgres:17.5-bookworm -c max_locks_per_transaction=4096 -c max_connections=300 >/dev/null
  for _ in $(seq 1 60); do
    docker exec "dynroute-e2e-pg-$$" pg_isready -U postgres -h 127.0.0.1 >/dev/null 2>&1 &&
      (exec 3<>"/dev/tcp/127.0.0.1/${PORT}") 2>/dev/null && break
    sleep 1
  done
  sleep 2
  docker exec -i "dynroute-e2e-pg-$$" psql -X -q -v ON_ERROR_STOP=1 -U postgres -d postgres <<'SQL'
CREATE ROLE cdnca_control_app NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
CREATE ROLE cdnca_plugin_webhook_runtime NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
CREATE ROLE cdnca_control_runtime NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
CREATE DATABASE dynroute_e2e TEMPLATE template0;
REVOKE CREATE ON DATABASE dynroute_e2e FROM PUBLIC;
REVOKE ALL ON DATABASE dynroute_e2e FROM cdnca_control_app, cdnca_plugin_webhook_runtime, cdnca_control_runtime;
SQL
  DYNROUTE_E2E_DATABASE_URL="postgres://postgres:pw@127.0.0.1:${PORT}/dynroute_e2e?sslmode=disable"
fi

if [ -z "${DYNROUTE_E2E_NATS_URL:-}" ]; then
  NATS_PORT="${DYNROUTE_E2E_NATS_PORT:-54285}"
  NATS_SERVER="${DYNROUTE_E2E_NATS_SERVER:-$(command -v nats-server || true)}"
  if [ -n "$NATS_SERVER" ]; then
    mkdir -p "$WORK/nats"
    "$NATS_SERVER" -js -sd "$WORK/nats" -a 127.0.0.1 -p "$NATS_PORT" >"$WORK/nats.log" 2>&1 &
    PIDS+=("$!")
  else
    CONTAINERS+=("dynroute-e2e-nats-$$")
    docker run -d --rm --name "dynroute-e2e-nats-$$" -p "127.0.0.1:${NATS_PORT}:4222" nats:2.11.9-alpine -js >/dev/null
  fi
  for _ in $(seq 1 30); do
    (exec 3<>"/dev/tcp/127.0.0.1/${NATS_PORT}") 2>/dev/null && break
    sleep 1
  done
  DYNROUTE_E2E_NATS_URL="nats://127.0.0.1:${NATS_PORT}"
fi
AGENT_PORT="${DYNROUTE_E2E_AGENT_PORT:-54286}"
export DYNROUTE_E2E_DIR="$WORK" DYNROUTE_E2E_NATS_URL

echo "[dynroute-e2e] building"
mkdir -p "$WORK/bin" "$WORK/lua"
go test -C "$ROOT/services/control-api" -tags integration -c -o "$WORK/bin/control.test" ./cmd/control-api
go test -C "$ROOT/services/agent-gateway" -c ${DYNROUTE_E2E_GATEWAY_OVERLAY:+-overlay "$DYNROUTE_E2E_GATEWAY_OVERLAY"} -o "$WORK/bin/gateway.test" .
GOWORK=off CGO_ENABLED=0 GOOS=linux GOARCH="$GO_ARCH" go test -C "$ROOT/agents/edge-agent" -c ${DYNROUTE_E2E_AGENT_OVERLAY:+-overlay "$DYNROUTE_E2E_AGENT_OVERLAY"} \
  -o "$WORK/bin/agent.test" ./cmd/edge-agent
# The node Lua tree as the runtime image installs it (tests/dynroute-agent/run.sh).
grep -E '^COPY edge/openresty/[^ ]+ /usr/local/share/cdnca/' "$ROOT/edge/openresty/native/Dockerfile" |
  while read -r _ source target; do
    mkdir -p "$WORK/lua$(dirname "${target#/usr/local/share/cdnca}")"
    cp "$ROOT/$source" "$WORK/lua${target#/usr/local/share/cdnca}"
  done
chmod -R a+rX "$WORK/bin" "$WORK/lua"

if [ -n "${DYNROUTE_E2E_PRESTART:-}" ]; then
  # shellcheck source=/dev/null
  . "$DYNROUTE_E2E_PRESTART"
fi
DYNROUTE_E2E_INSTALLATION_BAN=
if [ -n "${DYNROUTE_E2E_INSTALLATION_ID:-}" ]; then DYNROUTE_E2E_INSTALLATION_BAN=1; fi

echo "[dynroute-e2e] gateway"
(cd "$ROOT/services/agent-gateway" && DYNROUTE_E2E_INSTALLATION_BAN="$DYNROUTE_E2E_INSTALLATION_BAN" DYNROUTE_E2E_TELEMETRY="${DYNROUTE_E2E_TELEMETRY:-}" DYNROUTE_E2E_SITE_DROP="${DYNROUTE_E2E_SITE_DROP:-}" DYNROUTE_E2E_GATEWAY_LISTEN="${DYNROUTE_E2E_GATEWAY_LISTEN:-127.0.0.1:0}" exec "$WORK/bin/gateway.test" -test.run '^TestDynRouteGatewayProcess$' \
  -test.count=1 -test.v -test.timeout 45m) >"$WORK/gateway.log" 2>&1 &
GATEWAY_PID=$!
PIDS+=("$GATEWAY_PID")

echo "[dynroute-e2e] agent (container $IMAGE)"
# No privileges, no systemd: the agent test binary is PID 1's child under --init. The work directory is mounted at
# the same path so the JSON files' paths resolve inside the container.
CONTAINERS+=("$AGENT_CONTAINER")
docker run --rm --init --name "$AGENT_CONTAINER" --add-host host.docker.internal:host-gateway \
  -p "127.0.0.1:${AGENT_PORT}:${AGENT_PORT}" --tmpfs /run/cdnca:mode=0755 \
  -v "$WORK:$WORK" -v "$WORK/lua:/usr/local/share/cdnca:ro" \
  -e DYNROUTE_E2E_DIR="$WORK" -e DYNROUTE_E2E_STATE=/var/lib/dynroute-e2e -e DYNROUTE_E2E_TELEMETRY="${DYNROUTE_E2E_TELEMETRY:-}" \
  -e DYNROUTE_E2E_INSTALLATION_ID="${DYNROUTE_E2E_INSTALLATION_ID:-}" -e DYNROUTE_E2E_SITE_DROP="${DYNROUTE_E2E_SITE_DROP:-}" \
  -e DYNROUTE_E2E_OPENRESTY=/usr/local/openresty/bin/openresty \
  -e DYNROUTE_E2E_AGENT_LISTEN="0.0.0.0:${AGENT_PORT}" -e DYNROUTE_E2E_GATEWAY_HOST=host.docker.internal \
  --entrypoint "$WORK/bin/agent.test" "$IMAGE" \
  -test.run '^TestDynRouteAgentProcess$' -test.count=1 -test.v -test.timeout 45m >"$WORK/agent.log" 2>&1 &
AGENT_PID=$!
PIDS+=("$AGENT_PID")

echo "[dynroute-e2e] control-api"
set +e
(cd "$ROOT/services/control-api/cmd/control-api" && TEST_DATABASE_URL="$DYNROUTE_E2E_DATABASE_URL" \
  LICENSE_BAN_E2E="${LICENSE_BAN_E2E:-}" DYNROUTE_E2E_SITE_DROP="${DYNROUTE_E2E_SITE_DROP:-}" \
  DYNROUTE_E2E_AGENT_URL="http://127.0.0.1:${AGENT_PORT}" DYNROUTE_E2E_DEBUG="${DYNROUTE_E2E_DEBUG:-}" DYNROUTE_E2E_HOLD="${DYNROUTE_E2E_HOLD:-}" \
  TELEMETRY_E2E_CLICKHOUSE_URL="${TELEMETRY_E2E_CLICKHOUSE_URL:-}" TELEMETRY_E2E_OFFLINE="${TELEMETRY_E2E_OFFLINE:-}" \
  "$WORK/bin/control.test" -test.run "^${DYNROUTE_E2E_CONTROL_TEST:-TestDynRouteControlProcess}\$" -test.count=1 -test.v -test.timeout 45m) \
  >"$WORK/control.log" 2>&1
control=$?
if [ "$control" -ne 0 ]; then
  kill "$GATEWAY_PID" 2>/dev/null
  docker stop -t 5 "$AGENT_CONTAINER" >/dev/null 2>&1
fi
wait "$GATEWAY_PID"
gateway=$?
wait "$AGENT_PID"
agent=$?
license=0
if [ -n "${LICENSE_BAN_E2E_LICENSE_PID:-}" ]; then
  [ "$control" -ne 0 ] && kill "$LICENSE_BAN_E2E_LICENSE_PID" 2>/dev/null
  wait "$LICENSE_BAN_E2E_LICENSE_PID"
  license=$?
fi
set -e
grep -E 'PASS |^(--- |FAIL|ok)|_test.go:[0-9]+' "$WORK/control.log" | sed 's/^/[control] /'
grep -E '^(--- |FAIL|ok)|_test.go:[0-9]+' "$WORK/gateway.log" | sed 's/^/[gateway] /'
grep -E '^(--- |FAIL|ok)|_test.go:[0-9]+' "$WORK/agent.log" | sed 's/^/[agent] /'
[ -f "$WORK/license.log" ] && grep -E '^(--- |FAIL|ok)|_test.go:[0-9]+' "$WORK/license.log" | sed 's/^/[license] /'
if [ "$control" -ne 0 ] || [ "$gateway" -ne 0 ] || [ "$agent" -ne 0 ] || [ "$license" -ne 0 ]; then
  echo "[dynroute-e2e] FAILED control=$control gateway=$gateway agent=$agent license=$license (DYNROUTE_E2E_KEEP=1 keeps $WORK)" >&2
  exit 1
fi
echo "[dynroute-e2e] passed"
