#!/usr/bin/env bash
# GW-03 three-process e2e (ADR 0013 §4.2): node -> OpenResty "CDN" (own edge
# certificate, WebSocket back to origin) -> Gateway shared port.
#   gateway.test  TestGatewayCDNProcess  (services/agent-gateway)
#   OpenResty     docker --rm, removed on exit
#   agent.test    TestGatewayCDNAgentProcess (agents/edge-agent/cmd/edge-agent)
# Checks: session + heartbeats through the CDN, node address from the CDN
# header (trusted range = the CDN's back-to-origin address), automatic
# reconnect after the CDN restarts.
# Run: tests/gateway-cdn-e2e/run.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
HERE="$ROOT/tests/gateway-cdn-e2e"
WORK="$(cd "$(mktemp -d "${TMPDIR:-/tmp}/gateway-cdn-e2e.XXXXXX")" && pwd -P)"
chmod 700 "$WORK"
IMAGE=${GATEWAY_CDN_E2E_IMAGE:-openresty/openresty:1.27.1.2-alpine}
CDN_PORT=${GATEWAY_CDN_E2E_PORT:-18643}
CONTAINER=gateway-cdn-e2e-$$
PIDS=()
cleanup() {
  for pid in ${PIDS[@]+"${PIDS[@]}"}; do kill "$pid" 2>/dev/null || true; done
  docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
  if [ "${GATEWAY_CDN_E2E_KEEP:-}" = 1 ]; then echo "[gateway-cdn-e2e] kept $WORK" >&2; else rm -rf "$WORK"; fi
}
trap cleanup EXIT

echo "[gateway-cdn-e2e] building"
mkdir -p "$WORK/bin" "$WORK/cdn"
chmod 755 "$WORK/cdn"
go test -C "$ROOT/services/agent-gateway" -c -o "$WORK/bin/gateway.test" .
go test -C "$ROOT/agents/edge-agent" -c -o "$WORK/bin/agent.test" ./cmd/edge-agent

# Docker Desktop: the container reaches the host as host.docker.internal and
# the host sees its connections from the VM gateway. Trust every private
# range for X-Real-IP (only the CDN reaches the gateway in this test; the
# node dials the CDN on 127.0.0.1, so a direct node would never be trusted).
TRUSTED="127.0.0.0/8=X-Real-IP,10.0.0.0/8=X-Real-IP,172.16.0.0/12=X-Real-IP,192.168.0.0/16=X-Real-IP,::1/128=X-Real-IP,fd00::/8=X-Real-IP"
export GATEWAY_CDN_E2E_DIR="$WORK" GATEWAY_CDN_E2E_TRUSTED="$TRUSTED" GATEWAY_CDN_E2E_ADDRESS="127.0.0.1:${CDN_PORT}"

echo "[gateway-cdn-e2e] gateway"
(cd "$ROOT/services/agent-gateway" && exec "$WORK/bin/gateway.test" -test.run '^TestGatewayCDNProcess$' \
  -test.count=1 -test.v -test.timeout 12m) >"$WORK/gateway.log" 2>&1 &
GATEWAY_PID=$!
PIDS+=("$GATEWAY_PID")
for _ in $(seq 1 120); do [ -f "$WORK/gateway.json" ] && break; sleep 0.5; done
[ -f "$WORK/gateway.json" ] || { tail -20 "$WORK/gateway.log"; exit 1; }
PORT=$(sed -E 's/.*"gateway_port":([0-9]+).*/\1/' "$WORK/gateway.json")
sed "s/__GATEWAY_PORT__/${PORT}/" "$HERE/nginx.conf.template" >"$WORK/cdn/nginx.conf"
chmod 0644 "$WORK"/cdn/*

echo "[gateway-cdn-e2e] CDN (OpenResty ${IMAGE}) 127.0.0.1:${CDN_PORT} -> gateway :${PORT}"
docker run -d --rm --name "$CONTAINER" --add-host host.docker.internal:host-gateway \
  -p "127.0.0.1:${CDN_PORT}:8443" -v "$WORK/cdn:/cdn:ro" \
  -v "$WORK/cdn/nginx.conf:/usr/local/openresty/nginx/conf/nginx.conf:ro" "$IMAGE" >/dev/null
for _ in $(seq 1 30); do (exec 3<>"/dev/tcp/127.0.0.1/${CDN_PORT}") 2>/dev/null && break; sleep 0.5; done

echo "[gateway-cdn-e2e] agent"
(cd "$ROOT/agents/edge-agent/cmd/edge-agent" && exec "$WORK/bin/agent.test" -test.run '^TestGatewayCDNAgentProcess$' \
  -test.count=1 -test.v -test.timeout 10m) >"$WORK/agent.log" 2>&1 &
AGENT_PID=$!
PIDS+=("$AGENT_PID")
for _ in $(seq 1 240); do
  [ -f "$WORK/phase1-done" ] && break
  kill -0 "$AGENT_PID" 2>/dev/null || break
  sleep 0.5
done
if [ -f "$WORK/phase1-done" ]; then
  echo "[gateway-cdn-e2e] phase 1 ok; restarting the CDN"
  docker restart -t 1 "$CONTAINER" >/dev/null
  touch "$WORK/cdn-restarted"
fi
set +e
wait "$AGENT_PID"; agent=$?
touch "$WORK/finished"
wait "$GATEWAY_PID"; gateway=$?
set -e
echo "[gateway-cdn-e2e] sessions: $(cat "$WORK/sessions.json" 2>/dev/null)"
grep -E -- '--- (PASS|FAIL)|phase [12]:|_test.go:[0-9]+:' "$WORK/agent.log" "$WORK/gateway.log" | head -20
if [ "$agent" -ne 0 ] || [ "$gateway" -ne 0 ]; then
  echo "[gateway-cdn-e2e] FAIL agent=$agent gateway=$gateway" >&2
  docker logs --tail 20 "$CONTAINER" 2>&1 | tail -20 >&2 || true
  exit 1
fi
echo "[gateway-cdn-e2e] PASS"
