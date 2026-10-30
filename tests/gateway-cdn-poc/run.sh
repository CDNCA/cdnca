#!/usr/bin/env bash
# ADR 0013 PoC: node <-> CDN-like L7 proxy (OpenResty, TLS terminated) <-> Gateway
# over the real agent.v1 Connect/StreamTelemetry bidirectional streams.
# Local only: one OpenResty container (--rm), two Gateway processes on the host.
# Run: tests/gateway-cdn-poc/run.sh
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
OUT=${OUT:-/tmp/gwpoc}
IMAGE=${IMAGE:-openresty/openresty:1.27.1.2-alpine}
CONTAINER=gwpoc-edge-$$
BIN=$OUT/gateway-cdn-poc
PIDS=()

cleanup() {
  for pid in "${PIDS[@]:-}"; do [ -n "$pid" ] && kill "$pid" 2>/dev/null || true; done
  docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

mkdir -p "$OUT"
rm -rf "$OUT/pki" "$OUT/web" "$OUT"/*.json "$OUT"/*.log
GOWORK=off go -C "$HERE" build -o "$BIN" .
"$BIN" pki -pki "$OUT/pki" >/dev/null
chmod 0644 "$OUT"/pki/*.pem   # container reads as its own user

start_gateway() { # name mtls grpc ws shared trusted
  "$BIN" gateway -pki "$OUT/pki" -name "$1" -mtls "$2" -grpc-origin "$3" -ws-origin "$4" -shared "${5:-}" -trusted "${6:-}" -stats "$OUT/$1-stats.json" >"$OUT/$1.log" 2>&1 &
  PIDS+=($!)
  eval "PID_$1=$!"
}
# gwa :8443 is the shared gateway port (direct gRPC mTLS + tunnel). The CDN
# container reaches it from 127.0.0.1 (Docker Desktop), so 127.0.0.1 is the
# trusted CDN back-to-origin range; direct nodes dial [::1] and stay untrusted.
start_gateway gwa 127.0.0.1:19444 0.0.0.0:19445 0.0.0.0:19446 :8443 127.0.0.1/32=X-Forwarded-For
start_gateway gwb 127.0.0.1:19447 "" ""
docker run -d --rm --name "$CONTAINER" --add-host host.docker.internal:host-gateway \
  -p 127.0.0.1:18443:18443 -p 127.0.0.1:18444:18444 -p 127.0.0.1:18445:18445 \
  -p 127.0.0.1:18453:8443 \
  -v "$OUT/pki:/pki:ro" -v "$HERE/nginx.conf:/usr/local/openresty/nginx/conf/nginx.conf:ro" \
  "$IMAGE" >/dev/null
# Control plane: serves node-install-defaults on the management name; the
# node is configured with --control-plane only.
"$BIN" control -pki "$OUT/pki" -listen 127.0.0.1:18460 -defaults "$OUT/defaults.json" >"$OUT/control.log" 2>&1 &
PIDS+=($!)
sleep 2

agent() { # label endpoints heartbeat total session [extra agent flags]
  echo "== $1"
  "$BIN" agent -pki "$OUT/pki" -endpoints "$2" -heartbeat "$3" -total "$4" -session "$5" -result "$OUT/$1.json" "${@:6}" 2>&1 | sed 's/^/   /'
}

agent s1-direct-mtls   "mtls=127.0.0.1:19444" 5s 32s 30s
agent s2-cdn-grpc      "grpc=127.0.0.1:18443" 5s 32s 30s
agent s3-cdn-websocket "ws=127.0.0.1:18444"   5s 32s 30s
agent s4-idle-over     "grpc=127.0.0.1:18445" 15s 40s 40s
agent s5-idle-under    "grpc=127.0.0.1:18445" 5s 32s 30s
agent s0-cdn-unsigned  "grpc-unsigned=127.0.0.1:18443" 5s 3s 3s

# Default shape: the gateway listens on its own port (8443 here; 19444 by
# default), the node only knows the control plane and reads the gateway
# address from node-install-defaults. s8: direct to that port (gRPC preferred,
# tunnel on the same port also checked); s9: a CDN with the gateway name in
# front, pulling from the same port 8443. The edge is published as 18453
# only because the gateway already holds 8443 on this single host.
defaults() { # address prefer
  printf '{"gateway_endpoints":[{"address":"%s","server_name":"gateway.poc.test","prefer":"%s"}]}\n' "$1" "$2" >"$OUT/defaults.json"
}
CONTROL=https://127.0.0.1:18460
defaults '[::1]:8443' grpc
agent s8a-shared-grpc   "" 5s 32s 30s -control "$CONTROL"
agent s8b-shared-tunnel "tunnel=[::1]:8443" 5s 32s 30s -label s8b -xff 203.0.113.9
agent s8c-shared-nocert "nocert=[::1]:8443" 5s 3s 3s
defaults 127.0.0.1:18453 tunnel
agent s9a-cdn-tunnel    "" 5s 32s 30s -control "$CONTROL" -label s9a -xff 203.0.113.9
defaults 127.0.0.1:18453 grpc
agent s9b-cdn-wrong-preference "" 5s 20s 18s -control "$CONTROL" -label s9b

echo "== s6-failover-cdn-blackhole (edge paused at ~12s, expect switch to gwb direct)"
( sleep 12; docker pause "$CONTAINER" >/dev/null; date +%s >"$OUT/s6-paused-at" ) &
PIDS+=($!)
"$BIN" agent -pki "$OUT/pki" -endpoints "grpc=127.0.0.1:18443,mtls=127.0.0.1:19447" -heartbeat 5s -total 45s -session 45s -result "$OUT/s6-failover.json" 2>&1 | sed 's/^/   /'
docker unpause "$CONTAINER" >/dev/null 2>&1 || true

echo "== s7-failover-gateway-killed (gwa killed at ~10s, expect switch to gwb)"
( sleep 10; kill "$PID_gwa"; date +%s >"$OUT/s7-killed-at" ) &
PIDS+=($!)
"$BIN" agent -pki "$OUT/pki" -endpoints "ws=127.0.0.1:18444,mtls=127.0.0.1:19447" -heartbeat 5s -total 30s -session 30s -result "$OUT/s7-failover.json" 2>&1 | sed 's/^/   /'

switch_gap() { # result-file event-file : seconds from the event to the next session start
  python3 - "$1" "$2" <<'PY'
import json, sys
sessions = json.load(open(sys.argv[1])); event = float(open(sys.argv[2]).read())
after = [s for s in sessions if s["started_unix"] > event and s["established"]]
print("   switch gap: %.1fs (event -> %s established)" % (after[0]["started_unix"] - event, after[0]["endpoint"]) if after else "   switch gap: no session after event")
PY
}
echo "== failover timings"
switch_gap "$OUT/s6-failover.json" "$OUT/s6-paused-at"
switch_gap "$OUT/s7-failover.json" "$OUT/s7-killed-at"

sleep 1
echo "== gateway stats"
cat "$OUT/gwa-stats.json"; echo
cat "$OUT/gwb-stats.json"; echo
echo "== shared-port real IP check (forged 203.0.113.9 must not become real_ip)"
if grep -q 'real_ip=203.0.113.9' "$OUT/gwa-stats.json"; then echo "   FAIL: forged X-Forwarded-For trusted"; else echo "   ok"; fi
echo "== gateway rejects"
grep -h reject "$OUT"/gw*.log | head -5 || true
