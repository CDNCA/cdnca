#!/usr/bin/env bash
# Version-skew acceptance between edge-agent and agent-gateway: every pairing of the released baseline and the
# candidate (working tree) must negotiate a session with edge upgrades enabled, so a node can always be upgraded or
# rolled back from the console no matter which side was upgraded first.
#
#   SKEW_BASE_REF=<released commit> tests/version-skew-e2e/run.sh   # baseline (required; the 1.0.35 release commit
#                                                                     # once it exists; nothing older is supported)
#   SKEW_PAIRS="old-new" ... run.sh                                  # gateway-agent pairs to run (default: all four)
#
# The baseline is extracted with git archive (agents/edge-agent, services/agent-gateway, libs/edgeconfig,
# proto/gen/go) into a throwaway directory. The harness tests (harness/) are added to both trees through
# `go test -overlay`, so neither the working tree nor the baseline commit is modified.
# Each pair runs two processes: the production Gateway Connect service (gateway half) and the production gateway
# client with the production capability set of its tree (agent half).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
HARNESS="$ROOT/tests/version-skew-e2e/harness"
BASE_REF="${SKEW_BASE_REF:?set SKEW_BASE_REF to the released baseline commit (1.0.35 or later)}"
PAIRS="${SKEW_PAIRS:-old-old old-new new-old new-new}"
# Physical path: the edge-agent refuses journal files below a symlinked directory (macOS /var -> /private/var).
WORK="$(cd "$(mktemp -d "${TMPDIR:-/tmp}/skew-e2e.XXXXXX")" && pwd -P)"
chmod 700 "$WORK"
PIDS=()
cleanup() {
  for pid in "${PIDS[@]:-}"; do [ -n "$pid" ] && kill "$pid" 2>/dev/null || true; done
  if [ "${SKEW_E2E_KEEP:-}" = 1 ]; then echo "[skew-e2e] kept $WORK" >&2; else chmod -R u+rwx "$WORK" 2>/dev/null; rm -rf "$WORK"; fi
}
trap cleanup EXIT

echo "[skew-e2e] baseline $BASE_REF ($(git -C "$ROOT" rev-parse --short "$BASE_REF"))"
mkdir -p "$WORK/old" "$WORK/bin"
git -C "$ROOT" archive "$BASE_REF" agents/edge-agent services/agent-gateway services/control-api libs/edgeconfig libs/entitlement proto/gen/go |
  tar -x -C "$WORK/old"

failed=0

overlay() { # overlay <tree> <out>
  printf '{"Replace":{"%s":"%s","%s":"%s"}}\n' \
    "$1/services/agent-gateway/skew_gateway_test.go" "$HARNESS/gateway/skew_gateway_test.go" \
    "$1/agents/edge-agent/cmd/edge-agent/skew_agent_test.go" "$HARNESS/agent/skew_agent_test.go" >"$2"
}
overlay "$WORK/old" "$WORK/overlay-old.json"
overlay "$ROOT" "$WORK/overlay-new.json"

AGENT_MAIN=github.com/cdnca/cdnca/agents/edge-agent/cmd/edge-agent
echo "[skew-e2e] building test binaries"
for side in old new; do
  tree="$ROOT"
  gowork=""
  if [ "$side" = old ]; then tree="$WORK/old"; gowork=off; fi
  GOWORK="$gowork" go test -C "$tree/services/agent-gateway" -tags versionskew -overlay "$WORK/overlay-$side.json" \
    -c -o "$WORK/bin/gateway-$side.test" .
  # Release builds stamp the version and build ID; without a build ID the Gateway cannot record session facts.
  GOWORK="$gowork" go test -C "$tree/agents/edge-agent" -tags versionskew -overlay "$WORK/overlay-$side.json" \
    -ldflags "-X $AGENT_MAIN.agentVersion=1.0.0-skew-$side -X $AGENT_MAIN.buildID=skew-$side" -c -o "$WORK/bin/agent-$side.test" ./cmd/edge-agent
done

for pair in $PAIRS; do
  gateway_side="${pair%-*}"
  agent_side="${pair#*-}"
  dir="$WORK/$pair"
  mkdir -m 700 "$dir"
  SKEW_E2E_DIR="$dir" "$WORK/bin/gateway-$gateway_side.test" -test.run '^TestVersionSkewGatewayProcess$' \
    -test.count=1 -test.v -test.timeout 10m >"$dir/gateway.log" 2>&1 &
  gateway_pid=$!
  PIDS+=("$gateway_pid")
  set +e
  SKEW_E2E_DIR="$dir" "$WORK/bin/agent-$agent_side.test" -test.run '^TestVersionSkewAgentProcess$' \
    -test.count=1 -test.v -test.timeout 10m >"$dir/agent.log" 2>&1
  agent=$?
  wait "$gateway_pid"
  gateway=$?
  set -e
  result="$(cat "$dir/agent-result.json" 2>/dev/null || echo '{}')"
  facts="$(cat "$dir/gateway-facts.json" 2>/dev/null || echo '[]')"
  if [ "$agent" -eq 0 ] && [ "$gateway" -eq 0 ]; then
    echo "[skew-e2e] PASS gateway=$gateway_side agent=$agent_side result=$result facts=$facts"
  else
    failed=1
    echo "[skew-e2e] FAIL gateway=$gateway_side agent=$agent_side (agent=$agent gateway=$gateway) result=$result facts=$facts" >&2
    grep -E '^(--- |FAIL)|_test.go:[0-9]+' "$dir/agent.log" | sed 's/^/[agent] /' >&2 || true
    grep -E '^(--- |FAIL)|_test.go:[0-9]+' "$dir/gateway.log" | sed 's/^/[gateway] /' >&2 || true
  fi
done

if [ "$failed" -ne 0 ]; then
  echo "[skew-e2e] FAILED" >&2
  exit 1
fi
echo "[skew-e2e] PASS"
