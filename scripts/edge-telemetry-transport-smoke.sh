#!/usr/bin/env bash
set -euo pipefail

umask 077

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
edge_dir="${repo_root}/agents/edge-agent"
gateway_dir="${repo_root}/services/agent-gateway"
nats_url=${CDNCA_EDGE_TELEMETRY_SMOKE_NATS_URL:-}
container_name=""
volume_name=""

cleanup() {
  if [[ -n "${container_name}" ]]; then
    docker rm -f "${container_name}" >/dev/null 2>&1 || true
  fi
  if [[ -n "${volume_name}" ]]; then
    docker volume rm "${volume_name}" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

require_test() {
  local directory=$1
  local tags=$2
  local test_name=$3
  local listed

  if [[ -n "${tags}" ]]; then
    listed=$(cd "${directory}" && GOWORK=off go test -tags="${tags}" -list "^${test_name}$" ./...)
  else
    listed=$(cd "${directory}" && GOWORK=off go test -list "^${test_name}$" ./...)
  fi
  if ! grep -qx "${test_name}" <<<"${listed}"; then
    echo "required test ${test_name} is missing under ${directory}" >&2
    exit 1
  fi
}

if ! command -v go >/dev/null 2>&1; then
  echo "go is required" >&2
  exit 1
fi

if [[ -z "${nats_url}" ]]; then
  if ! command -v docker >/dev/null 2>&1; then
    echo "docker is required when CDNCA_EDGE_TELEMETRY_SMOKE_NATS_URL is unset" >&2
    exit 1
  fi
  container_name="cdnca-edge-telemetry-transport-${PPID}-$$"
  volume_name="cdnca-edge-telemetry-transport-${PPID}-$$-data"
  docker volume create "${volume_name}" >/dev/null
  docker run -d --rm \
    --name "${container_name}" \
    --volume "${volume_name}:/data" \
    -p 127.0.0.1::4222 \
    nats:2.11.4-alpine -js -sd /data >/dev/null

  for _ in {1..50}; do
    if docker logs "${container_name}" 2>&1 | grep -q "Server is ready"; then
      break
    fi
    sleep 0.1
  done
  if ! docker logs "${container_name}" 2>&1 | grep -q "Server is ready"; then
    echo "temporary NATS server did not become ready" >&2
    exit 1
  fi
  published_address=$(docker port "${container_name}" 4222/tcp)
  nats_url="nats://${published_address}"
fi

require_test "${edge_dir}" "" "TestClientMapsPartialAndDuplicateAcknowledgements"
require_test "${edge_dir}" "" "TestClientReconnectsUnknownResultWithStableBatch"
require_test "${edge_dir}" "" "TestClientRejectsVersionAndHonorsBackpressureAndCancellation"
require_test "${edge_dir}" "" "TestPublisherValidatesAndDropsEventSpoolSubject"
require_test "${edge_dir}" "" "TestDaemonTelemetryFailureDoesNotStopGatewayClient"
require_test "${edge_dir}" "" "TestDaemonTelemetryUnexpectedCleanExitIsDegraded"
require_test "${edge_dir}" "" "TestDaemonCancellationWaitsForTelemetryWorker"
require_test "${edge_dir}" "" "TestAssembleClientUsesSecureFilesAndRealRuntimeAdapter"

require_test "${gateway_dir}" "" "TestStreamTelemetryAcknowledgesOnlyDurableContiguousPrefix"
require_test "${gateway_dir}" "" "TestStreamTelemetryRejectsForgedIdentityAndRefreshesAuthorization"
require_test "${gateway_dir}" "" "TestStreamTelemetryUsesIndependentFenceAndHonorsCancellation"
require_test "${gateway_dir}" "" "TestStreamTelemetryIsMountedOnlyOnAgentMTLSListener"
require_test "${gateway_dir}" "" "TestTelemetryCertificateRequiresExplicitClientAudience"
require_test "${gateway_dir}" "" "TestTelemetryHealthDetailIsDegradedWithoutGatingCoreReadiness"
require_test "${gateway_dir}" "integration" "TestNATSTelemetryPublisherDurabilityDeduplicationAndRecovery"
require_test "${gateway_dir}" "integration" "TestStreamTelemetryJetStreamRestartResume"

(
  cd "${edge_dir}"
  GOWORK=off go test -race -count=1 -timeout=2m ./internal/telemetryclient
  GOWORK=off go test -race -count=1 -timeout=2m \
    -run '^(TestTelemetry|TestDaemonTelemetry|TestDaemonCancellationWaitsForTelemetryWorker|TestAssembleClientUsesSecureFilesAndRealRuntimeAdapter)' \
    ./cmd/edge-agent
  GOWORK=off go vet ./internal/telemetryclient ./cmd/edge-agent
)

(
  cd "${gateway_dir}"
  GOWORK=off go test -race -count=1 -timeout=2m -run 'Telemetry' . ./cmd/agent-gateway
  CDNCA_TEST_NATS_URL="${nats_url}" GOWORK=off \
    go test -race -tags=integration -count=1 -timeout=2m \
    -run '^(TestNATSTelemetryPublisherDurabilityDeduplicationAndRecovery|TestStreamTelemetryJetStreamRestartResume)$' .
  GOWORK=off go vet ./...
)
