#!/usr/bin/env bash
# shellcheck disable=SC2016 # Contract assertions intentionally match literal shell expressions.
set -Eeuo pipefail
umask 077

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly SCRIPT_DIR
readonly RUNNER="${SCRIPT_DIR}/run.sh"
readonly README="${SCRIPT_DIR}/README.md"

fail() {
  printf 'L401_BOOTSTRAP_CONTRACT FAIL check=%s\n' "$1" >&2
  exit 1
}

require_literal() {
  local literal=$1 check=$2
  grep -Fq -- "${literal}" "${RUNNER}" || fail "${check}"
}

[ -f "${RUNNER}" ] && [ ! -L "${RUNNER}" ] || fail 'run-file'
[ -f "${README}" ] && [ ! -L "${README}" ] || fail 'readme-file'

require_literal 'set -Eeuo pipefail' strict-mode
require_literal 'umask 077' private-umask
require_literal 'OWNERSHIP_TOKEN="l401-' unique-l401-prefix
require_literal 'io.cdnca.test.owner=' ownership-label
require_literal 'docker ps -aq --filter "label=${RESOURCE_LABEL}"' label-cleanup
require_literal 'cleanup=PASS containers=0 networks=0 images=0 processes=0' resource-zero
require_literal "postgres:17.9-alpine" postgres17
require_literal "nats:2.11.4-alpine" nats-jetstream
require_literal "redis:7.4.4-alpine" redis
require_literal 'openresty/openresty@sha256:' real-openresty
require_literal '"${WORK_DIR}/bin/control-api" migrate up' real-control-migrations
require_literal '"${WORK_DIR}/bin/control-api" bootstrap-user' production-bootstrap-user
require_literal '/v1/auth/login' production-login
require_literal '/v1/admin/site-publications' production-publication
require_literal "'l401-publication-old'" old-idempotency
require_literal "'l401-publication-new'" new-idempotency
require_literal 'old_rollout_id' old-rollout
require_literal 'new_rollout_id' new-rollout
require_literal 'old_deployment_id' old-deployment
require_literal 'new_deployment_id' new-deployment
require_literal "SELECT count(*) FROM edge_command_outbox" production-outbox-readback
require_literal 'L401_NATS_PREFLIGHT PASS' nats-readback
require_literal 'info.State.Consumers != 0' zero-agent-consumer
require_literal 'consumers=0 ack_pending=0' zero-pending-ack
require_literal 'chmod 0600 "${WORK_DIR}/secrets/control-bearer-token"' bearer-mode
require_literal 'chmod 0600 "${WORK_DIR}/secrets/edge-agent.json"' agent-config-mode
require_literal 'trap '\''cleanup "$?"'\'' EXIT' cleanup-trap
require_literal 'readonly RUNNER_IMAGE="${L401_RUNNER_IMAGE:-}"' explicit-runner-input
require_literal 'readonly RUNNER_PROVENANCE_INPUT_SHA256="${L401_RUNNER_PROVENANCE_INPUT_SHA256:-}"' explicit-provenance-input
require_literal 'runner-image-not-digest-pinned' digest-pin-preflight
require_literal '^sha256:[0-9a-f]{64}$' local-content-id-preflight
require_literal 'runner-image-not-prefetched' local-prefetch-preflight
require_literal 'io.cdnca.l401.runner.contract' runner-contract-label
require_literal 'io.cdnca.l401.runner.go-image' runner-go-label
require_literal 'io.cdnca.l401.runner.openresty-image' runner-openresty-label
require_literal 'io.cdnca.l401.runner.provenance-input-sha256' runner-provenance-label
require_literal 'docker run --pull=never --name "${RUNNER_CONTAINER}"' pull-never
require_literal '--user "$(id -u):$(id -g)"' owner-uid-runner
require_literal "[ \"\$(go env GOVERSION)\" = 'go1.27.3' ]" actual-go-version
require_literal '[ "${actual_openresty}" = "${OPENRESTY_VERSION}" ]' actual-openresty-version
# The runner's OpenResty is the node runtime of edge/openresty/runtime.env, read
# both outside and inside the runner; no second pin may drift from it.
[ "$(grep -Fc -- "sed -n 's/^OPENRESTY_VERSION=//p' \"\${REPO_ROOT}/edge/openresty/runtime.env\"" "${RUNNER}")" -eq 2 ] || \
  fail 'openresty-version-from-runtime-env'
require_literal "sed -n 's/^OPENRESTY_IMAGE=//p' \"\${REPO_ROOT}/edge/openresty/runtime.env\"" openresty-image-from-runtime-env
require_literal '--openresty-version "${OPENRESTY_VERSION}"' enrollment-openresty-version
require_literal 'version:$openresty_version}' agent-config-openresty-version
for pinned in "${RUNNER}" "${SCRIPT_DIR}/runner-image/build.sh" "${SCRIPT_DIR}/runner-image/Dockerfile" \
  "${SCRIPT_DIR}/runner-image/inputs.lock.json"; do
  if grep -Eiq 'openresty[^0-9]{0,40}[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+|openresty/openresty@sha256:[0-9a-f]{64}' "${pinned}"; then
    fail "openresty-pin-outside-runtime-env-$(basename "${pinned}")"
  fi
done

if grep -Fq 'apt-get' "${RUNNER}"; then
  fail 'forbidden-runtime-apt'
fi
if grep -Eq 'docker[[:space:]]+build' "${RUNNER}"; then
  fail 'forbidden-runtime-runner-build'
fi
if grep -Eq 'docker[[:space:]]+image[[:space:]]+rm' "${RUNNER}"; then
  fail 'forbidden-prefetched-image-removal'
fi

preflight_line="$(grep -n '^preflight_runner_image$' "${RUNNER}" | cut -d: -f1)"
workdir_line="$(grep -n '^WORK_DIR=.*mktemp' "${RUNNER}" | cut -d: -f1)"
network_line="$(grep -n '^docker network create' "${RUNNER}" | cut -d: -f1)"
[ -n "${preflight_line}" ] && [ -n "${workdir_line}" ] && [ -n "${network_line}" ] || \
  fail 'runner-preflight-order-markers'
[ "${preflight_line}" -lt "${workdir_line}" ] && [ "${preflight_line}" -lt "${network_line}" ] || \
  fail 'runner-preflight-before-mutation'

publication_count="$(grep -Fc -- '/v1/admin/site-publications"' "${RUNNER}")"
[ "${publication_count}" -eq 1 ] || fail 'single-publication-function-two-calls'
publish_call_count="$(grep -Ec '^publish "\$\{(old|new)_revision\}"' "${RUNNER}")"
[ "${publish_call_count}" -eq 2 ] || fail 'two-production-publications'
test_count="$(grep -Fc -- 'TestL401GatewayProcessE2E' "${RUNNER}")"
[ "${test_count}" -eq 1 ] || fail 'single-go-e2e-invocation'

if grep -Eq '(^|[[:space:]])nats[[:space:]]+pub([[:space:]]|$)' "${RUNNER}"; then
  fail 'forbidden-direct-nats-publication'
fi
if grep -Eiq '(INSERT[[:space:]]+INTO|UPDATE)[[:space:]]+(rollouts|node_deployments|edge_command_outbox|deployment_status_events)' "${RUNNER}"; then
  fail 'forbidden-final-state-write'
fi
if ! grep -Fq 'static-only' "${README}" || ! grep -Fq '尚未执行' "${README}"; then
  fail 'static-status-disclosure'
fi

printf 'L401_BOOTSTRAP_CONTRACT PASS\n'
