#!/usr/bin/env bash
# shellcheck disable=SC2016 # Contract assertions intentionally match literal wrapper expressions.
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
RUNNER="${SCRIPT_DIR}/run.sh"
README="${SCRIPT_DIR}/README.md"
INPUT_CONTRACT="${SCRIPT_DIR}/input-contract.json"
INPUT_PREFLIGHT="${SCRIPT_DIR}/input-preflight.sh"

fail() {
  printf 'FINAL_ACCEPTANCE_CONTRACT FAIL reason=%s\n' "$1" >&2
  exit 1
}

[ -f "${RUNNER}" ] || fail 'missing-runner'
[ -f "${README}" ] || fail 'missing-readme'
[ -f "${INPUT_CONTRACT}" ] || fail 'missing-input-contract'
[ -f "${INPUT_PREFLIGHT}" ] || fail 'missing-input-preflight'
[ -x "${RUNNER}" ] || fail 'runner-not-executable'

grep -F 'FINAL_ACCEPTANCE_STATIC PASS' "${RUNNER}" >/dev/null || fail 'missing-static-pass'
grep -F 'FINAL_ACCEPTANCE total=3' "${RUNNER}" >/dev/null || fail 'missing-total-result'
grep -F 'FINAL_ACCEPTANCE stage=' "${RUNNER}" >/dev/null || fail 'missing-stage-result'
grep -F "trap 'cleanup \"\$?\"' EXIT" "${RUNNER}" >/dev/null || fail 'missing-owned-cleanup-trap'

for required in \
  'edge-origin-route-smoke.sh' \
  'tests/l401-process-e2e/run.sh' \
  'tests/upgrade-process-e2e/run.sh'; do
  grep -F "${required}" "${RUNNER}" >/dev/null || fail "missing-driver-${required}"
done

grep -F 'readonly L4_PROCESS_DRIVER="${REPO_ROOT}/tests/l401-process-e2e/run.sh"' "${RUNNER}" >/dev/null || \
  fail 'missing-l401-bootstrap-driver'
[ "$(grep -Fc 'run_stage L4-01 bash "${L4_PROCESS_DRIVER}"' "${RUNNER}")" -eq 1 ] || \
  fail 'l401-bootstrap-invocation-count'
if grep -F 'TestL401GatewayProcessE2E' "${RUNNER}" >/dev/null; then
  fail 'wrapper-direct-go-e2e'
fi
if grep -F 'L401_REQUIRED_ENV' "${RUNNER}" >/dev/null; then
  fail 'external-l401-environment-contract'
fi
if grep -F 'UPGRADE_E2E_STATIC_ONLY' "${RUNNER}" >/dev/null; then
  fail 'nested-upgrade-static-rerun'
fi
grep -F 'local -a docker_stages=(SITE-04 L4-01 OPS-08)' "${RUNNER}" >/dev/null || \
  fail 'l401-docker-preflight'
grep -F 'require_stage_commands L4-01 bash chmod curl date docker jq mktemp openssl sed sha256sum' \
  "${RUNNER}" >/dev/null || fail 'l401-host-command-preflight'

for frozen in \
  'edge-cache-task-smoke.sh' \
  'edge-l4-smoke.sh' \
  'macro2_cross_process_integration_test.go' \
  'tests/analytics-observability/process-e2e/run.sh' \
  'tests/analytics-observability/clickhouse_smoke.sh' \
  'tests/browser-final-acceptance/runner.mjs'; do
  if grep -F "${frozen}" "${RUNNER}" >/dev/null; then
    fail "frozen-driver-requeued-${frozen}"
  fi
done

expected_stages=(SITE-04 L4-01 OPS-08)
previous_line=0
for stage in "${expected_stages[@]}"; do
  line=$(grep -n -F "run_stage ${stage}" "${RUNNER}" | tail -1 | cut -d: -f1)
  [ -n "${line}" ] || fail "missing-stage-${stage}"
  [ "${line}" -gt "${previous_line}" ] || fail "stage-order-${stage}"
  previous_line=${line}
done

preflight_line=$(grep -n -E '^[[:space:]]*preflight_all\(\)' "${RUNNER}" | head -1 | cut -d: -f1)
first_stage_line=$(grep -n -F 'run_stage SITE-04' "${RUNNER}" | tail -1 | cut -d: -f1)
[ -n "${preflight_line}" ] && [ "${preflight_line}" -lt "${first_stage_line}" ] || fail 'preflight-after-driver'

upgrade_env_count=$(sed -n '/^readonly -a UPGRADE_REQUIRED_ENV=(/,/^)/p' "${RUNNER}" | \
  rg -o '\b[A-Z][A-Z0-9_]+\b' | rg -v '^UPGRADE_REQUIRED_ENV$' | sort -u | wc -l | tr -d ' ')
[ "${upgrade_env_count}" -eq 119 ] || fail "upgrade-env-count-${upgrade_env_count}"

grep -F 'missing-command-' "${RUNNER}" >/dev/null || fail 'missing-command-diagnostic'
grep -F 'missing-file-' "${RUNNER}" >/dev/null || fail 'missing-file-diagnostic'
grep -F 'missing-env-' "${RUNNER}" >/dev/null || fail 'missing-env-diagnostic'
grep -F 'unified input preflight' "${README}" >/dev/null || fail 'missing-unified-input-preflight-doc'
grep -F 'task-owned' "${README}" >/dev/null || fail 'missing-l401-task-owned-doc'
grep -F 'tests/l401-process-e2e/run.sh' "${README}" >/dev/null || fail 'missing-l401-bootstrap-doc'
grep -F 'cleanup=PASS containers=0 networks=0 images=0 processes=0' "${README}" >/dev/null || \
  fail 'missing-l401-resource-zero-doc'
grep -E 'FINAL_ACCEPTANCE.*PASS' "${README}" >/dev/null || fail 'missing-pass-doc'
grep -E 'FINAL_ACCEPTANCE.*UNKNOWN' "${README}" >/dev/null || fail 'missing-unknown-doc'
grep -F 'UX-01' "${README}" >/dev/null || fail 'missing-separate-browser-wave-doc'
grep -F 'input-preflight.sh' "${README}" >/dev/null || fail 'missing-input-preflight-doc'
grep -F 'readonly INPUT_PREFLIGHT="${SCRIPT_DIR}/input-preflight.sh"' "${RUNNER}" >/dev/null || \
  fail 'missing-input-preflight-binding'
[ "$(grep -Fc 'if ! bash "${INPUT_PREFLIGHT}"; then' "${RUNNER}")" -eq 1 ] || \
  fail 'input-preflight-invocation-count'

input_preflight_line=$(grep -n -F 'if ! bash "${INPUT_PREFLIGHT}"; then' "${RUNNER}" | cut -d: -f1)
runtime_preflight_line=$(grep -n -F 'preflight_all || exit 77' "${RUNNER}" | cut -d: -f1)
work_dir_line=$(grep -n -F 'WORK_DIR="$(mktemp' "${RUNNER}" | cut -d: -f1)
first_runtime_stage_line=$(grep -n -F 'run_stage SITE-04' "${RUNNER}" | tail -1 | cut -d: -f1)
[ "${input_preflight_line}" -lt "${runtime_preflight_line}" ] || fail 'input-preflight-after-runtime-preflight'
[ "${input_preflight_line}" -lt "${work_dir_line}" ] || fail 'input-preflight-after-work-directory'
[ "${input_preflight_line}" -lt "${first_runtime_stage_line}" ] || fail 'input-preflight-after-stage'

FINAL_ACCEPTANCE_STATIC_ONLY=1 bash "${RUNNER}" | grep -Fx 'FINAL_ACCEPTANCE_STATIC PASS' >/dev/null || \
  fail 'static-entrypoint-failed'

printf 'FINAL_ACCEPTANCE_CONTRACT PASS\n'
