#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/../.." && pwd -P)"
readonly SCRIPT_DIR REPO_ROOT
readonly CONTRACT="${SCRIPT_DIR}/input-contract.json"
readonly PREFLIGHT="${SCRIPT_DIR}/input-preflight.sh"
readonly OPS_PREPARER="${REPO_ROOT}/tests/upgrade-process-e2e/prepare-inputs.sh"
readonly UX_CONFIG="${REPO_ROOT}/tests/browser-final-acceptance/config.json"
readonly SCENARIO_CONTRACT="${REPO_ROOT}/tests/browser-final-acceptance/scenario-driver/contract.json"
readonly PUBLIC_AUTH_CONTRACT="${REPO_ROOT}/tests/browser-final-acceptance/public-auth-bootstrap/contract.json"

fail() {
  printf 'FINAL_INPUT_PREFLIGHT_CONTRACT FAIL reason=%s\n' "$1" >&2
  exit 1
}

for command in bash cmp jq node rg shellcheck sort; do
  command -v "${command}" >/dev/null 2>&1 || fail "missing-command-${command}"
done
for path in "${CONTRACT}" "${PREFLIGHT}" "${OPS_PREPARER}" "${UX_CONFIG}" "${SCENARIO_CONTRACT}" "${PUBLIC_AUTH_CONTRACT}"; do
  [ -f "${path}" ] && [ ! -L "${path}" ] || fail "missing-file-${path#"${REPO_ROOT}/"}"
done

bash -n "${PREFLIGHT}" "$0"
shellcheck "${PREFLIGHT}" "$0"
jq -e '
  .schema == "cdnca:final-acceptance-input-preflight:v1" and
  (.l401.runtime_inputs == ["L401_RUNNER_IMAGE", "L401_RUNNER_PROVENANCE_INPUT_SHA256"]) and
  (.ops08.runtime_input_count == 119) and
  (.ops08.local_output_count == 100) and
  (.ops08.external_supply_chain_inputs | length == 19) and
  (.ops08.local_source_inputs | length == 21) and
  (.ux01.runner_inputs | length == 13) and
  (.ux01.scenario_driver_inputs | length == 10) and
  (.ux01.public_auth_inputs | length == 7) and
  (.ux01.offline_generated_inputs | length == 0) and
  (.invariants | length == 4)
' "${CONTRACT}" >/dev/null || fail 'contract-shape'

grep -Fq "readonly RUNNER_IMAGE=\"\${L401_RUNNER_IMAGE:-}\"" \
  "${REPO_ROOT}/tests/l401-process-e2e/run.sh" || fail 'l401-runner-image-drift'
grep -Fq "readonly RUNNER_PROVENANCE_INPUT_SHA256=\"\${L401_RUNNER_PROVENANCE_INPUT_SHA256:-}\"" \
  "${REPO_ROOT}/tests/l401-process-e2e/run.sh" || fail 'l401-runner-provenance-drift'

temporary=$(mktemp -d "${TMPDIR:-/tmp}/cdnca-final-input-contract.XXXXXX")
trap 'rm -rf -- "${temporary}"' EXIT HUP INT TERM

sed -n '/^readonly -a EXTERNAL_INPUT_NAMES=(/,/^)/p' "${OPS_PREPARER}" |
  rg -o 'UPGRADE_E2E_[A-Z0-9_]+' | sort -u >"${temporary}/ops-authoritative"
jq -r '.ops08.external_supply_chain_inputs[]' "${CONTRACT}" | sort -u >"${temporary}/ops-contract"
cmp -s "${temporary}/ops-authoritative" "${temporary}/ops-contract" || fail 'ops-external-drift'

jq -r '.ops08.local_source_inputs[]' "${CONTRACT}" | while IFS= read -r name; do
  grep -Fq -- "${name}" "${OPS_PREPARER}" || fail "ops-local-source-drift-${name}"
done

jq -r '[.required_env[], (.surface_base_env | to_entries[].value), (.identity_storage_env | to_entries[].value)] | unique[]' \
  "${UX_CONFIG}" | sort -u >"${temporary}/ux-runner-authoritative"
jq -r '.ux01.runner_inputs[]' "${CONTRACT}" | sort -u >"${temporary}/ux-runner-contract"
cmp -s "${temporary}/ux-runner-authoritative" "${temporary}/ux-runner-contract" || fail 'ux-runner-drift'

jq -r '.required_env[]' "${SCENARIO_CONTRACT}" | sort -u >"${temporary}/scenario-authoritative"
jq -r '.ux01.scenario_driver_inputs[]' "${CONTRACT}" | sort -u >"${temporary}/scenario-contract"
cmp -s "${temporary}/scenario-authoritative" "${temporary}/scenario-contract" || fail 'scenario-driver-drift'

jq -r '.required_inputs[].name' "${PUBLIC_AUTH_CONTRACT}" | sort -u >"${temporary}/public-auth-authoritative"
jq -r '.ux01.public_auth_inputs[]' "${CONTRACT}" | sort -u >"${temporary}/public-auth-contract"
cmp -s "${temporary}/public-auth-authoritative" "${temporary}/public-auth-contract" || fail 'public-auth-drift'

set +e
env -i PATH="${PATH}" ACCOUNT_REGISTRATION_TURNSTILE_SECRET='contract-secret-never-print' \
  bash "${PREFLIGHT}" >"${temporary}/preflight.stdout" 2>"${temporary}/preflight.stderr"
status=$?
set -e
[ "${status}" -eq 78 ] || fail "missing-input-exit-${status}"
grep -Fq 'stage=L4-01 status=BLOCKED' "${temporary}/preflight.stdout" || fail 'l401-missing-not-blocked'
grep -Fq 'stage=OPS-08 status=BLOCKED' "${temporary}/preflight.stdout" || fail 'ops-missing-not-blocked'
grep -Fq 'stage=UX-01 status=BLOCKED' "${temporary}/preflight.stdout" || fail 'ux-missing-not-blocked'
grep -Fxq 'FINAL_INPUT_PREFLIGHT BLOCKED resources=0' "${temporary}/preflight.stderr" || fail 'terminal-blocked-result'
if grep -Fq 'contract-secret-never-print' "${temporary}/preflight.stdout" "${temporary}/preflight.stderr"; then
  fail 'secret-value-leak'
fi

set +e
env -i PATH="${PATH}" \
  L401_RUNNER_IMAGE="localhost:5000/cdnca/l401-runner@sha256:$(printf 'a%.0s' {1..64})" \
  L401_RUNNER_PROVENANCE_INPUT_SHA256="$(printf 'b%.0s' {1..64})" \
  bash "${PREFLIGHT}" >"${temporary}/port.stdout" 2>"${temporary}/port.stderr"
status=$?
set -e
[ "${status}" -eq 78 ] || fail "port-input-overall-exit-${status}"
grep -Fq 'stage=L4-01 status=READY runtime=2 resources=0' "${temporary}/port.stdout" || \
  fail 'l401-port-reference-rejected'

printf 'FINAL_INPUT_PREFLIGHT_CONTRACT PASS l401-runtime=2 ops-external=19 ops-local-sources=21 ux-runner=13 ux-scenario=10 ux-public-auth=7 resources=0\n'
