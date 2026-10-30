#!/usr/bin/env bash
# shellcheck disable=SC2016
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/../.." && pwd -P)"
readonly SCRIPT_DIR REPO_ROOT
readonly SCRIPT="${SCRIPT_DIR}/bootstrap-source-inputs.sh"
readonly CONTRACT="${SCRIPT_DIR}/bootstrap-source-inputs.contract.json"
readonly AUTHORITY="${REPO_ROOT}/tests/final-acceptance/input-contract.json"

fail() { printf 'UPGRADE_SOURCE_BOOTSTRAP_CONTRACT FAIL reason=%s\n' "$1" >&2; exit 1; }

for command in bash jq rg shellcheck sort; do
  command -v "${command}" >/dev/null 2>&1 || fail "missing-command-${command}"
done
for path in "${SCRIPT}" "${CONTRACT}" "${AUTHORITY}"; do
  [ -f "${path}" ] && [ ! -L "${path}" ] || fail "missing-file-${path#"${REPO_ROOT}"/}"
done
bash -n "${SCRIPT}" "$0"
shellcheck "${SCRIPT}" "$0"
jq -e --argjson authority "$(jq -c '.ops08.local_source_inputs' "${AUTHORITY}")" '
  .schema == "cdnca:upgrade-e2e-source-bootstrap:v1" and
  .source_count == 21 and .generated_source_count == 11 and .upstream_source_count == 10 and
  (.generated_source_inputs | length) == 11 and (.upstream_source_inputs | length) == 10 and
  (($authority | sort) == ((.generated_source_inputs + .upstream_source_inputs) | sort)) and
  .output.atomic == true and .output.env_mode == "0600" and
  .output.manifest_mode == "0600" and .output.material_directory_mode == "0700" and
  .output.secret_file_mode == "0600" and .output.env_contains_only == ["path","sha256","version"]
' "${CONTRACT}" >/dev/null || fail 'contract-shape'
grep -F 'umask 077' "${SCRIPT}" >/dev/null || fail 'owner-default'
grep -F 'mktemp -d' "${SCRIPT}" >/dev/null || fail 'staging-atomicity'
grep -F 'mv -- "${temp_env}" "${output_env}"' "${SCRIPT}" >/dev/null || fail 'env-atomic-publish'
grep -F 'chmod 0600 "${output_env}" "${manifest}"' "${SCRIPT}" >/dev/null || fail 'output-mode'
if rg -n 'docker|docker-compose|postgres|psql|nats|playwright|final-acceptance/run' "${SCRIPT}" >/dev/null; then
  fail 'runtime-side-effect'
fi
printf 'UPGRADE_SOURCE_BOOTSTRAP_CONTRACT PASS source=21 generated=11 upstream=10 resources=0\n'
