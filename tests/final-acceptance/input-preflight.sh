#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/../.." && pwd -P)"
readonly SCRIPT_DIR REPO_ROOT
readonly CONTRACT="${SCRIPT_DIR}/input-contract.json"

if [ "$#" -ne 0 ]; then
  printf 'usage: %s\n' "$0" >&2
  exit 2
fi

for command in id jq node stat; do
  if ! command -v "${command}" >/dev/null 2>&1; then
    printf 'FINAL_INPUT_PREFLIGHT BLOCKED missing-command=%s resources=0\n' "${command}" >&2
    exit 78
  fi
done
if [ ! -f "${CONTRACT}" ] || [ -L "${CONTRACT}" ]; then
  printf 'FINAL_INPUT_PREFLIGHT BLOCKED missing-contract resources=0\n' >&2
  exit 78
fi
if ! jq -e '
  .schema == "cdnca:final-acceptance-input-preflight:v1" and
  (.l401.runtime_inputs == ["L401_RUNNER_IMAGE", "L401_RUNNER_PROVENANCE_INPUT_SHA256"]) and
  (.ops08.external_supply_chain_inputs | length == 19) and
  (.ops08.local_source_inputs | length == 21) and
  (.ux01.runner_inputs | length == 13) and
  (.ux01.scenario_driver_inputs | length == 10) and
  (.ux01.public_auth_inputs | length == 7)
' "${CONTRACT}" >/dev/null; then
  printf 'FINAL_INPUT_PREFLIGHT BLOCKED invalid-contract resources=0\n' >&2
  exit 78
fi

join_csv() {
  local IFS=,
  printf '%s' "$*"
}

clean_absolute_path() {
  node -e '
    const path = require("node:path")
    const value = process.argv[1]
    process.exit(path.isAbsolute(value) && path.normalize(value) === value ? 0 : 1)
  ' "$1" >/dev/null 2>&1
}

safe_url() {
  node -e '
    try {
      const value = new URL(process.argv[1])
      const loopback = ["127.0.0.1", "::1", "localhost"].includes(value.hostname)
      process.exit(!value.username && !value.password && !value.search && !value.hash &&
        (value.protocol === "https:" || (value.protocol === "http:" && loopback)) ? 0 : 1)
    } catch {
      process.exit(1)
    }
  ' "$1" >/dev/null 2>&1
}

file_mode_uid_size() {
  if stat -f '%Lp %u %z' -- "$1" >/dev/null 2>&1; then
    stat -f '%Lp %u %z' -- "$1"
  else
    stat -c '%a %u %s' -- "$1"
  fi
}

ops_missing=()
ops_unsafe=()
ops_invalid=()
ux_missing=()
ux_unsafe=()
ux_invalid=()
l401_missing=()
l401_invalid=()

if [ -z "${L401_RUNNER_IMAGE:-}" ]; then
  l401_missing+=(L401_RUNNER_IMAGE)
elif [[ ! ${L401_RUNNER_IMAGE} =~ ^sha256:[0-9a-f]{64}$ &&
        ! ${L401_RUNNER_IMAGE} =~ ^[[:alnum:]][[:alnum:].:_/-]*@sha256:[0-9a-f]{64}$ ]]; then
  l401_invalid+=(L401_RUNNER_IMAGE)
fi
if [ -z "${L401_RUNNER_PROVENANCE_INPUT_SHA256:-}" ]; then
  l401_missing+=(L401_RUNNER_PROVENANCE_INPUT_SHA256)
elif [[ ! ${L401_RUNNER_PROVENANCE_INPUT_SHA256} =~ ^[0-9a-f]{64}$ ]]; then
  l401_invalid+=(L401_RUNNER_PROVENANCE_INPUT_SHA256)
fi

ops_required=()
while IFS= read -r name; do ops_required+=("${name}"); done < <(
  jq -r '.ops08.external_supply_chain_inputs[], .ops08.local_source_inputs[]' "${CONTRACT}"
)
ops_files=()
while IFS= read -r name; do ops_files+=("${name}"); done < <(
  jq -r '.ops08.external_file_inputs[], .ops08.local_file_inputs[]' "${CONTRACT}"
)
ops_shas=()
while IFS= read -r name; do ops_shas+=("${name}"); done < <(
  jq -r '.ops08.external_sha256_inputs[], .ops08.local_sha256_inputs[]' "${CONTRACT}"
)
ops_versions=()
while IFS= read -r name; do ops_versions+=("${name}"); done < <(
  jq -r '.ops08.local_version_inputs[]' "${CONTRACT}"
)

for name in "${ops_required[@]}"; do
  if [ -z "${!name:-}" ]; then
    ops_missing+=("${name}")
  fi
done
for name in "${ops_files[@]}"; do
  [ -n "${!name:-}" ] || continue
  path=${!name}
  if [ -L "${path}" ] || [ ! -f "${path}" ] || [ ! -r "${path}" ]; then
    ops_unsafe+=("${name}")
  fi
done
for name in "${ops_shas[@]}"; do
  [ -n "${!name:-}" ] || continue
  if [[ ! ${!name} =~ ^[0-9a-f]{64}$ ]]; then
    ops_invalid+=("${name}")
  fi
done
for name in "${ops_versions[@]}"; do
  [ -n "${!name:-}" ] || continue
  if [[ ! ${!name} =~ ^[0-9]+\.[0-9]+\.[0-9]+([.-][A-Za-z0-9.-]+)?$ ]]; then
    ops_invalid+=("${name}")
  fi
done
for name in UPGRADE_E2E_SYSTEMD_IMAGE UPGRADE_E2E_SYSTEMD_AMD64_SUBJECT UPGRADE_E2E_SYSTEMD_ARM64_SUBJECT; do
  [ -n "${!name:-}" ] || continue
  if [[ ! ${!name} =~ ^[a-z0-9][a-z0-9./_-]*@sha256:[0-9a-f]{64}$ ]]; then
    ops_invalid+=("${name}")
  fi
done
if [ -n "${UPGRADE_E2E_SYSTEMD_COSIGN_ISSUER:-}" ] &&
  [ "${UPGRADE_E2E_SYSTEMD_COSIGN_ISSUER}" != 'https://token.actions.githubusercontent.com' ]; then
  ops_invalid+=(UPGRADE_E2E_SYSTEMD_COSIGN_ISSUER)
fi
if [ -n "${UPGRADE_E2E_SYSTEMD_COSIGN_IDENTITY:-}" ] &&
  [[ ! ${UPGRADE_E2E_SYSTEMD_COSIGN_IDENTITY} =~ \.github/workflows/edge-supply-chain\.yml@refs/(heads|tags)/[A-Za-z0-9._/-]+$ ]]; then
  ops_invalid+=(UPGRADE_E2E_SYSTEMD_COSIGN_IDENTITY)
fi
if ! command -v cosign >/dev/null 2>&1; then
  ops_missing+=(command:cosign)
fi
if [ ! -f "${REPO_ROOT}/tests/upgrade-process-e2e/prepare-inputs.sh" ] ||
  [ -L "${REPO_ROOT}/tests/upgrade-process-e2e/prepare-inputs.sh" ]; then
  ops_unsafe+=(preparer)
fi

ux_required=()
while IFS= read -r name; do ux_required+=("${name}"); done < <(
  jq -r '[.ux01.runner_inputs[], .ux01.scenario_driver_inputs[], .ux01.public_auth_inputs[]] | unique[]' "${CONTRACT}"
)
for name in "${ux_required[@]}"; do
  if [ -z "${!name:-}" ]; then
    ux_missing+=("${name}")
    continue
  fi
  value=${!name}
  case "${name}" in
    *_URL|*_ENDPOINT)
      safe_url "${value}" || ux_invalid+=("${name}")
      ;;
    *_FILE|*_STATE)
      if ! clean_absolute_path "${value}" || [ -L "${value}" ] || [ ! -f "${value}" ]; then
        ux_unsafe+=("${name}")
        continue
      fi
      if ! details=$(file_mode_uid_size "${value}" 2>/dev/null); then
        ux_unsafe+=("${name}")
        continue
      fi
      read -r mode uid size <<<"${details}"
      if [ "${name}" = ACCOUNT_REGISTRATION_TURNSTILE_CA_FILE ]; then
        if (( (8#${mode} & 0400) == 0 || (8#${mode} & 0022) != 0 || size < 1 || size > 1048576 )); then
          ux_unsafe+=("${name}")
        fi
      elif (( (8#${mode} & 0077) != 0 || uid != $(id -u) || size < 1 || size > 16777216 )); then
        ux_unsafe+=("${name}")
      fi
      ;;
  esac
done

ops_status=READY
ux_status=READY
l401_status=READY
if [ "${#l401_missing[@]}" -ne 0 ] || [ "${#l401_invalid[@]}" -ne 0 ]; then
  l401_status=BLOCKED
fi
if [ "${#ops_missing[@]}" -ne 0 ] || [ "${#ops_unsafe[@]}" -ne 0 ] || [ "${#ops_invalid[@]}" -ne 0 ]; then
  ops_status=BLOCKED
fi
if [ "${#ux_missing[@]}" -ne 0 ] || [ "${#ux_unsafe[@]}" -ne 0 ] || [ "${#ux_invalid[@]}" -ne 0 ]; then
  ux_status=BLOCKED
fi

printf 'FINAL_INPUT_PREFLIGHT stage=L4-01 status=%s runtime=2' "${l401_status}"
[ "${#l401_missing[@]}" -eq 0 ] || printf ' missing=%s' "$(join_csv "${l401_missing[@]}")"
[ "${#l401_invalid[@]}" -eq 0 ] || printf ' invalid=%s' "$(join_csv "${l401_invalid[@]}")"
printf ' resources=0\n'

printf 'FINAL_INPUT_PREFLIGHT stage=OPS-08 status=%s external=19 local-sources=21 local-output=100' "${ops_status}"
[ "${#ops_missing[@]}" -eq 0 ] || printf ' missing=%s' "$(join_csv "${ops_missing[@]}")"
[ "${#ops_unsafe[@]}" -eq 0 ] || printf ' unsafe=%s' "$(join_csv "${ops_unsafe[@]}")"
[ "${#ops_invalid[@]}" -eq 0 ] || printf ' invalid=%s' "$(join_csv "${ops_invalid[@]}")"
printf ' resources=0\n'

printf 'FINAL_INPUT_PREFLIGHT stage=UX-01 status=%s runner=13 scenario-driver=10 public-auth=7 offline-generated=0' "${ux_status}"
[ "${#ux_missing[@]}" -eq 0 ] || printf ' missing=%s' "$(join_csv "${ux_missing[@]}")"
[ "${#ux_unsafe[@]}" -eq 0 ] || printf ' unsafe=%s' "$(join_csv "${ux_unsafe[@]}")"
[ "${#ux_invalid[@]}" -eq 0 ] || printf ' invalid=%s' "$(join_csv "${ux_invalid[@]}")"
printf ' resources=0\n'

if [ "${l401_status}" = READY ] && [ "${ops_status}" = READY ] && [ "${ux_status}" = READY ]; then
  printf 'FINAL_INPUT_PREFLIGHT PASS resources=0\n'
  exit 0
fi
printf 'FINAL_INPUT_PREFLIGHT BLOCKED resources=0\n' >&2
exit 78
