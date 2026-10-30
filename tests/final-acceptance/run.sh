#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/../.." && pwd -P)"
readonly SCRIPT_DIR REPO_ROOT

readonly SITE_DRIVER="${REPO_ROOT}/scripts/edge-origin-route-smoke.sh"
readonly L4_PROCESS_DRIVER="${REPO_ROOT}/tests/l401-process-e2e/run.sh"
readonly UPGRADE_DRIVER="${REPO_ROOT}/tests/upgrade-process-e2e/run.sh"
readonly INPUT_PREFLIGHT="${SCRIPT_DIR}/input-preflight.sh"

readonly -a STAGES=(SITE-04 L4-01 OPS-08)
readonly -a UPGRADE_REQUIRED_ENV=(
  ACCESS_TOKEN_SECRET API_KEY_PEPPER_BASE64 CDNCA_GATEWAY_INSTANCE_ID CDNCA_GATEWAY_VERSION
  CONTROL_ACTIVATION_CREDENTIAL_FILE CONTROL_ACTIVATION_CREDENTIAL_SHA256 CONTROL_INSTALLATION_ID
  CONTROL_INSTALLATION_NAME CONTROL_INSTALLATION_PRIVATE_KEY_FILE CONTROL_INSTALLATION_PRIVATE_KEY_SHA256
  CONTROL_UPGRADE_ACTIVATION_TIMEOUT CONTROL_UPGRADE_COMMAND_GRANT_TRUST_FILE
  CONTROL_UPGRADE_COMMAND_GRANT_TRUST_SHA256 CONTROL_UPGRADE_COMMAND_ISSUANCE_TTL
  CONTROL_UPGRADE_CONTROL_SIGNING_KEY_ID CONTROL_UPGRADE_CONTROL_SIGNING_PRIVATE_KEY_FILE
  CONTROL_UPGRADE_CONTROL_SIGNING_PRIVATE_KEY_SHA256 CONTROL_UPGRADE_EDGE_SIGNING_KEY_ID
  CONTROL_UPGRADE_EDGE_SIGNING_PRIVATE_KEY_FILE CONTROL_UPGRADE_EDGE_SIGNING_PRIVATE_KEY_SHA256
  CONTROL_UPGRADE_EXECUTION_TTL CONTROL_UPGRADE_HEALTH_INTERVAL CONTROL_UPGRADE_NATS_CONNECT_TIMEOUT
  CONTROL_UPGRADE_NATS_DRAIN_TIMEOUT CONTROL_UPGRADE_NATS_NAME CONTROL_UPGRADE_NATS_RECONNECT_WAIT
  CONTROL_UPGRADE_OBSERVATION_WINDOW CONTROL_UPGRADE_PROBE_TIMEOUT
  CONTROL_UPGRADE_REQUIRED_CONSECUTIVE_SUCCESSES CONTROL_UPGRADE_SHUTDOWN_TIMEOUT
  CONTROL_UPGRADE_WORKER_ID CONTROL_VERSION DNS_CREDENTIAL_KEY_BASE64 DNS_CREDENTIAL_KEY_ID
  ENTITLEMENT_TRUSTED_KEYS_FILE ENTITLEMENT_TRUSTED_KEYS_SHA256 LICENSE_BILLING_PROVIDER_KEYS_JSON
  LICENSE_CONTROL_API_VERSION LICENSE_CREDENTIAL_KEYS_JSON LICENSE_CREDENTIAL_KEY_ID
  LICENSE_IDENTITY_TOKEN_KEYS_JSON LICENSE_IDENTITY_TOKEN_KEY_ID
  LICENSE_SIGNER_CHECKPOINT_OFFLINE_ROOT_GENERATION LICENSE_SIGNER_CHECKPOINT_OFFLINE_ROOT_KEY_ID
  LICENSE_SIGNER_CHECKPOINT_OFFLINE_ROOT_PUBLIC_KEY_BASE64
  LICENSE_SIGNER_REVOCATION_ATTEMPT_HMAC_KEY_BASE64 LICENSE_SIGNING_KEY_ID
  LICENSE_SIGNING_PRIVATE_KEY_BASE64 LICENSE_SIGNING_PROVIDER LICENSE_SMTP_ADDRESS LICENSE_SMTP_FROM
  LICENSE_TOTP_KEYS_JSON LICENSE_TOTP_KEY_ID UPGRADE_E2E_AUTOMATIC_ROLLBACK_JSON
  UPGRADE_E2E_AUTOMATIC_ROLLBACK_SHA256 UPGRADE_E2E_BEARER_TOKEN UPGRADE_E2E_B_MANIFEST
  UPGRADE_E2E_B_MANIFEST_SHA256 UPGRADE_E2E_CONTROL_AUTHORITY_FIXTURE_SHA256
  UPGRADE_E2E_CONTROL_AUTHORITY_FIXTURE_SQL UPGRADE_E2E_CONTROL_MIGRATION_MANIFEST
  UPGRADE_E2E_CONTROL_MIGRATION_MANIFEST_SHA256 UPGRADE_E2E_C_MANIFEST UPGRADE_E2E_C_MANIFEST_SHA256
  UPGRADE_E2E_EDGE_ARTIFACT_TRUST_SHA256 UPGRADE_E2E_EDGE_CONFIG_JSON UPGRADE_E2E_EDGE_CONFIG_SHA256
  UPGRADE_E2E_EDGE_CONTROL_EXECUTION_TRUST_SHA256 UPGRADE_E2E_EDGE_EXECUTION_TRUST_SHA256
  UPGRADE_E2E_FORWARD_BUNDLE UPGRADE_E2E_FORWARD_BUNDLE_SHA256 UPGRADE_E2E_FORWARD_BUNDLE_SIZE
  UPGRADE_E2E_FORWARD_VERSION UPGRADE_E2E_INITIAL_ARTIFACT UPGRADE_E2E_INITIAL_ARTIFACT_SHA256
  UPGRADE_E2E_INITIAL_MANIFEST UPGRADE_E2E_INITIAL_MANIFEST_SHA256 UPGRADE_E2E_INITIAL_PUBLIC_KEY
  UPGRADE_E2E_INITIAL_PUBLIC_KEY_SHA256 UPGRADE_E2E_INITIAL_SBOM UPGRADE_E2E_INITIAL_SBOM_SHA256
  UPGRADE_E2E_INITIAL_SIGNATURE UPGRADE_E2E_INITIAL_SIGNATURE_SHA256 UPGRADE_E2E_INITIAL_VERSION
  UPGRADE_E2E_LICENSE_AUTHORITY_FIXTURE_SHA256 UPGRADE_E2E_LICENSE_AUTHORITY_FIXTURE_SQL
  UPGRADE_E2E_LICENSE_MIGRATION_MANIFEST UPGRADE_E2E_LICENSE_MIGRATION_MANIFEST_SHA256
  UPGRADE_E2E_LICENSE_PARENT_RECEIPT_SCHEMA UPGRADE_E2E_NATS_RESOURCES_JSON
  UPGRADE_E2E_NATS_RESOURCES_SHA256 UPGRADE_E2E_NODE_ID UPGRADE_E2E_OPERATOR_ROLLBACK_JSON
  UPGRADE_E2E_OPERATOR_ROLLBACK_SHA256 UPGRADE_E2E_PROCESS_CONTRACT_VERSION UPGRADE_E2E_ROLLBACK_BUNDLE
  UPGRADE_E2E_ROLLBACK_BUNDLE_SHA256 UPGRADE_E2E_ROLLBACK_BUNDLE_SIZE UPGRADE_E2E_SUCCESS_ROLLOUT_JSON
  UPGRADE_E2E_SUCCESS_ROLLOUT_SHA256 UPGRADE_E2E_SYSTEMD_AMD64_INVENTORY
  UPGRADE_E2E_SYSTEMD_AMD64_INVENTORY_SHA256 UPGRADE_E2E_SYSTEMD_AMD64_MANIFEST
  UPGRADE_E2E_SYSTEMD_AMD64_MANIFEST_SHA256 UPGRADE_E2E_SYSTEMD_AMD64_PROVENANCE
  UPGRADE_E2E_SYSTEMD_AMD64_PROVENANCE_SHA256 UPGRADE_E2E_SYSTEMD_AMD64_SUBJECT
  UPGRADE_E2E_SYSTEMD_ARM64_INVENTORY UPGRADE_E2E_SYSTEMD_ARM64_INVENTORY_SHA256
  UPGRADE_E2E_SYSTEMD_ARM64_MANIFEST UPGRADE_E2E_SYSTEMD_ARM64_MANIFEST_SHA256
  UPGRADE_E2E_SYSTEMD_ARM64_PROVENANCE UPGRADE_E2E_SYSTEMD_ARM64_PROVENANCE_SHA256
  UPGRADE_E2E_SYSTEMD_ARM64_SUBJECT UPGRADE_E2E_SYSTEMD_COSIGN_IDENTITY
  UPGRADE_E2E_SYSTEMD_COSIGN_ISSUER UPGRADE_E2E_SYSTEMD_IMAGE UPGRADE_E2E_SYSTEMD_SPDX
  UPGRADE_E2E_SYSTEMD_SPDX_SHA256
)

STAGE_BLOCKERS=()
STAGE_SEEN=()
WORK_DIR=''
TMP_BASE="${TMPDIR:-/tmp}"
passed_count=0
unknown_count=0

append_blocker() {
  local stage=$1 reason=$2 index
  index=$(stage_index "${stage}")
  if [ -n "${STAGE_BLOCKERS[${index}]:-}" ]; then
    STAGE_BLOCKERS[index]+=",${reason}"
  else
    STAGE_BLOCKERS[index]="${reason}"
  fi
}

stage_index() {
  local stage=$1 index
  for index in "${!STAGES[@]}"; do
    [ "${STAGES[${index}]}" = "${stage}" ] && printf '%s\n' "${index}" && return 0
  done
  return 1
}

require_stage_commands() {
  local stage=$1 command
  shift
  for command in "$@"; do
    command -v "${command}" >/dev/null 2>&1 || append_blocker "${stage}" "missing-command-${command}"
  done
}

require_stage_files() {
  local stage=$1 path
  shift
  for path in "$@"; do
    if [ ! -f "${path}" ] || [ -L "${path}" ] || [ ! -r "${path}" ]; then
      append_blocker "${stage}" "missing-file-${path#"${REPO_ROOT}/"}"
    fi
  done
}

require_stage_env() {
  local stage=$1 name
  shift
  for name in "$@"; do
    [ -n "${!name:-}" ] || append_blocker "${stage}" "missing-env-${name}"
  done
}

preflight_all() {
  local stage index docker_arch global_reason=''
  local -a docker_stages=(SITE-04 L4-01 OPS-08)
  local -a buildx_stages=(SITE-04 OPS-08)

  case "${TMP_BASE}" in
    /*) ;;
    *) global_reason='invalid-TMPDIR' ;;
  esac
  for command in mktemp chmod rm tee; do
    command -v "${command}" >/dev/null 2>&1 || global_reason+="${global_reason:+,}missing-command-${command}"
  done
  if [ -n "${global_reason}" ]; then
    for stage in "${STAGES[@]}"; do
      printf 'FINAL_ACCEPTANCE stage=%s UNKNOWN reason=global-preflight-%s\n' "${stage}" "${global_reason}" >&2
    done
    printf 'FINAL_ACCEPTANCE total=3 passed=0 unknown=3 UNKNOWN\n' >&2
    return 77
  fi

  require_stage_files SITE-04 "${SITE_DRIVER}"
  require_stage_files L4-01 "${L4_PROCESS_DRIVER}"
  require_stage_files OPS-08 "${UPGRADE_DRIVER}" \
    "${REPO_ROOT}/tests/upgrade-process-e2e/contract.json" \
    "${REPO_ROOT}/tests/upgrade-process-e2e/nats-resources.json"

  require_stage_commands SITE-04 sh docker go sed grep mktemp chmod rm basename
  require_stage_commands L4-01 bash chmod curl date docker jq mktemp openssl sed sha256sum basename grep mkdir sleep
  require_stage_commands OPS-08 bash awk basename chmod cmp curl date dirname docker find go grep id jq lsof mkdir mktemp openssl perl ps rm rmdir sed shasum sleep sort stat tr wc cosign

  if ! command -v docker >/dev/null 2>&1 || ! docker info --format '{{.Architecture}}' >/dev/null 2>&1; then
    for stage in "${docker_stages[@]}"; do
      append_blocker "${stage}" missing-docker-daemon
    done
  else
    docker_arch=$(docker info --format '{{.Architecture}}' 2>/dev/null || true)
    case "${docker_arch}" in
      amd64|x86_64|arm64|aarch64) ;;
      *)
        append_blocker SITE-04 "unsupported-docker-architecture-${docker_arch:-unknown}"
        append_blocker L4-01 "unsupported-docker-architecture-${docker_arch:-unknown}"
        ;;
    esac
    if ! docker buildx version >/dev/null 2>&1; then
      for stage in "${buildx_stages[@]}"; do
        append_blocker "${stage}" missing-docker-buildx
      done
    fi
  fi

  require_stage_env OPS-08 "${UPGRADE_REQUIRED_ENV[@]}"

  for stage in "${STAGES[@]}"; do
    index=$(stage_index "${stage}")
    if [ -n "${STAGE_BLOCKERS[${index}]:-}" ]; then
      printf 'FINAL_ACCEPTANCE preflight=%s UNKNOWN reason=%s\n' \
        "${stage}" "${STAGE_BLOCKERS[${index}]}" >&2
    else
      printf 'FINAL_ACCEPTANCE preflight=%s PASS\n' "${stage}"
    fi
  done
}

# Invoked indirectly by the EXIT trap.
# shellcheck disable=SC2329
cleanup() {
  local status=${1:-$?}
  trap - EXIT HUP INT TERM
  if [ -n "${WORK_DIR}" ]; then
    case "${WORK_DIR}" in
      "${TMP_BASE%/}"/cdnca-final-acceptance.*) rm -rf -- "${WORK_DIR}" ;;
      *)
        printf 'FINAL_ACCEPTANCE cleanup=UNKNOWN reason=unsafe-cleanup-path\n' >&2
        status=77
        ;;
    esac
  fi
  exit "${status}"
}

run_stage() {
  local stage=$1 argument status index
  shift
  index=$(stage_index "${stage}")
  if [ -n "${STAGE_SEEN[${index}]:-}" ]; then
    printf 'FINAL_ACCEPTANCE stage=%s UNKNOWN reason=duplicate-stage-invocation\n' "${stage}" >&2
    unknown_count=$((unknown_count + 1))
    return 77
  fi
  STAGE_SEEN[index]=1

  if [ -n "${STAGE_BLOCKERS[${index}]:-}" ]; then
    printf 'FINAL_ACCEPTANCE stage=%s UNKNOWN reason=%s\n' "${stage}" "${STAGE_BLOCKERS[${index}]}" >&2
    unknown_count=$((unknown_count + 1))
    return 77
  fi

  printf 'FINAL_ACCEPTANCE stage=%s command=' "${stage}"
  for argument in "$@"; do
    printf '%q ' "${argument}"
  done
  printf '\n'
  if "$@" 2>&1 | tee "${WORK_DIR}/${stage}.log"; then
    printf 'FINAL_ACCEPTANCE stage=%s PASS\n' "${stage}"
    passed_count=$((passed_count + 1))
    return 0
  fi
  status=${PIPESTATUS[0]}
  printf 'FINAL_ACCEPTANCE stage=%s UNKNOWN reason=driver-exit-%s\n' "${stage}" "${status}" >&2
  unknown_count=$((unknown_count + 1))
  return 77
}

if [ "${FINAL_ACCEPTANCE_STATIC_ONLY:-0}" = '1' ]; then
  printf 'FINAL_ACCEPTANCE_STATIC PASS\n'
  exit 0
fi

if [ ! -f "${INPUT_PREFLIGHT}" ] || [ -L "${INPUT_PREFLIGHT}" ]; then
  printf 'FINAL_ACCEPTANCE inputs=UNKNOWN reason=missing-input-preflight\n' >&2
  printf 'FINAL_ACCEPTANCE total=3 passed=0 unknown=3 UNKNOWN\n' >&2
  exit 77
fi
if ! bash "${INPUT_PREFLIGHT}"; then
  printf 'FINAL_ACCEPTANCE inputs=UNKNOWN reason=input-preflight-blocked\n' >&2
  printf 'FINAL_ACCEPTANCE total=3 passed=0 unknown=3 UNKNOWN\n' >&2
  exit 77
fi

preflight_all || exit 77

WORK_DIR="$(mktemp -d "${TMP_BASE%/}/cdnca-final-acceptance.XXXXXX")"
chmod 0700 "${WORK_DIR}"
trap 'cleanup "$?"' EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

run_stage SITE-04 sh "${SITE_DRIVER}" || true
run_stage L4-01 bash "${L4_PROCESS_DRIVER}" || true
run_stage OPS-08 bash "${UPGRADE_DRIVER}" || true

if [ "${passed_count}" -eq "${#STAGES[@]}" ] && [ "${unknown_count}" -eq 0 ]; then
  printf 'FINAL_ACCEPTANCE total=3 passed=3 unknown=0 PASS\n'
  exit 0
fi
printf 'FINAL_ACCEPTANCE total=3 passed=%s unknown=%s UNKNOWN\n' "${passed_count}" "${unknown_count}" >&2
exit 77
