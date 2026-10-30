#!/usr/bin/env bash
# Assemble local upgrade-E2E inputs without manufacturing registry evidence.
# shellcheck disable=SC2016,SC2030,SC2031
set -Eeuo pipefail
umask 077

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/../.." && pwd -P)"
readonly SCRIPT_DIR REPO_ROOT

fail() {
  printf 'UPGRADE_INPUTS_FAIL reason=%s\n' "$1" >&2
  exit 1
}

usage() {
  printf 'usage: %s --output /absolute/path/runtime.env\n' "$0" >&2
  exit 2
}

sha256() {
  shasum -a 256 -- "$1" | awk '{print $1}'
}

require_regular() {
  local path=$1 label=$2
  [ -f "${path}" ] && [ ! -L "${path}" ] && [ -r "${path}" ] || fail "missing-local-input-${label}"
}

emit() {
  local name=$1 value=$2
  printf '%s=%q\n' "${name}" "${value}" >&3
}

random_hex() {
  openssl rand -hex "$1"
}

random_b64() {
  openssl rand -base64 "$1" | tr -d '\n'
}

random_rawurl_b64() {
  openssl rand -base64 "$1" | tr '+/' '-_' | tr -d '=\n'
}

random_uuid() {
  local hex
  hex=$(openssl rand -hex 16)
  printf '%s-%s-4%s-8%s-%s\n' \
    "${hex:0:8}" "${hex:8:4}" "${hex:13:3}" "${hex:17:3}" "${hex:20:12}"
}

readonly -a EXTERNAL_INPUT_NAMES=(
  UPGRADE_E2E_SYSTEMD_IMAGE UPGRADE_E2E_SYSTEMD_AMD64_SUBJECT UPGRADE_E2E_SYSTEMD_ARM64_SUBJECT
  UPGRADE_E2E_SYSTEMD_COSIGN_ISSUER UPGRADE_E2E_SYSTEMD_COSIGN_IDENTITY
  UPGRADE_E2E_SYSTEMD_AMD64_INVENTORY UPGRADE_E2E_SYSTEMD_AMD64_INVENTORY_SHA256
  UPGRADE_E2E_SYSTEMD_ARM64_INVENTORY UPGRADE_E2E_SYSTEMD_ARM64_INVENTORY_SHA256
  UPGRADE_E2E_SYSTEMD_AMD64_MANIFEST UPGRADE_E2E_SYSTEMD_AMD64_MANIFEST_SHA256
  UPGRADE_E2E_SYSTEMD_ARM64_MANIFEST UPGRADE_E2E_SYSTEMD_ARM64_MANIFEST_SHA256
  UPGRADE_E2E_SYSTEMD_AMD64_PROVENANCE UPGRADE_E2E_SYSTEMD_AMD64_PROVENANCE_SHA256
  UPGRADE_E2E_SYSTEMD_ARM64_PROVENANCE UPGRADE_E2E_SYSTEMD_ARM64_PROVENANCE_SHA256
  UPGRADE_E2E_SYSTEMD_SPDX UPGRADE_E2E_SYSTEMD_SPDX_SHA256
)

readonly -a LOCAL_INPUT_NAMES=(
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
  LICENSE_SIGNER_CHECKPOINT_OFFLINE_ROOT_PUBLIC_KEY_BASE64 LICENSE_SIGNER_REVOCATION_ATTEMPT_HMAC_KEY_BASE64
  LICENSE_SIGNING_KEY_ID LICENSE_SIGNING_PRIVATE_KEY_BASE64 LICENSE_SIGNING_PROVIDER LICENSE_SMTP_ADDRESS
  LICENSE_SMTP_FROM LICENSE_TOTP_KEYS_JSON LICENSE_TOTP_KEY_ID UPGRADE_E2E_AUTOMATIC_ROLLBACK_JSON
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
  UPGRADE_E2E_LICENSE_PARENT_RECEIPT_SCHEMA UPGRADE_E2E_NATS_RESOURCES_JSON UPGRADE_E2E_NATS_RESOURCES_SHA256
  UPGRADE_E2E_NODE_ID UPGRADE_E2E_OPERATOR_ROLLBACK_JSON UPGRADE_E2E_OPERATOR_ROLLBACK_SHA256
  UPGRADE_E2E_PROCESS_CONTRACT_VERSION UPGRADE_E2E_ROLLBACK_BUNDLE UPGRADE_E2E_ROLLBACK_BUNDLE_SHA256
  UPGRADE_E2E_ROLLBACK_BUNDLE_SIZE UPGRADE_E2E_SUCCESS_ROLLOUT_JSON UPGRADE_E2E_SUCCESS_ROLLOUT_SHA256
)

while [ "$#" -gt 0 ]; do
  case "$1" in
    --output)
      [ "$#" -ge 2 ] || usage
      OUTPUT_ENV=$2
      shift 2
      ;;
    *) usage ;;
  esac
done
[ -n "${OUTPUT_ENV:-}" ] || usage
case "${OUTPUT_ENV}" in
  /*) ;;
  *) fail 'output-must-be-absolute' ;;
esac
case "${OUTPUT_ENV}" in
  "${REPO_ROOT}"|"${REPO_ROOT}"/*) fail 'output-must-be-outside-repository' ;;
esac
for command in awk basename chmod cp find jq mktemp openssl shasum tail tr wc; do
  command -v "${command}" >/dev/null 2>&1 || fail "missing-command-${command}"
done
[ "${#EXTERNAL_INPUT_NAMES[@]}" -eq 19 ] || fail 'external-input-count'
[ "${#LOCAL_INPUT_NAMES[@]}" -eq 100 ] || fail 'local-input-count'

for name in "${EXTERNAL_INPUT_NAMES[@]}"; do
  [ -n "${!name-}" ] || fail "missing-external-input-${name}"
done
[[ "${UPGRADE_E2E_SYSTEMD_IMAGE}" =~ ^[a-z0-9][a-z0-9./_-]*@sha256:[0-9a-f]{64}$ ]] || fail 'invalid-external-image'
[[ "${UPGRADE_E2E_SYSTEMD_AMD64_SUBJECT}" =~ ^[a-z0-9][a-z0-9./_-]*@sha256:[0-9a-f]{64}$ ]] || fail 'invalid-external-amd64-subject'
[[ "${UPGRADE_E2E_SYSTEMD_ARM64_SUBJECT}" =~ ^[a-z0-9][a-z0-9./_-]*@sha256:[0-9a-f]{64}$ ]] || fail 'invalid-external-arm64-subject'
[ "${UPGRADE_E2E_SYSTEMD_COSIGN_ISSUER}" = 'https://token.actions.githubusercontent.com' ] || fail 'invalid-external-oidc-issuer'
[[ "${UPGRADE_E2E_SYSTEMD_COSIGN_IDENTITY}" =~ \.github/workflows/edge-supply-chain\.yml@refs/(heads|tags)/[A-Za-z0-9._/-]+$ ]] || fail 'invalid-external-oidc-identity'
image_repo=${UPGRADE_E2E_SYSTEMD_IMAGE%@*}
[ "${UPGRADE_E2E_SYSTEMD_AMD64_SUBJECT%@*}" = "${image_repo}" ] || fail 'external-amd64-repository-mismatch'
[ "${UPGRADE_E2E_SYSTEMD_ARM64_SUBJECT%@*}" = "${image_repo}" ] || fail 'external-arm64-repository-mismatch'
[ "${UPGRADE_E2E_SYSTEMD_AMD64_SUBJECT}" != "${UPGRADE_E2E_SYSTEMD_ARM64_SUBJECT}" ] || fail 'external-native-subjects-not-distinct'

for pair in \
  UPGRADE_E2E_SYSTEMD_AMD64_INVENTORY:UPGRADE_E2E_SYSTEMD_AMD64_INVENTORY_SHA256 \
  UPGRADE_E2E_SYSTEMD_ARM64_INVENTORY:UPGRADE_E2E_SYSTEMD_ARM64_INVENTORY_SHA256 \
  UPGRADE_E2E_SYSTEMD_AMD64_MANIFEST:UPGRADE_E2E_SYSTEMD_AMD64_MANIFEST_SHA256 \
  UPGRADE_E2E_SYSTEMD_ARM64_MANIFEST:UPGRADE_E2E_SYSTEMD_ARM64_MANIFEST_SHA256 \
  UPGRADE_E2E_SYSTEMD_AMD64_PROVENANCE:UPGRADE_E2E_SYSTEMD_AMD64_PROVENANCE_SHA256 \
  UPGRADE_E2E_SYSTEMD_ARM64_PROVENANCE:UPGRADE_E2E_SYSTEMD_ARM64_PROVENANCE_SHA256 \
  UPGRADE_E2E_SYSTEMD_SPDX:UPGRADE_E2E_SYSTEMD_SPDX_SHA256; do
  path_name=${pair%%:*}
  sha_name=${pair##*:}
  require_regular "${!path_name}" "${path_name}"
  [[ "${!sha_name}" =~ ^[0-9a-f]{64}$ ]] || fail "invalid-external-sha-${sha_name}"
  [ "$(sha256 "${!path_name}")" = "${!sha_name}" ] || fail "external-artifact-drift-${path_name}"
done

parent_dir=$(dirname -- "${OUTPUT_ENV}")
mkdir -p -- "${parent_dir}" || fail 'output-parent'
output_dir=$(mktemp -d "${parent_dir%/}/cdnca-upgrade-inputs.XXXXXX") || fail 'output-directory'
trap 'rm -rf -- "${output_dir}"' EXIT HUP INT TERM
mkdir -p -- "${output_dir}/inputs" || fail 'output-input-directory'
chmod 0700 "${output_dir}" "${output_dir}/inputs" || fail 'output-directory-mode'
temp_env="${output_dir}/runtime.env.tmp"
exec 3>"${temp_env}"

# External values are validated above and only passed through; they are never generated here.
for name in "${EXTERNAL_INPUT_NAMES[@]}"; do emit "${name}" "${!name}"; done

node_id=${UPGRADE_E2E_NODE_ID:-}
if [ -z "${node_id}" ]; then
  node_id=$(random_uuid)
fi
[[ "${node_id}" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$ ]] || fail 'invalid-local-node-id'
emit UPGRADE_E2E_NODE_ID "${node_id}"

write_manifest_tree() {
  local root=$1 destination relative source
  [ -d "${REPO_ROOT}/${root}" ] || fail "missing-local-tree-${root}"
  if find "${REPO_ROOT}/${root}" -type l -print -quit | grep -q .; then fail "symlink-in-local-tree-${root}"; fi
  : >"${destination}"
  while IFS= read -r relative; do
    source="${REPO_ROOT}/${relative}"
    printf '%s  %s\n' "$(sha256 "${source}")" "${relative}" >>"${destination}"
  done < <(cd "${REPO_ROOT}" && find "${root}" -type f -print | LC_ALL=C sort)
  LC_ALL=C sort -u -o "${destination}" "${destination}"
  chmod 0400 "${destination}"
}

write_scope_manifest() {
  local destination relative source
  destination=$1
  shift
  : >"${destination}"
  for relative in "$@"; do
    source="${REPO_ROOT}/${relative}"
    require_regular "${source}" "scope-${relative}"
    printf '%s  %s\n' "$(sha256 "${source}")" "${relative}" >>"${destination}"
  done
  LC_ALL=C sort -u -o "${destination}" "${destination}"
  chmod 0400 "${destination}"
}

copy_local_pair() {
  local path_name=$1 sha_name=$2 source destination file_id actual
  source=${!path_name-}
  require_regular "${source}" "${path_name}"
  file_id=$(printf '%s' "${path_name}" | tr '[:upper:]' '[:lower:]')
  destination="${output_dir}/inputs/${file_id}"
  cp -- "${source}" "${destination}"
  chmod 0400 "${destination}"
  actual=$(sha256 "${destination}")
  emit "${path_name}" "${destination}"
  emit "${sha_name}" "${actual}"
  case "${path_name}" in
    UPGRADE_E2E_FORWARD_BUNDLE|UPGRADE_E2E_ROLLBACK_BUNDLE)
      emit "${path_name}_SIZE" "$(wc -c <"${destination}" | tr -d ' ')"
      ;;
  esac
}

write_manifest_tree services/control-api "${output_dir}/inputs/upgrade_e2e_b_manifest"
emit UPGRADE_E2E_B_MANIFEST "${output_dir}/inputs/upgrade_e2e_b_manifest"
emit UPGRADE_E2E_B_MANIFEST_SHA256 "$(sha256 "${output_dir}/inputs/upgrade_e2e_b_manifest")"
write_manifest_tree agents/edge-agent "${output_dir}/inputs/upgrade_e2e_c_manifest"
emit UPGRADE_E2E_C_MANIFEST "${output_dir}/inputs/upgrade_e2e_c_manifest"
emit UPGRADE_E2E_C_MANIFEST_SHA256 "$(sha256 "${output_dir}/inputs/upgrade_e2e_c_manifest")"

license_head=$(sed -n "s/^readonly LICENSE_MIGRATION_HEAD='\([0-9][0-9]*\)'/\1/p" "${SCRIPT_DIR}/run.sh")
[ "${license_head}" = '046' ] || fail 'license-head-source-drift'
license_paths=()
while IFS= read -r path; do
  base=$(basename -- "${path}")
  if [[ "${base}" =~ ^${license_head}_.+\.(up|down)\.sql$ || "${base}" =~ ^.+_${license_head}_(integration_test|contract_test|test)\.go$ ]]; then
    license_paths+=("${path}")
  fi
done < <(cd "${REPO_ROOT}" && find services/license-service/migrations -maxdepth 1 -type f -print | LC_ALL=C sort)
[ "${#license_paths[@]}" -eq 3 ] || fail 'license-scope-manifest-members'
write_scope_manifest "${output_dir}/inputs/upgrade_e2e_license_manifest" "${license_paths[@]}"
emit UPGRADE_E2E_LICENSE_MIGRATION_MANIFEST "${output_dir}/inputs/upgrade_e2e_license_manifest"
emit UPGRADE_E2E_LICENSE_MIGRATION_MANIFEST_SHA256 "$(sha256 "${output_dir}/inputs/upgrade_e2e_license_manifest")"

control_paths=()
while IFS= read -r path; do control_paths+=("${path}"); done < <(
  sed -n '/^readonly -a CONTROL_MIGRATION_MANIFEST_PATHS=(/,/^)/p' "${SCRIPT_DIR}/run.sh" |
    sed -n "s/^[[:space:]]*'\([^']*\)'$/\1/p"
)
[ "${#control_paths[@]}" -eq 21 ] || fail 'control-scope-manifest-members'
write_scope_manifest "${output_dir}/inputs/upgrade_e2e_control_manifest" "${control_paths[@]}"
emit UPGRADE_E2E_CONTROL_MIGRATION_MANIFEST "${output_dir}/inputs/upgrade_e2e_control_manifest"
emit UPGRADE_E2E_CONTROL_MIGRATION_MANIFEST_SHA256 "$(sha256 "${output_dir}/inputs/upgrade_e2e_control_manifest")"

if [ -n "${UPGRADE_E2E_NATS_RESOURCES_JSON:-}" ]; then
  copy_local_pair UPGRADE_E2E_NATS_RESOURCES_JSON UPGRADE_E2E_NATS_RESOURCES_SHA256
else
  emit UPGRADE_E2E_NATS_RESOURCES_JSON "${SCRIPT_DIR}/nats-resources.json"
  emit UPGRADE_E2E_NATS_RESOURCES_SHA256 "$(sha256 "${SCRIPT_DIR}/nats-resources.json")"
fi
emit UPGRADE_E2E_PROCESS_CONTRACT_VERSION "sha256:$(sha256 "${SCRIPT_DIR}/contract.json")"
emit UPGRADE_E2E_LICENSE_PARENT_RECEIPT_SCHEMA "$(jq -er '.license_receipt_request_schema' "${SCRIPT_DIR}/contract.json")"

for label in success automatic-rollback operator-rollback; do
  destination="${output_dir}/inputs/${label}.json"
  jq -S -c --arg node_id "${node_id}" \
    '{automatic_rollback:true,batch_size:1,canary_node_ids:[$node_id],node_ids:[$node_id],schema:"cdnca.control-upgrade-rollout.create/v1"}' \
    >"${destination}"
  chmod 0400 "${destination}"
  upper=$(printf '%s' "${label}" | tr '[:lower:]-' '[:upper:]_')
  emit "UPGRADE_E2E_${upper}_JSON" "${destination}"
  emit "UPGRADE_E2E_${upper}_SHA256" "$(sha256 "${destination}")"
done

for pair in \
  UPGRADE_E2E_LICENSE_AUTHORITY_FIXTURE_SQL:UPGRADE_E2E_LICENSE_AUTHORITY_FIXTURE_SHA256 \
  UPGRADE_E2E_CONTROL_AUTHORITY_FIXTURE_SQL:UPGRADE_E2E_CONTROL_AUTHORITY_FIXTURE_SHA256 \
  UPGRADE_E2E_EDGE_CONFIG_JSON:UPGRADE_E2E_EDGE_CONFIG_SHA256 \
  ENTITLEMENT_TRUSTED_KEYS_FILE:ENTITLEMENT_TRUSTED_KEYS_SHA256 \
  CONTROL_INSTALLATION_PRIVATE_KEY_FILE:CONTROL_INSTALLATION_PRIVATE_KEY_SHA256 \
  CONTROL_ACTIVATION_CREDENTIAL_FILE:CONTROL_ACTIVATION_CREDENTIAL_SHA256 \
  CONTROL_UPGRADE_COMMAND_GRANT_TRUST_FILE:CONTROL_UPGRADE_COMMAND_GRANT_TRUST_SHA256 \
  CONTROL_UPGRADE_CONTROL_SIGNING_PRIVATE_KEY_FILE:CONTROL_UPGRADE_CONTROL_SIGNING_PRIVATE_KEY_SHA256 \
  CONTROL_UPGRADE_EDGE_SIGNING_PRIVATE_KEY_FILE:CONTROL_UPGRADE_EDGE_SIGNING_PRIVATE_KEY_SHA256 \
  UPGRADE_E2E_INITIAL_ARTIFACT:UPGRADE_E2E_INITIAL_ARTIFACT_SHA256 \
  UPGRADE_E2E_INITIAL_SBOM:UPGRADE_E2E_INITIAL_SBOM_SHA256 \
  UPGRADE_E2E_INITIAL_MANIFEST:UPGRADE_E2E_INITIAL_MANIFEST_SHA256 \
  UPGRADE_E2E_INITIAL_SIGNATURE:UPGRADE_E2E_INITIAL_SIGNATURE_SHA256 \
  UPGRADE_E2E_INITIAL_PUBLIC_KEY:UPGRADE_E2E_INITIAL_PUBLIC_KEY_SHA256 \
  UPGRADE_E2E_FORWARD_BUNDLE:UPGRADE_E2E_FORWARD_BUNDLE_SHA256 \
  UPGRADE_E2E_ROLLBACK_BUNDLE:UPGRADE_E2E_ROLLBACK_BUNDLE_SHA256; do
  path_name=${pair%%:*}
  sha_name=${pair##*:}
  copy_local_pair "${path_name}" "${sha_name}"
done

for name in UPGRADE_E2E_EDGE_ARTIFACT_TRUST_SHA256 UPGRADE_E2E_EDGE_CONTROL_EXECUTION_TRUST_SHA256 UPGRADE_E2E_EDGE_EXECUTION_TRUST_SHA256; do
  value=${!name:?missing-local-input-${name}}
  [[ "${value}" =~ ^[0-9a-f]{64}$ ]] || fail "invalid-local-sha-${name}"
  emit "${name}" "${value}"
done
for name in UPGRADE_E2E_INITIAL_VERSION UPGRADE_E2E_FORWARD_VERSION; do
  value=${!name:?missing-local-input-${name}}
  [[ "${value}" =~ ^[0-9]+\.[0-9]+\.[0-9]+([.-][A-Za-z0-9.-]+)?$ ]] || fail "invalid-local-version-${name}"
  emit "${name}" "${value}"
done
[ "${UPGRADE_E2E_INITIAL_VERSION}" != "${UPGRADE_E2E_FORWARD_VERSION}" ] || fail 'local-release-versions-not-distinct'

if [ -z "${LICENSE_SIGNING_PRIVATE_KEY_BASE64:-}" ]; then
  signing_pem="${output_dir}/license-signing-key.pem"
  signing_der="${output_dir}/license-signing-key.der"
  signing_public_der="${output_dir}/license-signing-public.der"
  signing_raw="${output_dir}/license-signing-key.raw"
  openssl genpkey -algorithm ED25519 -out "${signing_pem}" >/dev/null 2>&1 || fail 'generate-license-signing-key'
  openssl pkey -in "${signing_pem}" -outform DER -out "${signing_der}" >/dev/null 2>&1 || fail 'encode-license-signing-key'
  openssl pkey -in "${signing_pem}" -pubout -outform DER -out "${signing_public_der}" >/dev/null 2>&1 || fail 'encode-license-signing-public-key'
  [ "$(wc -c <"${signing_der}" | tr -d ' ')" -ge 32 ] || fail 'license-signing-key-too-short'
  [ "$(wc -c <"${signing_public_der}" | tr -d ' ')" -ge 32 ] || fail 'license-signing-public-key-too-short'
  tail -c 32 "${signing_der}" >"${signing_raw}" || fail 'extract-license-signing-seed'
  tail -c 32 "${signing_public_der}" >>"${signing_raw}" || fail 'extract-license-signing-public-key'
  [ "$(wc -c <"${signing_raw}" | tr -d ' ')" -eq 64 ] || fail 'license-signing-key-size'
  chmod 0400 "${signing_pem}" "${signing_der}" "${signing_public_der}" "${signing_raw}"
  LICENSE_SIGNING_PRIVATE_KEY_BASE64=$(openssl base64 -A -in "${signing_raw}") || fail 'encode-license-signing-key-base64'
fi

for name in "${LOCAL_INPUT_NAMES[@]}"; do
  case "${name}" in
    *_FILE|*_SHA256|*_BUNDLE|*_MANIFEST|*_SBOM|*_SIGNATURE|*_PUBLIC_KEY|UPGRADE_E2E_*_JSON|UPGRADE_E2E_FORWARD_VERSION|UPGRADE_E2E_INITIAL_VERSION|UPGRADE_E2E_NODE_ID)
      continue
      ;;
  esac
  value=${!name-}
  if [ -z "${value}" ]; then
    case "${name}" in
      CDNCA_GATEWAY_INSTANCE_ID|CONTROL_INSTALLATION_ID) value=$(random_uuid) ;;
      CONTROL_UPGRADE_COMMAND_ISSUANCE_TTL) value=10m ;;
      CONTROL_UPGRADE_EXECUTION_TTL) value=5m ;;
      CONTROL_UPGRADE_ACTIVATION_TIMEOUT) value=30s ;;
      CONTROL_UPGRADE_OBSERVATION_WINDOW) value=10s ;;
      CONTROL_UPGRADE_HEALTH_INTERVAL) value=2s ;;
      CONTROL_UPGRADE_PROBE_TIMEOUT) value=5s ;;
      CONTROL_UPGRADE_NATS_CONNECT_TIMEOUT) value=5s ;;
      CONTROL_UPGRADE_NATS_RECONNECT_WAIT) value=1s ;;
      CONTROL_UPGRADE_NATS_DRAIN_TIMEOUT) value=5s ;;
      CONTROL_UPGRADE_SHUTDOWN_TIMEOUT) value=10s ;;
      CONTROL_UPGRADE_CONTROL_SIGNING_KEY_ID) value=local-control-v1 ;;
      CONTROL_UPGRADE_EDGE_SIGNING_KEY_ID) value=local-edge-v1 ;;
      LICENSE_SIGNING_KEY_ID) value=local-license-v1 ;;
      LICENSE_SIGNER_CHECKPOINT_OFFLINE_ROOT_KEY_ID) value=local-offline-root-v1 ;;
      LICENSE_SMTP_ADDRESS) value=127.0.0.1:2525 ;;
      *_BASE64) value=$(random_b64 32) ;;
      *_KEY_ID) value=local-v1 ;;
      *_TIMEOUT|*_INTERVAL|*_TTL|*_WINDOW) value=10s ;;
      *_GENERATION|*_SUCCESSES) value=1 ;;
      *_NAME) value=upgrade-e2e-local ;;
      *_VERSION) value=0.1.0 ;;
      *_ADDRESS) value=127.0.0.1 ;;
      *_PROVIDER) value=raw ;;
      LICENSE_SMTP_FROM) value=upgrade-e2e-local@example.test ;;
      UPGRADE_E2E_BEARER_TOKEN) value=$(random_hex 32) ;;
      LICENSE_BILLING_PROVIDER_KEYS_JSON) value=$(printf '[{"provider":"local.billing","provider_account_id":"local-account","provider_config_revision":1,"verification_key_id":"local-billing-v1","public_key":"%s"}]' "$(random_rawurl_b64 32)") ;;
      *_JSON) value=$(printf '{"local-v1":"%s"}' "$(random_b64 32)") ;;
      *) value=$(random_hex 32) ;;
    esac
  fi
  emit "${name}" "${value}"
done

exec 3>&-
awk -F= 'NF < 2 || seen[$1]++ {exit 1}' "${temp_env}" || fail 'duplicate-or-invalid-output-name'
mv -- "${temp_env}" "${OUTPUT_ENV}"
chmod 0600 "${OUTPUT_ENV}"
trap - EXIT HUP INT TERM
rm -rf -- "${output_dir}"
# No secret values are printed; only the destination path and generated counts are reported.
printf 'UPGRADE_INPUTS PASS local=100 external=19 output=%s\n' "${OUTPUT_ENV}"
