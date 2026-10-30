#!/usr/bin/env bash
# Bootstrap only the 21 OPS-08 local source inputs.
# External GHCR/OIDC/cosign facts are intentionally outside this script.
# shellcheck disable=SC2016,SC2030,SC2031
set -Eeuo pipefail
umask 077

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/../.." && pwd -P)"
readonly SCRIPT_DIR REPO_ROOT
readonly AUTHORITY="${REPO_ROOT}/tests/final-acceptance/input-contract.json"
readonly CONTRACT="${SCRIPT_DIR}/bootstrap-source-inputs.contract.json"

fail() {
  printf 'UPGRADE_SOURCE_BOOTSTRAP_FAIL reason=%s\n' "$1" >&2
  exit 1
}

usage() {
  printf 'usage: %s --output /absolute/path/source.env\n' "$0" >&2
  exit 2
}

sha256_file() {
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 -- "$1" | awk '{print $1}'
  else
    sha256sum -- "$1" | awk '{print $1}'
  fi
}

file_size() {
  if stat -f '%z' -- "$1" >/dev/null 2>&1; then
    stat -f '%z' -- "$1"
  else
    stat -c '%s' -- "$1"
  fi
}

file_mode() {
  local path=$1
  if stat -f '%Lp' -- "$path" >/dev/null 2>&1; then
    stat -f '%Lp' -- "$path"
  else
    stat -c '%a' -- "$path"
  fi
}

require_absolute_clean() {
  local path=$1 label=$2
  [[ "${path}" = /* ]] || fail "${label}-must-be-absolute"
  case "${path}" in *//*|*/./*|*/../*|*/.|*/..) fail "${label}-path-not-clean" ;; esac
}

require_regular() {
  local path=$1 label=$2 maximum=${3:-16777216}
  require_absolute_clean "${path}" "${label}"
  [ -f "${path}" ] && [ ! -L "${path}" ] && [ -r "${path}" ] || fail "missing-or-unsafe-${label}"
  local size
  size=$(file_size "${path}") || fail "cannot-stat-${label}"
  [[ "${size}" =~ ^[1-9][0-9]*$ ]] && [ "${size}" -le "${maximum}" ] || fail "invalid-size-${label}"
}

require_owner_only() {
  local path=$1 label=$2 mode
  mode=$(file_mode "${path}") || fail "cannot-stat-${label}"
  [[ "${mode}" =~ ^[0-7]{3,4}$ ]] || fail "invalid-mode-${label}"
  (( (8#${mode} & 0077) == 0 )) || fail "${label}-must-be-owner-only"
}

emit_env() {
  local name=$1 value=$2
  case "${value}" in
    *$'\n'*|*$'\r'*) fail "newline-in-${name}" ;;
  esac
  printf '%s=%q\n' "${name}" "${value}" >&3
}

copy_input() {
  local name=$1 source=$2 destination=$3 mode=$4
  require_regular "${source}" "${name}" 285229182
  cp -- "${source}" "${destination}" || fail "copy-${name}"
  chmod "${mode}" "${destination}" || fail "mode-${name}"
  [ "$(sha256_file "${source}")" = "$(sha256_file "${destination}")" ] || fail "copy-drift-${name}"
}

random_uuid() {
  local hex
  hex=$(openssl rand -hex 16) || fail 'random-uuid'
  printf '%s-%s-4%s-8%s-%s\n' \
    "${hex:0:8}" "${hex:8:4}" "${hex:13:3}" "${hex:17:3}" "${hex:20:12}"
}

valid_sha256() { [[ "$1" =~ ^[0-9a-f]{64}$ ]]; }
valid_version() { [[ "$1" =~ ^[0-9]+\.[0-9]+\.[0-9]+([.-][A-Za-z0-9.-]+)?$ ]]; }

readonly -a UPSTREAM_NAMES=(
  UPGRADE_E2E_LICENSE_AUTHORITY_FIXTURE_SQL UPGRADE_E2E_CONTROL_AUTHORITY_FIXTURE_SQL
  CONTROL_ACTIVATION_CREDENTIAL_FILE UPGRADE_E2E_INITIAL_ARTIFACT UPGRADE_E2E_INITIAL_SBOM
  UPGRADE_E2E_INITIAL_MANIFEST UPGRADE_E2E_INITIAL_SIGNATURE UPGRADE_E2E_INITIAL_PUBLIC_KEY
  UPGRADE_E2E_FORWARD_BUNDLE UPGRADE_E2E_ROLLBACK_BUNDLE
)
validate_contract() {
  [ -f "${AUTHORITY}" ] && [ ! -L "${AUTHORITY}" ] || fail 'missing-authoritative-input-contract'
  [ -f "${CONTRACT}" ] && [ ! -L "${CONTRACT}" ] || fail 'missing-bootstrap-contract'
  jq -e --argjson expected "$(jq -c '.ops08.local_source_inputs' "${AUTHORITY}")" \
    --argjson generated "$(jq -c '.generated_source_inputs' "${CONTRACT}")" \
    --argjson upstream "$(jq -c '.upstream_source_inputs' "${CONTRACT}")" '
    .schema == "cdnca:upgrade-e2e-source-bootstrap:v1" and
    .source_count == 21 and .generated_source_count == 11 and .upstream_source_count == 10 and
    ($expected | length == 21) and (($expected | sort) == (($generated + $upstream) | sort)) and
    ($generated | length == 11) and ($upstream | length == 10)
  ' "${CONTRACT}" >/dev/null || fail 'source-contract-drift'
}

validate_fixture_sql() {
  local path=$1 label=$2
  require_regular "${path}" "${label}" 1048576
  grep -Eq '[[:graph:]]' "${path}" || fail "empty-${label}"
  ! grep -Eiq '\(connect|copy[[:space:]].*program|lo_import|lo_export|(^|[[:space:];])include([[:space:]]|$)' "${path}" || \
    fail "unsafe-command-${label}"
  ! grep -Eiq 'control_upgrade_rollout_(plans|events)|control_upgrade_node_commands|control_upgrade_(command_)?outbox|control_upgrade_status_receipts|upgrade_grant_receipts|deployment_status_events|agent_command|terminal_state' "${path}" || \
    fail "runtime-facts-in-${label}"
}

validate_upstream_inputs() {
  local name path
  for name in "${UPSTREAM_NAMES[@]}"; do
    path=${!name-}
    [ -n "${path}" ] || fail "missing-upstream-${name}"
    case "${name}" in
      UPGRADE_E2E_LICENSE_AUTHORITY_FIXTURE_SQL) validate_fixture_sql "${path}" "${name}" ;;
      UPGRADE_E2E_CONTROL_AUTHORITY_FIXTURE_SQL) validate_fixture_sql "${path}" "${name}" ;;
      CONTROL_ACTIVATION_CREDENTIAL_FILE) require_regular "${path}" "${name}" 8192; require_owner_only "${path}" "${name}" ;;
      *) require_regular "${path}" "${name}" 285229182 ;;
    esac
  done
}

validate_optional_sources() {
  local name path
  for name in ENTITLEMENT_TRUSTED_KEYS_FILE CONTROL_INSTALLATION_PRIVATE_KEY_FILE \
    CONTROL_UPGRADE_COMMAND_GRANT_TRUST_FILE CONTROL_UPGRADE_CONTROL_SIGNING_PRIVATE_KEY_FILE \
    CONTROL_UPGRADE_EDGE_SIGNING_PRIVATE_KEY_FILE; do
    path=${!name-}
    [ -z "${path}" ] || { require_regular "${path}" "${name}" 1048576; require_owner_only "${path}" "${name}"; }
  done
  if [ -n "${UPGRADE_E2E_EDGE_CONFIG_JSON:-}" ]; then
    require_regular "${UPGRADE_E2E_EDGE_CONFIG_JSON}" UPGRADE_E2E_EDGE_CONFIG_JSON 1048576
    jq -e type "${UPGRADE_E2E_EDGE_CONFIG_JSON}" >/dev/null || fail 'invalid-edge-config-json'
  fi
}

write_pem_key() {
  local path=$1 source=${2:-}
  if [ -n "${source}" ]; then
    copy_input CONTROL_UPGRADE_KEY "${source}" "${path}" 0600
  else
    openssl genpkey -algorithm ED25519 -out "${path}" >/dev/null 2>&1 || fail "generate-key-${path##*/}"
    chmod 0600 "${path}" || fail "mode-key-${path##*/}"
  fi
}

write_public_pem() {
  local private=$1 public=$2
  openssl pkey -in "${private}" -pubout -out "${public}" >/dev/null 2>&1 || fail "derive-public-${private##*/}"
  chmod 0400 "${public}" || fail "mode-public-${public##*/}"
}

write_trust_file() {
  local destination=$1 key_id=$2 public=$3
  jq -S -n --arg key_id "${key_id}" --rawfile public "${public}" \
    '{version:1,keys:[{key_id:$key_id,public_key_pem:$public}]}' >"${destination}" || fail "write-trust-${destination##*/}"
  chmod 0600 "${destination}" || fail "mode-trust-${destination##*/}"
}

write_entitlement_trust() {
  local destination=$1 public_der=$2 raw=$3 raw_b64
  openssl pkey -in "${CONTROL_KEY}" -pubout -outform DER -out "${public_der}" >/dev/null 2>&1 || fail 'derive-entitlement-public'
  tail -c 32 "${public_der}" >"${raw}" || fail 'extract-entitlement-public'
  raw_b64=$(openssl base64 -A -in "${raw}" | tr '+/' '-_' | tr -d '=') || fail 'encode-entitlement-public'
  jq -S -n --arg key_id local-control-v1 --arg public_key "${raw_b64}" \
    '{keys:[{key_id:$key_id,public_key:$public_key}]}' >"${destination}" || fail 'write-entitlement-trust'
  chmod 0600 "${destination}" || fail 'mode-entitlement-trust'
}

write_config() {
  local destination=$1 material=$2 installation_id=$3
  jq -S -c --arg installation_id "${installation_id}" \
    --arg artifact "${material}/edge-artifact-trust.json" \
    --arg control "${material}/edge-control-execution-trust.json" \
    --arg edge "${material}/edge-execution-trust.json" \
    --arg receipt "${material}/edge-installer-receipt-trust.json" \
    --arg ca "${material}/download-ca.pem" '
    del(.node_id, .artifact_encryption_key_id, .gateway.client_certificate_file,
      .gateway.client_private_key_file) |
    .version = 2 |
    .identity_dir = "/etc/cdnca-edge-agent/identity" |
    .gateway.address = "gateway.internal:8444" |
    .gateway.server_name = "gateway.internal" |
    .gateway.root_ca_file = $ca |
    .artifact_trust_file = $artifact |
    .upgrade = {
      enabled: true, installation_id: $installation_id,
      root: "/var/lib/cdnca-edge-agent/upgrades",
      control_execution_trust_file: $control,
      edge_execution_trust_file: $edge,
      installer_receipt_trust_file: $receipt,
      download_host: "control.internal", download_addresses: ["192.0.2.10"],
      download_port: 8445, download_root_ca_file: $ca,
      timeout: "5m", max_artifact_bytes: 134217728, disk_reserve_bytes: 1048576
    }
  ' "${REPO_ROOT}/agents/edge-agent/packaging/config/config.example.json" >"${destination}" || fail 'write-edge-config'
  chmod 0600 "${destination}" || fail 'mode-edge-config'
}

main() {
  local output_env='' parent base manifest material stage temp_env temp_manifest name path value
  local initial_version forward_version manifest_generated manifest_upstream
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --output) [ "$#" -ge 2 ] || usage; output_env=$2; shift 2 ;;
      *) usage ;;
    esac
  done
  [ -n "${output_env}" ] || usage
  require_absolute_clean "${output_env}" output
  case "${output_env}" in "${REPO_ROOT}"|"${REPO_ROOT}"/*) fail 'output-must-be-outside-repository' ;; esac
  parent=$(dirname -- "${output_env}")
  base=$(basename -- "${output_env}")
  [ -d "${parent}" ] && [ ! -L "${parent}" ] || fail 'output-parent-must-exist'
  manifest="${output_env}.manifest.json"
  material="${output_env}.inputs"
  for path in "${output_env}" "${manifest}" "${material}"; do
    [ ! -e "${path}" ] && [ ! -L "${path}" ] || fail "output-already-exists-${path##*/}"
  done
  for command in awk chmod cp dirname grep jq mktemp mv openssl shasum stat tail tr; do
    command -v "${command}" >/dev/null 2>&1 || fail "missing-command-${command}"
  done
  validate_contract
  validate_upstream_inputs
  validate_optional_sources
  initial_version=${UPGRADE_E2E_INITIAL_VERSION:-1.0.0}
  forward_version=${UPGRADE_E2E_FORWARD_VERSION:-1.1.0}
  valid_version "${initial_version}" || fail 'invalid-initial-version'
  valid_version "${forward_version}" || fail 'invalid-forward-version'
  [ "${initial_version}" != "${forward_version}" ] || fail 'local-release-versions-not-distinct'
  [ -f "${REPO_ROOT}/agents/edge-agent/packaging/config/config.example.json" ] || fail 'missing-edge-config-template'

  stage=$(mktemp -d "${parent}/.${base}.bootstrap.XXXXXX") || fail 'create-staging'
  trap 'rm -rf -- "${stage}"' EXIT HUP INT TERM
  chmod 0700 "${stage}" || fail 'mode-staging'
  mkdir "${stage}/inputs" || fail 'create-material-directory'
  chmod 0700 "${stage}/inputs" || fail 'mode-material-directory'
  temp_env="${stage}/runtime.env.tmp"
  temp_manifest="${stage}/manifest.json.tmp"
  exec 3>"${temp_env}"
  manifest_generated='[]'
  manifest_upstream='[]'

  # Generate trust/signing material only after every required source was preflighted.
  local control_key edge_key control_public edge_public
  CONTROL_KEY="${stage}/inputs/control-upgrade-control-signing-private-key-file"
  EDGE_KEY="${stage}/inputs/control-upgrade-edge-signing-private-key-file"
  control_key=${CONTROL_KEY}; edge_key=${EDGE_KEY}
  write_pem_key "${control_key}" "${CONTROL_UPGRADE_CONTROL_SIGNING_PRIVATE_KEY_FILE:-}"
  write_pem_key "${edge_key}" "${CONTROL_UPGRADE_EDGE_SIGNING_PRIVATE_KEY_FILE:-}"
  control_public="${stage}/control-public.pem"; edge_public="${stage}/edge-public.pem"
  write_public_pem "${control_key}" "${control_public}"
  write_public_pem "${edge_key}" "${edge_public}"

  if [ -n "${CONTROL_UPGRADE_COMMAND_GRANT_TRUST_FILE:-}" ]; then
    copy_input CONTROL_UPGRADE_COMMAND_GRANT_TRUST_FILE \
      "${CONTROL_UPGRADE_COMMAND_GRANT_TRUST_FILE}" \
      "${stage}/inputs/control-upgrade-command-grant-trust-file" 0600
  else
    jq -S -n --arg key_id local-control-v1 --rawfile public "${control_public}" \
      '{version:1,keys:[{key_id:$key_id,public_key_pem:$public}]}' \
      >"${stage}/inputs/control-upgrade-command-grant-trust-file" || fail 'write-command-trust'
  fi
  chmod 0600 "${stage}/inputs/control-upgrade-command-grant-trust-file" || fail 'mode-command-trust'

  local entitlement_input="${stage}/inputs/entitlement-trusted-keys-file"
  if [ -n "${ENTITLEMENT_TRUSTED_KEYS_FILE:-}" ]; then
    copy_input ENTITLEMENT_TRUSTED_KEYS_FILE "${ENTITLEMENT_TRUSTED_KEYS_FILE}" "${entitlement_input}" 0600
  else
    write_entitlement_trust "${entitlement_input}" "${stage}/entitlement-public.der" "${stage}/entitlement-public.raw"
  fi

  local installation_key="${stage}/inputs/control-installation-private-key-file"
  write_pem_key "${installation_key}" "${CONTROL_INSTALLATION_PRIVATE_KEY_FILE:-}"

  local artifact_trust="${stage}/inputs/edge-artifact-trust.json"
  local control_trust="${stage}/inputs/edge-control-execution-trust.json"
  local edge_trust="${stage}/inputs/edge-execution-trust.json"
  local receipt_trust="${stage}/inputs/edge-installer-receipt-trust.json"
  write_trust_file "${artifact_trust}" edge-signing-v1 "${edge_public}"
  write_trust_file "${control_trust}" control-signing-v1 "${control_public}"
  write_trust_file "${edge_trust}" edge-signing-v1 "${edge_public}"
  write_trust_file "${receipt_trust}" edge-signing-v1 "${edge_public}"
  # A placeholder CA is intentionally not a trust assertion; runtime provisioning replaces it.
  printf '%s\n' '-----BEGIN CERTIFICATE-----' 'local-bootstrap-ca-placeholder' '-----END CERTIFICATE-----' >"${stage}/inputs/download-ca.pem"
  chmod 0400 "${stage}/inputs/download-ca.pem"

  local final_material="${material}"
  write_config "${stage}/inputs/upgrade-e2e-edge-config-json" "${final_material}" "$(random_uuid)"
  copy_input UPGRADE_E2E_LICENSE_AUTHORITY_FIXTURE_SQL "${UPGRADE_E2E_LICENSE_AUTHORITY_FIXTURE_SQL}" "${stage}/inputs/upgrade_e2e_license_authority_fixture_sql" 0400
  copy_input UPGRADE_E2E_CONTROL_AUTHORITY_FIXTURE_SQL "${UPGRADE_E2E_CONTROL_AUTHORITY_FIXTURE_SQL}" "${stage}/inputs/upgrade_e2e_control_authority_fixture_sql" 0400
  copy_input CONTROL_ACTIVATION_CREDENTIAL_FILE "${CONTROL_ACTIVATION_CREDENTIAL_FILE}" "${stage}/inputs/control_activation_credential_file" 0600
  copy_input UPGRADE_E2E_INITIAL_ARTIFACT "${UPGRADE_E2E_INITIAL_ARTIFACT}" "${stage}/inputs/upgrade_e2e_initial_artifact" 0400
  copy_input UPGRADE_E2E_INITIAL_SBOM "${UPGRADE_E2E_INITIAL_SBOM}" "${stage}/inputs/upgrade_e2e_initial_sbom" 0400
  copy_input UPGRADE_E2E_INITIAL_MANIFEST "${UPGRADE_E2E_INITIAL_MANIFEST}" "${stage}/inputs/upgrade_e2e_initial_manifest" 0400
  copy_input UPGRADE_E2E_INITIAL_SIGNATURE "${UPGRADE_E2E_INITIAL_SIGNATURE}" "${stage}/inputs/upgrade_e2e_initial_signature" 0400
  copy_input UPGRADE_E2E_INITIAL_PUBLIC_KEY "${UPGRADE_E2E_INITIAL_PUBLIC_KEY}" "${stage}/inputs/upgrade_e2e_initial_public_key" 0400
  copy_input UPGRADE_E2E_FORWARD_BUNDLE "${UPGRADE_E2E_FORWARD_BUNDLE}" "${stage}/inputs/upgrade_e2e_forward_bundle" 0400
  copy_input UPGRADE_E2E_ROLLBACK_BUNDLE "${UPGRADE_E2E_ROLLBACK_BUNDLE}" "${stage}/inputs/upgrade_e2e_rollback_bundle" 0400

  for name in "${UPSTREAM_NAMES[@]}"; do
    case "${name}" in
      UPGRADE_E2E_LICENSE_AUTHORITY_FIXTURE_SQL) path="${material}/upgrade_e2e_license_authority_fixture_sql" ;;
      UPGRADE_E2E_CONTROL_AUTHORITY_FIXTURE_SQL) path="${material}/upgrade_e2e_control_authority_fixture_sql" ;;
      CONTROL_ACTIVATION_CREDENTIAL_FILE) path="${material}/control_activation_credential_file" ;;
      UPGRADE_E2E_INITIAL_ARTIFACT) path="${material}/upgrade_e2e_initial_artifact" ;;
      UPGRADE_E2E_INITIAL_SBOM) path="${material}/upgrade_e2e_initial_sbom" ;;
      UPGRADE_E2E_INITIAL_MANIFEST) path="${material}/upgrade_e2e_initial_manifest" ;;
      UPGRADE_E2E_INITIAL_SIGNATURE) path="${material}/upgrade_e2e_initial_signature" ;;
      UPGRADE_E2E_INITIAL_PUBLIC_KEY) path="${material}/upgrade_e2e_initial_public_key" ;;
      UPGRADE_E2E_FORWARD_BUNDLE) path="${material}/upgrade_e2e_forward_bundle" ;;
      UPGRADE_E2E_ROLLBACK_BUNDLE) path="${material}/upgrade_e2e_rollback_bundle" ;;
    esac
    emit_env "${name}" "${path}"
    manifest_upstream=$(jq -c --arg name "${name}" --arg path "${path}" \
      --arg sha256 "$(sha256_file "${path}")" \
      '. + [{name:$name,path:$path,sha256:$sha256}]' <<<"${manifest_upstream}")
  done
  emit_env UPGRADE_E2E_EDGE_CONFIG_JSON "${material}/upgrade-e2e-edge-config-json"
  emit_env ENTITLEMENT_TRUSTED_KEYS_FILE "${material}/entitlement-trusted-keys-file"
  emit_env CONTROL_INSTALLATION_PRIVATE_KEY_FILE "${material}/control-installation-private-key-file"
  emit_env CONTROL_UPGRADE_COMMAND_GRANT_TRUST_FILE "${material}/control-upgrade-command-grant-trust-file"
  emit_env CONTROL_UPGRADE_CONTROL_SIGNING_PRIVATE_KEY_FILE "${material}/control-upgrade-control-signing-private-key-file"
  emit_env CONTROL_UPGRADE_EDGE_SIGNING_PRIVATE_KEY_FILE "${material}/control-upgrade-edge-signing-private-key-file"
  emit_env UPGRADE_E2E_EDGE_ARTIFACT_TRUST_SHA256 "$(sha256_file "${artifact_trust}")"
  emit_env UPGRADE_E2E_EDGE_CONTROL_EXECUTION_TRUST_SHA256 "$(sha256_file "${control_trust}")"
  emit_env UPGRADE_E2E_EDGE_EXECUTION_TRUST_SHA256 "$(sha256_file "${edge_trust}")"
  emit_env UPGRADE_E2E_INITIAL_VERSION "${initial_version}"
  emit_env UPGRADE_E2E_FORWARD_VERSION "${forward_version}"
  manifest_generated=$(jq -c --arg name UPGRADE_E2E_EDGE_CONFIG_JSON \
    --arg path "${material}/upgrade-e2e-edge-config-json" \
    --arg sha256 "$(sha256_file "${stage}/inputs/upgrade-e2e-edge-config-json")" \
    '. + [{name:$name,path:$path,sha256:$sha256}]' <<<"${manifest_generated}")
  for name in ENTITLEMENT_TRUSTED_KEYS_FILE CONTROL_INSTALLATION_PRIVATE_KEY_FILE \
    CONTROL_UPGRADE_COMMAND_GRANT_TRUST_FILE CONTROL_UPGRADE_CONTROL_SIGNING_PRIVATE_KEY_FILE \
    CONTROL_UPGRADE_EDGE_SIGNING_PRIVATE_KEY_FILE; do
    case "${name}" in
      ENTITLEMENT_TRUSTED_KEYS_FILE) path="${material}/entitlement-trusted-keys-file" ;;
      CONTROL_INSTALLATION_PRIVATE_KEY_FILE) path="${material}/control-installation-private-key-file" ;;
      CONTROL_UPGRADE_COMMAND_GRANT_TRUST_FILE) path="${material}/control-upgrade-command-grant-trust-file" ;;
      CONTROL_UPGRADE_CONTROL_SIGNING_PRIVATE_KEY_FILE) path="${material}/control-upgrade-control-signing-private-key-file" ;;
      CONTROL_UPGRADE_EDGE_SIGNING_PRIVATE_KEY_FILE) path="${material}/control-upgrade-edge-signing-private-key-file" ;;
    esac
    manifest_generated=$(jq -c --arg name "${name}" --arg path "${path}" \
      --arg sha256 "$(sha256_file "${stage}/inputs/${path##*/}")" \
      '. + [{name:$name,path:$path,sha256:$sha256}]' <<<"${manifest_generated}")
  done
  for name in UPGRADE_E2E_EDGE_ARTIFACT_TRUST_SHA256 UPGRADE_E2E_EDGE_CONTROL_EXECUTION_TRUST_SHA256 \
    UPGRADE_E2E_EDGE_EXECUTION_TRUST_SHA256; do
    value=${!name}
    manifest_generated=$(jq -c --arg name "${name}" --arg sha256 "${value}" \
      '. + [{name:$name,sha256:$sha256}]' <<<"${manifest_generated}")
  done
  manifest_generated=$(jq -c --arg name UPGRADE_E2E_INITIAL_VERSION --arg version "${initial_version}" \
    '. + [{name:$name,version:$version}]' <<<"${manifest_generated}")
  manifest_generated=$(jq -c --arg name UPGRADE_E2E_FORWARD_VERSION --arg version "${forward_version}" \
    '. + [{name:$name,version:$version}]' <<<"${manifest_generated}")
  exec 3>&-

  awk -F= 'NF < 2 || seen[$1]++ {exit 1}' "${temp_env}" || fail 'invalid-env-output'
  jq -S -n --arg schema 'cdnca:upgrade-e2e-source-manifest:v1' \
    --arg env "${output_env}" --arg generated_dir "${material}" \
    --argjson generated "${manifest_generated}" --argjson upstream "${manifest_upstream}" \
    '{schema:$schema,env_file:$env,material_directory:$generated_dir,generated_source_inputs:$generated,upstream_source_inputs:$upstream}' \
    >"${temp_manifest}" || fail 'write-manifest'
  chmod 0600 "${temp_manifest}"
  mv -- "${stage}/inputs" "${material}" || fail 'publish-material-directory'
  mv -- "${temp_manifest}" "${manifest}" || fail 'publish-manifest'
  mv -- "${temp_env}" "${output_env}" || fail 'publish-env'
  chmod 0600 "${output_env}" "${manifest}"
  trap - EXIT HUP INT TERM
  rm -rf -- "${stage}"
  printf 'UPGRADE_SOURCE_BOOTSTRAP PASS generated=11 upstream=10 env=%s manifest=%s resources=0\n' "${output_env}" "${manifest}"
}

validate_contract
main "$@"
