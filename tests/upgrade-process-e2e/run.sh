#!/usr/bin/env bash
# Runtime bindings consume only frozen external manifests and the canonical local contracts.
# shellcheck disable=SC2016,SC2030,SC2031,SC2317,SC2329
if [ "${UPGRADE_E2E_BASH_REEXEC:-0}" != '1' ]; then
  export UPGRADE_E2E_BASH_REEXEC=1
  exec bash "$0" "$@"
fi
set -Eeuo pipefail
umask 077

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly SCRIPT_DIR
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/../.." && pwd -P)"
readonly REPO_ROOT

readonly POSTGRES_IMAGE='postgres:17.9-alpine'
readonly NATS_IMAGE='nats:2.11.4-alpine'
readonly NATS_BOX_IMAGE='natsio/nats-box:0.19.1'
readonly REDIS_IMAGE='redis:7.4.4-alpine'
SYSTEMD_IMAGE=''
SYSTEMD_AMD64_SUBJECT=''
SYSTEMD_ARM64_SUBJECT=''
SYSTEMD_COSIGN_IDENTITY=''
SYSTEMD_COSIGN_ISSUER=''
SYSTEMD_PROVENANCE_PREDICATE_TYPE=''
SYSTEMD_SPDX_PREDICATE_TYPE=''
readonly TLS_PROXY_IMAGE='nginx:1.28.0-alpine'
readonly TASK_LABEL_KEY='cdnca.upgrade-process-e2e'
readonly RESOURCE_ROLE_LABEL_KEY='cdnca.upgrade-process-e2e.role'
readonly LICENSE_MIGRATION_HEAD='046'
readonly CONTROL_MIGRATION_HEAD='186'
readonly GATEWAY_WORKLOAD_URI='spiffe://cdn-platform/gateway/control'
readonly -a CONTROL_MIGRATION_MANIFEST_PATHS=(
  'services/control-api/migrations/096_upgrade_runtime_control.down.sql'
  'services/control-api/migrations/096_upgrade_runtime_control.up.sql'
  'services/control-api/migrations/upgrade_runtime_control_096_integration_test.go'
  'services/control-api/migrations/097_upgrade_license_receipt_delivery.down.sql'
  'services/control-api/migrations/097_upgrade_license_receipt_delivery.up.sql'
  'services/control-api/migrations/upgrade_license_receipt_delivery_097_integration_test.go'
  'services/control-api/migrations/098_analytics_ingest_history_authority.down.sql'
  'services/control-api/migrations/098_analytics_ingest_history_authority.up.sql'
  'services/control-api/migrations/analytics_ingest_history_authority_098_integration_test.go'
  'services/control-api/migrations/099_billing_adjustment_denial_receipts.down.sql'
  'services/control-api/migrations/099_billing_adjustment_denial_receipts.up.sql'
  'services/control-api/migrations/billing_adjustment_denial_receipts_099_integration_test.go'
  'services/control-api/migrations/100_billing_adjustment_approval_authority.down.sql'
  'services/control-api/migrations/100_billing_adjustment_approval_authority.up.sql'
  'services/control-api/migrations/billing_adjustment_approval_100_integration_test.go'
  'services/control-api/migrations/101_upgrade_dual_sequence.down.sql'
  'services/control-api/migrations/101_upgrade_dual_sequence.up.sql'
  'services/control-api/migrations/upgrade_dual_sequence_101_integration_test.go'
  'services/control-api/migrations/102_upgrade_status_puback_identity.down.sql'
  'services/control-api/migrations/102_upgrade_status_puback_identity.up.sql'
  'services/control-api/migrations/upgrade_status_puback_identity_102_integration_test.go'
)
readonly -a CONTROL_FIXTURE_IDENTITY_VARIABLES=(
  e2e_node_certificate_serial
  e2e_node_leaf_der_sha256
  e2e_node_artifact_key_id
  e2e_node_artifact_public_key_hex
)

upgrade_e2e_fail() {
  printf 'UPGRADE_PROCESS_E2E_FAIL stage=%s\n' "$1" >&2
  exit 1
}

upgrade_e2e_unknown() {
  printf 'UPGRADE_PROCESS_E2E_UNKNOWN reason=%s\n' "$1" >&2
  exit 77
}

upgrade_e2e_sha256() {
  shasum -a 256 -- "$1" | awk '{print $1}'
}

upgrade_e2e_valid_sha256() {
  [[ "$1" =~ ^[0-9a-f]{64}$ ]]
}

upgrade_e2e_regular_file_size() {
  perl -MFcntl=:DEFAULT,:mode -e '
    use strict;
    use warnings;
    my ($path) = @ARGV;
    my @before = lstat $path or exit 2;
    exit 2 unless S_ISREG($before[2]);
    my $no_follow = eval { Fcntl::O_NOFOLLOW() } // 0;
    sysopen my $input, $path, O_RDONLY | $no_follow or exit 2;
    my @opened = stat $input or exit 2;
    close $input or exit 2;
    my @after = lstat $path or exit 2;
    exit 2 unless $before[0] == $opened[0] && $before[1] == $opened[1] &&
      $before[0] == $after[0] && $before[1] == $after[1] &&
      $before[7] == $after[7] && $before[9] == $after[9];
    print $opened[7];
  ' "$1"
}

upgrade_e2e_require_command() {
  command -v "$1" >/dev/null 2>&1 || upgrade_e2e_unknown "missing-command-$1"
}

upgrade_e2e_require_file() {
  local path=$1
  [ -f "${path}" ] && [ ! -L "${path}" ] && [ -r "${path}" ] || \
    upgrade_e2e_unknown "missing-or-unsafe-${2}"
}

upgrade_e2e_require_env() {
  local name=$1 value
  value=${!name-}
  [ -n "${value}" ] || upgrade_e2e_unknown "missing-env-${name}"
  printf '%s' "${value}"
}

upgrade_e2e_validate_contract_file() {
  local path=$1 canonical
  upgrade_e2e_require_file "${path}" process-contract
  canonical=$(jq -S -c . "${path}") || return 1
  cmp -s <(printf '%s\n' "${canonical}") "${path}" || return 1
  jq -e '
    keys == [
      "edge_command_schema",
      "edge_status_schema",
      "execution_schema",
      "license_receipt_request_schema",
      "license_receipt_response_schema",
      "nats_placeholders",
      "rollout_plan_schema_version",
      "status_delivery_identity_schema",
      "systemd_attestation_predicate_types",
      "systemd_image_evidence_schema",
      "systemd_image_platforms"
    ] and
    .edge_command_schema == "cdnca.edge.upgrade.command/v1" and
    .edge_status_schema == "cdnca.edge.upgrade.status/v1" and
    .execution_schema == "cdnca.upgrade.execution/v2" and
    .license_receipt_request_schema == "upgrade-grant.receipt-request/v2" and
    .license_receipt_response_schema == "upgrade-grant.receipt-response/v1" and
    .rollout_plan_schema_version == 2 and
    .status_delivery_identity_schema == "cdnca.control-upgrade.status-delivery/v1" and
    .systemd_attestation_predicate_types == {
      "provenance":"https://slsa.dev/provenance/v0.2",
      "spdx":"https://spdx.dev/Document"
    } and
    .systemd_image_evidence_schema == "cdnca.edge.systemd-image-evidence/v1" and
    .systemd_image_platforms == ["linux/amd64","linux/arm64"] and
    (.nats_placeholders | type == "object" and
      keys == ["filter_subject","resource_name"] and
      .filter_subject == "${NODE_ID}" and
      .resource_name == "${NODE_ID_UNDERSCORE}")
  ' "${path}" >/dev/null
}

upgrade_e2e_validate_nats_resources() {
  local path=$1 canonical
  canonical=$(jq -S -c . "${path}") || return 1
  cmp -s <(printf '%s\n' "${canonical}") "${path}" || return 1
  jq -e '
    def stream_config_keys:
      ["allow_direct","allow_msg_ttl","allow_rollup_hdrs","compression","consumer_limits",
       "deny_delete","deny_purge","description","discard","discard_new_per_subject",
       "duplicate_window","first_seq","max_age","max_bytes","max_consumers","max_msg_size",
       "max_msgs","max_msgs_per_subject","metadata","mirror","mirror_direct","name",
       "no_ack","num_replicas","placement","republish","retention","sealed","sources",
       "storage","subject_delete_marker_ttl","subject_transform","subjects","template_owner"];
    def consumer_config_keys:
      ["ack_policy","ack_wait","backoff","deliver_group","deliver_policy","deliver_subject",
       "description","durable_name","filter_subject","filter_subjects","flow_control",
       "headers_only","idle_heartbeat","inactive_threshold","max_ack_pending","max_batch",
       "max_bytes","max_deliver","max_expires","max_waiting","mem_storage","metadata",
       "name","num_replicas","opt_start_seq","opt_start_time","rate_limit_bps",
       "replay_policy","sample_freq"];
    def common_stream:
      (.config | keys == stream_config_keys) and
      .config.allow_direct == false and .config.allow_msg_ttl == false and
      .config.allow_rollup_hdrs == false and .config.compression == "none" and
      .config.consumer_limits == {"inactive_threshold":0,"max_ack_pending":0} and
      .config.deny_delete == false and .config.deny_purge == false and
      .config.description == "" and .config.discard == "old" and
      .config.discard_new_per_subject == false and .config.duplicate_window == 120000000000 and
      .config.first_seq == 0 and .config.max_age == 0 and .config.max_bytes == -1 and
      .config.max_consumers == -1 and .config.max_msg_size == -1 and
      .config.max_msgs == -1 and .config.max_msgs_per_subject == -1 and
      .config.metadata == {} and .config.mirror == null and .config.mirror_direct == false and
      .config.no_ack == false and .config.num_replicas == 1 and .config.placement == null and
      .config.republish == null and .config.retention == "limits" and .config.sealed == false and
      .config.sources == [] and .config.storage == "file" and
      .config.subject_delete_marker_ttl == 0 and .config.subject_transform == null and
      .config.template_owner == "" and .name == .config.name;
    def common_consumer:
      (.config | keys == consumer_config_keys) and
      .config.ack_policy == "explicit" and .config.backoff == [] and
      .config.deliver_group == "" and .config.deliver_policy == "all" and
      .config.deliver_subject == "" and .config.description == "" and
      .config.flow_control == false and
      .config.headers_only == false and .config.idle_heartbeat == 0 and
      .config.inactive_threshold == 0 and .config.max_batch == 1 and
      .config.max_deliver == -1 and .config.mem_storage == false and
      .config.metadata == {} and .config.num_replicas == 0 and
      .config.opt_start_seq == 0 and .config.opt_start_time == null and
      .config.rate_limit_bps == 0 and .config.replay_policy == "instant" and
      .config.sample_freq == "" and .name == .config.name and
      .name == .config.durable_name;
    keys == ["consumers","streams"] and
    (.streams | type == "array" and length == 3) and
    (.consumers | type == "array" and length == 4) and
    ([.streams[].name] | sort) == ["AGENT_COMMANDS","AGENT_DEPLOYMENT_STATUS","AGENT_HEARTBEATS"] and
    ([.consumers[].name] | sort) == [
      "control_api_edge_status","control_api_node_presence","control_api_upgrade_status",
      "node_upgrade_${NODE_ID_UNDERSCORE}"
    ] and
    all(.streams[]; (keys == ["config","name"]) and common_stream) and
    all(.consumers[]; (keys == ["config","name","stream"]) and common_consumer) and
    (.streams | map({key:.name,value:.config.subjects}) | from_entries) == {
      "AGENT_COMMANDS":[
        "cdnca.agent.commands.*","cdnca.agent.commands.acme-http01.*",
        "cdnca.agent.commands.cache.*","cdnca.agent.commands.cache-dlq.*",
        "cdnca.agent.commands.upgrade.*","cdnca.agent.commands.drain.*",
        "cdnca.agent.commands.gateway-port.*"
      ],
      "AGENT_DEPLOYMENT_STATUS":[
        "cdnca.agent.deployment-status.*","cdnca.agent.deployment-status.generic-v2.*.*",
        "cdnca.agent.deployment-status.terminal-receipt.*.*",
        "cdnca.agent.deployment-status.terminal-receipt-confirmation.*.*",
        "cdnca.agent.deployment-status.terminal-receipt-confirmation-index.*",
        "cdnca.agent.deployment-status.acme-http01.*",
        "cdnca.agent.deployment-status.cache.*","cdnca.agent.deployment-status.cache-dlq.*","cdnca.agent.deployment-status.upgrade.*",
        "cdnca.agent.deployment-status.upgrade-v2.*",
        "cdnca.agent.deployment-status.upgrade-proof.pending.*",
        "cdnca.agent.deployment-status.upgrade-proof.confirmed.*.*",
        "cdnca.agent.deployment-status.upgrade-proof.completed.*.*.*",
        "cdnca.agent.deployment-status.upgrade-proof.status.*.*",
        "cdnca.agent.deployment-status.drain.*",
        "cdnca.agent.deployment-status.gateway-port.*"
      ],
      "AGENT_HEARTBEATS":["cdnca.agent.heartbeats.*"]
    } and
    (.consumers | map({key:.name,value:{
      stream:.stream,filter:.config.filter_subject,filters:.config.filter_subjects,ack_wait:.config.ack_wait,
      pending:.config.max_ack_pending,max_bytes:.config.max_bytes,
      expires:.config.max_expires,waiting:.config.max_waiting
    }}) | from_entries) == {
      "control_api_edge_status":{
        stream:"AGENT_DEPLOYMENT_STATUS",filter:"",filters:[
          "cdnca.agent.deployment-status.*","cdnca.agent.deployment-status.generic-v2.*.*"
        ],
        ack_wait:120000000000,pending:256,max_bytes:0,expires:5000000000,waiting:32
      },
      "control_api_node_presence":{
        stream:"AGENT_HEARTBEATS",filter:"cdnca.agent.heartbeats.*",filters:[],
        ack_wait:30000000000,pending:256,max_bytes:0,expires:5000000000,waiting:32
      },
      "control_api_upgrade_status":{
        stream:"AGENT_DEPLOYMENT_STATUS",filter:"",filters:[
          "cdnca.agent.deployment-status.upgrade.*",
          "cdnca.agent.deployment-status.upgrade-v2.*"
        ],
        ack_wait:120000000000,pending:64,max_bytes:262144,expires:2000000000,waiting:16
      },
      "node_upgrade_${NODE_ID_UNDERSCORE}":{
        stream:"AGENT_COMMANDS",filter:"cdnca.agent.commands.upgrade.${NODE_ID}",filters:[],
        ack_wait:120000000000,pending:8,max_bytes:262144,expires:5000000000,waiting:32
      }
    } and
    ([.. | strings | select(contains("${"))] | sort) == [
      "cdnca.agent.commands.upgrade.${NODE_ID}",
      "node_upgrade_${NODE_ID_UNDERSCORE}",
      "node_upgrade_${NODE_ID_UNDERSCORE}",
      "node_upgrade_${NODE_ID_UNDERSCORE}"
    ]
  ' "${path}" >/dev/null
}

upgrade_e2e_validate_authority_fixture() {
  local path=$1
  upgrade_e2e_require_file "${path}" authority-fixture
  grep -Eq '[[:graph:]]' "${path}" || return 1
  ! grep -Eiq '\\(connect|copy|include)|copy[[:space:]].*program|lo_import|lo_export' "${path}" || return 1
  ! grep -Eiq 'control_upgrade_rollout_(plans|events)|control_upgrade_node_commands|control_upgrade_(command_)?outbox|control_upgrade_status_receipts|control_upgrade_license_receipt_(outbox|deliveries)_097|upgrade_grant_receipts|deployment_status_events|agent_command|terminal_state' "${path}" || return 1
}

upgrade_e2e_validate_control_authority_fixture() {
  local path=$1 variable literal_count total_count
  upgrade_e2e_validate_authority_fixture "${path}" || return 1
  [ "${#CONTROL_FIXTURE_IDENTITY_VARIABLES[@]}" -eq 4 ] || return 1
  for variable in "${CONTROL_FIXTURE_IDENTITY_VARIABLES[@]}"; do
    literal_count=$(grep -Fo -- ":'${variable}'" "${path}" | wc -l | tr -d ' ') || return 1
    total_count=$(grep -Fo -- "${variable}" "${path}" | wc -l | tr -d ' ') || return 1
    [ "${literal_count}" -eq 1 ] && [ "${total_count}" -eq 1 ] || return 1
  done
}

upgrade_e2e_snapshot_json_input() {
  local label=$1 path_name=$2 sha_name=$3 destination=$4 source expected actual canonical
  source="$(upgrade_e2e_require_env "${path_name}")"
  expected="$(upgrade_e2e_require_env "${sha_name}")"
  upgrade_e2e_valid_sha256 "${expected}" || upgrade_e2e_unknown "invalid-${label}-sha256"
  upgrade_e2e_snapshot_external_file "${source}" "${destination}" || upgrade_e2e_unknown "${label}-copy"
  actual=$(upgrade_e2e_sha256_regular_file "${destination}") || upgrade_e2e_unknown "${label}-read"
  [ "${actual}" = "${expected}" ] || upgrade_e2e_unknown "${label}-drift"
  canonical=$(jq -S -c . "${destination}") || upgrade_e2e_unknown "${label}-json"
  cmp -s <(printf '%s\n' "${canonical}") "${destination}" || upgrade_e2e_unknown "${label}-canonical"
}

upgrade_e2e_snapshot_input_pair() {
  local label=$1 path_name=$2 sha_name=$3 destination=$4 source expected actual
  source="$(upgrade_e2e_require_env "${path_name}")"
  expected="$(upgrade_e2e_require_env "${sha_name}")"
  upgrade_e2e_valid_sha256 "${expected}" || upgrade_e2e_unknown "invalid-${label}-sha256"
  upgrade_e2e_snapshot_external_file "${source}" "${destination}" || upgrade_e2e_unknown "${label}-copy"
  actual=$(upgrade_e2e_sha256_regular_file "${destination}") || upgrade_e2e_unknown "${label}-read"
  [ "${actual}" = "${expected}" ] || upgrade_e2e_unknown "${label}-drift"
}

upgrade_e2e_sha256_regular_file() {
  perl -MDigest::SHA -MFcntl=:DEFAULT,:mode -e '
    use strict;
    use warnings;
    my ($path) = @ARGV;
    my @before = lstat $path or exit 2;
    exit 2 unless S_ISREG($before[2]);
    my $no_follow = eval { Fcntl::O_NOFOLLOW() } // 0;
    sysopen my $input, $path, O_RDONLY | $no_follow or exit 2;
    binmode $input;
    my @opened = stat $input or exit 2;
    exit 2 unless $before[0] == $opened[0] && $before[1] == $opened[1];
    my $sha = Digest::SHA->new(256);
    $sha->addfile($input);
    close $input or exit 2;
    my @after = lstat $path or exit 2;
    exit 2 unless $before[0] == $after[0] && $before[1] == $after[1] &&
      $before[7] == $after[7] && $before[9] == $after[9];
    print $sha->hexdigest;
  ' "$1"
}

upgrade_e2e_copy_regular_file() {
  local source=$1 destination=$2
  perl -MFcntl=:DEFAULT,:mode -e '
    use strict;
    use warnings;
    my ($source, $destination) = @ARGV;
    my @before = lstat $source or exit 2;
    exit 2 unless S_ISREG($before[2]);
    my $no_follow = eval { Fcntl::O_NOFOLLOW() } // 0;
    sysopen my $input, $source, O_RDONLY | $no_follow or exit 2;
    binmode $input;
    my @opened = stat $input or exit 2;
    exit 2 unless $before[0] == $opened[0] && $before[1] == $opened[1];
    sysopen my $output, $destination, O_WRONLY | O_CREAT | O_EXCL, 0400 or exit 2;
    binmode $output;
    while (1) {
      my $buffer = "";
      my $read = read $input, $buffer, 1024 * 1024;
      exit 2 unless defined $read;
      last if $read == 0;
      my $offset = 0;
      while ($offset < length $buffer) {
        my $written = syswrite $output, $buffer, length($buffer) - $offset, $offset;
        exit 2 unless defined $written && $written > 0;
        $offset += $written;
      }
    }
    close $output or exit 2;
    close $input or exit 2;
    my @after = lstat $source or exit 2;
    exit 2 unless $before[0] == $after[0] && $before[1] == $after[1] &&
      $before[7] == $after[7] && $before[9] == $after[9];
    chmod 0444, $destination or exit 2;
  ' "${source}" "${destination}"
}

upgrade_e2e_canonical_repo_file() {
  local relative=$1 directory base physical
  [[ "${relative}" =~ ^[A-Za-z0-9][A-Za-z0-9._/-]*$ ]] || return 1
  case "/${relative}/" in *//*|*/./*|*/../*) return 1 ;; esac
  directory=${relative%/*}
  base=${relative##*/}
  [ "${directory}" != "${relative}" ] || directory='.'
  physical=$(cd -- "${REPO_ROOT}/${directory}" 2>/dev/null && pwd -P) || return 1
  case "${physical}" in "${REPO_ROOT}"|"${REPO_ROOT}"/*) ;; *) return 1 ;; esac
  [ -f "${physical}/${base}" ] && [ ! -L "${physical}/${base}" ] && [ -r "${physical}/${base}" ] || return 1
  printf '%s' "${physical}/${base}"
}

upgrade_e2e_edge_inventory() {
  local repo_root=$1 repo_physical edge_root edge_physical unsafe
  local source relative directory base physical expected_directory digest count
  [ -d "${repo_root}" ] && [ ! -L "${repo_root}" ] || return 1
  repo_physical=$(cd -- "${repo_root}" 2>/dev/null && pwd -P) || return 1
  [ "${repo_physical}" = "${repo_root}" ] || return 1
  edge_root="${repo_root}/agents/edge-agent"
  [ -d "${edge_root}" ] && [ ! -L "${edge_root}" ] || return 1
  edge_physical=$(cd -- "${edge_root}" 2>/dev/null && pwd -P) || return 1
  [ "${edge_physical}" = "${edge_root}" ] || return 1
  unsafe=$(find "${edge_root}" \( -type l -o \( ! -type d ! -type f \) \) -print -quit) || return 1
  [ -z "${unsafe}" ] || return 1
  find "${edge_root}" -type f -print0 |
    (
      count=0
      while IFS= read -r -d '' source; do
        relative=${source#"${repo_root}/"}
        [ "${relative}" != "${source}" ] || exit 1
        [[ "${relative}" =~ ^[A-Za-z0-9][A-Za-z0-9._/-]*$ ]] || exit 1
        case "/${relative}/" in *//*|*/./*|*/../*) exit 1 ;; esac
        directory=${relative%/*}
        base=${relative##*/}
        [ "${directory}" != "${relative}" ] || directory='.'
        physical=$(cd -- "${repo_root}/${directory}" 2>/dev/null && pwd -P) || exit 1
        if [ "${directory}" = '.' ]; then
          expected_directory=${repo_root}
        else
          expected_directory="${repo_root}/${directory}"
        fi
        [ "${physical}" = "${expected_directory}" ] || exit 1
        [ "${physical}/${base}" = "${source}" ] || exit 1
        digest=$(upgrade_e2e_sha256_regular_file "${source}") || exit 1
        upgrade_e2e_valid_sha256 "${digest}" || exit 1
        printf '%s  %s\n' "${digest}" "${relative}" || exit 1
        count=$((count + 1))
      done
      [ "${count}" -gt 0 ]
    ) | LC_ALL=C sort
}

upgrade_e2e_edge_manifest_matches() {
  local repo_root=$1 manifest=$2 inventory
  [ -f "${manifest}" ] && [ ! -L "${manifest}" ] && [ -r "${manifest}" ] || return 1
  inventory=$(upgrade_e2e_edge_inventory "${repo_root}") || return 1
  cmp -s "${manifest}" <(printf '%s\n' "${inventory}")
}

upgrade_e2e_validate_external_pair() {
  local label=$1 path_name=$2 sha_name=$3 source expected actual
  source="$(upgrade_e2e_require_env "${path_name}")"
  expected="$(upgrade_e2e_require_env "${sha_name}")"
  upgrade_e2e_valid_sha256 "${expected}" || upgrade_e2e_unknown "invalid-${label}-sha256"
  upgrade_e2e_require_file "${source}" "${label}"
  actual=$(upgrade_e2e_sha256_regular_file "${source}") || upgrade_e2e_unknown "${label}-read"
  [ "${actual}" = "${expected}" ] || upgrade_e2e_unknown "${label}-drift"
  last_validated_external_file=${source}
}

upgrade_e2e_validate_external_sized_pair() {
  local label=$1 path_name=$2 sha_name=$3 size_name=$4 expected_size actual_size
  upgrade_e2e_validate_external_pair "${label}" "${path_name}" "${sha_name}"
  expected_size="$(upgrade_e2e_require_env "${size_name}")"
  [[ "${expected_size}" =~ ^[1-9][0-9]*$ ]] || upgrade_e2e_unknown "invalid-${label}-size"
  actual_size=$(upgrade_e2e_regular_file_size "${last_validated_external_file}") || \
    upgrade_e2e_unknown "${label}-size-read"
  [ "${actual_size}" = "${expected_size}" ] || upgrade_e2e_unknown "${label}-size-drift"
}

upgrade_e2e_validate_live_manifest() {
  local label=$1 path_name=$2 sha_name=$3 manifest digest relative source
  upgrade_e2e_validate_external_pair "${label}-manifest" "${path_name}" "${sha_name}"
  manifest=${last_validated_external_file}
  LC_ALL=C sort -c -u "${manifest}" >/dev/null 2>&1 || upgrade_e2e_unknown "${label}-manifest-order"
  awk '
    !/^[0-9a-f]{64}  [A-Za-z0-9][A-Za-z0-9._\/-]*$/ {exit 1}
    index("/" $2 "/", "/../") || index("/" $2 "/", "/./") || index($2, "//") || substr($2, 1, 1) == "/" {exit 1}
    END {if (NR == 0) exit 1}
  ' "${manifest}" || upgrade_e2e_unknown "${label}-manifest-format"
  while IFS='  ' read -r digest relative; do
    source=$(upgrade_e2e_canonical_repo_file "${relative}") || upgrade_e2e_unknown "${label}-manifest-path"
    [ "$(upgrade_e2e_sha256_regular_file "${source}")" = "${digest}" ] || \
      upgrade_e2e_unknown "${label}-manifest-input-drift"
  done <"${manifest}"
  last_validated_manifest=${manifest}
}

upgrade_e2e_validate_live_edge_manifest() {
  upgrade_e2e_validate_live_manifest c "$1" "$2"
  upgrade_e2e_edge_manifest_matches "${REPO_ROOT}" "${last_validated_manifest}" || \
    upgrade_e2e_unknown 'c-manifest-members'
  upgrade_e2e_manifest_has "${last_validated_manifest}" \
    '^agents/edge-agent/packaging/build/contract\.json$'
  upgrade_e2e_validate_edge_release_build_contract \
    "${REPO_ROOT}/agents/edge-agent/packaging/build/contract.json" || \
    upgrade_e2e_unknown 'edge-release-build-contract'
}

upgrade_e2e_validate_edge_release_build_contract() {
  jq -e '
    keys == ["architectures","builder","recipe","schema","source_roots"] and
    .schema == "cdnca.edge.release-build/v1" and .builder.toolchain == "go1.27.3" and
    (.builder.image | test("^docker\\.io/library/golang:1\\.27\\.3-bookworm@sha256:[0-9a-f]{64}$")) and
    .source_roots == ["agents/edge-agent","libs/autodefense/detect","libs/autodefense/mine","libs/autodefense/sketch","libs/edgeconfig","libs/entitlement","libs/rulepack","proto/gen/go"] and
    .architectures == {"amd64":{"elf_machine":62,"goarch":"amd64"},"arm64":{"elf_machine":183,"goarch":"arm64"}} and
    .recipe.command == "./cmd/edge-agent" and
    .recipe.go_flags == ["-buildvcs=false","-mod=readonly","-trimpath"] and
    .recipe.ldflags == ["-buildid=","-s","-w","-X main.agentVersion=${VERSION}","-X main.buildID=${BUILD_ID}"]
  ' "$1" >/dev/null
}

upgrade_e2e_validate_rollout_body() {
  local label=$1 path=$2 node_id=$3 canonical
  canonical=$(jq -c '{schema,node_ids,canary_node_ids,batch_size,automatic_rollback}' "${path}") || \
    upgrade_e2e_unknown "${label}-json"
  cmp -s <(printf '%s\n' "${canonical}") "${path}" || upgrade_e2e_unknown "${label}-canonical"
  jq -e --arg node_id "${node_id}" '
    keys == ["automatic_rollback","batch_size","canary_node_ids","node_ids","schema"] and
    .schema == "cdnca.control-upgrade-rollout.create/v1" and
    .node_ids == [$node_id] and .canary_node_ids == [$node_id] and
    .batch_size == 1 and .automatic_rollback == true
  ' "${path}" >/dev/null || upgrade_e2e_unknown "${label}-contract"
}

upgrade_e2e_validate_edge_config_template() {
  jq -e '
    .version == 2 and .identity_dir == "/etc/cdnca-edge-agent/identity" and
    (has("node_id") | not) and (has("artifact_encryption_key_id") | not) and
    (.gateway | type == "object" and
      (has("client_certificate_file") | not) and (has("client_private_key_file") | not)) and
    .gateway.address == "gateway.internal:8444" and .gateway.server_name == "gateway.internal" and
    .upgrade.enabled == true and .upgrade.installation_id != "" and .artifact_trust_file != "" and
    .upgrade.control_execution_trust_file != "" and .upgrade.edge_execution_trust_file != "" and
    .upgrade.installer_receipt_trust_file != ""
  ' "$1" >/dev/null
}

upgrade_e2e_validate_runtime_input_pair() {
  upgrade_e2e_validate_external_pair "$1" "$2" "$3"
}

upgrade_e2e_snapshot_repo_file() {
  local relative=$1 source destination before snapshot after
  source=$(upgrade_e2e_canonical_repo_file "${relative}") || return 1
  destination="${INPUT_SNAPSHOT_DIR}/repo/${relative}"
  mkdir -p -- "${destination%/*}" || return 1
  before=$(upgrade_e2e_sha256_regular_file "${source}") || return 1
  upgrade_e2e_copy_regular_file "${source}" "${destination}" || return 1
  snapshot=$(upgrade_e2e_sha256_regular_file "${destination}") || return 1
  after=$(upgrade_e2e_sha256_regular_file "${source}") || return 1
  [ "${before}" = "${snapshot}" ] && [ "${snapshot}" = "${after}" ] || return 1
  printf '%s  %s\n' "${snapshot}" "${relative}" >>"${SNAPSHOT_INVENTORY_RAW}" || return 1
}

upgrade_e2e_exact_path_in() {
  local candidate=$1 expected
  shift
  for expected in "$@"; do
    [ "${candidate}" = "${expected}" ] && return 0
  done
  return 1
}

upgrade_e2e_snapshot_tree() {
  local relative_root=$1 source_root file_list unsafe source relative
  source_root="${REPO_ROOT}/${relative_root}"
  [ -d "${source_root}" ] && [ ! -L "${source_root}" ] || return 1
  unsafe=$(find "${source_root}" \( -type l -o \( ! -type d ! -type f \) \) -print -quit) || return 1
  [ -z "${unsafe}" ] || return 1
  file_list="${INPUT_SNAPSHOT_DIR}/lists/${relative_root//\//-}.files"
  find "${source_root}" -type f -print0 >"${file_list}" || return 1
  while IFS= read -r -d '' source; do
    relative=${source#"${REPO_ROOT}/"}
    [ "${relative}" != "${source}" ] || return 1
    upgrade_e2e_snapshot_repo_file "${relative}" || return 1
  done <"${file_list}"
}

upgrade_e2e_snapshot_external_file() {
  local source=$1 destination=$2 source_directory source_base before snapshot after
  source_directory=$(cd -- "$(dirname -- "${source}")" 2>/dev/null && pwd -P) || return 1
  source_base=$(basename -- "${source}") || return 1
  source="${source_directory}/${source_base}"
  [ -f "${source}" ] && [ ! -L "${source}" ] && [ -r "${source}" ] || return 1
  before=$(upgrade_e2e_sha256_regular_file "${source}") || return 1
  upgrade_e2e_copy_regular_file "${source}" "${destination}" || return 1
  snapshot=$(upgrade_e2e_sha256_regular_file "${destination}") || return 1
  after=$(upgrade_e2e_sha256_regular_file "${source}") || return 1
  [ "${before}" = "${snapshot}" ] && [ "${snapshot}" = "${after}" ] || return 1
  tracked_live_inputs+=("${source}")
  tracked_snapshot_inputs+=("${destination}")
  tracked_input_hashes+=("${snapshot}")
}

upgrade_e2e_verify_manifest() {
  local label=$1 path_name=$2 sha_name=$3 live_manifest snapshot_manifest expected actual digest relative file
  live_manifest="$(upgrade_e2e_require_env "${path_name}")"
  expected="$(upgrade_e2e_require_env "${sha_name}")"
  upgrade_e2e_valid_sha256 "${expected}" || upgrade_e2e_unknown "invalid-${label}-manifest-sha256"
  snapshot_manifest="${INPUT_SNAPSHOT_DIR}/manifests/${label}.sha256"
  upgrade_e2e_snapshot_external_file "${live_manifest}" "${snapshot_manifest}" || upgrade_e2e_unknown "${label}-manifest-copy"
  actual="$(upgrade_e2e_sha256_regular_file "${snapshot_manifest}")" || upgrade_e2e_unknown "${label}-manifest-read"
  [ "${actual}" = "${expected}" ] || upgrade_e2e_unknown "${label}-manifest-drift"
  LC_ALL=C sort -c -u "${snapshot_manifest}" >/dev/null 2>&1 || upgrade_e2e_unknown "${label}-manifest-order"
  awk '
    !/^[0-9a-f]{64}  [A-Za-z0-9][A-Za-z0-9._\/-]*$/ {exit 1}
    index("/" $2 "/", "/../") || index("/" $2 "/", "/./") || index($2, "//") || substr($2, 1, 1) == "/" {exit 1}
    END {if (NR == 0) exit 1}
  ' "${snapshot_manifest}" || upgrade_e2e_unknown "${label}-manifest-format"
  while IFS='  ' read -r digest relative; do
    [ -n "${digest}" ] && [ -n "${relative}" ] || upgrade_e2e_unknown "${label}-manifest-record"
    upgrade_e2e_canonical_repo_file "${relative}" >/dev/null || upgrade_e2e_unknown "${label}-release-input-path"
    file="${INPUT_SNAPSHOT_DIR}/repo/${relative}"
    upgrade_e2e_require_file "${file}" "${label}-snapshot-input"
    [ "$(upgrade_e2e_sha256_regular_file "${file}")" = "${digest}" ] || \
      upgrade_e2e_unknown "${label}-release-input-drift"
  done <"${snapshot_manifest}"
  last_snapshot_manifest=${snapshot_manifest}
}

upgrade_e2e_manifest_has() {
  local manifest=$1 pattern=$2
  awk -v pattern="${pattern}" '$2 ~ pattern {found++} END {exit(found == 1 ? 0 : 1)}' "${manifest}" || \
    upgrade_e2e_unknown "manifest-required-entry-${pattern//[^A-Za-z0-9]/-}"
}

upgrade_e2e_require_exact_control_migration_manifest() {
  local manifest=$1 actual expected
  actual=$(awk '{print $2}' "${manifest}" | LC_ALL=C sort) || \
    upgrade_e2e_unknown 'control-manifest-members-read'
  expected=$(printf '%s\n' "${CONTROL_MIGRATION_MANIFEST_PATHS[@]}" | LC_ALL=C sort) || \
    upgrade_e2e_unknown 'control-manifest-members-build'
  [ "${actual}" = "${expected}" ] || upgrade_e2e_unknown 'control-manifest-members'
}

upgrade_e2e_snapshot_edge_manifest_matches() {
  local manifest=$1 inventory
  inventory=$(awk '$2 ~ /^agents\/edge-agent\// {print}' "${SNAPSHOT_INVENTORY}") || return 1
  [ -n "${inventory}" ] || return 1
  cmp -s "${manifest}" <(printf '%s\n' "${inventory}")
}

upgrade_e2e_snapshot_systemd_supply_chain() {
  local amd64_inventory arm64_inventory
  upgrade_e2e_snapshot_input_pair systemd-amd64-manifest UPGRADE_E2E_SYSTEMD_AMD64_MANIFEST \
    UPGRADE_E2E_SYSTEMD_AMD64_MANIFEST_SHA256 "${SYSTEMD_AMD64_MANIFEST_SNAPSHOT}"
  upgrade_e2e_snapshot_input_pair systemd-arm64-manifest UPGRADE_E2E_SYSTEMD_ARM64_MANIFEST \
    UPGRADE_E2E_SYSTEMD_ARM64_MANIFEST_SHA256 "${SYSTEMD_ARM64_MANIFEST_SNAPSHOT}"
  upgrade_e2e_snapshot_input_pair systemd-amd64-inventory UPGRADE_E2E_SYSTEMD_AMD64_INVENTORY \
    UPGRADE_E2E_SYSTEMD_AMD64_INVENTORY_SHA256 "${SYSTEMD_AMD64_INVENTORY_SNAPSHOT}"
  upgrade_e2e_snapshot_input_pair systemd-arm64-inventory UPGRADE_E2E_SYSTEMD_ARM64_INVENTORY \
    UPGRADE_E2E_SYSTEMD_ARM64_INVENTORY_SHA256 "${SYSTEMD_ARM64_INVENTORY_SNAPSHOT}"
  upgrade_e2e_snapshot_input_pair systemd-amd64-provenance UPGRADE_E2E_SYSTEMD_AMD64_PROVENANCE \
    UPGRADE_E2E_SYSTEMD_AMD64_PROVENANCE_SHA256 "${SYSTEMD_PROVENANCE_AMD64_SNAPSHOT}"
  upgrade_e2e_snapshot_input_pair systemd-arm64-provenance UPGRADE_E2E_SYSTEMD_ARM64_PROVENANCE \
    UPGRADE_E2E_SYSTEMD_ARM64_PROVENANCE_SHA256 "${SYSTEMD_PROVENANCE_ARM64_SNAPSHOT}"
  upgrade_e2e_snapshot_input_pair systemd-spdx UPGRADE_E2E_SYSTEMD_SPDX UPGRADE_E2E_SYSTEMD_SPDX_SHA256 \
    "${SYSTEMD_SPDX_SNAPSHOT}"
  [ "$(upgrade_e2e_sha256_regular_file "${SYSTEMD_AMD64_MANIFEST_SNAPSHOT}")" = \
    "${SYSTEMD_AMD64_SUBJECT#*@sha256:}" ] || upgrade_e2e_unknown 'systemd-amd64-manifest-snapshot-digest'
  [ "$(upgrade_e2e_sha256_regular_file "${SYSTEMD_ARM64_MANIFEST_SNAPSHOT}")" = \
    "${SYSTEMD_ARM64_SUBJECT#*@sha256:}" ] || upgrade_e2e_unknown 'systemd-arm64-manifest-snapshot-digest'
  upgrade_e2e_validate_systemd_native_manifest "${SYSTEMD_AMD64_MANIFEST_SNAPSHOT}" || \
    upgrade_e2e_unknown 'systemd-amd64-manifest-snapshot-contract'
  upgrade_e2e_validate_systemd_native_manifest "${SYSTEMD_ARM64_MANIFEST_SNAPSHOT}" || \
    upgrade_e2e_unknown 'systemd-arm64-manifest-snapshot-contract'
  upgrade_e2e_validate_systemd_inventory "${SYSTEMD_AMD64_INVENTORY_SNAPSHOT}" || \
    upgrade_e2e_unknown 'systemd-amd64-inventory-snapshot-contract'
  upgrade_e2e_validate_systemd_inventory "${SYSTEMD_ARM64_INVENTORY_SNAPSHOT}" || \
    upgrade_e2e_unknown 'systemd-arm64-inventory-snapshot-contract'
  amd64_inventory=$(<"${SYSTEMD_AMD64_INVENTORY_SNAPSHOT}")
  arm64_inventory=$(<"${SYSTEMD_ARM64_INVENTORY_SNAPSHOT}")
  upgrade_e2e_validate_systemd_provenance "${SYSTEMD_PROVENANCE_AMD64_SNAPSHOT}" linux/amd64 \
    "${amd64_inventory}" || upgrade_e2e_unknown 'systemd-amd64-provenance-snapshot-contract'
  upgrade_e2e_validate_systemd_provenance "${SYSTEMD_PROVENANCE_ARM64_SNAPSHOT}" linux/arm64 \
    "${arm64_inventory}" || upgrade_e2e_unknown 'systemd-arm64-provenance-snapshot-contract'
  upgrade_e2e_validate_systemd_spdx "${SYSTEMD_SPDX_SNAPSHOT}" "${SYSTEMD_IMAGE}" \
    "${amd64_inventory}" "${arm64_inventory}" || upgrade_e2e_unknown 'systemd-spdx-snapshot-contract'
}

upgrade_e2e_snapshot_release_inputs() {
  local b_manifest c_manifest license_manifest control_manifest
  local relative_root nats_resources nats_resources_sha actual
  local fixture fixture_sha
  mkdir -p -- "${INPUT_SNAPSHOT_DIR}/repo" "${INPUT_SNAPSHOT_DIR}/manifests" \
    "${INPUT_SNAPSHOT_DIR}/lists" "${INPUT_SNAPSHOT_DIR}/runtime" \
    "${INPUT_SNAPSHOT_DIR}/artifacts" "${INPUT_SNAPSHOT_DIR}/initial" \
    "${INPUT_SNAPSHOT_DIR}/supply-chain" || \
    upgrade_e2e_unknown 'input-snapshot-directories'
  : >"${SNAPSHOT_INVENTORY_RAW}"
  for relative_root in "${snapshot_roots[@]}"; do
    upgrade_e2e_snapshot_tree "${relative_root}" || upgrade_e2e_unknown 'input-snapshot-tree'
  done
  LC_ALL=C sort -u "${SNAPSHOT_INVENTORY_RAW}" >"${SNAPSHOT_INVENTORY}" || upgrade_e2e_unknown 'input-snapshot-inventory'
  [ "$(upgrade_e2e_count_lines <"${SNAPSHOT_INVENTORY_RAW}")" = "$(upgrade_e2e_count_lines <"${SNAPSHOT_INVENTORY}")" ] || \
    upgrade_e2e_unknown 'input-snapshot-duplicate'
  chmod 0444 "${SNAPSHOT_INVENTORY}" || upgrade_e2e_unknown 'input-snapshot-inventory-mode'

  upgrade_e2e_verify_manifest b UPGRADE_E2E_B_MANIFEST UPGRADE_E2E_B_MANIFEST_SHA256
  b_manifest=${last_snapshot_manifest}
  upgrade_e2e_verify_manifest c UPGRADE_E2E_C_MANIFEST UPGRADE_E2E_C_MANIFEST_SHA256
  c_manifest=${last_snapshot_manifest}
  upgrade_e2e_snapshot_edge_manifest_matches "${c_manifest}" || \
    upgrade_e2e_unknown 'c-snapshot-manifest-members'
  EDGE_RELEASE_C_MANIFEST_SNAPSHOT=${c_manifest}
  upgrade_e2e_manifest_has "${c_manifest}" '^agents/edge-agent/packaging/build/contract\.json$'
  upgrade_e2e_validate_edge_release_build_contract "${EDGE_RELEASE_BUILD_CONTRACT_SNAPSHOT}" || \
    upgrade_e2e_unknown 'edge-release-build-contract-snapshot'
  awk '$2 ~ /^(agents\/edge-agent|libs\/edgeconfig|libs\/entitlement|libs\/rulepack|proto\/gen\/go)\// {print}' \
    "${SNAPSHOT_INVENTORY}" >"${EDGE_RELEASE_SOURCE_MANIFEST_SNAPSHOT}" || \
    upgrade_e2e_unknown 'edge-release-source-manifest'
  LC_ALL=C sort -c -u "${EDGE_RELEASE_SOURCE_MANIFEST_SNAPSHOT}" >/dev/null 2>&1 || \
    upgrade_e2e_unknown 'edge-release-source-manifest-order'
  [ "$(upgrade_e2e_count_lines <"${EDGE_RELEASE_SOURCE_MANIFEST_SNAPSHOT}")" -gt 3 ] || \
    upgrade_e2e_unknown 'edge-release-source-manifest-members'
  upgrade_e2e_verify_manifest license UPGRADE_E2E_LICENSE_MIGRATION_MANIFEST UPGRADE_E2E_LICENSE_MIGRATION_MANIFEST_SHA256
  license_manifest=${last_snapshot_manifest}
  upgrade_e2e_verify_manifest control UPGRADE_E2E_CONTROL_MIGRATION_MANIFEST UPGRADE_E2E_CONTROL_MIGRATION_MANIFEST_SHA256
  control_manifest=${last_snapshot_manifest}

  upgrade_e2e_manifest_has "${b_manifest}" '^services/control-api/cmd/control-api/control_upgrade_runtime\.go$'
  upgrade_e2e_manifest_has "${b_manifest}" '^services/control-api/internal/controlupgrade/nats\.go$'
  upgrade_e2e_manifest_has "${b_manifest}" '^services/agent-gateway/nats_upgrade_commands\.go$'
  upgrade_e2e_manifest_has "${c_manifest}" '^agents/edge-agent/internal/gatewayclient/upgrade\.go$'
  upgrade_e2e_manifest_has "${c_manifest}" '^agents/edge-agent/internal/updater/manager\.go$'
  upgrade_e2e_manifest_has "${c_manifest}" '^agents/edge-agent/internal/updater/command_store\.go$'

  upgrade_e2e_manifest_has "${license_manifest}" "^services/license-service/migrations/${LICENSE_MIGRATION_HEAD}_[a-z0-9_]+\\.up\\.sql$"
  upgrade_e2e_manifest_has "${license_manifest}" "^services/license-service/migrations/${LICENSE_MIGRATION_HEAD}_[a-z0-9_]+\\.down\\.sql$"
  upgrade_e2e_manifest_has "${license_manifest}" "^services/license-service/migrations/[a-z0-9_]+_${LICENSE_MIGRATION_HEAD}_(integration_test|contract_test|test)\\.go$"

  upgrade_e2e_require_exact_control_migration_manifest "${control_manifest}"

  upgrade_e2e_snapshot_external_file "${SCRIPT_DIR}/contract.json" "${PROCESS_CONTRACT_SNAPSHOT}" || \
    upgrade_e2e_unknown 'process-contract-copy'
  actual=$(upgrade_e2e_sha256_regular_file "${PROCESS_CONTRACT_SNAPSHOT}") || \
    upgrade_e2e_unknown 'process-contract-read'
  [ "${actual}" = "${PROCESS_CONTRACT_SHA256}" ] || upgrade_e2e_unknown 'process-contract-drift'
  upgrade_e2e_validate_contract_file "${PROCESS_CONTRACT_SNAPSHOT}" || \
    upgrade_e2e_unknown 'process-contract-invalid'

  nats_resources="$(upgrade_e2e_require_env UPGRADE_E2E_NATS_RESOURCES_JSON)"
  nats_resources_sha="$(upgrade_e2e_require_env UPGRADE_E2E_NATS_RESOURCES_SHA256)"
  upgrade_e2e_valid_sha256 "${nats_resources_sha}" || upgrade_e2e_unknown 'invalid-nats-resources-sha256'
  upgrade_e2e_snapshot_external_file "${nats_resources}" "${NATS_RESOURCES_SNAPSHOT}" || \
    upgrade_e2e_unknown 'nats-resources-copy'
  actual=$(upgrade_e2e_sha256_regular_file "${NATS_RESOURCES_SNAPSHOT}") || upgrade_e2e_unknown 'nats-resources-read'
  [ "${actual}" = "${nats_resources_sha}" ] || upgrade_e2e_unknown 'nats-resources-drift'
  upgrade_e2e_validate_nats_resources "${NATS_RESOURCES_SNAPSHOT}" || \
    upgrade_e2e_unknown 'nats-resources-contract'

  upgrade_e2e_snapshot_systemd_supply_chain

  fixture="$(upgrade_e2e_require_env UPGRADE_E2E_LICENSE_AUTHORITY_FIXTURE_SQL)"
  fixture_sha="$(upgrade_e2e_require_env UPGRADE_E2E_LICENSE_AUTHORITY_FIXTURE_SHA256)"
  upgrade_e2e_valid_sha256 "${fixture_sha}" || upgrade_e2e_unknown 'invalid-license-fixture-sha256'
  upgrade_e2e_snapshot_external_file "${fixture}" "${LICENSE_AUTHORITY_FIXTURE_SNAPSHOT}" || \
    upgrade_e2e_unknown 'license-fixture-copy'
  [ "$(upgrade_e2e_sha256_regular_file "${LICENSE_AUTHORITY_FIXTURE_SNAPSHOT}")" = "${fixture_sha}" ] || \
    upgrade_e2e_unknown 'license-fixture-drift'
  upgrade_e2e_validate_authority_fixture "${LICENSE_AUTHORITY_FIXTURE_SNAPSHOT}" || \
    upgrade_e2e_unknown 'license-fixture-contract'

  fixture="$(upgrade_e2e_require_env UPGRADE_E2E_CONTROL_AUTHORITY_FIXTURE_SQL)"
  fixture_sha="$(upgrade_e2e_require_env UPGRADE_E2E_CONTROL_AUTHORITY_FIXTURE_SHA256)"
  upgrade_e2e_valid_sha256 "${fixture_sha}" || upgrade_e2e_unknown 'invalid-control-fixture-sha256'
  upgrade_e2e_snapshot_external_file "${fixture}" "${CONTROL_AUTHORITY_FIXTURE_SNAPSHOT}" || \
    upgrade_e2e_unknown 'control-fixture-copy'
  [ "$(upgrade_e2e_sha256_regular_file "${CONTROL_AUTHORITY_FIXTURE_SNAPSHOT}")" = "${fixture_sha}" ] || \
    upgrade_e2e_unknown 'control-fixture-drift'
  upgrade_e2e_validate_control_authority_fixture "${CONTROL_AUTHORITY_FIXTURE_SNAPSHOT}" || \
    upgrade_e2e_unknown 'control-fixture-contract'

  upgrade_e2e_snapshot_json_input edge-config UPGRADE_E2E_EDGE_CONFIG_JSON \
    UPGRADE_E2E_EDGE_CONFIG_SHA256 "${EDGE_CONFIG_SNAPSHOT}"
  upgrade_e2e_snapshot_input_pair success-rollout UPGRADE_E2E_SUCCESS_ROLLOUT_JSON \
    UPGRADE_E2E_SUCCESS_ROLLOUT_SHA256 "${SUCCESS_ROLLOUT_SNAPSHOT}"
  upgrade_e2e_snapshot_input_pair automatic-rollback UPGRADE_E2E_AUTOMATIC_ROLLBACK_JSON \
    UPGRADE_E2E_AUTOMATIC_ROLLBACK_SHA256 "${AUTOMATIC_ROLLBACK_SNAPSHOT}"
  upgrade_e2e_snapshot_input_pair operator-rollback UPGRADE_E2E_OPERATOR_ROLLBACK_JSON \
    UPGRADE_E2E_OPERATOR_ROLLBACK_SHA256 "${OPERATOR_ROLLBACK_SNAPSHOT}"
  upgrade_e2e_validate_edge_config_template "${EDGE_CONFIG_SNAPSHOT}" || \
    upgrade_e2e_unknown 'edge-config-contract'
  upgrade_e2e_validate_rollout_body success-rollout "${SUCCESS_ROLLOUT_SNAPSHOT}" \
    "$(upgrade_e2e_require_env UPGRADE_E2E_NODE_ID)"
  upgrade_e2e_validate_rollout_body automatic-rollback "${AUTOMATIC_ROLLBACK_SNAPSHOT}" \
    "$(upgrade_e2e_require_env UPGRADE_E2E_NODE_ID)"
  upgrade_e2e_validate_rollout_body operator-rollback "${OPERATOR_ROLLBACK_SNAPSHOT}" \
    "$(upgrade_e2e_require_env UPGRADE_E2E_NODE_ID)"

  upgrade_e2e_snapshot_input_pair control-entitlement-trust ENTITLEMENT_TRUSTED_KEYS_FILE \
    ENTITLEMENT_TRUSTED_KEYS_SHA256 "${CONTROL_ENTITLEMENT_TRUST_SNAPSHOT}"
  upgrade_e2e_snapshot_input_pair control-installation-key CONTROL_INSTALLATION_PRIVATE_KEY_FILE \
    CONTROL_INSTALLATION_PRIVATE_KEY_SHA256 "${CONTROL_INSTALLATION_KEY_SNAPSHOT}"
  upgrade_e2e_snapshot_input_pair control-activation-credential CONTROL_ACTIVATION_CREDENTIAL_FILE \
    CONTROL_ACTIVATION_CREDENTIAL_SHA256 "${CONTROL_ACTIVATION_CREDENTIAL_SNAPSHOT}"
  upgrade_e2e_snapshot_input_pair control-command-trust CONTROL_UPGRADE_COMMAND_GRANT_TRUST_FILE \
    CONTROL_UPGRADE_COMMAND_GRANT_TRUST_SHA256 "${CONTROL_COMMAND_TRUST_SNAPSHOT}"
  upgrade_e2e_snapshot_input_pair control-signing-key CONTROL_UPGRADE_CONTROL_SIGNING_PRIVATE_KEY_FILE \
    CONTROL_UPGRADE_CONTROL_SIGNING_PRIVATE_KEY_SHA256 "${CONTROL_SIGNING_KEY_SNAPSHOT}"
  upgrade_e2e_snapshot_input_pair edge-signing-key CONTROL_UPGRADE_EDGE_SIGNING_PRIVATE_KEY_FILE \
    CONTROL_UPGRADE_EDGE_SIGNING_PRIVATE_KEY_SHA256 "${EDGE_SIGNING_KEY_SNAPSHOT}"

  upgrade_e2e_snapshot_external_file "$(jq -er '.artifact_trust_file' "${EDGE_CONFIG_SNAPSHOT}")" \
    "${EDGE_ARTIFACT_TRUST_SNAPSHOT}" || upgrade_e2e_unknown 'edge-artifact-trust-copy'
  [ "$(upgrade_e2e_sha256_regular_file "${EDGE_ARTIFACT_TRUST_SNAPSHOT}")" = \
    "$(upgrade_e2e_require_env UPGRADE_E2E_EDGE_ARTIFACT_TRUST_SHA256)" ] || \
    upgrade_e2e_unknown 'edge-artifact-trust-drift'
  upgrade_e2e_snapshot_external_file "$(jq -er '.upgrade.control_execution_trust_file' "${EDGE_CONFIG_SNAPSHOT}")" \
    "${EDGE_CONTROL_TRUST_SNAPSHOT}" || upgrade_e2e_unknown 'edge-control-trust-copy'
  [ "$(upgrade_e2e_sha256_regular_file "${EDGE_CONTROL_TRUST_SNAPSHOT}")" = \
    "$(upgrade_e2e_require_env UPGRADE_E2E_EDGE_CONTROL_EXECUTION_TRUST_SHA256)" ] || \
    upgrade_e2e_unknown 'edge-control-trust-drift'
  upgrade_e2e_snapshot_external_file "$(jq -er '.upgrade.edge_execution_trust_file' "${EDGE_CONFIG_SNAPSHOT}")" \
    "${EDGE_EXECUTION_TRUST_SNAPSHOT}" || upgrade_e2e_unknown 'edge-execution-trust-copy'
  [ "$(upgrade_e2e_sha256_regular_file "${EDGE_EXECUTION_TRUST_SNAPSHOT}")" = \
    "$(upgrade_e2e_require_env UPGRADE_E2E_EDGE_EXECUTION_TRUST_SHA256)" ] || \
    upgrade_e2e_unknown 'edge-execution-trust-drift'
  upgrade_e2e_snapshot_input_pair initial-artifact UPGRADE_E2E_INITIAL_ARTIFACT \
    UPGRADE_E2E_INITIAL_ARTIFACT_SHA256 "${INPUT_SNAPSHOT_DIR}/initial/edge-agent"
  chmod 0555 "${INPUT_SNAPSHOT_DIR}/initial/edge-agent" || upgrade_e2e_unknown 'initial-artifact-mode'
  upgrade_e2e_snapshot_input_pair initial-sbom UPGRADE_E2E_INITIAL_SBOM \
    UPGRADE_E2E_INITIAL_SBOM_SHA256 "${INPUT_SNAPSHOT_DIR}/initial/edge-agent.spdx.json"
  upgrade_e2e_snapshot_input_pair initial-manifest UPGRADE_E2E_INITIAL_MANIFEST \
    UPGRADE_E2E_INITIAL_MANIFEST_SHA256 "${INPUT_SNAPSHOT_DIR}/initial/manifest"
  upgrade_e2e_snapshot_input_pair initial-signature UPGRADE_E2E_INITIAL_SIGNATURE \
    UPGRADE_E2E_INITIAL_SIGNATURE_SHA256 "${INPUT_SNAPSHOT_DIR}/initial/manifest.sig"
  upgrade_e2e_snapshot_input_pair initial-public-key UPGRADE_E2E_INITIAL_PUBLIC_KEY \
    UPGRADE_E2E_INITIAL_PUBLIC_KEY_SHA256 "${INPUT_SNAPSHOT_DIR}/initial/public-key.pem"
  upgrade_e2e_snapshot_input_pair forward-bundle UPGRADE_E2E_FORWARD_BUNDLE \
    UPGRADE_E2E_FORWARD_BUNDLE_SHA256 "${FORWARD_BUNDLE_SNAPSHOT}"
  [ "$(upgrade_e2e_regular_file_size "${FORWARD_BUNDLE_SNAPSHOT}")" = \
    "$(upgrade_e2e_require_env UPGRADE_E2E_FORWARD_BUNDLE_SIZE)" ] || upgrade_e2e_unknown 'forward-bundle-size-drift'
  upgrade_e2e_snapshot_input_pair rollback-bundle UPGRADE_E2E_ROLLBACK_BUNDLE \
    UPGRADE_E2E_ROLLBACK_BUNDLE_SHA256 "${ROLLBACK_BUNDLE_SNAPSHOT}"
  [ "$(upgrade_e2e_regular_file_size "${ROLLBACK_BUNDLE_SNAPSHOT}")" = \
    "$(upgrade_e2e_require_env UPGRADE_E2E_ROLLBACK_BUNDLE_SIZE)" ] || upgrade_e2e_unknown 'rollback-bundle-size-drift'

  LICENSE_MIGRATION_SNAPSHOT_DIR="${INPUT_SNAPSHOT_DIR}/repo/services/license-service/migrations"
  CONTROL_MIGRATION_SNAPSHOT_DIR="${INPUT_SNAPSHOT_DIR}/repo/services/control-api/migrations"
  chmod -R a-w "${INPUT_SNAPSHOT_DIR}" || upgrade_e2e_unknown 'input-snapshot-read-only'
  upgrade_e2e_verify_live_inputs_unchanged || upgrade_e2e_unknown 'live-input-before-snapshot-mismatch'
}

upgrade_e2e_verify_live_inputs_unchanged() {
  local live_check_dir live_inventory relative_root source_root file_list unsafe source relative digest index
  live_check_dir="${WORK_DIR}/live-input-check"
  mkdir -p -- "${live_check_dir}" || return 1
  live_inventory="${live_check_dir}/live.inventory"
  : >"${live_inventory}"
  for relative_root in "${snapshot_roots[@]}"; do
    source_root="${REPO_ROOT}/${relative_root}"
    [ -d "${source_root}" ] && [ ! -L "${source_root}" ] || return 1
    unsafe=$(find "${source_root}" \( -type l -o \( ! -type d ! -type f \) \) -print -quit) || return 1
    [ -z "${unsafe}" ] || return 1
    file_list="${live_check_dir}/${relative_root//\//-}.files"
    find "${source_root}" -type f -print0 >"${file_list}" || return 1
    while IFS= read -r -d '' source; do
      relative=${source#"${REPO_ROOT}/"}
      upgrade_e2e_canonical_repo_file "${relative}" >/dev/null || return 1
      digest=$(upgrade_e2e_sha256_regular_file "${source}") || return 1
      printf '%s  %s\n' "${digest}" "${relative}" >>"${live_inventory}" || return 1
    done <"${file_list}"
  done
  LC_ALL=C sort -u -o "${live_inventory}" "${live_inventory}" || return 1
  cmp -s "${SNAPSHOT_INVENTORY}" "${live_inventory}" || return 1
  for index in "${!tracked_live_inputs[@]}"; do
    digest=$(upgrade_e2e_sha256_regular_file "${tracked_live_inputs[${index}]}") || return 1
    [ "${digest}" = "${tracked_input_hashes[${index}]}" ] || return 1
    [ "$(upgrade_e2e_sha256_regular_file "${tracked_snapshot_inputs[${index}]}")" = "${digest}" ] || return 1
  done
}

upgrade_e2e_require_final_contract() {
  local contract expected_version expected_receipt actual receipt provenance_predicate spdx_predicate
  contract="${SCRIPT_DIR}/contract.json"
  upgrade_e2e_validate_contract_file "${contract}" || upgrade_e2e_unknown 'process-contract-invalid'
  actual=$(upgrade_e2e_sha256_regular_file "${contract}") || upgrade_e2e_unknown 'process-contract-read'
  expected_version="$(upgrade_e2e_require_env UPGRADE_E2E_PROCESS_CONTRACT_VERSION)"
  [ "${expected_version}" = "sha256:${actual}" ] || upgrade_e2e_unknown 'process-contract-version-drift'
  receipt=$(jq -er '.license_receipt_request_schema' "${contract}") || \
    upgrade_e2e_unknown 'process-contract-receipt-schema'
  expected_receipt="$(upgrade_e2e_require_env UPGRADE_E2E_LICENSE_PARENT_RECEIPT_SCHEMA)"
  [ "${expected_receipt}" = "${receipt}" ] || upgrade_e2e_unknown 'parent-receipt-schema-drift'
  provenance_predicate=$(jq -er '.systemd_attestation_predicate_types.provenance' "${contract}") || \
    upgrade_e2e_unknown 'systemd-provenance-predicate-schema'
  spdx_predicate=$(jq -er '.systemd_attestation_predicate_types.spdx' "${contract}") || \
    upgrade_e2e_unknown 'systemd-spdx-predicate-schema'
  PROCESS_CONTRACT_SHA256=${actual}
  LICENSE_PARENT_RECEIPT_SCHEMA=${receipt}
  SYSTEMD_PROVENANCE_PREDICATE_TYPE=${provenance_predicate}
  SYSTEMD_SPDX_PREDICATE_TYPE=${spdx_predicate}
}

upgrade_e2e_validate_systemd_inventory() {
  local path=$1 value
  value=$(awk 'NR == 1 {print} NR > 1 {exit 1}' "${path}") || return 1
  [[ "${value}" =~ ^sha256:[0-9a-f]{64}$ ]]
}

upgrade_e2e_validate_systemd_native_manifest() {
  jq -e '
    def descriptor:
      type == "object" and
      ((keys - ["annotations","data","digest","mediaType","platform","size","urls"]) | length) == 0 and
      (.digest | test("^sha256:[0-9a-f]{64}$")) and
      (.size | type == "number" and . > 0) and
      (.mediaType | type == "string" and length > 0);
    .schemaVersion == 2 and
    (.mediaType == "application/vnd.oci.image.manifest.v1+json" or
      .mediaType == "application/vnd.docker.distribution.manifest.v2+json") and
    ((keys - ["annotations","config","layers","mediaType","schemaVersion","subject"]) | length) == 0 and
    (.config | descriptor) and
    (.layers | type == "array" and length > 0 and all(.[]; descriptor)) and
    (if .mediaType == "application/vnd.oci.image.manifest.v1+json" then
      .config.mediaType == "application/vnd.oci.image.config.v1+json" and
      all(.layers[]; .mediaType | startswith("application/vnd.oci.image.layer.v1.tar"))
    else
      .config.mediaType == "application/vnd.docker.container.image.v1+json" and
      all(.layers[]; .mediaType | startswith("application/vnd.docker.image.rootfs.diff.tar"))
    end)
  ' "$1" >/dev/null
}

upgrade_e2e_validate_systemd_provenance() {
  local path=$1 platform=$2 inventory=$3 bound_key unbound_key
  case "${platform}" in
    linux/amd64)
      bound_key='build-arg:EXPECTED_RUNTIME_INVENTORY_SHA256_AMD64'
      unbound_key='build-arg:EXPECTED_RUNTIME_INVENTORY_SHA256_ARM64'
      ;;
    linux/arm64)
      bound_key='build-arg:EXPECTED_RUNTIME_INVENTORY_SHA256_ARM64'
      unbound_key='build-arg:EXPECTED_RUNTIME_INVENTORY_SHA256_AMD64'
      ;;
    *) return 1 ;;
  esac
  jq -e --arg bound_key "${bound_key}" --arg inventory "${inventory}" --arg platform "${platform}" \
    --arg unbound_key "${unbound_key}" '
    .buildType == "https://mobyproject.org/buildkit@v1" and
    (.builder.id | test("^https://github\\.com/moby/buildkit@v[0-9]+\\.[0-9]+\\.[0-9]+([.-][0-9A-Za-z.-]+)?$")) and
    .invocation.configSource.entryPoint == "tests/edge-linux/Dockerfile" and
    .invocation.parameters.frontend == "dockerfile.v0" and
    .invocation.environment.platform == $platform and
    .invocation.parameters.args[$bound_key] == $inventory and
    .invocation.parameters.args[$unbound_key] == "UNBOUND" and
    (.invocation.parameters.args["build-arg:DISTRO_IMAGE"] |
      test("^[a-z0-9][a-z0-9._/-]*@sha256:[0-9a-f]{64}$")) and
    (.invocation.parameters.args["build-arg:OPENRESTY_IMAGE"] |
      test("^[a-z0-9][a-z0-9._/-]*@sha256:[0-9a-f]{64}$")) and
    (.invocation.parameters.args["build-arg:SOURCE_REVISION"] | test("^[0-9a-f]{40}$")) and
    (.materials | type == "array" and length == 3)
  ' "${path}" >/dev/null
}

upgrade_e2e_validate_systemd_spdx() {
  local path=$1 image=$2 amd64_inventory=$3 arm64_inventory=$4 digest
  digest=${image#*@sha256:}
  jq -e --arg amd64 "${amd64_inventory}" --arg arm64 "${arm64_inventory}" --arg digest "${digest}" '
    .spdxVersion == "SPDX-2.3" and .dataLicense == "CC0-1.0" and
    (.packages | type == "array" and length > 0) and
    (.files | type == "array" and length > 0) and
    (.relationships | type == "array" and length == ((.packages | length) + (.files | length))) and
    (.documentNamespace | endswith($digest)) and
    ([.annotations[].comment | select(
      contains("subject=sha256:" + $digest) and contains("amd64=" + $amd64) and contains("arm64=" + $arm64)
    )] | length == 1)
  ' "${path}" >/dev/null
}

upgrade_e2e_attestation_predicate_hashes() {
  local payload
  jq -er '.payload' | while IFS= read -r payload; do
    printf '%s' "${payload}" | perl -MMIME::Base64=decode_base64 -e '
      use strict; use warnings; local $/; my $value=<STDIN>; print decode_base64($value);' | \
      jq -S -c .predicate | shasum -a 256 | awk '{print $1}' || return 1
  done | LC_ALL=C sort -u
}

upgrade_e2e_verify_systemd_attestation_statements() {
  local statements=$1 predicate_type=$2 image=$3 repository digest
  repository=${image%@*}
  digest=${image#*@sha256:}
  jq -e -s --arg digest "${digest}" --arg predicate_type "${predicate_type}" --arg repository "${repository}" '
    length >= 1 and all(.[].payload | @base64d | fromjson;
      .predicateType == $predicate_type and (.subject | length) == 1 and
      .subject[0].name == $repository and .subject[0].digest.sha256 == $digest)
  ' <<<"${statements}" >/dev/null
}

upgrade_e2e_preflight_systemd_supply_chain() {
  local manifest amd64_manifest arm64_manifest signature provenance_attestations spdx_attestations
  local expected_hashes actual_hashes amd64_manifest_file arm64_manifest_file
  local amd64_inventory_file arm64_inventory_file amd64_provenance_file arm64_provenance_file spdx_file
  local amd64_inventory arm64_inventory amd64_media_type arm64_media_type repository

  SYSTEMD_IMAGE="$(upgrade_e2e_require_env UPGRADE_E2E_SYSTEMD_IMAGE)"
  SYSTEMD_AMD64_SUBJECT="$(upgrade_e2e_require_env UPGRADE_E2E_SYSTEMD_AMD64_SUBJECT)"
  SYSTEMD_ARM64_SUBJECT="$(upgrade_e2e_require_env UPGRADE_E2E_SYSTEMD_ARM64_SUBJECT)"
  for repository in "${SYSTEMD_IMAGE}" "${SYSTEMD_AMD64_SUBJECT}" "${SYSTEMD_ARM64_SUBJECT}"; do
    [[ "${repository}" =~ ^[a-z0-9][a-z0-9._/-]*@sha256:[0-9a-f]{64}$ ]] || \
      upgrade_e2e_unknown 'invalid-systemd-image-digest'
  done
  repository=${SYSTEMD_IMAGE%@*}
  [ "${SYSTEMD_AMD64_SUBJECT%@*}" = "${repository}" ] && \
    [ "${SYSTEMD_ARM64_SUBJECT%@*}" = "${repository}" ] && \
    [ "${SYSTEMD_AMD64_SUBJECT}" != "${SYSTEMD_ARM64_SUBJECT}" ] || \
    upgrade_e2e_unknown 'systemd-native-subject-set'

  SYSTEMD_COSIGN_ISSUER="$(upgrade_e2e_require_env UPGRADE_E2E_SYSTEMD_COSIGN_ISSUER)"
  SYSTEMD_COSIGN_IDENTITY="$(upgrade_e2e_require_env UPGRADE_E2E_SYSTEMD_COSIGN_IDENTITY)"
  [ "${SYSTEMD_COSIGN_ISSUER}" = 'https://token.actions.githubusercontent.com' ] || \
    upgrade_e2e_unknown 'systemd-cosign-issuer'
  [[ "${SYSTEMD_COSIGN_IDENTITY}" =~ ^https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/\.github/workflows/edge-supply-chain\.yml@refs/(heads|tags)/[A-Za-z0-9._/-]+$ ]] || \
    upgrade_e2e_unknown 'systemd-cosign-identity'

  upgrade_e2e_validate_external_pair systemd-amd64-inventory UPGRADE_E2E_SYSTEMD_AMD64_INVENTORY \
    UPGRADE_E2E_SYSTEMD_AMD64_INVENTORY_SHA256
  amd64_inventory_file=${last_validated_external_file}
  upgrade_e2e_validate_external_pair systemd-arm64-inventory UPGRADE_E2E_SYSTEMD_ARM64_INVENTORY \
    UPGRADE_E2E_SYSTEMD_ARM64_INVENTORY_SHA256
  arm64_inventory_file=${last_validated_external_file}
  upgrade_e2e_validate_external_pair systemd-amd64-provenance UPGRADE_E2E_SYSTEMD_AMD64_PROVENANCE \
    UPGRADE_E2E_SYSTEMD_AMD64_PROVENANCE_SHA256
  amd64_provenance_file=${last_validated_external_file}
  upgrade_e2e_validate_external_pair systemd-arm64-provenance UPGRADE_E2E_SYSTEMD_ARM64_PROVENANCE \
    UPGRADE_E2E_SYSTEMD_ARM64_PROVENANCE_SHA256
  arm64_provenance_file=${last_validated_external_file}
  upgrade_e2e_validate_external_pair systemd-spdx UPGRADE_E2E_SYSTEMD_SPDX UPGRADE_E2E_SYSTEMD_SPDX_SHA256
  spdx_file=${last_validated_external_file}
  upgrade_e2e_validate_external_pair systemd-amd64-manifest UPGRADE_E2E_SYSTEMD_AMD64_MANIFEST \
    UPGRADE_E2E_SYSTEMD_AMD64_MANIFEST_SHA256
  amd64_manifest_file=${last_validated_external_file}
  upgrade_e2e_validate_external_pair systemd-arm64-manifest UPGRADE_E2E_SYSTEMD_ARM64_MANIFEST \
    UPGRADE_E2E_SYSTEMD_ARM64_MANIFEST_SHA256
  arm64_manifest_file=${last_validated_external_file}
  [ "$(upgrade_e2e_sha256_regular_file "${amd64_manifest_file}")" = "${SYSTEMD_AMD64_SUBJECT#*@sha256:}" ] || \
    upgrade_e2e_unknown 'systemd-amd64-manifest-subject-digest'
  [ "$(upgrade_e2e_sha256_regular_file "${arm64_manifest_file}")" = "${SYSTEMD_ARM64_SUBJECT#*@sha256:}" ] || \
    upgrade_e2e_unknown 'systemd-arm64-manifest-subject-digest'
  upgrade_e2e_validate_systemd_native_manifest "${amd64_manifest_file}" || \
    upgrade_e2e_unknown 'systemd-amd64-manifest-contract'
  upgrade_e2e_validate_systemd_native_manifest "${arm64_manifest_file}" || \
    upgrade_e2e_unknown 'systemd-arm64-manifest-contract'
  upgrade_e2e_validate_systemd_inventory "${amd64_inventory_file}" || \
    upgrade_e2e_unknown 'systemd-amd64-inventory-contract'
  upgrade_e2e_validate_systemd_inventory "${arm64_inventory_file}" || \
    upgrade_e2e_unknown 'systemd-arm64-inventory-contract'
  amd64_inventory=$(<"${amd64_inventory_file}")
  arm64_inventory=$(<"${arm64_inventory_file}")
  upgrade_e2e_validate_systemd_provenance "${amd64_provenance_file}" linux/amd64 "${amd64_inventory}" || \
    upgrade_e2e_unknown 'systemd-amd64-provenance-contract'
  upgrade_e2e_validate_systemd_provenance "${arm64_provenance_file}" linux/arm64 "${arm64_inventory}" || \
    upgrade_e2e_unknown 'systemd-arm64-provenance-contract'
  upgrade_e2e_validate_systemd_spdx "${spdx_file}" "${SYSTEMD_IMAGE}" "${amd64_inventory}" "${arm64_inventory}" || \
    upgrade_e2e_unknown 'systemd-spdx-contract'

  amd64_manifest=$(upgrade_e2e_timeout 60 docker buildx imagetools inspect "${SYSTEMD_AMD64_SUBJECT}" --raw) || \
    upgrade_e2e_unknown 'systemd-amd64-manifest-read'
  arm64_manifest=$(upgrade_e2e_timeout 60 docker buildx imagetools inspect "${SYSTEMD_ARM64_SUBJECT}" --raw) || \
    upgrade_e2e_unknown 'systemd-arm64-manifest-read'
  [ "$(jq -S -c . <<<"${amd64_manifest}")" = "$(jq -S -c . "${amd64_manifest_file}")" ] || \
    upgrade_e2e_unknown 'systemd-amd64-manifest-registry-drift'
  [ "$(jq -S -c . <<<"${arm64_manifest}")" = "$(jq -S -c . "${arm64_manifest_file}")" ] || \
    upgrade_e2e_unknown 'systemd-arm64-manifest-registry-drift'
  amd64_media_type=$(jq -er '.mediaType' "${amd64_manifest_file}") || \
    upgrade_e2e_unknown 'systemd-amd64-manifest-media-type'
  arm64_media_type=$(jq -er '.mediaType' "${arm64_manifest_file}") || \
    upgrade_e2e_unknown 'systemd-arm64-manifest-media-type'

  manifest=$(upgrade_e2e_timeout 60 docker buildx imagetools inspect "${SYSTEMD_IMAGE}" --raw) || \
    upgrade_e2e_unknown 'systemd-image-manifest-read'
  jq -e --arg amd64 "${SYSTEMD_AMD64_SUBJECT#*@}" --arg arm64 "${SYSTEMD_ARM64_SUBJECT#*@}" \
    --arg amd64_media_type "${amd64_media_type}" --arg arm64_media_type "${arm64_media_type}" \
    --argjson amd64_size "$(upgrade_e2e_regular_file_size "${amd64_manifest_file}")" \
    --argjson arm64_size "$(upgrade_e2e_regular_file_size "${arm64_manifest_file}")" '
    .schemaVersion == 2 and
    (.mediaType == "application/vnd.oci.image.index.v1+json" or
      .mediaType == "application/vnd.docker.distribution.manifest.list.v2+json") and
    ((keys - ["annotations","manifests","mediaType","schemaVersion","subject"]) | length) == 0 and
    (.manifests | type == "array" and length == 2) and
    all(.manifests[];
      ((keys - ["annotations","data","digest","mediaType","platform","size","urls"]) | length) == 0 and
      (.platform | type == "object" and
        ((keys - ["architecture","os","os.features","os.version","variant"]) | length) == 0))) and
    ([.manifests[] | .platform.os + "/" + .platform.architecture] | sort) == ["linux/amd64","linux/arm64"] and
    ([.manifests[] | select(
      .platform.os == "linux" and .platform.architecture == "amd64" and .digest == $amd64 and
      .mediaType == $amd64_media_type and .size == $amd64_size)] | length) == 1 and
    ([.manifests[] | select(
      .platform.os == "linux" and .platform.architecture == "arm64" and .digest == $arm64 and
      .mediaType == $arm64_media_type and .size == $arm64_size)] | length) == 1
  ' <<<"${manifest}" >/dev/null || upgrade_e2e_unknown 'systemd-image-native-manifest-contract'

  signature=$(upgrade_e2e_timeout 60 cosign verify --certificate-oidc-issuer "${SYSTEMD_COSIGN_ISSUER}" --certificate-identity "${SYSTEMD_COSIGN_IDENTITY}" \
    "${SYSTEMD_IMAGE}") || upgrade_e2e_unknown 'systemd-cosign-signature'
  jq -e --arg digest "${SYSTEMD_IMAGE#*@}" --arg repository "${repository}" '
    type == "array" and length >= 1 and all(.[].critical;
      .identity["docker-reference"] == $repository and .image["docker-manifest-digest"] == $digest)
  ' <<<"${signature}" >/dev/null || upgrade_e2e_unknown 'systemd-cosign-signature-contract'
  provenance_attestations=$(upgrade_e2e_timeout 60 cosign verify-attestation --type slsaprovenance \
    --certificate-oidc-issuer "${SYSTEMD_COSIGN_ISSUER}" --certificate-identity "${SYSTEMD_COSIGN_IDENTITY}" \
    "${SYSTEMD_IMAGE}") || upgrade_e2e_unknown 'systemd-cosign-provenance'
  spdx_attestations=$(upgrade_e2e_timeout 60 cosign verify-attestation --type spdxjson \
    --certificate-oidc-issuer "${SYSTEMD_COSIGN_ISSUER}" --certificate-identity "${SYSTEMD_COSIGN_IDENTITY}" \
    "${SYSTEMD_IMAGE}") || upgrade_e2e_unknown 'systemd-cosign-spdx'
  upgrade_e2e_verify_systemd_attestation_statements "${provenance_attestations}" \
    "${SYSTEMD_PROVENANCE_PREDICATE_TYPE}" "${SYSTEMD_IMAGE}" || \
    upgrade_e2e_unknown 'systemd-provenance-attestation-subject'
  upgrade_e2e_verify_systemd_attestation_statements "${spdx_attestations}" \
    "${SYSTEMD_SPDX_PREDICATE_TYPE}" "${SYSTEMD_IMAGE}" || \
    upgrade_e2e_unknown 'systemd-spdx-attestation-subject'
  expected_hashes=$({ jq -S -c . "${amd64_provenance_file}"; jq -S -c . "${arm64_provenance_file}"; } | \
    while IFS= read -r line; do printf '%s' "${line}" | shasum -a 256 | awk '{print $1}'; done | LC_ALL=C sort -u) || \
    upgrade_e2e_unknown 'systemd-provenance-predicate-set'
  actual_hashes=$(upgrade_e2e_attestation_predicate_hashes <<<"${provenance_attestations}") || \
    upgrade_e2e_unknown 'systemd-provenance-attestation-read'
  [ "${actual_hashes}" = "${expected_hashes}" ] || upgrade_e2e_unknown 'systemd-provenance-attestation-drift'
  expected_hashes=$(jq -S -c . "${spdx_file}" | shasum -a 256 | awk '{print $1}') || \
    upgrade_e2e_unknown 'systemd-spdx-predicate-hash'
  actual_hashes=$(upgrade_e2e_attestation_predicate_hashes <<<"${spdx_attestations}") || \
    upgrade_e2e_unknown 'systemd-spdx-attestation-read'
  [ "${actual_hashes}" = "${expected_hashes}" ] || upgrade_e2e_unknown 'systemd-spdx-attestation-drift'

  readonly SYSTEMD_IMAGE SYSTEMD_AMD64_SUBJECT SYSTEMD_ARM64_SUBJECT
  readonly SYSTEMD_COSIGN_IDENTITY SYSTEMD_COSIGN_ISSUER
  readonly SYSTEMD_PROVENANCE_PREDICATE_TYPE SYSTEMD_SPDX_PREDICATE_TYPE
}

upgrade_e2e_preflight_external_inputs() {
  local node_id edge_config edge_path edge_sha index label initial_version forward_version token
  local -a edge_paths edge_sha_names scenario_paths

  upgrade_e2e_preflight_systemd_supply_chain

  upgrade_e2e_validate_live_manifest b UPGRADE_E2E_B_MANIFEST UPGRADE_E2E_B_MANIFEST_SHA256
  upgrade_e2e_manifest_has "${last_validated_manifest}" '^services/control-api/cmd/control-api/control_upgrade_runtime\.go$'
  upgrade_e2e_manifest_has "${last_validated_manifest}" '^services/agent-gateway/nats_upgrade_commands\.go$'
  upgrade_e2e_validate_live_edge_manifest UPGRADE_E2E_C_MANIFEST UPGRADE_E2E_C_MANIFEST_SHA256
  upgrade_e2e_validate_live_manifest license UPGRADE_E2E_LICENSE_MIGRATION_MANIFEST \
    UPGRADE_E2E_LICENSE_MIGRATION_MANIFEST_SHA256
  upgrade_e2e_manifest_has "${last_validated_manifest}" "^services/license-service/migrations/${LICENSE_MIGRATION_HEAD}_[a-z0-9_]+\\.up\\.sql$"
  upgrade_e2e_manifest_has "${last_validated_manifest}" "^services/license-service/migrations/${LICENSE_MIGRATION_HEAD}_[a-z0-9_]+\\.down\\.sql$"
  upgrade_e2e_manifest_has "${last_validated_manifest}" "^services/license-service/migrations/[a-z0-9_]+_${LICENSE_MIGRATION_HEAD}_(integration_test|contract_test|test)\\.go$"
  upgrade_e2e_validate_live_manifest control UPGRADE_E2E_CONTROL_MIGRATION_MANIFEST \
    UPGRADE_E2E_CONTROL_MIGRATION_MANIFEST_SHA256
  upgrade_e2e_require_exact_control_migration_manifest "${last_validated_manifest}"

  upgrade_e2e_validate_external_pair nats-resources UPGRADE_E2E_NATS_RESOURCES_JSON \
    UPGRADE_E2E_NATS_RESOURCES_SHA256
  upgrade_e2e_validate_nats_resources "${last_validated_external_file}" || \
    upgrade_e2e_unknown 'nats-resources-contract'
  upgrade_e2e_validate_external_pair license-fixture UPGRADE_E2E_LICENSE_AUTHORITY_FIXTURE_SQL \
    UPGRADE_E2E_LICENSE_AUTHORITY_FIXTURE_SHA256
  upgrade_e2e_validate_authority_fixture "${last_validated_external_file}" || \
    upgrade_e2e_unknown 'license-fixture-contract'
  upgrade_e2e_validate_external_pair control-fixture UPGRADE_E2E_CONTROL_AUTHORITY_FIXTURE_SQL \
    UPGRADE_E2E_CONTROL_AUTHORITY_FIXTURE_SHA256
  upgrade_e2e_validate_control_authority_fixture "${last_validated_external_file}" || \
    upgrade_e2e_unknown 'control-fixture-contract'

  node_id="$(upgrade_e2e_require_env UPGRADE_E2E_NODE_ID)"
  [[ "${node_id}" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$ ]] || \
    upgrade_e2e_unknown 'invalid-node-id'
  upgrade_e2e_validate_external_pair edge-config UPGRADE_E2E_EDGE_CONFIG_JSON UPGRADE_E2E_EDGE_CONFIG_SHA256
  edge_config=${last_validated_external_file}
  upgrade_e2e_validate_edge_config_template "${edge_config}" || upgrade_e2e_unknown 'edge-config-contract'

  scenario_paths=()
  for index in SUCCESS AUTOMATIC_ROLLBACK OPERATOR_ROLLBACK; do
    label=$(printf '%s' "${index}" | tr '[:upper:]_' '[:lower:]-')
    upgrade_e2e_validate_external_pair "${label}-rollout" "UPGRADE_E2E_${index}_JSON" \
      "UPGRADE_E2E_${index}_SHA256"
    upgrade_e2e_validate_rollout_body "${label}-rollout" "${last_validated_external_file}" "${node_id}"
    scenario_paths+=("${last_validated_external_file}")
  done
  [ "${scenario_paths[0]}" != "${scenario_paths[1]}" ] && \
    [ "${scenario_paths[0]}" != "${scenario_paths[2]}" ] && \
    [ "${scenario_paths[1]}" != "${scenario_paths[2]}" ] || \
    upgrade_e2e_unknown 'scenario-input-paths-not-distinct'

  upgrade_e2e_validate_runtime_input_pair control-entitlement-trust ENTITLEMENT_TRUSTED_KEYS_FILE \
    ENTITLEMENT_TRUSTED_KEYS_SHA256
  upgrade_e2e_validate_runtime_input_pair control-installation-key CONTROL_INSTALLATION_PRIVATE_KEY_FILE \
    CONTROL_INSTALLATION_PRIVATE_KEY_SHA256
  upgrade_e2e_validate_runtime_input_pair control-activation-credential CONTROL_ACTIVATION_CREDENTIAL_FILE \
    CONTROL_ACTIVATION_CREDENTIAL_SHA256
  upgrade_e2e_validate_runtime_input_pair control-command-trust CONTROL_UPGRADE_COMMAND_GRANT_TRUST_FILE \
    CONTROL_UPGRADE_COMMAND_GRANT_TRUST_SHA256
  upgrade_e2e_validate_runtime_input_pair control-signing-key CONTROL_UPGRADE_CONTROL_SIGNING_PRIVATE_KEY_FILE \
    CONTROL_UPGRADE_CONTROL_SIGNING_PRIVATE_KEY_SHA256
  upgrade_e2e_validate_runtime_input_pair edge-signing-key CONTROL_UPGRADE_EDGE_SIGNING_PRIVATE_KEY_FILE \
    CONTROL_UPGRADE_EDGE_SIGNING_PRIVATE_KEY_SHA256

  edge_paths=(
    "$(jq -er '.artifact_trust_file' "${edge_config}")"
    "$(jq -er '.upgrade.control_execution_trust_file' "${edge_config}")"
    "$(jq -er '.upgrade.edge_execution_trust_file' "${edge_config}")"
  ) || upgrade_e2e_unknown 'edge-trust-paths'
  edge_sha_names=(
    UPGRADE_E2E_EDGE_ARTIFACT_TRUST_SHA256
    UPGRADE_E2E_EDGE_CONTROL_EXECUTION_TRUST_SHA256
    UPGRADE_E2E_EDGE_EXECUTION_TRUST_SHA256
  )
  for index in "${!edge_paths[@]}"; do
    edge_path=${edge_paths[${index}]}
    edge_sha="$(upgrade_e2e_require_env "${edge_sha_names[${index}]}")"
    upgrade_e2e_valid_sha256 "${edge_sha}" || upgrade_e2e_unknown 'invalid-edge-trust-sha256'
    upgrade_e2e_require_file "${edge_path}" edge-runtime-trust
    [ "$(upgrade_e2e_sha256_regular_file "${edge_path}")" = "${edge_sha}" ] || \
      upgrade_e2e_unknown 'edge-runtime-trust-drift'
  done

  upgrade_e2e_validate_external_pair initial-artifact UPGRADE_E2E_INITIAL_ARTIFACT \
    UPGRADE_E2E_INITIAL_ARTIFACT_SHA256
  upgrade_e2e_validate_external_pair initial-sbom UPGRADE_E2E_INITIAL_SBOM UPGRADE_E2E_INITIAL_SBOM_SHA256
  upgrade_e2e_validate_external_pair initial-manifest UPGRADE_E2E_INITIAL_MANIFEST \
    UPGRADE_E2E_INITIAL_MANIFEST_SHA256
  upgrade_e2e_validate_external_pair initial-signature UPGRADE_E2E_INITIAL_SIGNATURE \
    UPGRADE_E2E_INITIAL_SIGNATURE_SHA256
  upgrade_e2e_validate_external_pair initial-public-key UPGRADE_E2E_INITIAL_PUBLIC_KEY \
    UPGRADE_E2E_INITIAL_PUBLIC_KEY_SHA256
  upgrade_e2e_validate_external_sized_pair forward-bundle UPGRADE_E2E_FORWARD_BUNDLE \
    UPGRADE_E2E_FORWARD_BUNDLE_SHA256 UPGRADE_E2E_FORWARD_BUNDLE_SIZE
  upgrade_e2e_validate_external_sized_pair rollback-bundle UPGRADE_E2E_ROLLBACK_BUNDLE \
    UPGRADE_E2E_ROLLBACK_BUNDLE_SHA256 UPGRADE_E2E_ROLLBACK_BUNDLE_SIZE
  initial_version="$(upgrade_e2e_require_env UPGRADE_E2E_INITIAL_VERSION)"
  forward_version="$(upgrade_e2e_require_env UPGRADE_E2E_FORWARD_VERSION)"
  [[ "${initial_version}" =~ ^[0-9]+\.[0-9]+\.[0-9]+([.-][A-Za-z0-9.-]+)?$ ]] && \
    [[ "${forward_version}" =~ ^[0-9]+\.[0-9]+\.[0-9]+([.-][A-Za-z0-9.-]+)?$ ]] && \
    [ "${initial_version}" != "${forward_version}" ] || upgrade_e2e_unknown 'invalid-release-version-pair'
  grep -Fx "version=${initial_version}" "$(upgrade_e2e_require_env UPGRADE_E2E_INITIAL_MANIFEST)" >/dev/null || \
    upgrade_e2e_unknown 'initial-version-manifest-mismatch'
  token="$(upgrade_e2e_require_env UPGRADE_E2E_BEARER_TOKEN)"
  [[ "${token}" =~ ^[A-Za-z0-9._~-]+$ ]] && [ "${#token}" -ge 16 ] && [ "${#token}" -le 8192 ] || \
    upgrade_e2e_unknown 'invalid-control-bearer-token'
}

upgrade_e2e_timeout() {
  local timeout_seconds=$1
  shift
  perl -e '
    use POSIX qw(setpgid);
    my $timeout = shift @ARGV;
    my $pid = fork();
    die "fork command: $!\n" unless defined $pid;
    if ($pid == 0) { setpgid(0, 0); exec @ARGV; exit 127; }
    setpgid($pid, $pid);
    my $stop = sub {
      my ($signal, $code) = @_;
      kill $signal, -$pid;
      for (1 .. 20) { last unless kill 0, -$pid; select undef, undef, undef, 0.05; }
      kill "KILL", -$pid if kill 0, -$pid;
      waitpid($pid, 0);
      exit $code;
    };
    $SIG{ALRM} = sub { $stop->("TERM", 124) };
    $SIG{INT} = sub { $stop->("INT", 130) };
    $SIG{TERM} = sub { $stop->("TERM", 143) };
    alarm $timeout;
    waitpid($pid, 0);
    alarm 0;
    my $status = $?;
    exit($status == -1 ? 127 : ($status & 127) ? 128 + ($status & 127) : $status >> 8);
  ' "${timeout_seconds}" "$@"
}

upgrade_e2e_docker() {
  upgrade_e2e_timeout 60 docker "$@"
}

WORK_DIR=''
EDGE_IDENTITY_DIR=''
INPUT_SNAPSHOT_DIR=''
SNAPSHOT_INVENTORY_RAW=''
SNAPSHOT_INVENTORY=''
NATS_RESOURCES_SNAPSHOT=''
PROCESS_CONTRACT_SNAPSHOT=''
LICENSE_AUTHORITY_FIXTURE_SNAPSHOT=''
CONTROL_AUTHORITY_FIXTURE_SNAPSHOT=''
EDGE_CONFIG_SNAPSHOT=''
SUCCESS_ROLLOUT_SNAPSHOT=''
AUTOMATIC_ROLLBACK_SNAPSHOT=''
OPERATOR_ROLLBACK_SNAPSHOT=''
FORWARD_BUNDLE_SNAPSHOT=''
ROLLBACK_BUNDLE_SNAPSHOT=''
CONTROL_ENTITLEMENT_TRUST_SNAPSHOT=''
CONTROL_INSTALLATION_KEY_SNAPSHOT=''
CONTROL_ACTIVATION_CREDENTIAL_SNAPSHOT=''
CONTROL_COMMAND_TRUST_SNAPSHOT=''
CONTROL_SIGNING_KEY_SNAPSHOT=''
EDGE_SIGNING_KEY_SNAPSHOT=''
EDGE_ARTIFACT_TRUST_SNAPSHOT=''
EDGE_CONTROL_TRUST_SNAPSHOT=''
EDGE_EXECUTION_TRUST_SNAPSHOT=''
EDGE_RELEASE_BUILD_CONTRACT_SNAPSHOT=''
EDGE_RELEASE_SOURCE_MANIFEST_SNAPSHOT=''
EDGE_RELEASE_C_MANIFEST_SNAPSHOT=''
PROCESS_CONTRACT_SHA256=''
LICENSE_PARENT_RECEIPT_SCHEMA=''
LICENSE_DATABASE_URL=''
CONTROL_DATABASE_URL=''
LICENSE_MIGRATION_SNAPSHOT_DIR=''
CONTROL_MIGRATION_SNAPSHOT_DIR=''
last_snapshot_manifest=''
last_validated_external_file=''
last_validated_manifest=''
TASK_ID=''
RESOURCE_LABEL=''
NETWORK_NAME=''
POSTGRES_CONTAINER=''
NATS_CONTAINER=''
REDIS_CONTAINER=''
license_pid=''
control_pid=''
gateway_pid=''
owned_ports=()
preexisting_container_ids=()
preexisting_network_ids=()
owned_container_ids=()
candidate_container_ids=()
registered_container_ids=()
registered_container_roles=()
owned_network_ids=()
candidate_network_ids=()
registered_pids=()
registered_pid_executables=()
registered_pid_markers=()
registered_pid_starts=()
registered_pid_pgids=()
registered_pid_group_markers=()
candidate_pids=()
candidate_pid_executables=()
candidate_pid_markers=()
candidate_pid_starts=()
candidate_pid_pgids=()
candidate_pid_group_markers=()
pending_group_markers=()
pending_group_executables=()
stopped_pgids=()
reaped_pids=()
last_candidate_pid_index=''
tracked_live_inputs=()
tracked_snapshot_inputs=()
tracked_input_hashes=()
readonly -a snapshot_roots=(
  services/license-service
  services/control-api
  services/agent-gateway
  agents/edge-agent
  libs/autodefense/detect
  libs/autodefense/mine
  libs/autodefense/sketch
  libs/edgeconfig
  libs/entitlement
  libs/rulepack
  proto/gen/go
)
docker_resources_possible=0
docker_inspection_failed=0
cleanup_probe_failed=0
secret_scan_completed=0
reservation_owned=0
LOCK_ROOT=''
RESERVATION_DIR=''
RESERVATION_OWNER_FILE=''
RESERVATION_OWNER_ID=''
RESERVATION_OWNER_SHA256=''
CLEANUP_EVIDENCE_FILE=''
CLEANUP_EVIDENCE_CONTENT=''
nats_container_id=''
nats_cli_container_id=''
redis_container_id=''
last_container_id=''
license_container_id=''
control_container_id=''
gateway_container_id=''
edge_container_id=''
license_health_port=''
control_http_port=''
gateway_health_port=''
control_api_header_file=''

upgrade_e2e_valid_docker_id() {
  [[ "$1" =~ ^[0-9a-f]{12,64}$ ]]
}

upgrade_e2e_verify_container_label() {
  local resource_id=$1 actual
  upgrade_e2e_valid_docker_id "${resource_id}" || return 1
  actual=$(upgrade_e2e_docker inspect --type container --format "{{ index .Config.Labels \"${TASK_LABEL_KEY}\" }}" "${resource_id}") || return 1
  [ "${actual}" = "${TASK_ID}" ]
}

upgrade_e2e_verify_network_label() {
  local resource_id=$1 actual
  upgrade_e2e_valid_docker_id "${resource_id}" || return 1
  actual=$(upgrade_e2e_docker network inspect --format "{{ index .Labels \"${TASK_LABEL_KEY}\" }}" "${resource_id}") || return 1
  [ "${actual}" = "${TASK_ID}" ]
}

upgrade_e2e_id_in_array() {
  local wanted=$1 item
  shift
  for item in "$@"; do
    [ -n "${item}" ] && [ "${item}" = "${wanted}" ] && return 0
  done
  return 1
}

upgrade_e2e_list_labeled_container_ids() {
  local listed resource_id
  listed=$(upgrade_e2e_timeout 20 docker ps -aq --no-trunc --filter "label=${RESOURCE_LABEL}") || return 1
  while IFS= read -r resource_id; do
    [ -n "${resource_id}" ] || continue
    upgrade_e2e_valid_docker_id "${resource_id}" || return 1
    printf '%s\n' "${resource_id}"
  done <<<"${listed}"
}

upgrade_e2e_list_labeled_network_ids() {
  local listed resource_id
  listed=$(upgrade_e2e_timeout 20 docker network ls -q --no-trunc --filter "label=${RESOURCE_LABEL}") || return 1
  while IFS= read -r resource_id; do
    [ -n "${resource_id}" ] || continue
    upgrade_e2e_valid_docker_id "${resource_id}" || return 1
    printf '%s\n' "${resource_id}"
  done <<<"${listed}"
}

upgrade_e2e_list_container_ids() {
  local listed resource_id
  listed=$(upgrade_e2e_timeout 20 docker ps -aq --no-trunc) || return 1
  while IFS= read -r resource_id; do
    [ -n "${resource_id}" ] || continue
    upgrade_e2e_valid_docker_id "${resource_id}" || return 1
    printf '%s\n' "${resource_id}"
  done <<<"${listed}"
}

upgrade_e2e_list_network_ids() {
  local listed resource_id
  listed=$(upgrade_e2e_timeout 20 docker network ls -q --no-trunc) || return 1
  while IFS= read -r resource_id; do
    [ -n "${resource_id}" ] || continue
    upgrade_e2e_valid_docker_id "${resource_id}" || return 1
    printf '%s\n' "${resource_id}"
  done <<<"${listed}"
}

upgrade_e2e_container_presence() {
  local resource_id=$1 listed existing
  listed=$(upgrade_e2e_list_container_ids) || return 2
  while IFS= read -r existing; do
    [ "${existing}" = "${resource_id}" ] && return 0
  done <<<"${listed}"
  return 1
}

upgrade_e2e_network_presence() {
  local resource_id=$1 listed existing
  listed=$(upgrade_e2e_list_network_ids) || return 2
  while IFS= read -r existing; do
    [ "${existing}" = "${resource_id}" ] && return 0
  done <<<"${listed}"
  return 1
}

upgrade_e2e_snapshot_preexisting_resources() {
  local listed resource_id
  upgrade_e2e_timeout 20 docker info >/dev/null 2>&1 || upgrade_e2e_unknown 'docker-unavailable-before-resource-snapshot'
  listed=$(upgrade_e2e_list_labeled_container_ids) || upgrade_e2e_unknown 'preexisting-container-snapshot'
  while IFS= read -r resource_id; do
    [ -n "${resource_id}" ] && preexisting_container_ids+=("${resource_id}")
  done <<<"${listed}"
  listed=$(upgrade_e2e_list_labeled_network_ids) || upgrade_e2e_unknown 'preexisting-network-snapshot'
  while IFS= read -r resource_id; do
    [ -n "${resource_id}" ] && preexisting_network_ids+=("${resource_id}")
  done <<<"${listed}"
}

upgrade_e2e_collect_post_minus_preexisting() {
  local kind=$1 listed=$2 resource_id
  while IFS= read -r resource_id; do
    [ -n "${resource_id}" ] || continue
    case "${kind}" in
      container)
        upgrade_e2e_id_in_array "${resource_id}" "${preexisting_container_ids[@]-}" || printf '%s\n' "${resource_id}"
        ;;
      network)
        upgrade_e2e_id_in_array "${resource_id}" "${preexisting_network_ids[@]-}" || printf '%s\n' "${resource_id}"
        ;;
      *) return 1 ;;
    esac
  done <<<"${listed}"
}

upgrade_e2e_registered_container_role() {
  local resource_id=$1 index
  for index in "${!registered_container_ids[@]}"; do
    if [ "${registered_container_ids[${index}]}" = "${resource_id}" ]; then
      printf '%s' "${registered_container_roles[${index}]}"
      return 0
    fi
  done
  return 1
}

upgrade_e2e_verify_registered_container_role() {
  local resource_id=$1 actual_role=$2 expected_role
  if expected_role=$(upgrade_e2e_registered_container_role "${resource_id}"); then
    [ "${actual_role}" = "${expected_role}" ]
  else
    return 0
  fi
}

upgrade_e2e_container_role() {
  local resource_id=$1 role
  upgrade_e2e_verify_container_label "${resource_id}" || return 1
  role=$(upgrade_e2e_docker inspect --type container \
    --format "{{ index .Config.Labels \"${RESOURCE_ROLE_LABEL_KEY}\" }}" "${resource_id}") || return 1
  case "${role}" in
    edge|gateway|control|license|tls-proxy|nats|redis|postgres) ;;
    *) return 1 ;;
  esac
  upgrade_e2e_verify_registered_container_role "${resource_id}" "${role}" || return 1
  printf '%s' "${role}"
}

upgrade_e2e_register_container() {
  local role=$1 resource_id=$2 actual_role
  candidate_container_ids+=("${resource_id}")
  upgrade_e2e_verify_container_label "${resource_id}" || upgrade_e2e_fail 'container-label-ownership'
  actual_role=$(upgrade_e2e_container_role "${resource_id}") || upgrade_e2e_fail 'container-role-ownership'
  [ "${actual_role}" = "${role}" ] || upgrade_e2e_fail 'container-role-ownership'
  registered_container_ids+=("${resource_id}")
  registered_container_roles+=("${role}")
  owned_container_ids+=("${resource_id}")
}

upgrade_e2e_register_network() {
  local resource_id=$1
  candidate_network_ids+=("${resource_id}")
  upgrade_e2e_verify_network_label "${resource_id}" || upgrade_e2e_fail 'network-label-ownership'
  owned_network_ids+=("${resource_id}")
}

upgrade_e2e_run_container() {
  local role=$1 resource_id status
  shift
  resource_id=''
  if resource_id=$(upgrade_e2e_docker run "$@"); then
    status=0
  else
    status=$?
  fi
  resource_id=${resource_id%%$'\n'*}
  if upgrade_e2e_valid_docker_id "${resource_id}"; then
    candidate_container_ids+=("${resource_id}")
  elif [ "${status}" -eq 0 ]; then
    return 1
  fi
  [ "${status}" -eq 0 ] || return "${status}"
  upgrade_e2e_register_container "${role}" "${resource_id}"
  last_container_id=${resource_id}
}

upgrade_e2e_create_network() {
  local resource_id status
  resource_id=''
  if resource_id=$(upgrade_e2e_docker network create "$@"); then
    status=0
  else
    status=$?
  fi
  resource_id=${resource_id%%$'\n'*}
  if upgrade_e2e_valid_docker_id "${resource_id}"; then
    candidate_network_ids+=("${resource_id}")
  elif [ "${status}" -eq 0 ]; then
    return 1
  fi
  [ "${status}" -eq 0 ] || return "${status}"
  upgrade_e2e_register_network "${resource_id}"
}

upgrade_e2e_container_port() {
  local resource_id=$1 container_port=$2 port
  upgrade_e2e_verify_container_label "${resource_id}" || return 1
  port=$(upgrade_e2e_docker inspect --type container \
    --format "{{(index (index .NetworkSettings.Ports \"${container_port}\") 0).HostPort}}" "${resource_id}") || return 1
  [[ "${port}" =~ ^[0-9]+$ ]] && [ "${port}" -ge 1 ] && [ "${port}" -le 65535 ] || return 1
  printf '%s' "${port}"
}

upgrade_e2e_record_recovered_port() {
  local port=$1 existing
  for existing in "${owned_ports[@]-}"; do
    [ "${existing}" = "${port}" ] && return 0
  done
  owned_ports+=("${port}")
}

upgrade_e2e_capture_owned_ports() {
  local resource_id=$1 ports_json port_list port
  upgrade_e2e_verify_container_label "${resource_id}" || return 1
  ports_json=$(upgrade_e2e_docker inspect --type container --format '{{json .NetworkSettings.Ports}}' "${resource_id}") || return 1
  port_list=$(jq -er '
    if type != "object" then error("invalid ports")
    else [.. | objects | .HostPort? | select(type == "string")] | join("\n") end
  ' <<<"${ports_json}") || return 1
  while IFS= read -r port; do
    [ -n "${port}" ] || continue
    [[ "${port}" =~ ^[0-9]+$ ]] && [ "${port}" -ge 1 ] && [ "${port}" -le 65535 ] || return 1
    upgrade_e2e_record_recovered_port "${port}"
  done <<<"${port_list}"
}

upgrade_e2e_capture_candidate_ports() {
  local candidates=$1 resource_id presence failure
  failure=0
  while IFS= read -r resource_id; do
    [ -n "${resource_id}" ] || continue
    if upgrade_e2e_container_presence "${resource_id}"; then
      presence=0
    else
      presence=$?
    fi
    case "${presence}" in
      0) upgrade_e2e_capture_owned_ports "${resource_id}" || failure=1 ;;
      1) ;;
      *) failure=1 ;;
    esac
  done <<<"${candidates}"
  [ "${failure}" -eq 0 ]
}

upgrade_e2e_list_process_group_members() {
  local pgid=$1
  ps -axo pid=,pgid=,stat= | awk -v pgid="${pgid}" '
    $2 == pgid && $3 !~ /^Z/ {print $1}
  '
}

upgrade_e2e_group_member_identity() {
  local pid=$1 pgid=$2 group_marker=$3 actual_pgid ppid started executable environment
  [[ "${pid}" =~ ^[0-9]+$ ]] && [ "${pid}" -gt 1 ] || return 1
  actual_pgid=$(ps -p "${pid}" -o pgid= 2>/dev/null | awk 'NR == 1 {print $1}') || return 1
  ppid=$(ps -p "${pid}" -o ppid= 2>/dev/null | awk 'NR == 1 {print $1}') || return 1
  started=$(LC_ALL=C ps -p "${pid}" -o lstart= 2>/dev/null | awk 'NR == 1 {$1=$1; print}') || return 1
  executable=$(ps -p "${pid}" -o comm= 2>/dev/null | awk 'NR == 1 {$1=$1; print}') || return 1
  environment=$(ps eww -p "${pid}" -o command= 2>/dev/null) || return 1
  [ "${actual_pgid}" = "${pgid}" ] && [ -n "${ppid}" ] && [ -n "${started}" ] && [ -n "${executable}" ] || return 1
  case " ${environment} " in
    *" UPGRADE_E2E_PROCESS_GROUP_MARKER=${group_marker} "*) ;;
    *) return 1 ;;
  esac
  printf '%s\t%s\t%s\n' "${ppid}" "${started}" "${executable}"
}

upgrade_e2e_list_marker_processes() {
  local group_marker=$1
  ps eww -axo pid=,pgid=,command= | awk -v marker="${group_marker}" '
    $1 ~ /^[0-9]+$/ && $2 ~ /^[0-9]+$/ && $1 > 1 && $2 > 1 &&
      index($0, " UPGRADE_E2E_PROCESS_GROUP_MARKER=" marker " ") {print $1 "\t" $2}
  '
}

upgrade_e2e_process_identity() {
  local pid=$1 executable=$2 marker=$3 group_marker=$4 pgid member_identity ppid started observed_executable command
  [[ "${pid}" =~ ^[0-9]+$ ]] && [ "${pid}" -gt 1 ] || return 1
  pgid=$(ps -p "${pid}" -o pgid= 2>/dev/null | awk 'NR == 1 {print $1}') || return 1
  member_identity=$(upgrade_e2e_group_member_identity "${pid}" "${pgid}" "${group_marker}") || return 1
  IFS=$'\t' read -r ppid started observed_executable <<<"${member_identity}"
  command=$(ps -p "${pid}" -o command= 2>/dev/null) || return 1
  [ "${pgid}" = "${pid}" ] && [ -n "${ppid}" ] && [ -n "${started}" ] && [ -n "${observed_executable}" ] || return 1
  case "${command}" in
    "${executable}"|"${executable} "*) ;;
    *) return 1 ;;
  esac
  case "${command}" in
    *"${marker}"*) ;;
    *) return 1 ;;
  esac
  printf '%s\t%s\n' "${pgid}" "${started}"
}

upgrade_e2e_register_pid() {
  local pid=$1 executable=$2 group_marker=$3 candidate_index=$4 identity pgid started
  [ -n "${WORK_DIR}" ] || return 1
  case "${executable}" in
    "${WORK_DIR}"/bin/*) ;;
    *) return 1 ;;
  esac
  [ -f "${executable}" ] && [ ! -L "${executable}" ] && [ -x "${executable}" ] || return 1
  identity=$(upgrade_e2e_process_identity "${pid}" "${executable}" "${WORK_DIR}" "${group_marker}") || return 1
  IFS=$'\t' read -r pgid started <<<"${identity}"
  [ -n "${pgid}" ] && [ -n "${started}" ] || return 1
  [ "${candidate_pid_pgids[${candidate_index}]}" = "${pgid}" ] || return 1
  [ "${candidate_pid_markers[${candidate_index}]}" = "${WORK_DIR}" ] || return 1
  if [ -n "${candidate_pid_starts[${candidate_index}]}" ]; then
    [ "${candidate_pid_starts[${candidate_index}]}" = "${started}" ] || return 1
  else
    candidate_pid_starts[candidate_index]=${started}
  fi
  registered_pids+=("${pid}")
  registered_pid_executables+=("${executable}")
  registered_pid_markers+=("${WORK_DIR}")
  registered_pid_starts+=("${started}")
  registered_pid_pgids+=("${pgid}")
  registered_pid_group_markers+=("${group_marker}")
}

upgrade_e2e_register_candidate_pid() {
  local pid=$1 executable=$2 group_marker=$3
  candidate_pids+=("${pid}")
  candidate_pid_executables+=("${executable}")
  candidate_pid_markers+=("${WORK_DIR}")
  candidate_pid_starts+=('')
  candidate_pid_pgids+=("${pid}")
  candidate_pid_group_markers+=("${group_marker}")
  last_candidate_pid_index=$((${#candidate_pids[@]} - 1))
}

upgrade_e2e_capture_candidate_identity() {
  local index=$1 pid pgid group_marker identity ppid started executable
  pid=${candidate_pids[${index}]}
  pgid=${candidate_pid_pgids[${index}]}
  group_marker=${candidate_pid_group_markers[${index}]}
  identity=$(upgrade_e2e_group_member_identity "${pid}" "${pgid}" "${group_marker}") || return 1
  IFS=$'\t' read -r ppid started executable <<<"${identity}"
  [ "${ppid}" = "$$" ] && [ -n "${started}" ] && [ -n "${executable}" ] || return 1
  candidate_pid_starts[index]=${started}
}

upgrade_e2e_validate_group_members() {
  local pgid=$1 group_marker=$2 leader_pid=$3 leader_start=$4 expected_executable=$5
  local members before after pid identity ppid started executable
  members=$(upgrade_e2e_list_process_group_members "${pgid}") || return 1
  [ -n "${members}" ] || return 1
  before=''
  while IFS= read -r pid; do
    [ -n "${pid}" ] || continue
    identity=$(upgrade_e2e_group_member_identity "${pid}" "${pgid}" "${group_marker}") || return 1
    IFS=$'\t' read -r ppid started executable <<<"${identity}"
    if [ "${pid}" = "${leader_pid}" ]; then
      [ -z "${leader_start}" ] || [ "${started}" = "${leader_start}" ] || return 1
      if [ -n "${expected_executable}" ]; then
        case "$(ps -p "${pid}" -o command= 2>/dev/null)" in
          "${expected_executable}"|"${expected_executable} "*) ;;
          *) return 1 ;;
        esac
      fi
    fi
    before+="${pid}"$'\t'"${identity}"$'\n'
  done <<<"${members}"
  members=$(upgrade_e2e_list_process_group_members "${pgid}") || return 1
  after=''
  while IFS= read -r pid; do
    [ -n "${pid}" ] || continue
    identity=$(upgrade_e2e_group_member_identity "${pid}" "${pgid}" "${group_marker}") || return 1
    after+="${pid}"$'\t'"${identity}"$'\n'
  done <<<"${members}"
  [ "${before}" = "${after}" ]
}

upgrade_e2e_pgid_is_stopped() {
  upgrade_e2e_id_in_array "$1" "${stopped_pgids[@]-}"
}

upgrade_e2e_process_group_alive() {
  local members
  members=$(upgrade_e2e_list_process_group_members "$1") || return 2
  [ -n "${members}" ]
}

upgrade_e2e_terminate_owned_group() {
  local pgid=$1 group_marker=$2 leader_pid=$3 leader_start=$4 expected_executable=$5 state
  upgrade_e2e_pgid_is_stopped "${pgid}" && return 0
  if upgrade_e2e_process_group_alive "${pgid}"; then
    state=0
  else
    state=$?
  fi
  if [ "${state}" -eq 1 ]; then
    stopped_pgids+=("${pgid}")
    return 0
  fi
  [ "${state}" -eq 0 ] || return 1
  upgrade_e2e_validate_group_members "${pgid}" "${group_marker}" "${leader_pid}" "${leader_start}" \
    "${expected_executable}" || return 1
  kill -TERM -- "-${pgid}" 2>/dev/null || return 1
  for _ in {1..100}; do
    if upgrade_e2e_process_group_alive "${pgid}"; then state=0; else state=$?; fi
    [ "${state}" -eq 0 ] || break
    sleep 0.1 || return 1
  done
  [ "${state}" -ne 2 ] || return 1
  if [ "${state}" -eq 0 ]; then
    upgrade_e2e_validate_group_members "${pgid}" "${group_marker}" "${leader_pid}" "${leader_start}" \
      "${expected_executable}" || return 1
    kill -KILL -- "-${pgid}" 2>/dev/null || return 1
  fi
  for _ in {1..100}; do
    if upgrade_e2e_process_group_alive "${pgid}"; then state=0; else state=$?; fi
    [ "${state}" -eq 0 ] || break
    sleep 0.1 || return 1
  done
  [ "${state}" -eq 1 ] || return 1
  stopped_pgids+=("${pgid}")
}

upgrade_e2e_pid_is_reaped() {
  upgrade_e2e_id_in_array "$1" "${reaped_pids[@]-}"
}

upgrade_e2e_wait_status_is_reapable() {
  [ "$1" -ne 127 ]
}

upgrade_e2e_terminate_candidate_group() {
  local index=$1 pid wait_status
  pid=${candidate_pids[${index}]}
  upgrade_e2e_pid_is_reaped "${pid}" && return 0
  case "${candidate_pid_executables[${index}]}" in
    "${candidate_pid_markers[${index}]}"/bin/*) ;;
    *) return 1 ;;
  esac
  upgrade_e2e_terminate_owned_group "${candidate_pid_pgids[${index}]}" \
    "${candidate_pid_group_markers[${index}]}" "${pid}" "${candidate_pid_starts[${index}]}" \
    "${candidate_pid_executables[${index}]}" || return 1
  if wait "${pid}" 2>/dev/null; then wait_status=0; else wait_status=$?; fi
  [ "${wait_status}" -ne 127 ] || return 1
  reaped_pids+=("${pid}")
}

upgrade_e2e_terminate_pending_group() {
  local group_marker=$1 executable=$2 discovered pgids pgid pid identity ppid started observed_executable
  local shell_pgid ready=0 leader_pid='' wait_status
  local -a child_pids=()
  [[ "${group_marker}" =~ ^[0-9a-f]{32}$ ]] || return 1
  case "${executable}" in
    "${WORK_DIR}"/bin/*) ;;
    *) return 1 ;;
  esac
  shell_pgid=$(ps -p "$$" -o pgid= 2>/dev/null | awk 'NR == 1 {print $1}') || return 1
  [[ "${shell_pgid}" =~ ^[0-9]+$ ]] || return 1
  for _ in {1..100}; do
    discovered=$(upgrade_e2e_list_marker_processes "${group_marker}") || return 1
    [ -n "${discovered}" ] || return 0
    pgids=$(printf '%s\n' "${discovered}" | awk -F '\t' '{print $2}' | LC_ALL=C sort -u) || return 1
    if [ "$(printf '%s\n' "${pgids}" | awk 'NF {n++} END {print n+0}')" -eq 1 ]; then
      pgid=${pgids}
      if [ "${pgid}" != "${shell_pgid}" ]; then
        ready=1
        break
      fi
    fi
    sleep 0.02 || return 1
  done
  [ "${ready}" -eq 1 ] || return 1
  while IFS=$'\t' read -r pid discovered_pgid; do
    [ -n "${pid}" ] || continue
    [ "${discovered_pgid}" = "${pgid}" ] || return 1
    identity=$(upgrade_e2e_group_member_identity "${pid}" "${pgid}" "${group_marker}") || return 1
    IFS=$'\t' read -r ppid started observed_executable <<<"${identity}"
    [ -n "${started}" ] && [ -n "${observed_executable}" ] || return 1
    [ -n "${leader_pid}" ] || leader_pid=${pid}
    if [ "${ppid}" = "$$" ]; then
      child_pids+=("${pid}")
    fi
  done <<<"${discovered}"
  [ -n "${leader_pid}" ] || return 1
  upgrade_e2e_terminate_owned_group "${pgid}" "${group_marker}" "${leader_pid}" '' '' || return 1
  for pid in "${child_pids[@]-}"; do
    if wait "${pid}" 2>/dev/null; then
      wait_status=0
    else
      wait_status=$?
    fi
    upgrade_e2e_wait_status_is_reapable "${wait_status}" || return 1
    reaped_pids+=("${pid}")
  done
}

upgrade_e2e_cleanup_pending_groups() {
  local index failure
  failure=0
  for index in "${!pending_group_markers[@]}"; do
    upgrade_e2e_terminate_pending_group "${pending_group_markers[${index}]}" \
      "${pending_group_executables[${index}]}" || failure=1
  done
  [ "${failure}" -eq 0 ]
}

upgrade_e2e_start_owned_process() {
  local destination=$1 executable=$2 pid group_marker candidate_index
  shift 2
  case "${destination}" in
    license_pid|control_pid|gateway_pid) ;;
    *) return 1 ;;
  esac
  group_marker=$(openssl rand -hex 16) || return 1
  pending_group_markers+=("${group_marker}")
  pending_group_executables+=("${executable}")
  UPGRADE_E2E_PROCESS_GROUP_MARKER="${group_marker}" perl -MPOSIX=setpgid -e '
    setpgid(0, 0) == 0 or exit 125;
    exec @ARGV;
    exit 126;
  ' "${executable}" "$@" &
  pid=$!
  upgrade_e2e_register_candidate_pid "${pid}" "${executable}" "${group_marker}" || return 1
  candidate_index=${last_candidate_pid_index}
  for _ in {1..100}; do
    if [ -z "${candidate_pid_starts[${candidate_index}]}" ]; then
      upgrade_e2e_capture_candidate_identity "${candidate_index}" || { sleep 0.02; continue; }
    fi
    if upgrade_e2e_register_pid "${pid}" "${executable}" "${group_marker}" "${candidate_index}"; then
      printf -v "${destination}" '%s' "${pid}"
      return 0
    fi
    kill -0 "${pid}" 2>/dev/null || break
    sleep 0.02 || break
  done
  upgrade_e2e_terminate_candidate_group "${candidate_index}" || return 1
  return 1
}

upgrade_e2e_registered_pid_index() {
  local pid=$1 index
  for index in "${!registered_pids[@]}"; do
    [ "${registered_pids[${index}]}" = "${pid}" ] && { printf '%s' "${index}"; return 0; }
  done
  return 1
}

upgrade_e2e_stop_pid() {
  local pid=$1 index pgid started wait_status
  [ -n "${pid}" ] || return 0
  upgrade_e2e_pid_is_reaped "${pid}" && return 0
  index=$(upgrade_e2e_registered_pid_index "${pid}") || return 1
  pgid=${registered_pid_pgids[${index}]}
  started=${registered_pid_starts[${index}]}
  case "${registered_pid_executables[${index}]}" in
    "${registered_pid_markers[${index}]}"/bin/*) ;;
    *) return 1 ;;
  esac
  upgrade_e2e_terminate_owned_group "${pgid}" "${registered_pid_group_markers[${index}]}" "${pid}" \
    "${started}" "${registered_pid_executables[${index}]}" || return 1
  if wait "${pid}" 2>/dev/null; then
    wait_status=0
  else
    wait_status=$?
  fi
  [ "${wait_status}" -ne 127 ] || return 1
  reaped_pids+=("${pid}")
}

upgrade_e2e_cleanup_all_pids() {
  local pid index failure
  failure=0
  for pid in "${registered_pids[@]-}"; do
    [ -n "${pid}" ] || continue
    upgrade_e2e_stop_pid "${pid}" || failure=1
  done
  for index in "${!candidate_pids[@]}"; do
    upgrade_e2e_terminate_candidate_group "${index}" || failure=1
  done
  upgrade_e2e_cleanup_pending_groups || failure=1
  [ "${failure}" -eq 0 ]
}

upgrade_e2e_stop_edge_services() {
  local resource_id=$1 running failure
  failure=0
  running=$(upgrade_e2e_docker inspect --type container --format '{{.State.Running}}' "${resource_id}") || return 1
  [ "${running}" = 'true' ] || return 0
  upgrade_e2e_docker exec "${resource_id}" systemctl stop cdnca-edge-agent.service >/dev/null 2>&1 || failure=1
  upgrade_e2e_docker exec "${resource_id}" systemctl stop cdnca-edge-agent-helper.service >/dev/null 2>&1 || failure=1
  upgrade_e2e_docker exec "${resource_id}" systemctl stop cdnca-edge-agent-helper.socket >/dev/null 2>&1 || failure=1
  [ "${failure}" -eq 0 ]
}

upgrade_e2e_stop_container_role() {
  local wanted_role=$1 candidates=$2 resource_id actual_role running presence failure
  failure=0
  while IFS= read -r resource_id; do
    [ -n "${resource_id}" ] || continue
    if upgrade_e2e_container_presence "${resource_id}"; then presence=0; else presence=$?; fi
    case "${presence}" in
      0) ;;
      1) continue ;;
      *) failure=1; continue ;;
    esac
    if ! actual_role=$(upgrade_e2e_container_role "${resource_id}"); then
      failure=1
      continue
    fi
    [ "${actual_role}" = "${wanted_role}" ] || continue
    [ "${actual_role}" != 'edge' ] || upgrade_e2e_stop_edge_services "${resource_id}" || failure=1
    if ! running=$(upgrade_e2e_docker inspect --type container --format '{{.State.Running}}' "${resource_id}"); then
      failure=1
      continue
    fi
    if [ "${running}" = 'true' ]; then
      upgrade_e2e_docker stop -t 10 "${resource_id}" >/dev/null 2>&1 || failure=1
    elif [ "${running}" != 'false' ]; then
      failure=1
    fi
  done <<<"${candidates}"
  [ "${failure}" -eq 0 ]
}

upgrade_e2e_remove_container_role() {
  local wanted_role=$1 candidates=$2 resource_id actual_role presence failure
  failure=0
  while IFS= read -r resource_id; do
    [ -n "${resource_id}" ] || continue
    if upgrade_e2e_container_presence "${resource_id}"; then presence=0; else presence=$?; fi
    case "${presence}" in
      0) ;;
      1) continue ;;
      *) failure=1; continue ;;
    esac
    if ! actual_role=$(upgrade_e2e_container_role "${resource_id}"); then
      failure=1
      continue
    fi
    [ "${actual_role}" = "${wanted_role}" ] || continue
    [ "${actual_role}" != 'edge' ] || upgrade_e2e_stop_edge_services "${resource_id}" || failure=1
    upgrade_e2e_docker rm -f "${resource_id}" >/dev/null 2>&1 || failure=1
  done <<<"${candidates}"
  [ "${failure}" -eq 0 ]
}

upgrade_e2e_remove_network_candidates() {
  local candidates=$1 resource_id presence failure
  failure=0
  while IFS= read -r resource_id; do
    [ -n "${resource_id}" ] || continue
    if upgrade_e2e_network_presence "${resource_id}"; then presence=0; else presence=$?; fi
    case "${presence}" in
      0) ;;
      1) continue ;;
      *) failure=1; continue ;;
    esac
    if ! upgrade_e2e_verify_network_label "${resource_id}"; then
      failure=1
      continue
    fi
    upgrade_e2e_docker network rm "${resource_id}" >/dev/null 2>&1 || failure=1
  done <<<"${candidates}"
  [ "${failure}" -eq 0 ]
}

upgrade_e2e_count_lines() {
  awk 'NF {n++} END {print n+0}'
}

upgrade_e2e_probe_listener() {
  local port=$1 output status
  output=''
  if output=$(lsof -nP -iTCP:"${port}" -sTCP:LISTEN 2>&1); then
    printf '1'
    return 0
  else
    status=$?
  fi
  [ "${status}" -eq 1 ] && [ -z "${output}" ] || return 1
  printf '0'
}

upgrade_e2e_write_cleanup_evidence() {
  local status=$1 containers=$2 networks=$3 listeners=$4 processes=$5 ppid1=$6 sockets=$7
  upgrade_e2e_verify_reservation_owner || return 1
  CLEANUP_EVIDENCE_FILE="${RESERVATION_DIR}/cleanup-evidence"
  CLEANUP_EVIDENCE_CONTENT="status=${status};containers=${containers};networks=${networks};listeners=${listeners};processes=${processes};ppid1=${ppid1};sockets=${sockets};secret_scan=${secret_scan_completed}"
  [ ! -e "${CLEANUP_EVIDENCE_FILE}" ] || return 1
  printf '%s' "${CLEANUP_EVIDENCE_CONTENT}" >"${CLEANUP_EVIDENCE_FILE}" || return 1
  chmod 0400 "${CLEANUP_EVIDENCE_FILE}" || return 1
}

upgrade_e2e_restore_reservation_metadata() {
  [ -d "${RESERVATION_DIR}" ] && [ ! -L "${RESERVATION_DIR}" ] || return 1
  if [ ! -e "${RESERVATION_OWNER_FILE}" ]; then
    printf '%s' "${RESERVATION_OWNER_ID}" >"${RESERVATION_OWNER_FILE}" || return 1
    chmod 0400 "${RESERVATION_OWNER_FILE}" || return 1
  fi
  if [ -n "${CLEANUP_EVIDENCE_FILE}" ] && [ ! -e "${CLEANUP_EVIDENCE_FILE}" ]; then
    printf '%s' "${CLEANUP_EVIDENCE_CONTENT}" >"${CLEANUP_EVIDENCE_FILE}" || return 1
    chmod 0400 "${CLEANUP_EVIDENCE_FILE}" || return 1
  fi
  upgrade_e2e_verify_reservation_owner
}

upgrade_e2e_probe_cleanup_absent() {
  local container_candidates=$1 network_candidates=$2 listed remaining count resource_id presence port probe
  local pid index state processes ppid1
  if [ "${docker_resources_possible}" -eq 1 ]; then
    upgrade_e2e_timeout 20 docker info >/dev/null 2>&1 || return 1
    listed=$(upgrade_e2e_list_labeled_container_ids) || return 1
    remaining=$(upgrade_e2e_collect_post_minus_preexisting container "${listed}") || return 1
    count=$(printf '%s\n' "${remaining}" | upgrade_e2e_count_lines) || return 1
    [ "${count}" -eq 0 ] || return 1
    while IFS= read -r resource_id; do
      [ -n "${resource_id}" ] || continue
      if upgrade_e2e_container_presence "${resource_id}"; then presence=0; else presence=$?; fi
      [ "${presence}" -eq 1 ] || return 1
    done <<<"${container_candidates}"
    listed=$(upgrade_e2e_list_labeled_network_ids) || return 1
    remaining=$(upgrade_e2e_collect_post_minus_preexisting network "${listed}") || return 1
    count=$(printf '%s\n' "${remaining}" | upgrade_e2e_count_lines) || return 1
    [ "${count}" -eq 0 ] || return 1
    while IFS= read -r resource_id; do
      [ -n "${resource_id}" ] || continue
      if upgrade_e2e_network_presence "${resource_id}"; then presence=0; else presence=$?; fi
      [ "${presence}" -eq 1 ] || return 1
    done <<<"${network_candidates}"
  fi
  for port in "${owned_ports[@]-}"; do
    [ -n "${port}" ] || continue
    probe=$(upgrade_e2e_probe_listener "${port}") || return 1
    [ "${probe}" -eq 0 ] || return 1
  done
  for pid in "${registered_pids[@]-}"; do
    [ -n "${pid}" ] || continue
    index=$(upgrade_e2e_registered_pid_index "${pid}") || return 1
    if upgrade_e2e_process_group_alive "${registered_pid_pgids[${index}]}"; then state=0; else state=$?; fi
    [ "${state}" -eq 1 ] || return 1
  done
  for index in "${!candidate_pids[@]}"; do
    if upgrade_e2e_process_group_alive "${candidate_pid_pgids[${index}]}"; then state=0; else state=$?; fi
    [ "${state}" -eq 1 ] || return 1
  done
  processes=$(ps -axo pid=,ppid=,command= | awk -v marker="${WORK_DIR}" 'index($0,marker) && $3 !~ /awk$/ {n++} END {print n+0}') || return 1
  ppid1=$(ps -axo pid=,ppid=,command= | awk -v marker="${WORK_DIR}" '$2==1 && index($0,marker) && $3 !~ /awk$/ {n++} END {print n+0}') || return 1
  [ "${processes}" -eq 0 ] && [ "${ppid1}" -eq 0 ] || return 1
  [ ! -e "${WORK_DIR}" ] || return 1
  upgrade_e2e_verify_reservation_owner
}

upgrade_e2e_cleanup() {
  local status=$? port processes ppid1 containers networks listeners sockets tmp probe cleanup_failed
  local listed container_candidates network_candidates remaining
  trap - EXIT INT TERM
  set +e
  cleanup_failed=0
  container_candidates=''
  network_candidates=''
  processes=0; ppid1=0; containers=0; networks=0; listeners=0; sockets=0; tmp=0
  if [ "${docker_resources_possible}" -eq 1 ]; then
    if ! command -v docker >/dev/null 2>&1 || ! upgrade_e2e_timeout 20 docker info >/dev/null 2>&1; then
      docker_inspection_failed=1
      cleanup_failed=1
      containers=-1
      networks=-1
    else
      if listed=$(upgrade_e2e_list_labeled_container_ids); then
        if ! container_candidates=$(
          printf '%s\n' "${candidate_container_ids[@]-}" "${owned_container_ids[@]-}"
          upgrade_e2e_collect_post_minus_preexisting container "${listed}"
        ); then
          docker_inspection_failed=1
          cleanup_failed=1
          container_candidates=''
        elif ! container_candidates=$(printf '%s\n' "${container_candidates}" | awk 'NF' | LC_ALL=C sort -u); then
          cleanup_probe_failed=1
          cleanup_failed=1
          container_candidates=''
        fi
      else
        docker_inspection_failed=1
        cleanup_failed=1
        if ! container_candidates=$(printf '%s\n' "${candidate_container_ids[@]-}" "${owned_container_ids[@]-}" | awk 'NF' | LC_ALL=C sort -u); then
          cleanup_probe_failed=1
          cleanup_failed=1
          container_candidates=''
        fi
      fi
      if listed=$(upgrade_e2e_list_labeled_network_ids); then
        if ! network_candidates=$(
          printf '%s\n' "${candidate_network_ids[@]-}" "${owned_network_ids[@]-}"
          upgrade_e2e_collect_post_minus_preexisting network "${listed}"
        ); then
          docker_inspection_failed=1
          cleanup_failed=1
          network_candidates=''
        elif ! network_candidates=$(printf '%s\n' "${network_candidates}" | awk 'NF' | LC_ALL=C sort -u); then
          cleanup_probe_failed=1
          cleanup_failed=1
          network_candidates=''
        fi
      else
        docker_inspection_failed=1
        cleanup_failed=1
        if ! network_candidates=$(printf '%s\n' "${candidate_network_ids[@]-}" "${owned_network_ids[@]-}" | awk 'NF' | LC_ALL=C sort -u); then
          cleanup_probe_failed=1
          cleanup_failed=1
          network_candidates=''
        fi
      fi

      upgrade_e2e_capture_candidate_ports "${container_candidates}" || { docker_inspection_failed=1; cleanup_failed=1; }
      upgrade_e2e_remove_container_role edge "${container_candidates}" || { docker_inspection_failed=1; cleanup_failed=1; }
      upgrade_e2e_stop_pid "${gateway_pid}" || { cleanup_probe_failed=1; cleanup_failed=1; }
      upgrade_e2e_remove_container_role gateway "${container_candidates}" || { docker_inspection_failed=1; cleanup_failed=1; }
      upgrade_e2e_stop_pid "${control_pid}" || { cleanup_probe_failed=1; cleanup_failed=1; }
      upgrade_e2e_remove_container_role control "${container_candidates}" || { docker_inspection_failed=1; cleanup_failed=1; }
      upgrade_e2e_remove_container_role tls-proxy "${container_candidates}" || { docker_inspection_failed=1; cleanup_failed=1; }
      upgrade_e2e_stop_pid "${license_pid}" || { cleanup_probe_failed=1; cleanup_failed=1; }
      upgrade_e2e_remove_container_role license "${container_candidates}" || { docker_inspection_failed=1; cleanup_failed=1; }
      upgrade_e2e_remove_container_role nats "${container_candidates}" || { docker_inspection_failed=1; cleanup_failed=1; }
      upgrade_e2e_remove_container_role redis "${container_candidates}" || { docker_inspection_failed=1; cleanup_failed=1; }
      upgrade_e2e_remove_container_role postgres "${container_candidates}" || { docker_inspection_failed=1; cleanup_failed=1; }
      upgrade_e2e_remove_network_candidates "${network_candidates}" || { docker_inspection_failed=1; cleanup_failed=1; }

      if listed=$(upgrade_e2e_list_labeled_container_ids) && \
        remaining=$(upgrade_e2e_collect_post_minus_preexisting container "${listed}"); then
        if ! containers=$(printf '%s\n' "${remaining}" | upgrade_e2e_count_lines); then
          containers=-1
          cleanup_probe_failed=1
          cleanup_failed=1
        fi
      else
        containers=-1
        docker_inspection_failed=1
        cleanup_failed=1
      fi
      if listed=$(upgrade_e2e_list_labeled_network_ids) && \
        remaining=$(upgrade_e2e_collect_post_minus_preexisting network "${listed}"); then
        if ! networks=$(printf '%s\n' "${remaining}" | upgrade_e2e_count_lines); then
          networks=-1
          cleanup_probe_failed=1
          cleanup_failed=1
        fi
      else
        networks=-1
        docker_inspection_failed=1
        cleanup_failed=1
      fi
    fi
  fi
  upgrade_e2e_cleanup_all_pids || { cleanup_probe_failed=1; cleanup_failed=1; }
  for port in "${owned_ports[@]-}"; do
    [ -n "${port}" ] || continue
    if probe=$(upgrade_e2e_probe_listener "${port}"); then
      listeners=$((listeners + probe))
    else
      cleanup_probe_failed=1
      cleanup_failed=1
      listeners=-1
    fi
  done
  if [ -n "${WORK_DIR}" ]; then
    if processes=$(ps -axo pid=,ppid=,command= | awk -v marker="${WORK_DIR}" 'index($0,marker) && $3 !~ /awk$/ {n++} END {print n+0}'); then :; else
      processes=-1
      cleanup_probe_failed=1
      cleanup_failed=1
    fi
    if ppid1=$(ps -axo pid=,ppid=,command= | awk -v marker="${WORK_DIR}" '$2==1 && index($0,marker) && $3 !~ /awk$/ {n++} END {print n+0}'); then :; else
      ppid1=-1
      cleanup_probe_failed=1
      cleanup_failed=1
    fi
    if [ -e "${WORK_DIR}" ]; then
      if sockets=$(find "${WORK_DIR}" -type s -print 2>/dev/null | wc -l | tr -d ' '); then :; else
        sockets=-1
        cleanup_probe_failed=1
        cleanup_failed=1
      fi
    fi
  fi
  if [ "${status}" -eq 0 ] && [ "${secret_scan_completed}" -eq 1 ] && [ "${cleanup_failed}" -eq 0 ] && \
    [ "${containers}" -eq 0 ] && [ "${networks}" -eq 0 ] && [ "${listeners}" -eq 0 ] && \
    [ "${processes}" -eq 0 ] && [ "${ppid1}" -eq 0 ] && [ "${sockets}" -eq 0 ]; then
    if ! upgrade_e2e_write_cleanup_evidence "${status}" "${containers}" "${networks}" "${listeners}" \
      "${processes}" "${ppid1}" "${sockets}"; then
      cleanup_probe_failed=1
      cleanup_failed=1
    elif [ -d "${INPUT_SNAPSHOT_DIR}" ] && ! chmod -R u+w "${INPUT_SNAPSHOT_DIR}"; then
      cleanup_probe_failed=1
      cleanup_failed=1
    elif [ -n "${WORK_DIR}" ]; then
      case "${WORK_DIR}" in
        */cdnca-upgrade-process-e2e-*)
          [ ! -e "${WORK_DIR}" ] || find "${WORK_DIR}" -depth -delete 2>/dev/null || { cleanup_probe_failed=1; cleanup_failed=1; }
          ;;
        *) cleanup_probe_failed=1; cleanup_failed=1 ;;
      esac
    fi
    if [ "${cleanup_failed}" -eq 0 ] && ! upgrade_e2e_probe_cleanup_absent "${container_candidates}" "${network_candidates}"; then
      cleanup_probe_failed=1
      cleanup_failed=1
    fi
    if [ "${cleanup_failed}" -eq 0 ] && [ "${reservation_owned}" -eq 1 ]; then
      if ! upgrade_e2e_verify_reservation_owner; then
        cleanup_probe_failed=1
        cleanup_failed=1
      elif ! rm -f -- "${RESERVATION_OWNER_FILE}"; then
        cleanup_probe_failed=1
        cleanup_failed=1
      elif ! rm -f -- "${CLEANUP_EVIDENCE_FILE}"; then
        upgrade_e2e_restore_reservation_metadata >/dev/null 2>&1 || cleanup_probe_failed=1
        cleanup_probe_failed=1
        cleanup_failed=1
      elif ! rmdir -- "${RESERVATION_DIR}" 2>/dev/null; then
        upgrade_e2e_restore_reservation_metadata >/dev/null 2>&1 || cleanup_probe_failed=1
        cleanup_probe_failed=1
        cleanup_failed=1
      else
        reservation_owned=0
      fi
    fi
  fi
  [ -z "${WORK_DIR}" ] || [ ! -e "${WORK_DIR}" ] || tmp=$((tmp + 1))
  [ "${reservation_owned}" -eq 0 ] || [ ! -e "${RESERVATION_DIR}" ] || tmp=$((tmp + 1))
  printf 'UPGRADE_PROCESS_E2E_CLEANUP containers=%s networks=%s listeners=%s processes=%s ppid1=%s sockets=%s tmp=%s\n' \
    "${containers}" "${networks}" "${listeners}" "${processes}" "${ppid1}" "${sockets}" "${tmp}"
  if [ "${cleanup_failed}" -ne 0 ] || [ "${docker_inspection_failed}" -ne 0 ] || [ "${cleanup_probe_failed}" -ne 0 ] || \
    [ "${containers}" -ne 0 ] || \
    [ "${networks}" -ne 0 ] || [ "${listeners}" -ne 0 ] || \
    [ "${processes}" -ne 0 ] || [ "${ppid1}" -ne 0 ] || [ "${sockets}" -ne 0 ] || \
    [ "${tmp}" -ne 0 ]; then
    exit 1
  fi
  exit "${status}"
}

upgrade_e2e_path_owner_uid() {
  stat -f '%u' "$1" 2>/dev/null || stat -c '%u' "$1" 2>/dev/null
}

upgrade_e2e_path_mode() {
  stat -f '%Lp' "$1" 2>/dev/null || stat -c '%a' "$1" 2>/dev/null
}

upgrade_e2e_system_lock_root() {
  local uid system_tmp root owner mode
  uid=$(id -u) || return 1
  [[ "${uid}" =~ ^[0-9]+$ ]] || return 1
  system_tmp=$(cd -P /tmp 2>/dev/null && pwd -P) || return 1
  [ -d "${system_tmp}" ] || return 1
  root="${system_tmp}/cdnca-upgrade-process-e2e-locks-${uid}"
  if [ ! -e "${root}" ]; then
    mkdir -m 0700 -- "${root}" 2>/dev/null || [ -d "${root}" ] || return 1
  fi
  [ -d "${root}" ] && [ ! -L "${root}" ] || return 1
  owner=$(upgrade_e2e_path_owner_uid "${root}") || return 1
  mode=$(upgrade_e2e_path_mode "${root}") || return 1
  [ "${owner}" = "${uid}" ] && [ "${mode}" = '700' ] || return 1
  printf '%s' "${root}"
}

upgrade_e2e_verify_reservation_owner() {
  local uid directory_owner directory_mode file_owner file_mode actual
  [ "${reservation_owned}" -eq 1 ] || return 1
  uid=$(id -u) || return 1
  [ -d "${RESERVATION_DIR}" ] && [ ! -L "${RESERVATION_DIR}" ] || return 1
  directory_owner=$(upgrade_e2e_path_owner_uid "${RESERVATION_DIR}") || return 1
  directory_mode=$(upgrade_e2e_path_mode "${RESERVATION_DIR}") || return 1
  [ "${directory_owner}" = "${uid}" ] && [ "${directory_mode}" = '700' ] || return 1
  [ -f "${RESERVATION_OWNER_FILE}" ] && [ ! -L "${RESERVATION_OWNER_FILE}" ] || return 1
  file_owner=$(upgrade_e2e_path_owner_uid "${RESERVATION_OWNER_FILE}") || return 1
  file_mode=$(upgrade_e2e_path_mode "${RESERVATION_OWNER_FILE}") || return 1
  [ "${file_owner}" = "${uid}" ] && [ "${file_mode}" = '400' ] || return 1
  actual=$(upgrade_e2e_sha256_regular_file "${RESERVATION_OWNER_FILE}") || return 1
  [ "${actual}" = "${RESERVATION_OWNER_SHA256}" ] || return 1
  [ "$(<"${RESERVATION_OWNER_FILE}")" = "${RESERVATION_OWNER_ID}" ]
}

upgrade_e2e_reserve_task_identity() {
  local uid started
  uid=$(id -u) || upgrade_e2e_fail 'task-reservation-uid'
  started=$(LC_ALL=C ps -p "$$" -o lstart= 2>/dev/null | awk 'NR == 1 {$1=$1; print}') || \
    upgrade_e2e_fail 'task-reservation-start-identity'
  [ -n "${started}" ] || upgrade_e2e_fail 'task-reservation-start-identity'
  LOCK_ROOT=$(upgrade_e2e_system_lock_root) || upgrade_e2e_fail 'task-lock-root'
  RESERVATION_DIR="${LOCK_ROOT}/${TASK_ID}.lock"
  case "${RESERVATION_DIR}" in
    /private/tmp/cdnca-upgrade-process-e2e-locks-*/*|/tmp/cdnca-upgrade-process-e2e-locks-*/*) ;;
    *) upgrade_e2e_fail 'unsafe-task-reservation' ;;
  esac
  mkdir -m 0700 -- "${RESERVATION_DIR}" 2>/dev/null || upgrade_e2e_fail 'task-identity-already-reserved'
  reservation_owned=1
  RESERVATION_OWNER_FILE="${RESERVATION_DIR}/owner"
  RESERVATION_OWNER_ID="uid=${uid};pid=$$;started=${started};task=${TASK_ID};script=${SCRIPT_DIR}/run.sh"
  printf '%s' "${RESERVATION_OWNER_ID}" >"${RESERVATION_OWNER_FILE}" || upgrade_e2e_fail 'task-reservation-owner-write'
  chmod 0400 "${RESERVATION_OWNER_FILE}" || upgrade_e2e_fail 'task-reservation-owner-mode'
  RESERVATION_OWNER_SHA256=$(upgrade_e2e_sha256_regular_file "${RESERVATION_OWNER_FILE}") || \
    upgrade_e2e_fail 'task-reservation-owner-digest'
  upgrade_e2e_verify_reservation_owner || upgrade_e2e_fail 'task-reservation-owner-identity'
}

upgrade_e2e_initialize_task() {
  local suffix
  suffix=${UPGRADE_E2E_TASK_SUFFIX:-$(date -u +%Y%m%d%H%M%S)-$$}
  [[ "${suffix}" =~ ^[A-Za-z0-9_-]+$ ]] || upgrade_e2e_fail 'invalid-task-suffix'
  TASK_ID="upgrade-process-e2e-${suffix}"
  RESOURCE_LABEL="${TASK_LABEL_KEY}=${TASK_ID}"
  NETWORK_NAME="cdnca-${TASK_ID}"
  POSTGRES_CONTAINER="${TASK_ID}-postgres"
  NATS_CONTAINER="${TASK_ID}-nats"
  REDIS_CONTAINER="${TASK_ID}-redis"
  readonly TASK_ID RESOURCE_LABEL NETWORK_NAME
  readonly POSTGRES_CONTAINER NATS_CONTAINER REDIS_CONTAINER
  trap upgrade_e2e_cleanup EXIT
  trap 'exit 130' INT TERM
  upgrade_e2e_reserve_task_identity
  WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/cdnca-${TASK_ID}.XXXXXX")"
  EDGE_IDENTITY_DIR="${WORK_DIR}/edge/identity"
  INPUT_SNAPSHOT_DIR="${WORK_DIR}/input-snapshot"
  SNAPSHOT_INVENTORY_RAW="${INPUT_SNAPSHOT_DIR}/inventory.raw"
  SNAPSHOT_INVENTORY="${INPUT_SNAPSHOT_DIR}/inventory.sha256"
  PROCESS_CONTRACT_SNAPSHOT="${INPUT_SNAPSHOT_DIR}/config/contract.json"
  NATS_RESOURCES_SNAPSHOT="${INPUT_SNAPSHOT_DIR}/config/nats-resources.json"
  LICENSE_AUTHORITY_FIXTURE_SNAPSHOT="${INPUT_SNAPSHOT_DIR}/config/license-authority.sql"
  CONTROL_AUTHORITY_FIXTURE_SNAPSHOT="${INPUT_SNAPSHOT_DIR}/config/control-authority.sql"
  EDGE_CONFIG_SNAPSHOT="${INPUT_SNAPSHOT_DIR}/config/edge-agent.json"
  SUCCESS_ROLLOUT_SNAPSHOT="${INPUT_SNAPSHOT_DIR}/config/success-rollout.json"
  AUTOMATIC_ROLLBACK_SNAPSHOT="${INPUT_SNAPSHOT_DIR}/config/automatic-rollback.json"
  OPERATOR_ROLLBACK_SNAPSHOT="${INPUT_SNAPSHOT_DIR}/config/operator-rollback.json"
  FORWARD_BUNDLE_SNAPSHOT="${INPUT_SNAPSHOT_DIR}/artifacts/forward.bundle"
  ROLLBACK_BUNDLE_SNAPSHOT="${INPUT_SNAPSHOT_DIR}/artifacts/rollback.bundle"
  CONTROL_ENTITLEMENT_TRUST_SNAPSHOT="${INPUT_SNAPSHOT_DIR}/runtime/control-entitlement-trust.json"
  CONTROL_INSTALLATION_KEY_SNAPSHOT="${INPUT_SNAPSHOT_DIR}/runtime/control-installation-key.pem"
  CONTROL_ACTIVATION_CREDENTIAL_SNAPSHOT="${INPUT_SNAPSHOT_DIR}/runtime/control-activation-credential"
  CONTROL_COMMAND_TRUST_SNAPSHOT="${INPUT_SNAPSHOT_DIR}/runtime/control-command-trust.json"
  CONTROL_SIGNING_KEY_SNAPSHOT="${INPUT_SNAPSHOT_DIR}/runtime/control-signing-key.pem"
  EDGE_SIGNING_KEY_SNAPSHOT="${INPUT_SNAPSHOT_DIR}/runtime/edge-signing-key.pem"
  EDGE_ARTIFACT_TRUST_SNAPSHOT="${INPUT_SNAPSHOT_DIR}/runtime/edge-artifact-trust.json"
  EDGE_CONTROL_TRUST_SNAPSHOT="${INPUT_SNAPSHOT_DIR}/runtime/edge-control-trust.json"
  EDGE_EXECUTION_TRUST_SNAPSHOT="${INPUT_SNAPSHOT_DIR}/runtime/edge-execution-trust.json"
  EDGE_RELEASE_BUILD_CONTRACT_SNAPSHOT="${INPUT_SNAPSHOT_DIR}/repo/agents/edge-agent/packaging/build/contract.json"
  EDGE_RELEASE_SOURCE_MANIFEST_SNAPSHOT="${INPUT_SNAPSHOT_DIR}/manifests/edge-release-source.sha256"
  EDGE_RELEASE_C_MANIFEST_SNAPSHOT="${INPUT_SNAPSHOT_DIR}/manifests/c.sha256"
  SYSTEMD_AMD64_INVENTORY_SNAPSHOT="${INPUT_SNAPSHOT_DIR}/supply-chain/amd64-runtime-inventory.sha256"
  SYSTEMD_ARM64_INVENTORY_SNAPSHOT="${INPUT_SNAPSHOT_DIR}/supply-chain/arm64-runtime-inventory.sha256"
  SYSTEMD_AMD64_MANIFEST_SNAPSHOT="${INPUT_SNAPSHOT_DIR}/supply-chain/amd64-manifest.json"
  SYSTEMD_ARM64_MANIFEST_SNAPSHOT="${INPUT_SNAPSHOT_DIR}/supply-chain/arm64-manifest.json"
  SYSTEMD_PROVENANCE_AMD64_SNAPSHOT="${INPUT_SNAPSHOT_DIR}/supply-chain/amd64-provenance.json"
  SYSTEMD_PROVENANCE_ARM64_SNAPSHOT="${INPUT_SNAPSHOT_DIR}/supply-chain/arm64-provenance.json"
  SYSTEMD_SPDX_SNAPSHOT="${INPUT_SNAPSHOT_DIR}/supply-chain/systemd-image.spdx.json"
  mkdir -p -- "${NATS_RESOURCES_SNAPSHOT%/*}" || upgrade_e2e_unknown 'input-snapshot-config-directory'
  upgrade_e2e_snapshot_release_inputs
  upgrade_e2e_snapshot_preexisting_resources
  readonly LOCK_ROOT RESERVATION_DIR RESERVATION_OWNER_FILE RESERVATION_OWNER_ID RESERVATION_OWNER_SHA256
  readonly WORK_DIR EDGE_IDENTITY_DIR INPUT_SNAPSHOT_DIR SNAPSHOT_INVENTORY_RAW SNAPSHOT_INVENTORY
  readonly PROCESS_CONTRACT_SNAPSHOT NATS_RESOURCES_SNAPSHOT
  readonly LICENSE_AUTHORITY_FIXTURE_SNAPSHOT CONTROL_AUTHORITY_FIXTURE_SNAPSHOT
  readonly EDGE_CONFIG_SNAPSHOT SUCCESS_ROLLOUT_SNAPSHOT AUTOMATIC_ROLLBACK_SNAPSHOT
  readonly OPERATOR_ROLLBACK_SNAPSHOT
  readonly FORWARD_BUNDLE_SNAPSHOT ROLLBACK_BUNDLE_SNAPSHOT
  readonly CONTROL_ENTITLEMENT_TRUST_SNAPSHOT CONTROL_INSTALLATION_KEY_SNAPSHOT
  readonly CONTROL_ACTIVATION_CREDENTIAL_SNAPSHOT CONTROL_COMMAND_TRUST_SNAPSHOT
  readonly CONTROL_SIGNING_KEY_SNAPSHOT EDGE_SIGNING_KEY_SNAPSHOT
  readonly EDGE_ARTIFACT_TRUST_SNAPSHOT EDGE_CONTROL_TRUST_SNAPSHOT EDGE_EXECUTION_TRUST_SNAPSHOT
  readonly EDGE_RELEASE_BUILD_CONTRACT_SNAPSHOT EDGE_RELEASE_SOURCE_MANIFEST_SNAPSHOT EDGE_RELEASE_C_MANIFEST_SNAPSHOT
  readonly SYSTEMD_AMD64_INVENTORY_SNAPSHOT SYSTEMD_ARM64_INVENTORY_SNAPSHOT
  readonly SYSTEMD_AMD64_MANIFEST_SNAPSHOT SYSTEMD_ARM64_MANIFEST_SNAPSHOT
  readonly SYSTEMD_PROVENANCE_AMD64_SNAPSHOT SYSTEMD_PROVENANCE_ARM64_SNAPSHOT SYSTEMD_SPDX_SNAPSHOT
  readonly PROCESS_CONTRACT_SHA256 LICENSE_PARENT_RECEIPT_SCHEMA
  readonly LICENSE_MIGRATION_SNAPSHOT_DIR CONTROL_MIGRATION_SNAPSHOT_DIR
}

upgrade_e2e_require_runtime() {
  local image
  upgrade_e2e_timeout 60 docker info >/dev/null 2>&1 || upgrade_e2e_unknown 'docker-unavailable'
  for image in "${POSTGRES_IMAGE}" "${NATS_IMAGE}" "${NATS_BOX_IMAGE}" "${REDIS_IMAGE}" \
    "${SYSTEMD_IMAGE}" "${TLS_PROXY_IMAGE}"; do
    upgrade_e2e_docker image inspect "${image}" >/dev/null 2>&1 || \
      upgrade_e2e_unknown "missing-image-${image//[:\/]/-}"
  done
}

upgrade_e2e_create_foundation() {
  local nats_port redis_port resource_id
  mkdir -p "${WORK_DIR}/bin" "${WORK_DIR}/certs" "${WORK_DIR}/postgres" \
    "${WORK_DIR}/nats" "${WORK_DIR}/edge" "${WORK_DIR}/logs" "${WORK_DIR}/artifact-cache"
  chmod 0700 "${WORK_DIR}" "${WORK_DIR}/certs" "${WORK_DIR}/edge"
  chmod 0777 "${WORK_DIR}/postgres"
  docker_resources_possible=1
  upgrade_e2e_create_network --label "${RESOURCE_LABEL}" "${NETWORK_NAME}" || upgrade_e2e_fail 'network-create'
  upgrade_e2e_run_container postgres -d --name "${POSTGRES_CONTAINER}" --network "${NETWORK_NAME}" \
    --label "${RESOURCE_LABEL}" --label "${RESOURCE_ROLE_LABEL_KEY}=postgres" \
    -e POSTGRES_USER=cdnca -e POSTGRES_DB=postgres \
    -e POSTGRES_HOST_AUTH_METHOD=trust -v "${WORK_DIR}/postgres:/var/run/postgresql" \
    "${POSTGRES_IMAGE}" postgres -c listen_addresses= -c unix_socket_directories=/var/run/postgresql \
    -c max_connections=20 -c max_locks_per_transaction=512 || upgrade_e2e_fail 'postgres-start'
  resource_id=${last_container_id}
  upgrade_e2e_run_container nats -d --name "${NATS_CONTAINER}" --network "${NETWORK_NAME}" \
    --label "${RESOURCE_LABEL}" --label "${RESOURCE_ROLE_LABEL_KEY}=nats" \
    -p 127.0.0.1::4222 -v "${WORK_DIR}/nats:/data" \
    "${NATS_IMAGE}" -js --store_dir /data || upgrade_e2e_fail 'nats-start'
  resource_id=${last_container_id}
  nats_container_id=${resource_id}
  nats_port=$(upgrade_e2e_container_port "${nats_container_id}" '4222/tcp') || upgrade_e2e_fail 'nats-port-inspect'
  owned_ports+=("${nats_port}")
  upgrade_e2e_run_container redis -d --name "${REDIS_CONTAINER}" --network "${NETWORK_NAME}" \
    --label "${RESOURCE_LABEL}" --label "${RESOURCE_ROLE_LABEL_KEY}=redis" \
    -p 127.0.0.1::6379 "${REDIS_IMAGE}" \
    redis-server --save '' --appendonly no || upgrade_e2e_fail 'redis-start'
  resource_id=${last_container_id}
  redis_container_id=${resource_id}
  redis_port=$(upgrade_e2e_container_port "${redis_container_id}" '6379/tcp') || upgrade_e2e_fail 'redis-port-inspect'
  owned_ports+=("${redis_port}")
}

upgrade_e2e_bundle_executable_identity() {
  perl -MDigest::SHA -e '
    use strict;
    use warnings;
    my ($path) = @ARGV;
    open my $input, "<:raw", $path or exit 2;
    my $magic = "";
    read($input, $magic, 30) == 30 or exit 2;
    $magic eq "cdnca-edge-release-bundle/v1\0" or exit 2;
    my @limits = (16384, 64, 16777216, 268435456);
    my ($executable_size, $executable_digest);
    for my $index (0 .. 3) {
      my $encoded = "";
      read($input, $encoded, 8) == 8 or exit 2;
      my $length = unpack("Q>", $encoded);
      exit 2 if $length < 1 || $length > $limits[$index] || ($index == 1 && $length != 64);
      my $remaining = $length;
      my $sha = Digest::SHA->new(256);
      while ($remaining > 0) {
        my $wanted = $remaining > 1048576 ? 1048576 : $remaining;
        my $buffer = "";
        my $count = read($input, $buffer, $wanted);
        exit 2 unless defined $count && $count == $wanted;
        $sha->add($buffer);
        $remaining -= $count;
      }
      if ($index == 3) {
        $executable_size = $length;
        $executable_digest = $sha->hexdigest;
      }
    }
    my $suffix = "";
    exit 2 if read($input, $suffix, 1) != 0;
    close $input or exit 2;
    print "$executable_digest:$executable_size";
  ' "$1"
}

upgrade_e2e_bundle_build_inputs() {
  perl -MTime::Local=timegm -e '
    use strict;
    use warnings;
    my ($path) = @ARGV;
    open my $input, "<:raw", $path or exit 2;
    read($input, my $magic, 30) == 30 or exit 2;
    $magic eq "cdnca-edge-release-bundle/v1\0" or exit 2;
    read($input, my $encoded, 8) == 8 or exit 2;
    my $length = unpack("Q>", $encoded);
    exit 2 if $length < 1 || $length > 16384;
    read($input, my $manifest, $length) == $length or exit 2;
    my @lines = split /\n/, $manifest, -1;
    exit 2 unless pop(@lines) eq "" && @lines == 16;
    my %facts;
    for my $line (@lines) {
      my ($key, $value) = split /=/, $line, 2;
      exit 2 unless defined $value && !exists $facts{$key};
      $facts{$key} = $value;
    }
    for my $key (qw(version arch source_repository source_commit build_time)) { exit 2 unless defined $facts{$key}; }
    exit 2 unless $facts{version} =~ /\A[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?\z/;
    exit 2 unless $facts{arch} eq "amd64" || $facts{arch} eq "arm64";
    exit 2 unless $facts{source_repository} =~ /\Ahttps:\/\/[A-Za-z0-9._\/-]+\z/;
    exit 2 unless $facts{source_commit} =~ /\A[0-9a-f]{40}\z/;
    my ($y,$m,$d,$h,$min,$s) = $facts{build_time} =~ /\A([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})Z\z/;
    exit 2 unless defined $s;
    my $epoch = eval { timegm($s,$min,$h,$d,$m-1,$y) };
    exit 2 unless defined $epoch && $epoch > 0;
    print join("\t", @facts{qw(version arch source_repository source_commit)}, $epoch);
  ' "$1"
}

upgrade_e2e_build_binaries() {
  local docker_arch go_arch built_identity forward_identity rollback_identity release_inputs
  local release_version release_arch source_repository source_commit source_epoch source_sha build_id release_output
  docker_arch=$(upgrade_e2e_timeout 20 docker info --format '{{.Architecture}}') || \
    upgrade_e2e_unknown 'docker-architecture-inspect'
  case "${docker_arch}" in amd64|x86_64) go_arch=amd64 ;; arm64|aarch64) go_arch=arm64 ;; *) upgrade_e2e_unknown 'unsupported-docker-architecture' ;; esac
  (cd "${INPUT_SNAPSHOT_DIR}/repo/services/license-service" && GOWORK=off CGO_ENABLED=0 GOOS=linux GOARCH="${go_arch}" \
    go build -trimpath -o "${WORK_DIR}/bin/license-service" ./cmd/license-service)
  (cd "${INPUT_SNAPSHOT_DIR}/repo/services/control-api" && GOWORK=off CGO_ENABLED=0 GOOS=linux GOARCH="${go_arch}" \
    go build -trimpath -o "${WORK_DIR}/bin/control-api" ./cmd/control-api)
  (cd "${INPUT_SNAPSHOT_DIR}/repo/services/agent-gateway" && GOWORK=off CGO_ENABLED=0 GOOS=linux GOARCH="${go_arch}" \
    go build -trimpath -o "${WORK_DIR}/bin/agent-gateway" ./cmd/agent-gateway)
  release_inputs=$(upgrade_e2e_bundle_build_inputs "${FORWARD_BUNDLE_SNAPSHOT}") || \
    upgrade_e2e_fail 'forward-bundle-build-inputs'
  IFS=$'\t' read -r release_version release_arch source_repository source_commit source_epoch <<<"${release_inputs}"
  [ "${release_version}" = "$(upgrade_e2e_require_env UPGRADE_E2E_FORWARD_VERSION)" ] && \
    [ "${release_arch}" = "${go_arch}" ] || upgrade_e2e_fail 'forward-bundle-build-input-mismatch'
  source_sha=$(upgrade_e2e_sha256_regular_file "${EDGE_RELEASE_SOURCE_MANIFEST_SNAPSHOT}") || \
    upgrade_e2e_fail 'edge-release-source-manifest-read'
  build_id="edge-${release_version}-${source_sha:0:16}"
  release_output="${WORK_DIR}/edge-release-build"
  EDGE_RELEASE_GO=go bash "${INPUT_SNAPSHOT_DIR}/repo/agents/edge-agent/packaging/build/recipe.sh" \
    --source-root "${INPUT_SNAPSHOT_DIR}/repo" \
    --source-manifest "${EDGE_RELEASE_SOURCE_MANIFEST_SNAPSHOT}" \
    --c-manifest "${EDGE_RELEASE_C_MANIFEST_SNAPSHOT}" \
    --contract "${EDGE_RELEASE_BUILD_CONTRACT_SNAPSHOT}" \
    --output-dir "${release_output}" --version "${release_version}" --build-id "${build_id}" \
    --source-repository "${source_repository}" --source-commit "${source_commit}" \
    --source-date-epoch "${source_epoch}" --arch "${go_arch}" || upgrade_e2e_fail 'edge-release-recipe'
  upgrade_e2e_copy_regular_file "${release_output}/edge-agent" "${WORK_DIR}/bin/cdnca-edge-agent" || \
    upgrade_e2e_fail 'edge-release-binary-copy'
  chmod 0555 "${WORK_DIR}/bin/cdnca-edge-agent" || upgrade_e2e_fail 'edge-release-binary-mode'
  (cd "${INPUT_SNAPSHOT_DIR}/repo/agents/edge-agent" && GOWORK=off CGO_ENABLED=0 GOOS=linux GOARCH="${go_arch}" \
    go build -trimpath -o "${WORK_DIR}/bin/cdnca-edge-agent-helper" ./packaging/helper/cmd/cdnca-edge-agent-helper)
  built_identity="$(upgrade_e2e_sha256_regular_file "${WORK_DIR}/bin/cdnca-edge-agent"):$(upgrade_e2e_regular_file_size "${WORK_DIR}/bin/cdnca-edge-agent")"
  forward_identity=$(upgrade_e2e_bundle_executable_identity "${FORWARD_BUNDLE_SNAPSHOT}") || \
    upgrade_e2e_fail 'forward-bundle-format'
  [ "${forward_identity}" = "${built_identity}" ] || upgrade_e2e_fail 'forward-bundle-built-binary-mismatch'
  rollback_identity=$(upgrade_e2e_bundle_executable_identity "${ROLLBACK_BUNDLE_SNAPSHOT}") || \
    upgrade_e2e_fail 'rollback-bundle-format'
  [ "${rollback_identity}" = \
    "$(upgrade_e2e_sha256_regular_file "${INPUT_SNAPSHOT_DIR}/initial/edge-agent"):$(upgrade_e2e_regular_file_size "${INPUT_SNAPSHOT_DIR}/initial/edge-agent")" ] || \
    upgrade_e2e_fail 'rollback-bundle-initial-binary-mismatch'
}

upgrade_e2e_issue_certificate() {
  local name=$1 san=$2 usage=$3 usage_text key csr certificate extensions mode
  [[ "${name}" =~ ^[a-z][a-z0-9-]{0,62}$ ]] || upgrade_e2e_fail 'pki-leaf-name'
  case "${san}" in DNS:license.internal|DNS:control.internal|DNS:gateway.internal|URI:spiffe://cdn-platform/gateway/control|URI:spiffe://cdn-platform/node/*) ;;
    *) upgrade_e2e_fail 'pki-leaf-san' ;;
  esac
  case "${usage}" in
    serverAuth) usage_text='TLS Web Server Authentication' ;;
    clientAuth) usage_text='TLS Web Client Authentication' ;;
    *) upgrade_e2e_fail 'pki-leaf-usage' ;;
  esac
  key="${WORK_DIR}/certs/${name}.key"
  csr="${WORK_DIR}/certs/${name}.csr"
  certificate="${WORK_DIR}/certs/${name}.pem"
  extensions="${WORK_DIR}/certs/${name}.ext"
  openssl genpkey -algorithm ED25519 -out "${key}" >/dev/null 2>&1 || upgrade_e2e_fail 'pki-leaf-key'
  chmod 0600 "${key}"
  openssl req -new -key "${key}" -out "${csr}" -subj "/CN=${name}" >/dev/null 2>&1 || \
    upgrade_e2e_fail 'pki-leaf-csr'
  {
    printf 'basicConstraints=critical,CA:false\n'
    printf 'keyUsage=critical,digitalSignature\n'
    printf 'extendedKeyUsage=%s\n' "${usage}"
    printf 'subjectAltName=%s\n' "${san}"
  } >"${extensions}"
  openssl x509 -req -in "${csr}" -CA "${WORK_DIR}/certs/ca.pem" -CAkey "${WORK_DIR}/certs/ca.key" \
    -CAcreateserial -days 1 -extfile "${extensions}" -out "${certificate}" >/dev/null 2>&1 || \
    upgrade_e2e_fail 'pki-leaf-sign'
  chmod 0444 "${certificate}"
  rm -f -- "${csr}" "${extensions}"
  mode=$(stat -f '%Lp' "${key}" 2>/dev/null || stat -c '%a' "${key}" 2>/dev/null) || \
    upgrade_e2e_fail 'pki-key-mode-inspect'
  [ "${mode}" = '600' ] || upgrade_e2e_fail 'pki-key-mode'
  openssl verify -CAfile "${WORK_DIR}/certs/ca.pem" "${certificate}" >/dev/null 2>&1 || \
    upgrade_e2e_fail 'pki-leaf-verify'
  openssl x509 -in "${certificate}" -noout -text | grep -F "${san}" >/dev/null || \
    upgrade_e2e_fail 'pki-leaf-san-verify'
  openssl x509 -in "${certificate}" -noout -text | grep -F "${usage_text}" >/dev/null || \
    upgrade_e2e_fail 'pki-leaf-usage-verify'
}

upgrade_e2e_fsync_path() {
  perl -MFcntl=:DEFAULT -MIO::Handle -e '
    use strict;
    use warnings;
    sysopen my $handle, $ARGV[0], O_RDONLY or exit 2;
    $handle->sync or exit 2;
    close $handle or exit 2;
  ' "$1"
}

upgrade_e2e_x25519_key_id_from_raw() {
  perl -MFcntl=:DEFAULT,:mode -e '
    use strict;
    use warnings;
    my ($path) = @ARGV;
    my @before = lstat $path or exit 2;
    exit 2 unless S_ISREG($before[2]) && ($before[2] & 0777) == 0600;
    my $no_follow = eval { Fcntl::O_NOFOLLOW() } // 0;
    sysopen my $input, $path, O_RDONLY | $no_follow or exit 2;
    binmode $input;
    local $/;
    my $raw = <$input>;
    close $input or exit 2;
    exit 2 unless defined $raw && length($raw) == 32;
    print pack("H*", "302e020100300506032b656e04220420"), $raw;
  ' "$1" | openssl pkey -inform DER -pubout -outform DER 2>/dev/null | \
    perl -MDigest::SHA=sha256_hex -e '
      use strict;
      use warnings;
      binmode STDIN;
      local $/;
      my $der = <STDIN>;
      my $prefix = pack("H*", "302a300506032b656e032100");
      exit 2 unless defined $der && length($der) == length($prefix) + 32 && substr($der, 0, length($prefix)) eq $prefix;
      print "x25519:", sha256_hex(substr($der, length($prefix)));
    '
}

upgrade_e2e_x25519_public_key_hex_from_raw() {
  perl -MFcntl=:DEFAULT,:mode -e '
    use strict;
    use warnings;
    my ($path) = @ARGV;
    my @before = lstat $path or exit 2;
    exit 2 unless S_ISREG($before[2]) && ($before[2] & 0777) == 0600;
    my $no_follow = eval { Fcntl::O_NOFOLLOW() } // 0;
    sysopen my $input, $path, O_RDONLY | $no_follow or exit 2;
    binmode $input;
    local $/;
    my $raw = <$input>;
    close $input or exit 2;
    exit 2 unless defined $raw && length($raw) == 32;
    print pack("H*", "302e020100300506032b656e04220420"), $raw;
  ' "$1" | openssl pkey -inform DER -pubout -outform DER 2>/dev/null | perl -e '
    use strict;
    use warnings;
    binmode STDIN;
    local $/;
    my $der = <STDIN>;
    my $prefix = pack("H*", "302a300506032b656e032100");
    exit 2 unless defined $der && length($der) == length($prefix) + 32 &&
      substr($der, 0, length($prefix)) eq $prefix;
    print unpack("H*", substr($der, length($prefix)));
  '
}

upgrade_e2e_validate_edge_identity() {
  local directory=$1 node_id=$2 key_id=$3 source_certificate=$4 source_key=$5 canonical fingerprint
  local certificate_public key_public san basic key_usage extended_usage
  perl -MFcntl=:mode -e '
    use strict;
    use warnings;
    my ($path, @required) = @ARGV;
    exit 2 unless $path =~ m{\A/} && $path ne "/" && $path !~ m{//|/(?:\.|\.\.)(?:/|\z)};
    my $current = "/";
    for my $component (grep { length } split m{/}, $path) {
      $current .= ($current eq "/" ? "" : "/") . $component;
      my @info = lstat $current or exit 2;
      exit 2 if S_ISLNK($info[2]);
    }
    my @directory = stat $path or exit 2;
    exit 2 unless S_ISDIR($directory[2]) && ($directory[2] & 0777) == 0700;
    opendir my $entries, $path or exit 2;
    my @actual = sort grep { $_ ne "." && $_ ne ".." } readdir $entries;
    closedir $entries or exit 2;
    @required = sort @required;
    exit 2 unless "@actual" eq "@required";
    for my $name (@required) {
      my @file = lstat "$path/$name" or exit 2;
      exit 2 unless S_ISREG($file[2]) && !S_ISLNK($file[2]) && ($file[2] & 0777) == 0600;
    }
  ' "${directory}" identity.json client.pem client-key.pem artifact-x25519-key.bin || return 1
  canonical=$(jq -S -c . "${directory}/identity.json") || return 1
  cmp -s <(printf '%s\n' "${canonical}") "${directory}/identity.json" || return 1
  jq -e --arg node_id "${node_id}" --arg key_id "${key_id}" '
    keys == ["artifact_encryption_key_id","artifact_encryption_private_key_file","client_certificate_file",
      "client_private_key_file","machine_fingerprint_sha256","node_id","selected_protocol_major",
      "selected_protocol_minor","version"] and
    .version == 1 and .node_id == $node_id and .selected_protocol_major == 1 and
    .selected_protocol_minor == 0 and .artifact_encryption_key_id == $key_id and
    .client_certificate_file == "client.pem" and .client_private_key_file == "client-key.pem" and
    .artifact_encryption_private_key_file == "artifact-x25519-key.bin"
  ' "${directory}/identity.json" >/dev/null || return 1
  fingerprint=$(jq -er '.machine_fingerprint_sha256' "${directory}/identity.json") || return 1
  perl -MMIME::Base64=decode_base64,encode_base64 -e '
    use strict;
    use warnings;
    my $encoded = $ARGV[0];
    exit 2 unless $encoded =~ m{\A[A-Za-z0-9+/]{43}\z};
    my $decoded = decode_base64($encoded . "=");
    my $canonical = encode_base64($decoded, "");
    $canonical =~ s/=+\z//;
    exit 2 unless length($decoded) == 32 && $canonical eq $encoded;
  ' "${fingerprint}" || return 1
  perl -MFcntl=:DEFAULT,:mode -e '
    use strict;
    use warnings;
    sub read_regular {
      my ($path) = @_;
      my @info = lstat $path or exit 2;
      exit 2 unless S_ISREG($info[2]);
      my $no_follow = eval { Fcntl::O_NOFOLLOW() } // 0;
      sysopen my $input, $path, O_RDONLY | $no_follow or exit 2;
      binmode $input;
      local $/;
      my $value = <$input>;
      close $input or exit 2;
      return $value;
    }
    exit 2 unless read_regular($ARGV[0]) eq read_regular($ARGV[1]) . read_regular($ARGV[2]);
    exit 2 unless read_regular($ARGV[3]) eq read_regular($ARGV[4]);
  ' "${directory}/client.pem" "${source_certificate}" "${WORK_DIR}/certs/ca.pem" \
    "${directory}/client-key.pem" "${source_key}" || return 1
  openssl verify -purpose sslclient -CAfile "${WORK_DIR}/certs/ca.pem" "${directory}/client.pem" >/dev/null 2>&1 || return 1
  openssl x509 -in "${directory}/client.pem" -noout -checkend 0 >/dev/null 2>&1 || return 1
  certificate_public=$(openssl x509 -in "${directory}/client.pem" -pubkey -noout | \
    openssl pkey -pubin -outform DER 2>/dev/null | shasum -a 256 | awk '{print $1}') || return 1
  key_public=$(openssl pkey -in "${directory}/client-key.pem" -pubout -outform DER 2>/dev/null | \
    shasum -a 256 | awk '{print $1}') || return 1
  [ "${certificate_public}" = "${key_public}" ] || return 1
  san=$(openssl x509 -in "${directory}/client.pem" -noout -ext subjectAltName | tr -d '[:space:]') || return 1
  [ "${san}" = "X509v3SubjectAlternativeName:URI:spiffe://cdn-platform/node/${node_id}" ] || return 1
  basic=$(openssl x509 -in "${directory}/client.pem" -noout -ext basicConstraints | tr -d '[:space:]') || return 1
  [ "${basic}" = 'X509v3BasicConstraints:criticalCA:FALSE' ] || return 1
  key_usage=$(openssl x509 -in "${directory}/client.pem" -noout -ext keyUsage | tr -d '[:space:]') || return 1
  [ "${key_usage}" = 'X509v3KeyUsage:criticalDigitalSignature' ] || return 1
  extended_usage=$(openssl x509 -in "${directory}/client.pem" -noout -ext extendedKeyUsage | tr -d '[:space:]') || return 1
  [ "${extended_usage}" = 'X509v3ExtendedKeyUsage:TLSWebClientAuthentication' ] || return 1
  [ "$(openssl x509 -in "${directory}/client.pem" -noout -text | grep -c -F 'Public Key Algorithm: ED25519')" -eq 1 ] || return 1
  [ "$(upgrade_e2e_x25519_key_id_from_raw "${directory}/artifact-x25519-key.bin")" = "${key_id}" ]
}

upgrade_e2e_edge_identity_public_facts() {
  local certificate serial leaf_der_sha256 artifact_key_id artifact_public_key_hex expected_key_id
  certificate="${EDGE_IDENTITY_DIR}/client.pem"
  serial=$(openssl x509 -in "${certificate}" -noout -serial 2>/dev/null | \
    awk -F= 'NR == 1 && $1 == "serial" && NF == 2 {print tolower($2)}') || return 1
  leaf_der_sha256=$(openssl x509 -in "${certificate}" -outform DER 2>/dev/null | \
    shasum -a 256 | awk 'NR == 1 {print $1}') || return 1
  artifact_key_id=$(jq -er '.artifact_encryption_key_id' "${EDGE_IDENTITY_DIR}/identity.json") || return 1
  artifact_public_key_hex=$(upgrade_e2e_x25519_public_key_hex_from_raw \
    "${EDGE_IDENTITY_DIR}/artifact-x25519-key.bin") || return 1
  [[ "${serial}" =~ ^[0-9a-f]{1,128}$ ]] || return 1
  upgrade_e2e_valid_sha256 "${leaf_der_sha256}" || return 1
  [[ "${artifact_key_id}" =~ ^x25519:[0-9a-f]{64}$ ]] || return 1
  [[ "${artifact_public_key_hex}" =~ ^[0-9a-f]{64}$ ]] || return 1
  expected_key_id=$(perl -MDigest::SHA=sha256_hex -e '
    my $raw = pack("H*", $ARGV[0]);
    exit 2 unless length($raw) == 32;
    print "x25519:", sha256_hex($raw);
  ' "${artifact_public_key_hex}") || return 1
  [ "${artifact_key_id}" = "${expected_key_id}" ] || return 1
  printf '%s\t%s\t%s\t%s\n' "${serial}" "${leaf_der_sha256}" \
    "${artifact_key_id}" "${artifact_public_key_hex}"
}

upgrade_e2e_atomic_publish_identity() {
  local staging=$1 destination=$2
  [ "${destination}" = "${EDGE_IDENTITY_DIR}" ] && [ ! -e "${destination}" ] && [ ! -L "${destination}" ] || return 1
  upgrade_e2e_fsync_path "${staging}" || return 1
  perl -MFcntl=:mode -e '
    use strict;
    use warnings;
    my ($source, $destination) = @ARGV;
    my @source = lstat $source or exit 2;
    exit 2 unless S_ISDIR($source[2]) && !S_ISLNK($source[2]);
    exit 2 if lstat $destination;
    rename $source, $destination or exit 2;
  ' "${staging}" "${destination}" || return 1
  upgrade_e2e_fsync_path "${destination%/*}"
}

upgrade_e2e_create_edge_identity() {
  local node_id staging x25519_pem key_id fingerprint file
  node_id="$(upgrade_e2e_require_env UPGRADE_E2E_NODE_ID)"
  staging=$(mktemp -d "${WORK_DIR}/edge/.identity.XXXXXX") || upgrade_e2e_fail 'edge-identity-staging'
  chmod 0700 "${staging}" || upgrade_e2e_fail 'edge-identity-directory-mode'
  upgrade_e2e_copy_regular_file "${WORK_DIR}/certs/edge-agent-client.key" "${staging}/client-key.pem" || \
    upgrade_e2e_fail 'edge-identity-client-key-copy'
  chmod 0600 "${staging}/client-key.pem" || upgrade_e2e_fail 'edge-identity-client-key-mode'
  perl -MFcntl=:DEFAULT,:mode -e '
    use strict;
    use warnings;
    for my $path (@ARGV) {
      my @info = lstat $path or exit 2;
      exit 2 unless S_ISREG($info[2]);
      my $no_follow = eval { Fcntl::O_NOFOLLOW() } // 0;
      sysopen my $input, $path, O_RDONLY | $no_follow or exit 2;
      binmode $input;
      while (1) {
        my $buffer = "";
        my $read = read $input, $buffer, 65536;
        exit 2 unless defined $read;
        last if $read == 0;
        print $buffer or exit 2;
      }
      close $input or exit 2;
    }
  ' "${WORK_DIR}/certs/edge-agent-client.pem" "${WORK_DIR}/certs/ca.pem" >"${staging}/client.pem" || \
    upgrade_e2e_fail 'edge-identity-client-bundle'
  chmod 0600 "${staging}/client.pem" || upgrade_e2e_fail 'edge-identity-client-bundle-mode'
  x25519_pem="${WORK_DIR}/edge/.artifact-x25519-key.pem"
  openssl genpkey -algorithm X25519 -out "${x25519_pem}" >/dev/null 2>&1 || upgrade_e2e_fail 'edge-identity-x25519-generate'
  chmod 0600 "${x25519_pem}" || upgrade_e2e_fail 'edge-identity-x25519-source-mode'
  openssl pkey -in "${x25519_pem}" -outform DER 2>/dev/null | perl -e '
    use strict;
    use warnings;
    binmode STDIN;
    binmode STDOUT;
    local $/;
    my $der = <STDIN>;
    my $prefix = pack("H*", "302e020100300506032b656e04220420");
    exit 2 unless defined $der && length($der) == length($prefix) + 32 && substr($der, 0, length($prefix)) eq $prefix;
    print substr($der, length($prefix));
  ' >"${staging}/artifact-x25519-key.bin" || upgrade_e2e_fail 'edge-identity-x25519-raw'
  chmod 0600 "${staging}/artifact-x25519-key.bin" || upgrade_e2e_fail 'edge-identity-x25519-mode'
  key_id=$(upgrade_e2e_x25519_key_id_from_raw "${staging}/artifact-x25519-key.bin") || \
    upgrade_e2e_fail 'edge-identity-x25519-key-id'
  fingerprint=$(perl -MDigest::SHA=sha256 -MMIME::Base64=encode_base64 -e '
    my $encoded = encode_base64(sha256("cdnca-upgrade-e2e-machine-v1\0" . $ARGV[0]), "");
    $encoded =~ s/=+\z//;
    print $encoded;
  ' "${TASK_ID}") || upgrade_e2e_fail 'edge-identity-fingerprint'
  jq -S -c -n --arg node_id "${node_id}" --arg fingerprint "${fingerprint}" --arg key_id "${key_id}" '{
    version:1,node_id:$node_id,machine_fingerprint_sha256:$fingerprint,
    selected_protocol_major:1,selected_protocol_minor:0,artifact_encryption_key_id:$key_id,
    client_certificate_file:"client.pem",client_private_key_file:"client-key.pem",
    artifact_encryption_private_key_file:"artifact-x25519-key.bin"
  }' >"${staging}/identity.json" || upgrade_e2e_fail 'edge-identity-metadata'
  chmod 0600 "${staging}/identity.json" || upgrade_e2e_fail 'edge-identity-metadata-mode'
  for file in "${staging}"/identity.json "${staging}"/client.pem "${staging}"/client-key.pem \
    "${staging}"/artifact-x25519-key.bin; do
    upgrade_e2e_fsync_path "${file}" || upgrade_e2e_fail 'edge-identity-file-fsync'
  done
  upgrade_e2e_validate_edge_identity "${staging}" "${node_id}" "${key_id}" \
    "${WORK_DIR}/certs/edge-agent-client.pem" "${WORK_DIR}/certs/edge-agent-client.key" || \
    upgrade_e2e_fail 'edge-identity-staging-validate'
  upgrade_e2e_atomic_publish_identity "${staging}" "${EDGE_IDENTITY_DIR}" || \
    upgrade_e2e_fail 'edge-identity-publish'
  upgrade_e2e_validate_edge_identity "${EDGE_IDENTITY_DIR}" "${node_id}" "${key_id}" \
    "${WORK_DIR}/certs/edge-agent-client.pem" "${WORK_DIR}/certs/edge-agent-client.key" || \
    upgrade_e2e_fail 'edge-identity-published-validate'
  rm -f -- "${x25519_pem}" "${WORK_DIR}/certs/edge-agent-client.key" || upgrade_e2e_fail 'edge-identity-source-cleanup'
}

upgrade_e2e_generate_pki() {
  local node_id
  # Final runtime binds TLS 1.3 and exact SANs in the production processes. This function creates only task-owned keys.
  node_id="$(upgrade_e2e_require_env UPGRADE_E2E_NODE_ID)"
  [[ "${node_id}" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$ ]] || \
    upgrade_e2e_unknown 'invalid-node-id'
  openssl genpkey -algorithm ED25519 -out "${WORK_DIR}/certs/ca.key" >/dev/null 2>&1
  openssl req -x509 -new -key "${WORK_DIR}/certs/ca.key" -out "${WORK_DIR}/certs/ca.pem" \
    -days 1 -subj '/CN=cdnca-upgrade-e2e-ca' -addext 'basicConstraints=critical,CA:true' \
    -addext 'keyUsage=critical,keyCertSign,cRLSign' >/dev/null 2>&1 || upgrade_e2e_fail 'pki-ca'
  chmod 0600 "${WORK_DIR}/certs/ca.key"
  upgrade_e2e_issue_certificate license-server 'DNS:license.internal' serverAuth
  upgrade_e2e_issue_certificate control-server 'DNS:control.internal' serverAuth
  upgrade_e2e_issue_certificate gateway-server 'DNS:gateway.internal' serverAuth
  upgrade_e2e_issue_certificate gateway-control-client "URI:${GATEWAY_WORKLOAD_URI}" clientAuth
  upgrade_e2e_issue_certificate edge-agent-client "URI:spiffe://cdn-platform/node/${node_id}" clientAuth
  upgrade_e2e_create_edge_identity
}

upgrade_e2e_precreate_nats() {
  local node_id node_name config_dir expanded stream consumer stream_file consumer_file
  node_id="$(upgrade_e2e_require_env UPGRADE_E2E_NODE_ID)"
  [[ "${node_id}" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$ ]] || \
    upgrade_e2e_unknown 'invalid-node-id'
  node_name=${node_id//-/_}
  config_dir="${WORK_DIR}/nats-config"
  expanded="${config_dir}/resources.json"
  mkdir -p -- "${config_dir}" || upgrade_e2e_fail 'nats-config-directory'
  jq -S -c --arg node_id "${node_id}" --arg node_name "${node_name}" '
    .consumers |= map(
      if .name == "node_upgrade_${NODE_ID_UNDERSCORE}" then
        .name = ("node_upgrade_" + $node_name) |
        .config.name = ("node_upgrade_" + $node_name) |
        .config.durable_name = ("node_upgrade_" + $node_name) |
        .config.filter_subject = ("cdnca.agent.commands.upgrade." + $node_id)
      else . end
    )
  ' "${NATS_RESOURCES_SNAPSHOT}" >"${expanded}" || upgrade_e2e_fail 'nats-placeholder-expansion'
  ! grep -F '${NODE_ID' "${expanded}" >/dev/null || upgrade_e2e_fail 'nats-placeholder-remains'

  while IFS= read -r stream; do
    stream_file="${config_dir}/stream-${stream}.json"
    jq -S -c --arg name "${stream}" '.streams[] | select(.name == $name) | .config' \
      "${expanded}" >"${stream_file}" || upgrade_e2e_fail 'nats-stream-config'
  done < <(jq -r '.streams[].name' "${expanded}")
  while IFS=$'\t' read -r stream consumer; do
    consumer_file="${config_dir}/consumer-${stream}-${consumer}.json"
    jq -S -c --arg stream "${stream}" --arg name "${consumer}" \
      '.consumers[] | select(.stream == $stream and .name == $name) | .config' \
      "${expanded}" >"${consumer_file}" || upgrade_e2e_fail 'nats-consumer-config'
  done < <(jq -r '.consumers[] | [.stream,.name] | @tsv' "${expanded}")
  chmod -R a-w "${config_dir}" || upgrade_e2e_fail 'nats-config-read-only'

  upgrade_e2e_run_container nats -d --name "${TASK_ID}-nats-cli" --network "${NETWORK_NAME}" \
    --label "${RESOURCE_LABEL}" --label "${RESOURCE_ROLE_LABEL_KEY}=nats" \
    -v "${config_dir}:/config:ro" "${NATS_BOX_IMAGE}" sleep infinity || \
    upgrade_e2e_fail 'nats-cli-start'
  nats_cli_container_id=${last_container_id}
  for _ in {1..100}; do
    upgrade_e2e_docker exec "${nats_cli_container_id}" nats \
      --server "nats://${NATS_CONTAINER}:4222" server check jetstream >/dev/null 2>&1 && break
    sleep 0.05
  done
  upgrade_e2e_docker exec "${nats_cli_container_id}" nats \
    --server "nats://${NATS_CONTAINER}:4222" server check jetstream >/dev/null || \
    upgrade_e2e_fail 'nats-jetstream-readiness'
  while IFS= read -r stream; do
    upgrade_e2e_docker exec "${nats_cli_container_id}" nats \
      --server "nats://${NATS_CONTAINER}:4222" stream add --config "/config/stream-${stream}.json" >/dev/null || \
      upgrade_e2e_fail 'nats-stream-create'
  done < <(jq -r '.streams[].name' "${expanded}")
  while IFS=$'\t' read -r stream consumer; do
    upgrade_e2e_docker exec "${nats_cli_container_id}" nats \
      --server "nats://${NATS_CONTAINER}:4222" consumer add "${stream}" \
      --config "/config/consumer-${stream}-${consumer}.json" >/dev/null || \
      upgrade_e2e_fail 'nats-consumer-create'
  done < <(jq -r '.consumers[] | [.stream,.name] | @tsv' "${expanded}")
  upgrade_e2e_verify_nats_server_state
}

upgrade_e2e_strip_nats_server_metadata() {
  jq -S -c '
    if type != "object" or (.metadata | type) != "object" then
      error("invalid NATS metadata")
    elif (.metadata | with_entries(select(.key | startswith("_nats.")))) !=
      {"_nats.level":"1","_nats.req.level":"0","_nats.ver":"2.11.4"} then
      error("unexpected NATS server metadata")
    else
      .metadata |= with_entries(select(.key | startswith("_nats.") | not))
    end
  '
}

upgrade_e2e_verify_nats_server_state() {
  local config_dir expanded stream consumer stream_file consumer_file actual expected listed
  local stream_projection consumer_projection
  config_dir="${WORK_DIR}/nats-config"
  expanded="${config_dir}/resources.json"
  stream_projection='{
    allow_direct:(.allow_direct // false),allow_msg_ttl:(.allow_msg_ttl // false),
    allow_rollup_hdrs:(.allow_rollup_hdrs // false),compression,consumer_limits:((.consumer_limits // {}) | {
      inactive_threshold:(.inactive_threshold // 0),max_ack_pending:(.max_ack_pending // 0)}),
    deny_delete:(.deny_delete // false),deny_purge:(.deny_purge // false),description:(.description // ""),
    discard,discard_new_per_subject:(.discard_new_per_subject // false),duplicate_window,
    first_seq:(.first_seq // 0),max_age,max_bytes,max_consumers,max_msg_size,max_msgs,max_msgs_per_subject,
    metadata:(.metadata // {}),mirror:(.mirror // null),mirror_direct:(.mirror_direct // false),name,
    no_ack:(.no_ack // false),num_replicas,placement:(.placement // null),republish:(.republish // null),
    retention,sealed:(.sealed // false),sources:(.sources // []),storage,
    subject_delete_marker_ttl:(.subject_delete_marker_ttl // 0),
    subject_transform:(.subject_transform // null),subjects,template_owner:(.template_owner // "")
  }'
  consumer_projection='{
    ack_policy,ack_wait,backoff:(.backoff // []),deliver_group:(.deliver_group // ""),deliver_policy,
    deliver_subject:(.deliver_subject // ""),description:(.description // ""),durable_name,filter_subject,
    filter_subjects:(.filter_subjects // []),flow_control:(.flow_control // false),
    headers_only:(.headers_only // false),idle_heartbeat:(.idle_heartbeat // 0),
    inactive_threshold:(.inactive_threshold // 0),max_ack_pending,max_batch,max_bytes,max_deliver,
    max_expires,max_waiting,mem_storage:(.mem_storage // false),metadata:(.metadata // {}),name,
    num_replicas:(.num_replicas // 0),opt_start_seq:(.opt_start_seq // 0),
    opt_start_time:(.opt_start_time // null),rate_limit_bps:(.rate_limit_bps // 0),replay_policy,
    sample_freq:(.sample_freq // "")
  }'
  while IFS= read -r stream; do
    stream_file="${config_dir}/stream-${stream}.json"
    actual=$(upgrade_e2e_docker exec "${nats_cli_container_id}" nats \
      --server "nats://${NATS_CONTAINER}:4222" stream info "${stream}" --json) || \
      upgrade_e2e_fail 'nats-stream-readback'
    actual=$(jq -S -c ".config | ${stream_projection}" <<<"${actual}") || \
      upgrade_e2e_fail 'nats-stream-readback-json'
    actual=$(upgrade_e2e_strip_nats_server_metadata <<<"${actual}") || \
      upgrade_e2e_fail 'nats-stream-server-metadata'
    expected=$(jq -S -c "${stream_projection}" "${stream_file}") || \
      upgrade_e2e_fail 'nats-stream-expected-json'
    [ "${actual}" = "${expected}" ] || upgrade_e2e_fail 'nats-stream-readback-mismatch'
  done < <(jq -r '.streams[].name' "${expanded}")
  while IFS=$'\t' read -r stream consumer; do
    consumer_file="${config_dir}/consumer-${stream}-${consumer}.json"
    actual=$(upgrade_e2e_docker exec "${nats_cli_container_id}" nats \
      --server "nats://${NATS_CONTAINER}:4222" consumer info "${stream}" "${consumer}" --json) || \
      upgrade_e2e_fail 'nats-consumer-readback'
    [ "$(jq -r '.stream_name' <<<"${actual}")" = "${stream}" ] && \
      [ "$(jq -r '.name' <<<"${actual}")" = "${consumer}" ] || \
      upgrade_e2e_fail 'nats-consumer-readback-identity'
    actual=$(jq -S -c ".config | ${consumer_projection}" <<<"${actual}") || \
      upgrade_e2e_fail 'nats-consumer-readback-json'
    actual=$(upgrade_e2e_strip_nats_server_metadata <<<"${actual}") || \
      upgrade_e2e_fail 'nats-consumer-server-metadata'
    expected=$(jq -S -c "${consumer_projection}" "${consumer_file}") || \
      upgrade_e2e_fail 'nats-consumer-expected-json'
    [ "${actual}" = "${expected}" ] || upgrade_e2e_fail 'nats-consumer-readback-mismatch'
  done < <(jq -r '.consumers[] | [.stream,.name] | @tsv' "${expanded}")
  listed=$(upgrade_e2e_docker exec "${nats_cli_container_id}" nats \
    --server "nats://${NATS_CONTAINER}:4222" request --raw '$JS.API.STREAM.NAMES' '{}') || \
    upgrade_e2e_fail 'nats-stream-enumeration'
  [ "$(jq -S -c '.streams // [] | sort' <<<"${listed}")" = \
    '["AGENT_COMMANDS","AGENT_DEPLOYMENT_STATUS","AGENT_HEARTBEATS"]' ] || \
    upgrade_e2e_fail 'nats-stream-set-mismatch'
  while IFS= read -r stream; do
    listed=$(upgrade_e2e_docker exec "${nats_cli_container_id}" nats \
      --server "nats://${NATS_CONTAINER}:4222" request --raw "\$JS.API.CONSUMER.NAMES.${stream}" '{}') || \
      upgrade_e2e_fail 'nats-consumer-enumeration'
    actual=$(jq -S -c '.consumers // [] | sort' <<<"${listed}") || \
      upgrade_e2e_fail 'nats-consumer-enumeration-json'
    expected=$(jq -S -c --arg stream "${stream}" \
      '[.consumers[] | select(.stream == $stream) | .name] | sort' "${expanded}") || \
      upgrade_e2e_fail 'nats-consumer-expected-set'
    [ "${actual}" = "${expected}" ] || upgrade_e2e_fail 'nats-consumer-set-mismatch'
  done < <(jq -r '.streams[].name' "${expanded}")
}

upgrade_e2e_apply_migrations_and_fixtures() {
  local license_head control_head migration_status identity_facts
  local certificate_serial leaf_der_sha256 artifact_key_id artifact_public_key_hex
  [ -d "${LICENSE_MIGRATION_SNAPSHOT_DIR}" ] && [ ! -L "${LICENSE_MIGRATION_SNAPSHOT_DIR}" ] || \
    upgrade_e2e_unknown 'license-migration-snapshot-unavailable'
  [ -d "${CONTROL_MIGRATION_SNAPSHOT_DIR}" ] && [ ! -L "${CONTROL_MIGRATION_SNAPSHOT_DIR}" ] || \
    upgrade_e2e_unknown 'control-migration-snapshot-unavailable'
  for _ in {1..200}; do
    upgrade_e2e_docker exec "${POSTGRES_CONTAINER}" pg_isready -q -U cdnca -d postgres && break
    sleep 0.05
  done
  upgrade_e2e_docker exec "${POSTGRES_CONTAINER}" pg_isready -q -U cdnca -d postgres || \
    upgrade_e2e_fail 'postgres-readiness'
  upgrade_e2e_docker exec -i "${POSTGRES_CONTAINER}" psql -v ON_ERROR_STOP=1 -U cdnca -d postgres <<'SQL'
SELECT 'CREATE ROLE license_e2e_runtime NOLOGIN'
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='license_e2e_runtime')\gexec
SELECT 'CREATE ROLE license_e2e_callback NOLOGIN'
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='license_e2e_callback')\gexec
SELECT 'CREATE ROLE license_e2e_fixture LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION'
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='license_e2e_fixture')\gexec
SELECT 'CREATE ROLE control_e2e_fixture LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION'
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='control_e2e_fixture')\gexec
SELECT 'CREATE DATABASE license_e2e OWNER cdnca'
WHERE NOT EXISTS (SELECT 1 FROM pg_database WHERE datname='license_e2e')\gexec
SELECT 'CREATE DATABASE control_e2e OWNER cdnca'
WHERE NOT EXISTS (SELECT 1 FROM pg_database WHERE datname='control_e2e')\gexec
SQL
  LICENSE_DATABASE_URL='postgresql://cdnca@/license_e2e?host=/var/run/postgresql'
  CONTROL_DATABASE_URL='postgresql://cdnca@/control_e2e?host=/var/run/postgresql'
  upgrade_e2e_run_container license -d --name "${TASK_ID}-license-migrate" --network "${NETWORK_NAME}" \
    --label "${RESOURCE_LABEL}" --label "${RESOURCE_ROLE_LABEL_KEY}=license" \
    -v "${WORK_DIR}/bin:/task/bin:ro" -v "${WORK_DIR}/postgres:/var/run/postgresql" \
    -v "${WORK_DIR}/logs:/task/logs" \
    -e LICENSE_MIGRATION_DATABASE_URL="${LICENSE_DATABASE_URL}" \
    -e LICENSE_RUNTIME_DATABASE_ROLE=license_e2e_runtime \
    -e LICENSE_BILLING_CALLBACK_DATABASE_ROLE=license_e2e_callback \
    "${SYSTEMD_IMAGE}" /task/bin/license-service migrate up || \
    upgrade_e2e_fail 'license-migrate-container'
  migration_status=$(upgrade_e2e_timeout 240 docker wait "${last_container_id}") || \
    upgrade_e2e_fail 'license-migrate-wait'
  [ "${migration_status}" = '0' ] || upgrade_e2e_fail 'license-migrate-up'
  upgrade_e2e_run_container control -d --name "${TASK_ID}-control-migrate" --network "${NETWORK_NAME}" \
    --label "${RESOURCE_LABEL}" --label "${RESOURCE_ROLE_LABEL_KEY}=control" \
    -v "${WORK_DIR}/bin:/task/bin:ro" -v "${WORK_DIR}/postgres:/var/run/postgresql" \
    -v "${WORK_DIR}/logs:/task/logs" -e DATABASE_URL="${CONTROL_DATABASE_URL}" \
    "${SYSTEMD_IMAGE}" /task/bin/control-api migrate up || \
    upgrade_e2e_fail 'control-migrate-container'
  migration_status=$(upgrade_e2e_timeout 240 docker wait "${last_container_id}") || \
    upgrade_e2e_fail 'control-migrate-wait'
  [ "${migration_status}" = '0' ] || upgrade_e2e_fail 'control-migrate-up'
  license_head=$(upgrade_e2e_docker exec "${POSTGRES_CONTAINER}" psql -qAtX -v ON_ERROR_STOP=1 \
    -U cdnca -d license_e2e -c 'SELECT max(version)::text FROM license_schema_migrations') || \
    upgrade_e2e_fail 'license-migration-head-read'
  control_head=$(upgrade_e2e_docker exec "${POSTGRES_CONTAINER}" psql -qAtX -v ON_ERROR_STOP=1 \
    -U cdnca -d control_e2e -c 'SELECT max(version)::text FROM schema_migrations') || \
    upgrade_e2e_fail 'control-migration-head-read'
  [ "${license_head}" = "${LICENSE_MIGRATION_HEAD}" ] || upgrade_e2e_fail 'license-migration-head'
  [ "${control_head}" = "${CONTROL_MIGRATION_HEAD}" ] || upgrade_e2e_fail 'control-migration-head'
  upgrade_e2e_docker exec -i "${POSTGRES_CONTAINER}" psql -qX -v ON_ERROR_STOP=1 \
    -U cdnca -d license_e2e <<'SQL'
GRANT CONNECT ON DATABASE license_e2e TO license_e2e_fixture;
GRANT USAGE ON SCHEMA public TO license_e2e_fixture;
GRANT SELECT,INSERT,UPDATE ON customers,control_installations,license_features,license_grants,license_quotas,
  activation_credentials,signing_keys,signing_key_rotations,release_artifacts,release_artifact_size_attestations,
  release_channels,release_channel_artifacts,release_channel_targets,installation_upgrade_targets,
  issued_leases,issued_upgrade_grants,issued_upgrade_plan_artifact_bundles,upgrade_command_profiles,
  upgrade_plan_command_profiles,license_audit_events TO license_e2e_fixture;
GRANT USAGE,SELECT ON ALL SEQUENCES IN SCHEMA public TO license_e2e_fixture;
SQL
  upgrade_e2e_docker exec -i "${POSTGRES_CONTAINER}" psql -qX -v ON_ERROR_STOP=1 \
    -U cdnca -d control_e2e <<'SQL'
GRANT CONNECT ON DATABASE control_e2e TO control_e2e_fixture;
GRANT USAGE ON SCHEMA public TO control_e2e_fixture;
GRANT SELECT,INSERT,UPDATE ON users,memberships,roles,permissions,role_assignments,role_permissions,audit_events,
  nodes,node_presence,node_identity_state,node_identity_authorizations,node_artifact_encryption_keys,
  control_installation_entitlement,control_signer_trust_snapshots,control_signer_checkpoint_snapshots,
  control_signer_checkpoint_manifests,control_entitlement_revocation_lkg,control_entitlement_revoked_serials
  TO control_e2e_fixture;
GRANT INSERT ON access_scopes,node_enrollment_tokens,node_enrollment_authorizations,
  node_ca_key_epochs,node_certificates TO control_e2e_fixture;
GRANT USAGE,SELECT ON ALL SEQUENCES IN SCHEMA public TO control_e2e_fixture;
SQL
  identity_facts=$(upgrade_e2e_edge_identity_public_facts) || \
    upgrade_e2e_fail 'control-fixture-identity-facts'
  IFS=$'\t' read -r certificate_serial leaf_der_sha256 artifact_key_id artifact_public_key_hex \
    <<<"${identity_facts}"
  [ -n "${certificate_serial}" ] && [ -n "${leaf_der_sha256}" ] && \
    [ -n "${artifact_key_id}" ] && [ -n "${artifact_public_key_hex}" ] || \
    upgrade_e2e_fail 'control-fixture-identity-facts'
  upgrade_e2e_docker exec -i "${POSTGRES_CONTAINER}" psql -qX -v ON_ERROR_STOP=1 \
    -U license_e2e_fixture -d license_e2e <"${LICENSE_AUTHORITY_FIXTURE_SNAPSHOT}" || \
    upgrade_e2e_fail 'license-authority-fixture'
  upgrade_e2e_docker exec -i "${POSTGRES_CONTAINER}" psql -qX -v ON_ERROR_STOP=1 \
    -v e2e_node_certificate_serial="${certificate_serial}" \
    -v e2e_node_leaf_der_sha256="${leaf_der_sha256}" \
    -v e2e_node_artifact_key_id="${artifact_key_id}" \
    -v e2e_node_artifact_public_key_hex="${artifact_public_key_hex}" \
    -U control_e2e_fixture -d control_e2e <"${CONTROL_AUTHORITY_FIXTURE_SNAPSHOT}" || \
    upgrade_e2e_fail 'control-authority-fixture'
  [ "$(upgrade_e2e_docker exec "${POSTGRES_CONTAINER}" psql -qAtX -v ON_ERROR_STOP=1 \
    -U cdnca -d license_e2e -c 'SELECT (SELECT count(*) FROM upgrade_grant_receipts)')" = '0' ] || \
    upgrade_e2e_fail 'license-fixture-fabricated-runtime-facts'
  [ "$(upgrade_e2e_docker exec "${POSTGRES_CONTAINER}" psql -qAtX -v ON_ERROR_STOP=1 \
    -U cdnca -d control_e2e -c 'SELECT (SELECT count(*) FROM control_upgrade_rollout_plans)+
      (SELECT count(*) FROM control_upgrade_rollout_events)+(SELECT count(*) FROM control_upgrade_node_commands)+
      (SELECT count(*) FROM control_upgrade_outbox)+(SELECT count(*) FROM control_upgrade_status_receipts)+
      (SELECT count(*) FROM control_upgrade_license_receipt_outbox_097)+
      (SELECT count(*) FROM control_upgrade_license_receipt_deliveries_097)')" = '0' ] || \
    upgrade_e2e_fail 'control-fixture-fabricated-runtime-facts'
  # License registry source URLs: Control fetches (and caches) from here; nodes
  # download only from Control (see upgrade_e2e_assert_command_wire).
  [ "$(upgrade_e2e_docker exec "${POSTGRES_CONTAINER}" psql -qAtX -v ON_ERROR_STOP=1 \
    -U cdnca -d license_e2e -v forward_digest="$(upgrade_e2e_require_env UPGRADE_E2E_FORWARD_BUNDLE_SHA256)" \
    -v rollback_digest="$(upgrade_e2e_require_env UPGRADE_E2E_ROLLBACK_BUNDLE_SHA256)" \
    -v forward_size="$(upgrade_e2e_require_env UPGRADE_E2E_FORWARD_BUNDLE_SIZE)" \
    -v rollback_size="$(upgrade_e2e_require_env UPGRADE_E2E_ROLLBACK_BUNDLE_SIZE)" -c \
    "SELECT count(*) FROM release_artifacts artifact JOIN release_artifact_size_attestations size ON size.artifact_id=artifact.id
      WHERE (artifact.download_url='https://license.internal:8443/artifacts/forward.bundle' AND
        encode(artifact.sha256_digest,'hex')=:'forward_digest' AND size.artifact_size_bytes=:forward_size) OR
      (artifact.download_url='https://license.internal:8443/artifacts/rollback.bundle' AND
        encode(artifact.sha256_digest,'hex')=:'rollback_digest' AND size.artifact_size_bytes=:rollback_size)")" = '2' ] || \
    upgrade_e2e_fail 'license-fixture-artifact-binding'
  upgrade_e2e_docker exec -i "${POSTGRES_CONTAINER}" psql -qX -v ON_ERROR_STOP=1 \
    -U cdnca -d license_e2e <<'SQL'
REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM license_e2e_fixture;
REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public FROM license_e2e_fixture;
REVOKE USAGE ON SCHEMA public FROM license_e2e_fixture;
SQL
  upgrade_e2e_docker exec -i "${POSTGRES_CONTAINER}" psql -qX -v ON_ERROR_STOP=1 \
    -U cdnca -d control_e2e <<'SQL'
REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM control_e2e_fixture;
REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public FROM control_e2e_fixture;
REVOKE USAGE ON SCHEMA public FROM control_e2e_fixture;
SQL
  upgrade_e2e_docker exec -i "${POSTGRES_CONTAINER}" psql -qX -v ON_ERROR_STOP=1 \
    -U cdnca -d postgres <<'SQL'
REVOKE CONNECT ON DATABASE license_e2e FROM license_e2e_fixture;
REVOKE CONNECT ON DATABASE control_e2e FROM control_e2e_fixture;
ALTER ROLE license_e2e_fixture NOLOGIN;
ALTER ROLE control_e2e_fixture NOLOGIN;
SQL
}

upgrade_e2e_collect_forwarded_env() {
  local name
  forwarded_env_args=()
  for name in "$@"; do
    upgrade_e2e_require_env "${name}" >/dev/null
    forwarded_env_args+=(-e "${name}")
  done
}

upgrade_e2e_wait_http_status() {
  local url=$1 expected=$2 actual
  for _ in {1..600}; do
    actual=$(curl --silent --show-error --output /dev/null --write-out '%{http_code}' \
      --connect-timeout 1 --max-time 2 "${url}" 2>/dev/null) || actual='000'
    [ "${actual}" = "${expected}" ] && return 0
    sleep 0.1
  done
  return 1
}

upgrade_e2e_write_license_proxy_config() {
  local path=$1
  {
    printf 'events {}\n'
    printf 'http { server { listen 8443 ssl; server_name license.internal;\n'
    printf 'ssl_protocols TLSv1.3; ssl_certificate /task/certs/license-server.pem;\n'
    printf 'ssl_certificate_key /task/certs/license-server.key;\n'
    printf 'location = /artifacts/forward.bundle { limit_except GET { deny all; } alias /task/artifacts/forward.bundle; }\n'
    printf 'location = /artifacts/rollback.bundle { limit_except GET { deny all; } alias /task/artifacts/rollback.bundle; }\n'
    printf 'location / { proxy_pass http://license-runtime:8081; proxy_set_header Host $host; }\n'
    printf '} }\n'
  } >"${path}" || return 1
  chmod 0444 "${path}" || return 1
}

# Control web stand-in: serves the control-api artifact cache under /downloads
# (production: the console nginx location ^~ /downloads/ on the same host).
upgrade_e2e_write_control_downloads_config() {
  local path=$1
  {
    printf 'events {}\n'
    printf 'http { server { listen 8445 ssl; server_name control.internal;\n'
    printf 'ssl_protocols TLSv1.3; ssl_certificate /task/certs/control-server.pem;\n'
    printf 'ssl_certificate_key /task/certs/control-server.key;\n'
    printf 'location ^~ /downloads/edge-agent/upgrades/sha256/ { limit_except GET { deny all; } alias /task/artifact-cache/; }\n'
    printf 'location / { return 404; }\n'
    printf '} }\n'
  } >"${path}" || return 1
  chmod 0444 "${path}" || return 1
}

upgrade_e2e_write_edge_runtime_config() {
  local path=$1 control_address=$2
  jq -S -c '
    del(.node_id, .artifact_encryption_key_id, .gateway.client_certificate_file, .gateway.client_private_key_file) |
    .identity_dir = "/etc/cdnca-edge-agent/identity" |
    .gateway.address = "gateway.internal:8444" |
    .gateway.server_name = "gateway.internal" |
    .gateway.root_ca_file = "/etc/cdnca-edge-agent/tls/ca.pem" |
    .artifact_trust_file = "/etc/cdnca-edge-agent/trust/artifact.json" |
    .upgrade.control_execution_trust_file = "/etc/cdnca-edge-agent/trust/control-execution.json" |
    .upgrade.edge_execution_trust_file = "/etc/cdnca-edge-agent/trust/edge-execution.json" |
    .upgrade.installer_receipt_trust_file = "/etc/cdnca-edge-agent/trust/installer-receipt.json" |
    .upgrade.download_host = "control.internal" |
    .upgrade.download_port = 8445 |
    .upgrade.download_addresses = [$control_address] |
    .upgrade.download_root_ca_file = "/etc/cdnca-edge-agent/tls/ca.pem"
  ' --arg control_address "${control_address}" "${EDGE_CONFIG_SNAPSHOT}" >"${path}" || return 1
  chmod 0400 "${path}" || return 1
}

# The helper pin is {schema_version,key_id,public_key(raw base64)} mode 0440
# root:cdnca-edge; the updater accepts only an owner-only 0400
# {version:1,keys:[{key_id,public_key_pem}]} trust store. Convert the exact
# 32-byte Ed25519 key (SPKI prefix 302a300506032b6570032100) and fail closed on
# any other shape.
upgrade_e2e_receipt_trust_from_pin() {
  local pin=$1 key_id raw_b64 der_file pem
  jq -e '(keys == ["key_id","public_key","schema_version"]) and .schema_version == 1 and
    (.key_id | type == "string" and test("^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")) and
    (.public_key | type == "string" and test("^[A-Za-z0-9+/]{43}$"))' <<<"${pin}" >/dev/null || return 1
  key_id=$(jq -r .key_id <<<"${pin}") || return 1
  raw_b64=$(jq -r .public_key <<<"${pin}") || return 1
  der_file=$(mktemp) || return 1
  { printf '\x30\x2a\x30\x05\x06\x03\x2b\x65\x70\x03\x21\x00'; base64 -d <<<"${raw_b64}="; } >"${der_file}" || {
    rm -f -- "${der_file}"; return 1; }
  [ "$(wc -c <"${der_file}")" -eq 44 ] || { rm -f -- "${der_file}"; return 1; }
  pem=$(openssl pkey -pubin -inform DER -in "${der_file}" -outform PEM 2>/dev/null) || { rm -f -- "${der_file}"; return 1; }
  rm -f -- "${der_file}"
  jq -cn --arg key_id "${key_id}" --arg pem "${pem}"$'\n' \
    '{version: 1, keys: [{key_id: $key_id, public_key_pem: $pem}]}'
}

upgrade_e2e_assert_systemd_runtime_supply_chain() {
  upgrade_e2e_docker exec "${edge_container_id}" sh -ceu '
    image_packaging=/opt/cdnca-upgrade-e2e/packaging
    snapshot_packaging=/task/packaging
    unit_root=/usr/lib/systemd/system
    test -x /opt/cdnca-upgrade-e2e/packaging/scripts/install.sh
    cmp -s "${image_packaging}/scripts/install.sh" /task/packaging/scripts/install.sh
    for unit in cdnca-edge-agent.service cdnca-edge-agent-helper.service cdnca-edge-agent-helper.socket; do
      fragment=$(systemctl show -p FragmentPath --value "${unit}")
      test "${fragment}" = "${unit_root}/${unit}"
      cmp -s "${image_packaging}/systemd/${unit}" "${snapshot_packaging}/systemd/${unit}"
      cmp -s "/usr/lib/systemd/system/${unit}" "${image_packaging}/systemd/${unit}"
      loaded_sha=$(sha256sum "/usr/lib/systemd/system/${unit}" | awk "{print \$1}")
      image_sha=$(sha256sum "${image_packaging}/systemd/${unit}" | awk "{print \$1}")
      snapshot_sha=$(sha256sum "${snapshot_packaging}/systemd/${unit}" | awk "{print \$1}")
      test "${loaded_sha}" = "${image_sha}"
      test "${image_sha}" = "${snapshot_sha}"
    done
    systemctl is-enabled --quiet cdnca-edge-agent.service
    test "$(systemctl is-enabled cdnca-edge-agent.service)" = enabled
    systemctl is-active --quiet cdnca-edge-agent.service
    test "$(systemctl is-active cdnca-edge-agent.service)" = active
    systemctl is-enabled --quiet cdnca-edge-agent-helper.socket
    test "$(systemctl is-enabled cdnca-edge-agent-helper.socket)" = enabled
    systemctl is-active --quiet cdnca-edge-agent-helper.socket
    test "$(systemctl is-active cdnca-edge-agent-helper.socket)" = active
    test "$(systemctl is-enabled cdnca-edge-agent-helper.service 2>/dev/null || true)" = disabled
    test "$(systemctl is-active cdnca-edge-agent-helper.service 2>/dev/null || true)" = inactive
    test -S /run/cdnca-edge-agent/helper.sock
    test "$(stat -c %a /run/cdnca-edge-agent/helper.sock)" = 600
  ' || upgrade_e2e_fail 'edge-systemd-supply-chain-layout'
}

upgrade_e2e_start_four_processes() {
  local control_entitlement_trust control_installation_key control_activation_credential
  local control_command_trust control_signing_key edge_signing_key
  local license_proxy_config edge_runtime_config edge_env_file receipt_pin control_downloads_config control_address
  local -a license_env_args control_env_args gateway_env_args edge_mount_args

  control_entitlement_trust=${CONTROL_ENTITLEMENT_TRUST_SNAPSHOT}
  control_installation_key=${CONTROL_INSTALLATION_KEY_SNAPSHOT}
  control_activation_credential=${CONTROL_ACTIVATION_CREDENTIAL_SNAPSHOT}
  control_command_trust=${CONTROL_COMMAND_TRUST_SNAPSHOT}
  control_signing_key=${CONTROL_SIGNING_KEY_SNAPSHOT}
  edge_signing_key=${EDGE_SIGNING_KEY_SNAPSHOT}
  edge_mount_args=(
    -v "${EDGE_ARTIFACT_TRUST_SNAPSHOT}:/task/runtime-secrets/edge-artifact-trust.json:ro"
    -v "${EDGE_CONTROL_TRUST_SNAPSHOT}:/task/runtime-secrets/edge-control-trust.json:ro"
    -v "${EDGE_EXECUTION_TRUST_SNAPSHOT}:/task/runtime-secrets/edge-execution-trust.json:ro"
  )

  license_proxy_config="${WORK_DIR}/certs/license-proxy.conf"
  edge_runtime_config="${WORK_DIR}/edge/edge-agent.json"
  edge_env_file="${WORK_DIR}/edge/agent.env"
  upgrade_e2e_write_license_proxy_config "${license_proxy_config}" || upgrade_e2e_fail 'license-proxy-config'
  control_downloads_config="${WORK_DIR}/certs/control-downloads.conf"
  upgrade_e2e_write_control_downloads_config "${control_downloads_config}" || upgrade_e2e_fail 'control-downloads-config'
  printf 'CDNCA_EDGE_CONFIG=/etc/cdnca-edge-agent/config.json\n' >"${edge_env_file}" || \
    upgrade_e2e_fail 'edge-runtime-env'
  chmod 0400 "${edge_env_file}" || upgrade_e2e_fail 'edge-runtime-env-mode'

  upgrade_e2e_collect_forwarded_env \
    LICENSE_CONTROL_API_VERSION LICENSE_BILLING_PROVIDER_KEYS_JSON LICENSE_TOTP_KEY_ID \
    LICENSE_TOTP_KEYS_JSON LICENSE_CREDENTIAL_KEY_ID LICENSE_CREDENTIAL_KEYS_JSON \
    LICENSE_IDENTITY_TOKEN_KEY_ID LICENSE_IDENTITY_TOKEN_KEYS_JSON LICENSE_SMTP_ADDRESS \
    LICENSE_SMTP_FROM LICENSE_SIGNING_PROVIDER LICENSE_SIGNING_KEY_ID \
    LICENSE_SIGNING_PRIVATE_KEY_BASE64 LICENSE_SIGNER_REVOCATION_ATTEMPT_HMAC_KEY_BASE64 \
    LICENSE_SIGNER_CHECKPOINT_OFFLINE_ROOT_KEY_ID LICENSE_SIGNER_CHECKPOINT_OFFLINE_ROOT_GENERATION \
    LICENSE_SIGNER_CHECKPOINT_OFFLINE_ROOT_PUBLIC_KEY_BASE64
  license_env_args=("${forwarded_env_args[@]}")
  upgrade_e2e_run_container license -d --name "${TASK_ID}-license" --network "${NETWORK_NAME}" \
    --network-alias license-runtime --label "${RESOURCE_LABEL}" \
    --label "${RESOURCE_ROLE_LABEL_KEY}=license" -p 127.0.0.1::8083 \
    -v "${WORK_DIR}/bin:/task/bin:ro" -v "${WORK_DIR}/postgres:/var/run/postgresql" \
    -v "${WORK_DIR}/logs:/task/logs" \
    "${license_env_args[@]}" -e LICENSE_DATABASE_URL="${LICENSE_DATABASE_URL}&options=-c%20role%3Dlicense_e2e_runtime" \
    -e LICENSE_BILLING_CALLBACK_DATABASE_URL="${LICENSE_DATABASE_URL}&options=-c%20role%3Dlicense_e2e_callback" \
    -e LICENSE_LISTEN_ADDRESS=:8081 -e LICENSE_HEALTH_ADDRESS=:8083 \
    -e LICENSE_OPERATOR_ORIGIN=https://license.internal:8443 \
    "${SYSTEMD_IMAGE}" /task/bin/license-service serve || upgrade_e2e_fail 'license-runtime-start'
  license_container_id=${last_container_id}
  license_health_port=$(upgrade_e2e_container_port "${license_container_id}" '8083/tcp') || \
    upgrade_e2e_fail 'license-health-port'
  owned_ports+=("${license_health_port}")
  upgrade_e2e_wait_http_status "http://127.0.0.1:${license_health_port}/health/ready" 200 || \
    upgrade_e2e_fail 'license-runtime-readiness'

  upgrade_e2e_run_container tls-proxy -d --name "${TASK_ID}-license-proxy" --network "${NETWORK_NAME}" \
    --network-alias license.internal --label "${RESOURCE_LABEL}" \
    --label "${RESOURCE_ROLE_LABEL_KEY}=tls-proxy" -v "${WORK_DIR}/certs:/task/certs:ro" \
    -v "${INPUT_SNAPSHOT_DIR}/artifacts:/task/artifacts:ro" \
    -v "${license_proxy_config}:/etc/nginx/nginx.conf:ro" "${TLS_PROXY_IMAGE}" || \
    upgrade_e2e_fail 'license-proxy-start'
  upgrade_e2e_collect_forwarded_env ACCESS_TOKEN_SECRET API_KEY_PEPPER_BASE64 \
    DNS_CREDENTIAL_KEY_ID DNS_CREDENTIAL_KEY_BASE64 CONTROL_INSTALLATION_ID \
    CONTROL_INSTALLATION_NAME CONTROL_VERSION CONTROL_UPGRADE_NATS_NAME CONTROL_UPGRADE_WORKER_ID \
    CONTROL_UPGRADE_CONTROL_SIGNING_KEY_ID CONTROL_UPGRADE_EDGE_SIGNING_KEY_ID \
    CONTROL_UPGRADE_COMMAND_ISSUANCE_TTL CONTROL_UPGRADE_EXECUTION_TTL \
    CONTROL_UPGRADE_ACTIVATION_TIMEOUT CONTROL_UPGRADE_OBSERVATION_WINDOW \
    CONTROL_UPGRADE_HEALTH_INTERVAL CONTROL_UPGRADE_PROBE_TIMEOUT \
    CONTROL_UPGRADE_REQUIRED_CONSECUTIVE_SUCCESSES CONTROL_UPGRADE_NATS_CONNECT_TIMEOUT \
    CONTROL_UPGRADE_NATS_RECONNECT_WAIT CONTROL_UPGRADE_NATS_DRAIN_TIMEOUT \
    CONTROL_UPGRADE_SHUTDOWN_TIMEOUT
  control_env_args=("${forwarded_env_args[@]}")
  upgrade_e2e_run_container control -d --name "${TASK_ID}-control" --network "${NETWORK_NAME}" \
    --network-alias control.internal --label "${RESOURCE_LABEL}" \
    --label "${RESOURCE_ROLE_LABEL_KEY}=control" -p 127.0.0.1::8080 \
    -v "${WORK_DIR}/bin:/task/bin:ro" -v "${WORK_DIR}/postgres:/var/run/postgresql" \
    -v "${WORK_DIR}/certs:/task/certs:ro" -v "${WORK_DIR}/logs:/task/logs" \
    -v "${control_entitlement_trust}:/task/runtime-secrets/entitlement-trust.json:ro" \
    -v "${control_installation_key}:/task/runtime-secrets/installation-key.pem:ro" \
    -v "${control_activation_credential}:/task/runtime-secrets/activation-credential:ro" \
    -v "${control_command_trust}:/task/runtime-secrets/command-trust.json:ro" \
    -v "${control_signing_key}:/task/runtime-secrets/control-signing.pem:ro" \
    -v "${edge_signing_key}:/task/runtime-secrets/edge-signing.pem:ro" \
    -v "${WORK_DIR}/artifact-cache:/task/artifact-cache" \
    "${control_env_args[@]}" -e DATABASE_URL="${CONTROL_DATABASE_URL}" -e HTTP_ADDR=:8080 \
    -e ENTITLEMENT_TRUSTED_KEYS_FILE=/task/runtime-secrets/entitlement-trust.json \
    -e LICENSE_SERVICE_URL=https://license.internal:8443 \
    -e CONTROL_INSTALLATION_PRIVATE_KEY_FILE=/task/runtime-secrets/installation-key.pem \
    -e CONTROL_ACTIVATION_CREDENTIAL_FILE=/task/runtime-secrets/activation-credential \
    -e CONTROL_INTERNAL_GRPC_ADDR=:9091 -e CONTROL_INTERNAL_SERVER_CERT_FILE=/task/certs/control-server.pem \
    -e CONTROL_INTERNAL_SERVER_PRIVATE_KEY_FILE=/task/certs/control-server.key \
    -e CONTROL_INTERNAL_GATEWAY_CLIENT_CA_FILE=/task/certs/ca.pem \
    -e CONTROL_INTERNAL_GATEWAY_WORKLOAD_URI_SAN="${GATEWAY_WORKLOAD_URI}" \
    -e NODE_CA_CERTIFICATE_CHAIN_FILE=/task/certs/ca.pem -e NODE_CA_PRIVATE_KEY_FILE=/task/certs/ca.key \
    -e EDGE_DEPLOYMENT_NATS_URL="nats://${NATS_CONTAINER}:4222" \
    -e NODE_PRESENCE_NATS_URL="nats://${NATS_CONTAINER}:4222" \
    -e NODE_PRESENCE_REDIS_URL="redis://${REDIS_CONTAINER}:6379/0" \
    -e CONTROL_UPGRADE_RUNTIME_ENABLED=true \
    -e CONTROL_UPGRADE_COMMAND_GRANT_TRUST_FILE=/task/runtime-secrets/command-trust.json \
    -e CONTROL_UPGRADE_CONTROL_SIGNING_PRIVATE_KEY_FILE=/task/runtime-secrets/control-signing.pem \
    -e CONTROL_UPGRADE_EDGE_SIGNING_PRIVATE_KEY_FILE=/task/runtime-secrets/edge-signing.pem \
    -e CONTROL_UPGRADE_ARTIFACT_CACHE_DIR=/task/artifact-cache \
    -e CONTROL_UPGRADE_ARTIFACT_BASE_URL=https://control.internal:8445/downloads/edge-agent/upgrades/sha256 \
    -e SSL_CERT_FILE=/task/certs/ca.pem "${SYSTEMD_IMAGE}" /task/bin/control-api serve || \
    upgrade_e2e_fail 'control-runtime-start'
  control_container_id=${last_container_id}
  control_http_port=$(upgrade_e2e_container_port "${control_container_id}" '8080/tcp') || \
    upgrade_e2e_fail 'control-http-port'
  owned_ports+=("${control_http_port}")
  upgrade_e2e_wait_http_status "http://127.0.0.1:${control_http_port}/health/ready" 200 || \
    upgrade_e2e_fail 'control-runtime-readiness'
  upgrade_e2e_assert_control_identity_fixture_binding
  upgrade_e2e_run_container tls-proxy -d --name "${TASK_ID}-control-downloads" \
    --network "container:${control_container_id}" --label "${RESOURCE_LABEL}" \
    --label "${RESOURCE_ROLE_LABEL_KEY}=tls-proxy" -v "${WORK_DIR}/certs:/task/certs:ro" \
    -v "${WORK_DIR}/artifact-cache:/task/artifact-cache:ro" \
    -v "${control_downloads_config}:/etc/nginx/nginx.conf:ro" "${TLS_PROXY_IMAGE}" || \
    upgrade_e2e_fail 'control-downloads-start'
  control_address=$(upgrade_e2e_docker inspect --type container \
    --format "{{ (index .NetworkSettings.Networks \"${NETWORK_NAME}\").IPAddress }}" "${control_container_id}") || \
    upgrade_e2e_fail 'control-address'
  [[ "${control_address}" =~ ^[0-9]+(\.[0-9]+){3}$ ]] || upgrade_e2e_fail 'control-address'
  upgrade_e2e_write_edge_runtime_config "${edge_runtime_config}" "${control_address}" || \
    upgrade_e2e_fail 'edge-runtime-config'

  upgrade_e2e_collect_forwarded_env CDNCA_GATEWAY_INSTANCE_ID CDNCA_GATEWAY_VERSION
  gateway_env_args=("${forwarded_env_args[@]}")
  upgrade_e2e_run_container gateway -d --name "${TASK_ID}-gateway" --network "${NETWORK_NAME}" \
    --network-alias gateway.internal --label "${RESOURCE_LABEL}" \
    --label "${RESOURCE_ROLE_LABEL_KEY}=gateway" -p 127.0.0.1::8082 \
    -v "${WORK_DIR}/bin:/task/bin:ro" -v "${WORK_DIR}/certs:/task/certs:ro" \
    -v "${WORK_DIR}/logs:/task/logs" "${gateway_env_args[@]}" \
    -e CDNCA_GATEWAY_ENROLLMENT_ADDR=:8443 -e CDNCA_GATEWAY_AGENT_ADDR=:8444 \
    -e CDNCA_GATEWAY_HEALTH_ADDR=:8082 -e CDNCA_GATEWAY_TLS_CERT_FILE=/task/certs/gateway-server.pem \
    -e CDNCA_GATEWAY_TLS_KEY_FILE=/task/certs/gateway-server.key \
    -e CDNCA_GATEWAY_AGENT_CLIENT_CA_FILE=/task/certs/ca.pem \
    -e CDNCA_CONTROL_ADDRESS=control.internal:9091 -e CDNCA_CONTROL_SERVER_NAME=control.internal \
    -e CDNCA_CONTROL_CLIENT_CERT_FILE=/task/certs/gateway-control-client.pem \
    -e CDNCA_CONTROL_CLIENT_KEY_FILE=/task/certs/gateway-control-client.key \
    -e CDNCA_CONTROL_SERVER_CA_FILE=/task/certs/ca.pem \
    -e CDNCA_CONTROL_CLIENT_WORKLOAD_URI_SAN="${GATEWAY_WORKLOAD_URI}" \
    -e CDNCA_REDIS_URL="redis://${REDIS_CONTAINER}:6379/0" \
    -e CDNCA_NATS_URL="nats://${NATS_CONTAINER}:4222" \
    -e CDNCA_TELEMETRY_NATS_URL="nats://${NATS_CONTAINER}:4222" \
    "${SYSTEMD_IMAGE}" /task/bin/agent-gateway || \
    upgrade_e2e_fail 'gateway-runtime-start'
  gateway_container_id=${last_container_id}
  gateway_health_port=$(upgrade_e2e_container_port "${gateway_container_id}" '8082/tcp') || \
    upgrade_e2e_fail 'gateway-health-port'
  owned_ports+=("${gateway_health_port}")
  upgrade_e2e_wait_http_status "http://127.0.0.1:${gateway_health_port}/health/ready" 200 || \
    upgrade_e2e_fail 'gateway-runtime-readiness'

  upgrade_e2e_run_container edge -d --name "${TASK_ID}-edge" --network "${NETWORK_NAME}" \
    --label "${RESOURCE_LABEL}" --label "${RESOURCE_ROLE_LABEL_KEY}=edge" --privileged --cgroupns=host \
    --tmpfs /run --tmpfs /run/lock \
    --tmpfs /var/lib/cdnca-edge-agent-helper:rw,noexec,nosuid,nodev,size=16m \
    -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
    -v "${INPUT_SNAPSHOT_DIR}/repo/agents/edge-agent/packaging:/task/packaging:ro" \
    -v "${INPUT_SNAPSHOT_DIR}/initial:/task/initial:ro" \
    -v "${WORK_DIR}/bin/cdnca-edge-agent-helper:/task/bin/cdnca-edge-agent-helper:ro" \
    -v "${edge_runtime_config}:/task/bootstrap/config.json:ro" \
    -v "${edge_env_file}:/task/bootstrap/agent.env:ro" \
    -v "${EDGE_IDENTITY_DIR}:/task/bootstrap/identity:ro" \
    -v "${WORK_DIR}/certs/ca.pem:/task/certs/ca.pem:ro" \
    "${edge_mount_args[@]}" "${SYSTEMD_IMAGE}" /sbin/init || upgrade_e2e_fail 'edge-runtime-start'
  edge_container_id=${last_container_id}
  for _ in {1..600}; do
    upgrade_e2e_docker exec "${edge_container_id}" systemctl show --property=Version >/dev/null 2>&1 && break
    sleep 0.1
  done
  upgrade_e2e_docker exec "${edge_container_id}" systemctl show --property=Version >/dev/null || \
    upgrade_e2e_fail 'edge-systemd-readiness'
  upgrade_e2e_docker exec "${edge_container_id}" /opt/cdnca-upgrade-e2e/packaging/scripts/install.sh \
    --artifact /task/initial/edge-agent --sbom /task/initial/edge-agent.spdx.json \
    --manifest /task/initial/manifest --signature /task/initial/manifest.sig \
    --public-key /task/initial/public-key.pem || upgrade_e2e_fail 'edge-initial-package-install'
  upgrade_e2e_docker exec -i "${edge_container_id}" sh -ceu '
    install -d -o cdnca-edge -g cdnca-edge -m 0700 /etc/cdnca-edge-agent/tls /etc/cdnca-edge-agent/trust /etc/cdnca-edge-agent/identity
    install -o cdnca-edge -g cdnca-edge -m 0400 /task/bootstrap/config.json /etc/cdnca-edge-agent/config.json
    install -o root -g root -m 0600 /task/bootstrap/agent.env /etc/cdnca-edge-agent/agent.env
    install -o cdnca-edge -g cdnca-edge -m 0444 /task/certs/ca.pem /etc/cdnca-edge-agent/tls/ca.pem
    for name in identity.json client.pem client-key.pem artifact-x25519-key.bin; do
      install -o cdnca-edge -g cdnca-edge -m 0600 "/task/bootstrap/identity/${name}" "/etc/cdnca-edge-agent/identity/${name}"
    done
    install -o cdnca-edge -g cdnca-edge -m 0444 /task/runtime-secrets/edge-artifact-trust.json /etc/cdnca-edge-agent/trust/artifact.json
    install -o cdnca-edge -g cdnca-edge -m 0444 /task/runtime-secrets/edge-control-trust.json /etc/cdnca-edge-agent/trust/control-execution.json
    install -o cdnca-edge -g cdnca-edge -m 0444 /task/runtime-secrets/edge-execution-trust.json /etc/cdnca-edge-agent/trust/edge-execution.json
    install -o root -g root -m 0555 /task/bin/cdnca-edge-agent-helper /usr/libexec/cdnca-edge-agent-helper
    install -o root -g root -m 0644 /opt/cdnca-upgrade-e2e/packaging/systemd/cdnca-edge-agent-helper.service /usr/lib/systemd/system/cdnca-edge-agent-helper.service
    install -o root -g root -m 0644 /opt/cdnca-upgrade-e2e/packaging/systemd/cdnca-edge-agent-helper.socket /usr/lib/systemd/system/cdnca-edge-agent-helper.socket
    /usr/libexec/cdnca-edge-agent-helper key-init
  ' || upgrade_e2e_fail 'edge-production-layout'
  receipt_pin=$(upgrade_e2e_docker exec "${edge_container_id}" cat /etc/cdnca-edge-agent/helper-receipt-public.json) || \
    upgrade_e2e_fail 'edge-helper-receipt-pin'
  upgrade_e2e_receipt_trust_from_pin "${receipt_pin}" | upgrade_e2e_docker exec -i "${edge_container_id}" \
    install -o cdnca-edge -g cdnca-edge -m 0400 /dev/stdin /etc/cdnca-edge-agent/trust/installer-receipt.json || \
    upgrade_e2e_fail 'edge-installer-receipt-trust'
  upgrade_e2e_docker exec "${edge_container_id}" sh -ceu '
    systemctl daemon-reload
    systemctl enable --now cdnca-edge-agent-helper.socket
    systemctl enable --now cdnca-edge-agent.service
  ' || upgrade_e2e_fail 'edge-production-layout'
  [ "$(upgrade_e2e_docker exec "${edge_container_id}" readlink /usr/lib/cdnca-edge-agent/current)" = \
    "versions/$(upgrade_e2e_require_env UPGRADE_E2E_INITIAL_VERSION)" ] || \
    upgrade_e2e_fail 'edge-initial-current-version'
  for _ in {1..600}; do
    upgrade_e2e_docker exec "${edge_container_id}" systemctl is-active --quiet \
      cdnca-edge-agent-helper.socket && \
      upgrade_e2e_docker exec "${edge_container_id}" systemctl is-active --quiet \
        cdnca-edge-agent.service && break
    sleep 0.1
  done
  upgrade_e2e_docker exec "${edge_container_id}" systemctl is-active --quiet \
    cdnca-edge-agent-helper.socket || upgrade_e2e_fail 'edge-helper-socket-readiness'
  upgrade_e2e_docker exec "${edge_container_id}" systemctl is-active --quiet \
    cdnca-edge-agent.service || upgrade_e2e_fail 'edge-agent-readiness'
  upgrade_e2e_assert_systemd_runtime_supply_chain
}

upgrade_e2e_control_request() {
  local method=$1 path=$2 body=$3 idempotency_key=$4 expected_status=$5 output=$6 status
  local -a arguments
  arguments=(--silent --show-error --config "${control_api_header_file}" --request "${method}"
    --header "X-Request-ID: ${idempotency_key}-request" --output "${output}" --write-out '%{http_code}'
    --connect-timeout 2 --max-time 30)
  if [ -n "${body}" ]; then
    arguments+=(--header 'Content-Type: application/json' --header "Idempotency-Key: ${idempotency_key}"
      --data-binary "@${body}")
  fi
  status=$(curl "${arguments[@]}" "http://127.0.0.1:${control_http_port}${path}") || \
    upgrade_e2e_fail 'control-http-transport'
  [ "${status}" = "${expected_status}" ] || upgrade_e2e_fail "control-http-status-${status}"
  jq -e 'type == "object"' "${output}" >/dev/null || upgrade_e2e_fail 'control-http-json'
}

upgrade_e2e_control_sql() {
  upgrade_e2e_docker exec "${POSTGRES_CONTAINER}" psql -qAtX -v ON_ERROR_STOP=1 \
    -U cdnca -d control_e2e -c "SET default_transaction_read_only=on; $1"
}

upgrade_e2e_assert_control_identity_fixture_binding() {
  local node_id identity_facts certificate_serial leaf_der_sha256 artifact_key_id artifact_public_key_hex actual
  node_id="$(upgrade_e2e_require_env UPGRADE_E2E_NODE_ID)"
  [[ "${node_id}" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$ ]] || \
    upgrade_e2e_fail 'control-fixture-node-id'
  identity_facts=$(upgrade_e2e_edge_identity_public_facts) || \
    upgrade_e2e_fail 'control-fixture-identity-readback-facts'
  IFS=$'\t' read -r certificate_serial leaf_der_sha256 artifact_key_id artifact_public_key_hex \
    <<<"${identity_facts}"
  actual=$(upgrade_e2e_control_sql "SELECT count(*)
    FROM nodes node
    JOIN access_scopes scope ON scope.id=node.scope_id
    JOIN node_identity_state state ON state.node_id=node.id
    JOIN node_artifact_encryption_keys artifact
      ON artifact.node_id=node.id AND state.active_artifact_key_id=artifact.id
    JOIN node_identity_authorizations authorization
      ON authorization.id=artifact.authorization_id AND authorization.node_id=node.id
    JOIN node_certificates certificate
      ON certificate.node_id=node.id AND certificate.enrollment_authorization_id=authorization.id
    JOIN control_installation_entitlement installation
      ON installation.singleton AND certificate.installation_id=installation.installation_id
    JOIN node_ca_key_epochs epoch
      ON epoch.id=certificate.ca_epoch_id AND epoch.installation_id=certificate.installation_id
    WHERE node.id='${node_id}'::uuid AND node.admin_state='active'
      AND state.authorization_revision>0
      AND certificate.serial_number='${certificate_serial}'
      AND encode(certificate.leaf_der_sha256,'hex')='${leaf_der_sha256}'
      AND certificate.status='active' AND certificate.rotation_status='current'
      AND certificate.owner_scope_id=node.scope_id
      AND artifact.id='${artifact_key_id}'
      AND encode(artifact.public_key,'hex')='${artifact_public_key_hex}'
      AND encode(artifact.public_key_sha256,'hex')=substring('${artifact_key_id}' from 8)
      AND artifact.status='active'
      AND authorization.status='issued'
      AND authorization.gateway_workload_identity='${GATEWAY_WORKLOAD_URI}'
      AND authorization.artifact_key_id=artifact.id
      AND authorization.artifact_public_key=artifact.public_key
      AND epoch.status='active'") || upgrade_e2e_fail 'control-fixture-identity-readback'
  [ "${actual}" = '1' ] || upgrade_e2e_fail 'control-fixture-identity-mismatch'
}

upgrade_e2e_license_sql() {
  upgrade_e2e_docker exec "${POSTGRES_CONTAINER}" psql -qAtX -v ON_ERROR_STOP=1 \
    -U cdnca -d license_e2e -c "SET default_transaction_read_only=on; $1"
}

upgrade_e2e_wait_control_sql() {
  local query=$1 expected=$2 actual
  for _ in {1..1200}; do
    actual=$(upgrade_e2e_control_sql "${query}") || upgrade_e2e_fail 'control-observation-query'
    [ "${actual}" = "${expected}" ] && return 0
    sleep 0.1
  done
  return 1
}

upgrade_e2e_restart_edge_agent() {
  upgrade_e2e_docker exec "${edge_container_id}" systemctl restart cdnca-edge-agent.service || \
    upgrade_e2e_fail 'edge-agent-restart'
  upgrade_e2e_docker exec "${edge_container_id}" systemctl is-active --quiet cdnca-edge-agent.service || \
    upgrade_e2e_fail 'edge-agent-restart-readiness'
}

upgrade_e2e_edge_agent_identity() {
  local pid start_time
  pid=$(upgrade_e2e_docker exec "${edge_container_id}" systemctl show -p MainPID --value \
    cdnca-edge-agent.service) || return 1
  [[ "${pid}" =~ ^[1-9][0-9]*$ ]] || return 1
  start_time=$(upgrade_e2e_docker exec "${edge_container_id}" awk '{print $22}' "/proc/${pid}/stat") || return 1
  [[ "${start_time}" =~ ^[1-9][0-9]*$ ]] || return 1
  printf '%s\t%s\n' "${pid}" "${start_time}"
}

upgrade_e2e_edge_lkg_snapshot() {
  upgrade_e2e_docker exec "${edge_container_id}" sh -ceu '
    active_root=/var/lib/cdnca-edge-agent-backups/active-state
    backup_root=/var/lib/cdnca-edge-agent-backups
    current=$(readlink /usr/lib/cdnca-edge-agent/current)
    case "${current}" in versions/[A-Za-z0-9._-]*) ;; *) exit 1 ;; esac
    {
      printf "current=%s\n" "${current}"
      if [ -L "${backup_root}/last-upgrade" ]; then
        lkg=$(readlink "${backup_root}/last-upgrade")
        case "${lkg}" in [A-Za-z0-9._-]*) ;; *) exit 1 ;; esac
        printf "last-upgrade=%s\n" "${lkg}"
        find "${backup_root}/${lkg}/state" -xdev -type f -print0 | sort -z | \
          xargs -0 -r sha256sum
      else
        printf "last-upgrade=none\n"
      fi
      find "${active_root}" -xdev -type f -print0 | sort -z | xargs -0 -r sha256sum
    } | shasum -a 256 | cut -d " " -f 1
  '
}

upgrade_e2e_helper_journal_snapshot() {
  upgrade_e2e_docker exec "${edge_container_id}" sh -ceu '
    directory=/var/lib/cdnca-edge-agent-helper
    [ -d "${directory}" ]
    find "${directory}" -maxdepth 1 -type f -name "journal-*.json" -print0 | \
      sort -z | xargs -0 -r sha256sum
  '
}

upgrade_e2e_inject_helper_enospc() {
  upgrade_e2e_docker exec "${edge_container_id}" sh -ceu '
    directory=/var/lib/cdnca-edge-agent-helper
    test "$(stat -f -c %T "${directory}")" = tmpfs
    install -d -m 0700 /run/cdnca-upgrade-e2e
    rm -f -- "${directory}/.upgrade-e2e-enospc-filler" /run/cdnca-upgrade-e2e/helper-enospc.stderr
    if dd if=/dev/zero of="${directory}/.upgrade-e2e-enospc-filler" bs=1M count=64 \
      conv=fsync 2>/run/cdnca-upgrade-e2e/helper-enospc.stderr; then
      exit 1
    fi
    grep -F "No space left on device" /run/cdnca-upgrade-e2e/helper-enospc.stderr >/dev/null
    test -s "${directory}/.upgrade-e2e-enospc-filler"
    sync
  ' || upgrade_e2e_fail 'helper-enospc-injection'
}

upgrade_e2e_remove_helper_enospc() {
  upgrade_e2e_docker exec "${edge_container_id}" sh -ceu '
    rm -f -- /var/lib/cdnca-edge-agent-helper/.upgrade-e2e-enospc-filler \
      /run/cdnca-upgrade-e2e/helper-enospc.stderr
    sync
  ' || upgrade_e2e_fail 'helper-enospc-removal'
}

upgrade_e2e_sigkill_edge_agent_and_wait() {
  local before_pid before_start_time after_pid after_start_time identity
  identity=$(upgrade_e2e_edge_agent_identity) || upgrade_e2e_fail 'edge-agent-sigkill-before-identity'
  IFS=$'\t' read -r before_pid before_start_time <<<"${identity}"
  upgrade_e2e_docker exec "${edge_container_id}" systemctl kill --kill-who=main --signal=KILL \
    cdnca-edge-agent.service || upgrade_e2e_fail 'edge-agent-sigkill'
  for _ in {1..1200}; do
    if upgrade_e2e_docker exec "${edge_container_id}" systemctl is-active --quiet \
      cdnca-edge-agent.service; then
      identity=$(upgrade_e2e_edge_agent_identity) || continue
      IFS=$'\t' read -r after_pid after_start_time <<<"${identity}"
      if [ "${after_pid}" != "${before_pid}" ] && [ "${after_start_time}" != "${before_start_time}" ]; then
        printf '%s\t%s\t%s\t%s\n' "${before_pid}" "${before_start_time}" \
          "${after_pid}" "${after_start_time}" >"${WORK_DIR}/logs/edge-agent-sigkill-identity.tsv"
        return 0
      fi
    fi
    sleep 0.1
  done
  return 1
}

upgrade_e2e_create_rollout() {
  local body=$1 key=$2 response
  response="${WORK_DIR}/logs/${key}-create.json"
  upgrade_e2e_control_request POST /v1/admin/control-upgrade-rollouts "${body}" "${key}" 201 "${response}"
  last_rollout_id=$(jq -er '.data.id' "${response}") || upgrade_e2e_fail 'rollout-create-id'
  last_rollout_revision=$(jq -er '.data.revision' "${response}") || upgrade_e2e_fail 'rollout-create-revision'
  [[ "${last_rollout_id}" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$ ]] || \
    upgrade_e2e_fail 'rollout-create-canonical-id'
  [[ "${last_rollout_revision}" =~ ^[1-9][0-9]*$ ]] || upgrade_e2e_fail 'rollout-create-canonical-revision'
}

upgrade_e2e_rollout_action() {
  local plan_id=$1 revision=$2 action=$3 reason=$4 key=$5 response=$6 body
  body="${WORK_DIR}/logs/${key}-${action}.json"
  jq -cn --arg revision "${revision}" --arg reason "${reason}" \
    '{expected_revision:$revision,reason:$reason}' >"${body}" || upgrade_e2e_fail 'rollout-action-body'
  chmod 0400 "${body}" || upgrade_e2e_fail 'rollout-action-body-mode'
  upgrade_e2e_control_request POST "/v1/admin/control-upgrade-rollouts/${plan_id}/${action}" \
    "${body}" "${key}" 200 "${response}"
  last_action_body=${body}
}

upgrade_e2e_wait_rollout() {
  local plan_id=$1 state=$2 completion=$3 output=$4 observed_state observed_completion
  for _ in {1..1800}; do
    upgrade_e2e_control_request GET "/v1/admin/control-upgrade-rollouts/${plan_id}" '' \
      "get-${plan_id}" 200 "${output}"
    observed_state=$(jq -er '.data.state' "${output}") || upgrade_e2e_fail 'rollout-state-json'
    observed_completion=$(jq -r '.data.completion' "${output}") || upgrade_e2e_fail 'rollout-completion-json'
    [ "${observed_state}" = "${state}" ] && [ "${observed_completion}" = "${completion}" ] && return 0
    sleep 0.1
  done
  return 1
}

upgrade_e2e_edge_fact_snapshot() {
  local upgrade_root
  upgrade_root=$(jq -er '.upgrade.root' "${EDGE_CONFIG_SNAPSHOT}") || return 1
  case "${upgrade_root}" in /var/lib/cdnca-edge-agent/*) ;; *) return 1 ;; esac
  upgrade_e2e_docker exec "${edge_container_id}" sh -ceu '
    root=$1
    for directory in "$root/state/upgrade-wire-v1/inbox" "$root/state/upgrade-wire-v1/claims" \
      "$root/state/upgrade-wire-v1/outbox" "$root/state/upgrade-wire-v1/acked" \
      /var/lib/cdnca-edge-agent-helper/transactions; do
      [ -d "$directory" ] || exit 1
      find "$directory" -type f -print0 | sort -z | xargs -0 -r sha256sum
    done
    if [ -f "$root/state/transaction.json" ]; then
      sha256sum "$root/state/transaction.json"
    fi
    find /var/lib/cdnca-edge-agent-helper -maxdepth 1 -type f -name "journal-*.json" -print0 | \
      sort -z | xargs -0 -r sha256sum
  ' sh "${upgrade_root}"
}

upgrade_e2e_rollout_snapshot() {
  local plan_id=$1 grant_id control_facts license_facts edge_facts
  grant_id=$(upgrade_e2e_control_sql "SELECT parent_grant_id FROM control_upgrade_rollout_plans
    WHERE id='${plan_id}'") || return 1
  [[ "${grant_id}" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$ ]] || return 1
  control_facts=$(upgrade_e2e_control_sql "SELECT COALESCE(string_agg(fact::text,E'\\n' ORDER BY fact::text),'') FROM (
    SELECT jsonb_build_object('kind','plan','row',to_jsonb(value)) fact FROM control_upgrade_rollout_plans value WHERE id='${plan_id}'
    UNION ALL SELECT jsonb_build_object('kind','event','row',to_jsonb(value)) FROM control_upgrade_rollout_events value WHERE plan_id='${plan_id}'
    UNION ALL SELECT jsonb_build_object('kind','command','row',to_jsonb(value)) FROM control_upgrade_node_commands value WHERE plan_id='${plan_id}'
    UNION ALL SELECT jsonb_build_object('kind','outbox','row',to_jsonb(value)) FROM control_upgrade_outbox value WHERE plan_id='${plan_id}'
    UNION ALL SELECT jsonb_build_object('kind','status','row',to_jsonb(value)) FROM control_upgrade_status_receipts value WHERE plan_id='${plan_id}'
    UNION ALL SELECT jsonb_build_object('kind','license_outbox','row',to_jsonb(value)) FROM control_upgrade_license_receipt_outbox_097 value WHERE plan_id='${plan_id}'
    UNION ALL SELECT jsonb_build_object('kind','license_delivery','row',to_jsonb(delivery))
      FROM control_upgrade_license_receipt_deliveries_097 delivery JOIN control_upgrade_license_receipt_outbox_097 outbox
        ON outbox.id=delivery.request_id WHERE outbox.plan_id='${plan_id}'
  ) facts") || return 1
  license_facts=$(upgrade_e2e_license_sql "SELECT COALESCE(string_agg(fact::text,E'\\n' ORDER BY fact::text),'') FROM (
    SELECT jsonb_build_object('kind','upgrade_grant_receipts','row',to_jsonb(receipt)) fact
    FROM upgrade_grant_receipts receipt WHERE receipt.grant_id='${grant_id}'
  ) facts") || return 1
  edge_facts=$(upgrade_e2e_edge_fact_snapshot) || return 1
  printf '%s\n%s\n%s\n' "${control_facts}" "${license_facts}" "${edge_facts}" | \
    shasum -a 256 | awk '{print $1}'
}

upgrade_e2e_assert_parent_chain() {
  local plan_id=$1 terminal=$2 expected_count expected_states grant_id control_rows license_rows
  local control_commands license_commands
  case "${terminal}" in
    applied) expected_count=3; expected_states="ARRAY['fetched','verified','applied']::text[]" ;;
    rolled_back) expected_count=4; expected_states="ARRAY['fetched','verified','applied','rolled_back']::text[]" ;;
    *) return 1 ;;
  esac
  upgrade_e2e_wait_control_sql "SELECT count(*) FROM control_upgrade_license_receipt_outbox_097
    WHERE plan_id='${plan_id}' AND state='delivered'" "${expected_count}" || return 1
  [ "$(upgrade_e2e_control_sql "SELECT count(*) FROM control_upgrade_license_receipt_outbox_097 receipt
    WHERE receipt.plan_id='${plan_id}'
    HAVING count(*)=${expected_count} AND count(DISTINCT receipt.receipt_sequence)=${expected_count}
      AND min(receipt.receipt_sequence)=1 AND max(receipt.receipt_sequence)=${expected_count}
      AND array_agg(receipt.status ORDER BY receipt.receipt_sequence)=${expected_states}")" = "${expected_count}" ] || return 1
  [ "$(upgrade_e2e_control_sql "SELECT count(*) FROM control_upgrade_license_receipt_outbox_097 child
    LEFT JOIN control_upgrade_license_receipt_outbox_097 parent ON parent.id=child.predecessor_id
    WHERE child.plan_id='${plan_id}' AND ((child.receipt_sequence=1 AND child.status='fetched' AND child.predecessor_id IS NULL) OR
      (child.receipt_sequence=2 AND child.status='verified' AND parent.receipt_sequence=1) OR
      (child.receipt_sequence=3 AND child.status='applied' AND parent.receipt_sequence=2) OR
      (child.receipt_sequence=4 AND child.status='rolled_back' AND parent.receipt_sequence=3))")" = \
    "${expected_count}" ] || return 1
  [ "$(upgrade_e2e_control_sql "SELECT count(*) FROM control_upgrade_license_receipt_deliveries_097 delivery
    JOIN control_upgrade_license_receipt_outbox_097 outbox ON outbox.id=delivery.request_id
    WHERE outbox.plan_id='${plan_id}' AND delivery.response_schema='upgrade-grant.receipt-response/v1'
      AND sha256(delivery.response_bytes)=delivery.response_sha256
      AND delivery.response_bytes=convert_to(format(
        '{\"schema\":\"upgrade-grant.receipt-response/v1\",\"request_id\":\"%s\",\"receipt_id\":\"%s\",\"accepted_status\":\"%s\",\"received_at\":%s}' || E'\\n',
        delivery.request_id,delivery.receipt_id,delivery.accepted_status,
        extract(epoch FROM delivery.received_at)::bigint),'UTF8')
      AND (SELECT array_agg(key ORDER BY key) FROM jsonb_object_keys(
        convert_from(delivery.response_bytes,'UTF8')::jsonb) key)=
        ARRAY['accepted_status','receipt_id','received_at','request_id','schema']::text[]")" = "${expected_count}" ] || return 1
  grant_id=$(upgrade_e2e_control_sql "SELECT parent_grant_id FROM control_upgrade_rollout_plans WHERE id='${plan_id}'") || return 1
  [ "$(upgrade_e2e_license_sql "SELECT count(*) FROM upgrade_grant_receipts receipt
    JOIN issued_upgrade_grants parent_grant ON parent_grant.id=receipt.grant_id
      AND parent_grant.installation_id=receipt.installation_id
    WHERE receipt.grant_id='${grant_id}' AND receipt.request_schema='${LICENSE_PARENT_RECEIPT_SCHEMA}'
    HAVING count(*)=${expected_count} AND count(DISTINCT receipt.id)=${expected_count}
      AND array_agg(receipt.status ORDER BY CASE receipt.status WHEN 'fetched' THEN 1 WHEN 'verified' THEN 2
        WHEN 'applied' THEN 3 WHEN 'rolled_back' THEN 4 ELSE 5 END)=${expected_states}")" = "${expected_count}" ] || return 1
  control_rows=$(upgrade_e2e_control_sql "SELECT string_agg(concat_ws('|',outbox.id,delivery.receipt_id,
    outbox.installation_id,outbox.grant_id,outbox.status,encode(outbox.logical_digest,'hex')),E'\\n' ORDER BY outbox.receipt_sequence)
    FROM control_upgrade_license_receipt_outbox_097 outbox JOIN control_upgrade_license_receipt_deliveries_097 delivery
      ON delivery.request_id=outbox.id WHERE outbox.plan_id='${plan_id}'") || return 1
  license_rows=$(upgrade_e2e_license_sql "SELECT string_agg(concat_ws('|',receipt.request_id,receipt.id,
    receipt.installation_id,receipt.grant_id,receipt.status,encode(receipt.request_digest,'hex')),E'\\n'
    ORDER BY CASE receipt.status WHEN 'fetched' THEN 1 WHEN 'verified' THEN 2 WHEN 'applied' THEN 3 ELSE 4 END)
    FROM upgrade_grant_receipts receipt WHERE receipt.grant_id='${grant_id}'") || return 1
  [ "${control_rows}" = "${license_rows}" ] || return 1
  control_commands=$(upgrade_e2e_control_sql "SELECT string_agg(concat_ws('|',command.command_id,command.plan_id,
    command.installation_id,command.action,plan.parent_grant_id,plan.artifact_bundle_id,
    CASE command.action WHEN 'upgrade' THEN convert_from(plan.canonical_snapshot_bytes,'UTF8')::jsonb->>'ArtifactID'
      ELSE convert_from(plan.canonical_snapshot_bytes,'UTF8')::jsonb->>'RollbackArtifactID' END),E'\\n' ORDER BY command.command_id)
    FROM control_upgrade_node_commands command JOIN control_upgrade_rollout_plans plan ON plan.id=command.plan_id
    WHERE command.plan_id='${plan_id}'") || return 1
  license_commands=$(upgrade_e2e_license_sql "SELECT string_agg(concat_ws('|',command_grant.command_id,command_grant.plan_id,
    command_grant.installation_id,command_grant.operation,command_grant.parent_grant_id,
    command_grant.artifact_bundle_id,command_grant.artifact_id),E'\\n' ORDER BY command_grant.command_id)
    FROM issued_upgrade_plan_artifact_bundles bundle
    JOIN issued_upgrade_command_grants command_grant ON command_grant.plan_id='${plan_id}'
      AND bundle.id=command_grant.artifact_bundle_id AND bundle.installation_id=command_grant.installation_id
    WHERE bundle.plan_id='${plan_id}'") || return 1
  [ "${control_commands}" = "${license_commands}" ]
}

upgrade_e2e_assert_status_sequence() {
  local plan_id=$1 action=$2 expected=$3 actual
  actual=$(upgrade_e2e_control_sql "SELECT array_to_string(array_agg(state ORDER BY status_revision),',')
    FROM control_upgrade_status_receipts WHERE plan_id='${plan_id}' AND action='${action}'") || return 1
  [ "${actual}" = "${expected}" ]
}

upgrade_e2e_assert_installing_journal() {
  local plan_id=$1 action=$2 transaction_id journal
  transaction_id=$(upgrade_e2e_control_sql "SELECT convert_from(status_bytes,'UTF8')::jsonb->>'installer_transaction_id'
    FROM control_upgrade_status_receipts WHERE plan_id='${plan_id}' AND action='${action}' AND state='installing'") || return 1
  [[ "${transaction_id}" =~ ^[A-Za-z0-9._-]{1,128}$ ]] || return 1
  journal="${WORK_DIR}/logs/${plan_id}-${action}-helper-journal.json"
  upgrade_e2e_docker exec "${edge_container_id}" cat \
    "/var/lib/cdnca-edge-agent-helper/journal-${transaction_id}.json" >"${journal}" || return 1
  jq -e --arg transaction_id "${transaction_id}" '
    .transaction_id == $transaction_id and
      (.phase == "installing" or .phase == "active" or
       .phase == "rollbacking" or .phase == "rolled_back")
  ' "${journal}" >/dev/null || return 1
  upgrade_e2e_docker exec "${edge_container_id}" test -d \
    "/var/lib/cdnca-edge-agent-helper/transactions/${transaction_id}"
}

upgrade_e2e_assert_command_wire() {
  local plan_id=$1 rows sequence subject message_key digest stored stored_digest actual_headers expected_headers count
  rows="${WORK_DIR}/logs/${plan_id}-command-wire.tsv"
  upgrade_e2e_control_sql "SELECT published_sequence,topic,message_key,encode(payload_sha256,'hex')
    FROM control_upgrade_outbox WHERE plan_id='${plan_id}' AND state='published'
      AND published_stream='AGENT_COMMANDS' AND published_sequence>0 ORDER BY published_sequence" >"${rows}" || return 1
  count=0
  while IFS=$'\t' read -r sequence subject message_key digest; do
    [ -n "${sequence}" ] || continue
    stored="${WORK_DIR}/logs/${plan_id}-command-${sequence}.json"
    upgrade_e2e_docker exec "${nats_cli_container_id}" nats --server "nats://${NATS_CONTAINER}:4222" \
      stream get -j AGENT_COMMANDS "${sequence}" >"${stored}" || return 1
    [ "$(jq -er '.seq' "${stored}")" = "${sequence}" ] && \
      [ "$(jq -er '.subject' "${stored}")" = "${subject}" ] || return 1
    stored_digest=$(jq -er '.data' "${stored}" | perl -MMIME::Base64=decode_base64 -e '
      use strict; use warnings; local $/; my $value=<STDIN>; binmode STDOUT; print decode_base64($value);' | \
      shasum -a 256 | awk '{print $1}') || return 1
    [ "${stored_digest}" = "${digest}" ] || return 1
    actual_headers=$(jq -er '.hdrs' "${stored}" | perl -MMIME::Base64=decode_base64 -e '
      use strict; use warnings; local $/; my $value=<STDIN>; print decode_base64($value);' | \
      tr -d '\r' | awk 'NR>1 && NF {print tolower($0)}' | LC_ALL=C sort) || return 1
    expected_headers=$(printf '%s\n' \
      "nats-expected-stream: agent_commands" \
      "nats-msg-id: control-upgrade-v1-${digest}" \
      "x-cdnca-message-key: ${message_key}" \
      "x-cdnca-payload-sha256: ${digest}" | LC_ALL=C sort) || return 1
    [ "${actual_headers}" = "${expected_headers}" ] || return 1
    # Nodes never contact the license server: the signed execution points at
    # the Control artifact cache (content addressed by the signed digest).
    jq -er '.data' "${stored}" | perl -MMIME::Base64=decode_base64 -e '
      use strict; use warnings; local $/; my $value=<STDIN>; binmode STDOUT; print decode_base64($value);' | \
      jq -e '.signed_execution | @base64d | fromjson | .execution.download_url |
        test("^https://control\\.internal:8445/downloads/edge-agent/upgrades/sha256/[0-9a-f]{64}$")' \
      >/dev/null || return 1
    count=$((count + 1))
  done <"${rows}"
  [ "${count}" -ge 1 ]
}

upgrade_e2e_edge_status_ack_snapshot() {
  local upgrade_root
  upgrade_root=$(jq -er '.upgrade.root' "${EDGE_CONFIG_SNAPSHOT}") || return 1
  case "${upgrade_root}" in /var/lib/cdnca-edge-agent/*) ;; *) return 1 ;; esac
  upgrade_e2e_docker exec "${edge_container_id}" sh -ceu '
    directory="$1/state/upgrade-wire-v1/acked"
    [ -d "$directory" ]
    [ -z "$(find "$directory" -mindepth 1 -maxdepth 1 ! -type f -print -quit)" ]
    [ -z "$(find "$directory" -mindepth 1 -maxdepth 1 -type f ! -name "*.json" -print -quit)" ]
    find "$directory" -mindepth 1 -maxdepth 1 -type f -name "*.json" -print0 | \
      sort -z | xargs -0 -r sha256sum
  ' sh "${upgrade_root}"
}

upgrade_e2e_assert_edge_status_acks() {
  local plan_id=$1 upgrade_root rows expected_count file_count count
  local status_id status_revision command_id installation_id node_id state transaction_id digest sequence
  local ack_file ack_digest ack_encoded confirmation_subject confirmation_message confirmation_sequence
  local confirmation_wire confirmation_ack confirmation_digest actual_headers expected_headers
  local ledger_subject ledger_message ledger_sequence ledger_wire previous_sequence ledger_digest
  local snapshot_before snapshot_after
  upgrade_root=$(jq -er '.upgrade.root' "${EDGE_CONFIG_SNAPSHOT}") || return 1
  case "${upgrade_root}" in /var/lib/cdnca-edge-agent/*) ;; *) return 1 ;; esac
  rows="${WORK_DIR}/logs/${plan_id}-edge-status-acks.tsv"
  upgrade_e2e_control_sql "SELECT concat_ws(E'\\t',status_id,status_revision,command_id,installation_id,
    node_id,state,convert_from(status_bytes,'UTF8')::jsonb->>'installer_transaction_id',
    encode(status_sha256,'hex'),delivery_sequence) FROM control_upgrade_status_receipts
    WHERE delivery_stream='AGENT_DEPLOYMENT_STATUS'
      AND delivery_consumer='control_api_upgrade_status' AND delivery_sequence>0
    ORDER BY delivery_sequence" >"${rows}" || return 1
  expected_count=$(wc -l <"${rows}" | tr -d '[:space:]') || return 1
  [[ "${expected_count}" =~ ^[1-9][0-9]*$ ]] || return 1
  file_count=$(upgrade_e2e_docker exec "${edge_container_id}" sh -ceu '
    directory="$1/state/upgrade-wire-v1/acked"
    [ -d "$directory" ]
    [ -z "$(find "$directory" -mindepth 1 -maxdepth 1 ! -type f -print -quit)" ]
    [ -z "$(find "$directory" -mindepth 1 -maxdepth 1 -type f ! -name "*.json" -print -quit)" ]
    find "$directory" -mindepth 1 -maxdepth 1 -type f -name "*.json" | wc -l | tr -d "[:space:]"
  ' sh "${upgrade_root}") || return 1
  [ "${file_count}" = "${expected_count}" ] || return 1
  count=0
  while IFS=$'\t' read -r status_id status_revision command_id installation_id node_id state \
    transaction_id digest sequence; do
    [ -n "${sequence}" ] || continue
    [[ "${status_id}" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$ ]] || return 1
    [[ "${command_id}" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$ ]] || return 1
    [[ "${installation_id}" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$ ]] || return 1
    [[ "${node_id}" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$ ]] || return 1
    [[ "${status_revision}" =~ ^[1-9][0-9]*$ ]] && [[ "${sequence}" =~ ^[1-9][0-9]*$ ]] || return 1
    upgrade_e2e_valid_sha256 "${digest}" || return 1
    ack_file="${WORK_DIR}/logs/${plan_id}-edge-status-ack-${status_id}.json"
    upgrade_e2e_docker exec "${edge_container_id}" cat \
      "${upgrade_root}/state/upgrade-wire-v1/acked/${status_id}.json" >"${ack_file}" || return 1
    jq -e --arg status_id "${status_id}" --arg status_revision "${status_revision}" \
      --arg command_id "${command_id}" --arg state "${state}" --arg transaction_id "${transaction_id}" \
      --arg digest "${digest}" --arg sequence "${sequence}" '
        type == "object" and
        keys == ["ack_sha256","command_id","encoded","installer_transaction_id","persisted_at",
          "published_sequence","published_stream","receipt_confirmed","receipt_required","sha256","state",
          "status_id","status_revision","version"] and
        .version == 1 and .status_id == $status_id and .status_revision == ($status_revision | tonumber) and
        .command_id == $command_id and .state == $state and .installer_transaction_id == $transaction_id and
        .sha256 == $digest and .published_stream == "AGENT_DEPLOYMENT_STATUS" and
        .published_sequence == ($sequence | tonumber) and
        .receipt_required == true and .receipt_confirmed == true and
        (.persisted_at | type == "string" and length > 0) and
        (.encoded | type == "string" and length > 0) and
        (.ack_sha256 | type == "string" and test("^[0-9a-f]{64}$"))
      ' "${ack_file}" >/dev/null || return 1
    ack_digest=$(jq -er '.ack_sha256' "${ack_file}") || return 1
    ack_encoded="${WORK_DIR}/logs/${plan_id}-edge-status-ack-${status_id}.pb"
    jq -er '.encoded' "${ack_file}" | perl -MMIME::Base64=decode_base64 -e '
      use strict; use warnings; local $/; my $value=<STDIN>; binmode STDOUT; print decode_base64($value);' \
      >"${ack_encoded}" || return 1
    [ -s "${ack_encoded}" ] && [ "$(upgrade_e2e_sha256 "${ack_encoded}")" = "${ack_digest}" ] || return 1
    confirmation_subject="cdnca.agent.deployment-status.upgrade-proof.confirmed.${node_id}.${ack_digest}"
    confirmation_message="${WORK_DIR}/logs/${plan_id}-status-ack-confirmation-${status_id}.json"
    upgrade_e2e_docker exec "${nats_cli_container_id}" nats --server "nats://${NATS_CONTAINER}:4222" \
      stream get -j AGENT_DEPLOYMENT_STATUS --last-by-subject "${confirmation_subject}" \
      >"${confirmation_message}" || return 1
    confirmation_sequence=$(jq -er '.seq' "${confirmation_message}") || return 1
    [[ "${confirmation_sequence}" =~ ^[1-9][0-9]*$ ]] && [ "${confirmation_sequence}" -gt "${sequence}" ] || return 1
    [ "$(jq -er '.subject' "${confirmation_message}")" = "${confirmation_subject}" ] || return 1
    confirmation_wire="${WORK_DIR}/logs/${plan_id}-status-ack-confirmation-${status_id}-wire.json"
    jq -er '.data' "${confirmation_message}" | perl -MMIME::Base64=decode_base64 -e '
      use strict; use warnings; local $/; my $value=<STDIN>; binmode STDOUT; print decode_base64($value);' \
      >"${confirmation_wire}" || return 1
    jq -e --arg node_id "${node_id}" --arg installation_id "${installation_id}" --arg ack_digest "${ack_digest}" '
      type == "object" and keys == ["ack","ack_sha256","installation_id","node_id","receipt","schema"] and
      .schema == "cdnca.gateway.upgrade-status-ack-confirmation/v1" and .node_id == $node_id and
      .installation_id == $installation_id and .ack_sha256 == $ack_digest and
      (.ack | type == "string" and length > 0) and (.receipt | type == "string" and length > 0)
    ' "${confirmation_wire}" >/dev/null || return 1
    confirmation_ack="${WORK_DIR}/logs/${plan_id}-status-ack-confirmation-${status_id}.pb"
    jq -er '.ack' "${confirmation_wire}" | perl -MMIME::Base64=decode_base64 -e '
      use strict; use warnings; local $/; my $value=<STDIN>; binmode STDOUT; print decode_base64($value);' \
      >"${confirmation_ack}" || return 1
    cmp -s "${ack_encoded}" "${confirmation_ack}" || return 1
    confirmation_digest=$(upgrade_e2e_sha256 "${confirmation_wire}") || return 1
    actual_headers=$(jq -er '.hdrs' "${confirmation_message}" | perl -MMIME::Base64=decode_base64 -e '
      use strict; use warnings; local $/; my $value=<STDIN>; print decode_base64($value);' | \
      tr -d '\r' | awk 'NR>1 && NF {print tolower($0)}' | LC_ALL=C sort) || return 1
    expected_headers=$(printf '%s\n' \
      'nats-expected-last-subject-sequence: 0' \
      'nats-expected-stream: agent_deployment_status' \
      "nats-msg-id: gateway-upgrade-status-ack-confirmation-v1-${confirmation_digest}" \
      "x-cdnca-message-key: ${ack_digest}" \
      "x-cdnca-payload-sha256: ${confirmation_digest}" | LC_ALL=C sort) || return 1
    [ "${actual_headers}" = "${expected_headers}" ] || return 1
    count=$((count + 1))
  done <"${rows}"
  [ "${count}" = "${expected_count}" ] || return 1

  snapshot_before=$(upgrade_e2e_edge_status_ack_snapshot) || return 1
  [ -n "${snapshot_before}" ] || return 1
  printf '%s\n' "${snapshot_before}" >"${WORK_DIR}/logs/${plan_id}-edge-status-acks-before-restart.sha256"
  upgrade_e2e_restart_edge_agent
  snapshot_after=$(upgrade_e2e_edge_status_ack_snapshot) || return 1
  printf '%s\n' "${snapshot_after}" >"${WORK_DIR}/logs/${plan_id}-edge-status-acks-after-restart.sha256"
  [ "${snapshot_before}" = "${snapshot_after}" ] || return 1

  node_id="$(upgrade_e2e_require_env UPGRADE_E2E_NODE_ID)"
  ledger_subject="cdnca.agent.deployment-status.upgrade-proof.pending.${node_id}"
  ledger_message="${WORK_DIR}/logs/${plan_id}-status-ack-ledger.json"
  upgrade_e2e_docker exec "${nats_cli_container_id}" nats --server "nats://${NATS_CONTAINER}:4222" \
    stream get -j AGENT_DEPLOYMENT_STATUS --last-by-subject "${ledger_subject}" >"${ledger_message}" || return 1
  ledger_sequence=$(jq -er '.seq' "${ledger_message}") || return 1
  [[ "${ledger_sequence}" =~ ^[1-9][0-9]*$ ]] || return 1
  [ "$(jq -er '.subject' "${ledger_message}")" = "${ledger_subject}" ] || return 1
  ledger_wire="${WORK_DIR}/logs/${plan_id}-status-ack-ledger-wire.json"
  jq -er '.data' "${ledger_message}" | perl -MMIME::Base64=decode_base64 -e '
    use strict; use warnings; local $/; my $value=<STDIN>; binmode STDOUT; print decode_base64($value);' \
    >"${ledger_wire}" || return 1
  previous_sequence=$(jq -er --arg node_id "${node_id}" '
    select(type == "object" and keys == ["node_id","pending","previous_sequence","schema"] and
      .schema == "cdnca.gateway.upgrade-status-ack-ledger/v1" and .node_id == $node_id and
      (.previous_sequence | type == "number" and . >= 0 and floor == .) and
      (.pending | type == "array" and length == 0)) | .previous_sequence
  ' "${ledger_wire}") || return 1
  [[ "${previous_sequence}" =~ ^[0-9]+$ ]] || return 1
  (( previous_sequence < ledger_sequence )) || return 1
  ledger_digest=$(upgrade_e2e_sha256 "${ledger_wire}") || return 1
  actual_headers=$(jq -er '.hdrs' "${ledger_message}" | perl -MMIME::Base64=decode_base64 -e '
    use strict; use warnings; local $/; my $value=<STDIN>; print decode_base64($value);' | \
    tr -d '\r' | awk 'NR>1 && NF {print tolower($0)}' | LC_ALL=C sort) || return 1
  expected_headers=$(printf '%s\n' \
    "nats-expected-last-subject-sequence: ${previous_sequence}" \
    'nats-expected-stream: agent_deployment_status' \
    "nats-msg-id: gateway-upgrade-status-ack-ledger-v1-${ledger_digest}" \
    "x-cdnca-message-key: ${node_id}" \
    "x-cdnca-payload-sha256: ${ledger_digest}" | LC_ALL=C sort) || return 1
  [ "${actual_headers}" = "${expected_headers}" ]
}

upgrade_e2e_assert_status_puback_wire() {
  local plan_id=$1 rows detail count status_id status_revision command_id node_id action state
  local stream consumer sequence digest stored stored_digest actual_headers expected_headers api_count ordered_count
  rows="${WORK_DIR}/logs/${plan_id}-status-puback-wire.tsv"
  detail="${WORK_DIR}/logs/${plan_id}-status-puback-api.json"
  upgrade_e2e_control_request GET "/v1/admin/control-upgrade-rollouts/${plan_id}" '' \
    "get-status-puback-${plan_id}" 200 "${detail}"
  upgrade_e2e_control_sql "SELECT status_id,status_revision,command_id,node_id,action,state,
    delivery_stream,delivery_consumer,delivery_sequence,encode(status_sha256,'hex')
    FROM control_upgrade_status_receipts WHERE plan_id='${plan_id}'
      AND delivery_stream='AGENT_DEPLOYMENT_STATUS'
      AND delivery_consumer='control_api_upgrade_status' AND delivery_sequence>0
    ORDER BY delivery_sequence" >"${rows}" || return 1
  ordered_count=$(upgrade_e2e_control_sql "SELECT count(*) FROM (
    SELECT delivery_sequence,lag(delivery_sequence) OVER (
      PARTITION BY command_id ORDER BY status_revision) previous_sequence
    FROM control_upgrade_status_receipts WHERE plan_id='${plan_id}'
  ) ordered WHERE previous_sequence IS NULL OR delivery_sequence>previous_sequence") || return 1
  [ "${ordered_count}" = "$(upgrade_e2e_control_sql "SELECT count(*) FROM control_upgrade_status_receipts
    WHERE plan_id='${plan_id}'")" ] || return 1
  count=0
  while IFS=$'\t' read -r status_id status_revision command_id node_id action state \
    stream consumer sequence digest; do
    [ -n "${sequence}" ] || continue
    [ "${stream}" = 'AGENT_DEPLOYMENT_STATUS' ] && [ "${consumer}" = 'control_api_upgrade_status' ] || return 1
    [[ "${sequence}" =~ ^[1-9][0-9]*$ ]] || return 1
    api_count=$(jq -er --arg status_id "${status_id}" --arg status_revision "${status_revision}" \
      --arg command_id "${command_id}" --arg node_id "${node_id}" --arg action "${action}" \
      --arg state "${state}" --arg stream "${stream}" --arg consumer "${consumer}" \
      --arg sequence "${sequence}" --arg digest "${digest}" '
        [.data.status_receipts[] | select(
          .status_id == $status_id and .status_revision == $status_revision and
          .command_id == $command_id and .node_id == $node_id and .action == $action and
          .state == $state and .delivery_stream == $stream and .delivery_consumer == $consumer and
          .delivery_sequence == $sequence and .status_sha256 == $digest)] | length
      ' "${detail}") || return 1
    [ "${api_count}" = '1' ] || return 1
    stored="${WORK_DIR}/logs/${plan_id}-status-${sequence}.json"
    upgrade_e2e_docker exec "${nats_cli_container_id}" nats --server "nats://${NATS_CONTAINER}:4222" \
      stream get -j AGENT_DEPLOYMENT_STATUS "${sequence}" >"${stored}" || return 1
    [ "$(jq -er '.seq' "${stored}")" = "${sequence}" ] && \
      [ "$(jq -er '.subject' "${stored}")" = "cdnca.agent.deployment-status.upgrade-v2.${status_id}" ] || return 1
    stored_digest=$(jq -er '.data' "${stored}" | perl -MMIME::Base64=decode_base64 -e '
      use strict; use warnings; local $/; my $value=<STDIN>; binmode STDOUT; print decode_base64($value);' | \
      shasum -a 256 | awk '{print $1}') || return 1
    [ "${stored_digest}" = "${digest}" ] || return 1
    actual_headers=$(jq -er '.hdrs' "${stored}" | perl -MMIME::Base64=decode_base64 -e '
      use strict; use warnings; local $/; my $value=<STDIN>; print decode_base64($value);' | \
      tr -d '\r' | awk 'NR>1 && NF {print tolower($0)}' | LC_ALL=C sort) || return 1
    expected_headers=$(printf '%s\n' \
      'nats-expected-last-subject-sequence: 0' \
      'nats-expected-stream: agent_deployment_status' \
      "nats-msg-id: gateway-upgrade-status-v2-${status_id}" \
      "x-cdnca-message-key: ${status_id}" \
      "x-cdnca-payload-sha256: ${digest}" | LC_ALL=C sort) || return 1
    [ "${actual_headers}" = "${expected_headers}" ] || return 1
    count=$((count + 1))
  done <"${rows}"
  [ "${count}" -ge 1 ] && [ "${count}" = "$(jq -er '.data.status_receipts | length' "${detail}")" ] || return 1
  upgrade_e2e_assert_edge_status_acks "${plan_id}"
}

upgrade_e2e_install_auto_rollback_fault() {
  local target_version=$1
  printf '#!/bin/sh\n[ "$(readlink /usr/lib/cdnca-edge-agent/current)" != "versions/%s" ]\n' \
    "${target_version}" | upgrade_e2e_docker exec -i "${edge_container_id}" sh -ceu '
      install -d -m 0755 /run/cdnca-upgrade-e2e
      cat >/run/cdnca-upgrade-e2e/reject-forward
      chmod 0555 /run/cdnca-upgrade-e2e/reject-forward
      install -d -m 0755 /run/systemd/system/cdnca-edge-agent.service.d
      printf "[Service]\nExecStartPre=/run/cdnca-upgrade-e2e/reject-forward\n" > \
        /run/systemd/system/cdnca-edge-agent.service.d/upgrade-e2e.conf
      systemctl daemon-reload
    ' || upgrade_e2e_fail 'auto-rollback-fault-install'
}

upgrade_e2e_remove_auto_rollback_fault() {
  upgrade_e2e_docker exec "${edge_container_id}" sh -ceu '
    rm -f /run/systemd/system/cdnca-edge-agent.service.d/upgrade-e2e.conf
    rm -f /run/cdnca-upgrade-e2e/reject-forward
    systemctl daemon-reload
    systemctl restart cdnca-edge-agent.service
  ' || upgrade_e2e_fail 'auto-rollback-fault-remove'
}

upgrade_e2e_assert_scenarios() {
  local token operator_plan auto_plan success_plan revision counts replay_counts response detail
  local operator_key auto_key success_key
  local lkg_before lkg_during journal_before journal_during
  token="$(upgrade_e2e_require_env UPGRADE_E2E_BEARER_TOKEN)"
  [[ "${token}" =~ ^[A-Za-z0-9._~-]+$ ]] && [ "${#token}" -ge 16 ] && [ "${#token}" -le 8192 ] || \
    upgrade_e2e_unknown 'invalid-control-bearer-token'
  control_api_header_file="${WORK_DIR}/control-api.curl"
  printf 'header = "Authorization: Bearer %s"\n' "${token}" >"${control_api_header_file}" || \
    upgrade_e2e_fail 'control-auth-config'
  chmod 0600 "${control_api_header_file}" || upgrade_e2e_fail 'control-auth-config-mode'
  operator_key="e2e-operator-${TASK_ID: -24}"
  auto_key="e2e-auto-${TASK_ID: -24}"
  success_key="e2e-success-${TASK_ID: -24}"

  upgrade_e2e_create_rollout "${OPERATOR_ROLLBACK_SNAPSHOT}" "${operator_key}"
  operator_plan=${last_rollout_id}
  revision=${last_rollout_revision}
  response="${WORK_DIR}/logs/${operator_key}-start.json"
  upgrade_e2e_rollout_action "${operator_plan}" "${revision}" start e2e_operator_start \
    "${operator_key}-start" "${response}"
  for state in accepted claimed installing; do
    upgrade_e2e_wait_control_sql "SELECT count(*) FROM control_upgrade_status_receipts
      WHERE plan_id='${operator_plan}' AND state='${state}'" 1 || upgrade_e2e_fail "restart-boundary-${state}"
    upgrade_e2e_restart_edge_agent
  done
  upgrade_e2e_wait_control_sql "SELECT count(*) FROM control_upgrade_outbox
    WHERE plan_id='${operator_plan}' AND state='published'" 1 || upgrade_e2e_fail 'restart-boundary-broker-ack'
  upgrade_e2e_restart_edge_agent
  upgrade_e2e_wait_control_sql "SELECT count(*) FROM control_upgrade_node_commands
    WHERE plan_id='${operator_plan}' AND acknowledged_at IS NOT NULL" 1 || upgrade_e2e_fail 'restart-boundary-database-ack'
  upgrade_e2e_restart_edge_agent
  detail="${WORK_DIR}/logs/${operator_key}-upgraded.json"
  upgrade_e2e_wait_rollout "${operator_plan}" completed upgraded "${detail}" || \
    upgrade_e2e_fail 'operator-scenario-upgrade-terminal'
  upgrade_e2e_assert_status_sequence "${operator_plan}" upgrade accepted,claimed,installing,healthy || \
    upgrade_e2e_fail 'operator-upgrade-status-sequence'
  upgrade_e2e_assert_installing_journal "${operator_plan}" upgrade || \
    upgrade_e2e_fail 'operator-upgrade-helper-journal'
  upgrade_e2e_assert_command_wire "${operator_plan}" || upgrade_e2e_fail 'operator-upgrade-command-wire'
  upgrade_e2e_assert_status_puback_wire "${operator_plan}" || upgrade_e2e_fail 'operator-upgrade-status-puback-wire'
  counts=$(upgrade_e2e_rollout_snapshot "${operator_plan}") || upgrade_e2e_fail 'operator-replay-snapshot-before'
  upgrade_e2e_control_request POST "/v1/admin/control-upgrade-rollouts/${operator_plan}/start" \
    "${last_action_body}" "${operator_key}-start" 200 "${WORK_DIR}/logs/${operator_key}-start-replay.json"
  jq -e '.replayed == true' "${WORK_DIR}/logs/${operator_key}-start-replay.json" >/dev/null || \
    upgrade_e2e_fail 'operator-start-not-replayed'
  replay_counts=$(upgrade_e2e_rollout_snapshot "${operator_plan}") || upgrade_e2e_fail 'operator-replay-snapshot-after'
  [ "${counts}" = "${replay_counts}" ] || upgrade_e2e_fail 'operator-replay-created-facts'
  revision=$(jq -er '.data.revision' "${detail}") || upgrade_e2e_fail 'operator-rollback-revision'
  upgrade_e2e_rollout_action "${operator_plan}" "${revision}" rollback e2e_operator_rollback \
    "${operator_key}-rollback" "${WORK_DIR}/logs/${operator_key}-rollback.json"
  upgrade_e2e_wait_rollout "${operator_plan}" completed rolled_back \
    "${WORK_DIR}/logs/${operator_key}-rolled-back.json" || upgrade_e2e_fail 'operator-rollback-terminal'
  upgrade_e2e_assert_status_sequence "${operator_plan}" rollback accepted,claimed,installing,rolled_back || \
    upgrade_e2e_fail 'operator-rollback-status-sequence'
  upgrade_e2e_assert_installing_journal "${operator_plan}" rollback || \
    upgrade_e2e_fail 'operator-rollback-helper-journal'
  upgrade_e2e_assert_command_wire "${operator_plan}" || upgrade_e2e_fail 'operator-rollback-command-wire'
  upgrade_e2e_assert_status_puback_wire "${operator_plan}" || upgrade_e2e_fail 'operator-rollback-status-puback-wire'
  upgrade_e2e_assert_parent_chain "${operator_plan}" rolled_back || upgrade_e2e_fail 'operator-parent-receipt-chain'

  upgrade_e2e_install_auto_rollback_fault "$(upgrade_e2e_require_env UPGRADE_E2E_FORWARD_VERSION)"
  upgrade_e2e_create_rollout "${AUTOMATIC_ROLLBACK_SNAPSHOT}" "${auto_key}"
  auto_plan=${last_rollout_id}
  upgrade_e2e_rollout_action "${auto_plan}" "${last_rollout_revision}" start e2e_auto_start \
    "${auto_key}-start" "${WORK_DIR}/logs/${auto_key}-start.json"
  upgrade_e2e_wait_rollout "${auto_plan}" completed rolled_back \
    "${WORK_DIR}/logs/${auto_key}-rolled-back.json" || upgrade_e2e_fail 'automatic-rollback-terminal'
  upgrade_e2e_assert_status_sequence "${auto_plan}" upgrade \
    accepted,claimed,installing,rolling_back,rolled_back || upgrade_e2e_fail 'automatic-status-sequence'
  upgrade_e2e_assert_installing_journal "${auto_plan}" upgrade || \
    upgrade_e2e_fail 'automatic-helper-journal'
  upgrade_e2e_assert_command_wire "${auto_plan}" || upgrade_e2e_fail 'automatic-command-wire'
  upgrade_e2e_assert_status_puback_wire "${auto_plan}" || upgrade_e2e_fail 'automatic-status-puback-wire'
  upgrade_e2e_assert_parent_chain "${auto_plan}" rolled_back || upgrade_e2e_fail 'automatic-parent-receipt-chain'
  upgrade_e2e_remove_auto_rollback_fault

  upgrade_e2e_create_rollout "${SUCCESS_ROLLOUT_SNAPSHOT}" "${success_key}"
  success_plan=${last_rollout_id}
  lkg_before=$(upgrade_e2e_edge_lkg_snapshot) || upgrade_e2e_fail 'enospc-lkg-before'
  journal_before=$(upgrade_e2e_helper_journal_snapshot) || upgrade_e2e_fail 'enospc-journal-before'
  upgrade_e2e_inject_helper_enospc
  upgrade_e2e_rollout_action "${success_plan}" "${last_rollout_revision}" start e2e_success_start \
    "${success_key}-start" "${WORK_DIR}/logs/${success_key}-start.json"
  upgrade_e2e_wait_control_sql "SELECT count(*) FROM control_upgrade_status_receipts
    WHERE plan_id='${success_plan}' AND state='claimed'" 1 || upgrade_e2e_fail 'enospc-claimed-checkpoint'
  [ "$(upgrade_e2e_control_sql "SELECT count(*) FROM control_upgrade_status_receipts
    WHERE plan_id='${success_plan}' AND state='installing'")" = '0' ] || \
    upgrade_e2e_fail 'enospc-published-installing'
  lkg_during=$(upgrade_e2e_edge_lkg_snapshot) || upgrade_e2e_fail 'enospc-lkg-during'
  journal_during=$(upgrade_e2e_helper_journal_snapshot) || upgrade_e2e_fail 'enospc-journal-during'
  [ "${lkg_before}" = "${lkg_during}" ] || upgrade_e2e_fail 'enospc-lkg-mutated'
  [ "${journal_before}" = "${journal_during}" ] || upgrade_e2e_fail 'enospc-helper-journal-mutated'
  upgrade_e2e_remove_helper_enospc
  upgrade_e2e_sigkill_edge_agent_and_wait || upgrade_e2e_fail 'sigkill-agent-recovery'
  upgrade_e2e_wait_rollout "${success_plan}" completed upgraded \
    "${WORK_DIR}/logs/${success_key}-completed.json" || upgrade_e2e_fail 'success-rollout-terminal'
  upgrade_e2e_assert_status_sequence "${success_plan}" upgrade accepted,claimed,installing,healthy || \
    upgrade_e2e_fail 'success-status-sequence'
  upgrade_e2e_assert_installing_journal "${success_plan}" upgrade || upgrade_e2e_fail 'success-helper-journal'
  upgrade_e2e_assert_command_wire "${success_plan}" || upgrade_e2e_fail 'success-command-wire'
  upgrade_e2e_assert_status_puback_wire "${success_plan}" || upgrade_e2e_fail 'success-status-puback-wire'
  upgrade_e2e_assert_parent_chain "${success_plan}" applied || upgrade_e2e_fail 'success-parent-receipt-chain'
  [ "$(upgrade_e2e_control_sql "SELECT count(*) FROM control_upgrade_license_receipt_outbox_097 receipt
    JOIN control_upgrade_rollout_plans plan ON plan.id=receipt.plan_id
    WHERE plan.completion='' AND receipt.status IN ('applied','rolled_back')")" = '0' ] || \
    upgrade_e2e_fail 'false-terminal-parent-receipt'
  rm -f -- "${control_api_header_file}" || upgrade_e2e_fail 'control-auth-config-remove'
  control_api_header_file=''
}

upgrade_e2e_append_secret_bytes() {
  local destination=$1
  perl -MMIME::Base64=decode_base64,encode_base64 -e '
    use strict;
    use warnings;
    binmode STDIN;
    local $/;
    my $value = <STDIN>;
    $value = "" unless defined $value;
    my %emitted;
    my $emit_forms = sub {
      my ($bytes) = @_;
      return unless length($bytes) > 0;
      my $base64 = encode_base64($bytes, "");
      my $base64_raw = $base64;
      $base64_raw =~ s/=+\z//;
      my $base64url = $base64;
      $base64url =~ tr{+/}{-_};
      my $base64url_raw = $base64url;
      $base64url_raw =~ s/=+\z//;
      for my $form ($bytes, $base64, $base64_raw, $base64url, $base64url_raw,
        unpack("H*", $bytes), uc(unpack("H*", $bytes))) {
        next unless length($form) > 0;
        my $hex = unpack("H*", $form);
        next if $emitted{$hex}++;
        print $hex, "\n";
      }
    };
    $emit_forms->($value);

    my @decoded;
    if ($value =~ /\A(?:[0-9a-f]+|[0-9A-F]+)\z/ && length($value) % 2 == 0) {
      push @decoded, pack("H*", $value);
    }
    if ($value =~ /\A[A-Za-z0-9+\/_-]+={0,2}\z/) {
      my $normalized = $value;
      $normalized =~ tr{-_}{+/};
      $normalized =~ s/=+\z//;
      if (length($normalized) % 4 != 1) {
        my $padded = $normalized . ("=" x ((4 - length($normalized) % 4) % 4));
        my $bytes = decode_base64($padded);
        my $standard = encode_base64($bytes, "");
        my $standard_raw = $standard;
        $standard_raw =~ s/=+\z//;
        my $url = $standard;
        $url =~ tr{+/}{-_};
        my $url_raw = $url;
        $url_raw =~ s/=+\z//;
        push @decoded, $bytes if $value eq $standard || $value eq $standard_raw ||
          $value eq $url || $value eq $url_raw;
      }
    }
    my %decoded_seen;
    for my $bytes (@decoded) {
      next unless length($bytes) > 0;
      my $key = unpack("H*", $bytes);
      next if $decoded_seen{$key}++;
      $emit_forms->($bytes);
    }
  ' >>"${destination}"
}

upgrade_e2e_append_secret_value() {
  local destination=$1 value=$2 members encoded_member
  printf '%s' "${value}" | upgrade_e2e_append_secret_bytes "${destination}" || return 1
  if members=$(printf '%s' "${value}" | jq -r '.. | strings | @base64' 2>/dev/null); then
    while IFS= read -r encoded_member; do
      [ -n "${encoded_member}" ] || continue
      printf '%s' "${encoded_member}" | perl -MMIME::Base64=decode_base64 -e '
        use strict;
        use warnings;
        local $/;
        my $encoded = <STDIN>;
        print decode_base64($encoded // "");
      ' | upgrade_e2e_append_secret_bytes "${destination}" || return 1
    done <<<"${members}"
  fi
}

upgrade_e2e_append_secret_file() {
  local destination=$1 source=$2 line
  [ -f "${source}" ] && [ ! -L "${source}" ] && [ -r "${source}" ] || return 1
  upgrade_e2e_append_secret_bytes "${destination}" <"${source}" || return 1
  while IFS= read -r line || [ -n "${line}" ]; do
    upgrade_e2e_append_secret_value "${destination}" "${line}" || return 1
  done <"${source}"
}

upgrade_e2e_file_has_secret() {
  local patterns=$1 file=$2
  perl -e '
    use strict;
    use warnings;
    my ($patterns_path, $file_path) = @ARGV;
    open my $patterns, "<", $patterns_path or exit 2;
    my @needles;
    my $maximum = 0;
    while (my $hex = <$patterns>) {
      chomp $hex;
      exit 2 unless $hex =~ /\A[0-9a-f]+\z/ && length($hex) >= 2 && length($hex) % 2 == 0;
      my $needle = pack("H*", $hex);
      push @needles, $needle;
      $maximum = length($needle) if length($needle) > $maximum;
    }
    close $patterns or exit 2;
    open my $input, "<", $file_path or exit 2;
    binmode $input;
    my $tail = "";
    while (1) {
      my $chunk = "";
      my $read = read($input, $chunk, 1024 * 1024);
      exit 2 unless defined $read;
      last if $read == 0;
      my $data = $tail . $chunk;
      for my $needle (@needles) {
        exit 0 if index($data, $needle) >= 0;
      }
      $tail = $maximum > 1 && length($data) >= $maximum - 1
        ? substr($data, -($maximum - 1))
        : $data;
    }
    close $input or exit 2;
    exit 1;
  ' "${patterns}" "${file}"
}

upgrade_e2e_quiesce_writers() {
  local listed candidates
  if [ "${docker_resources_possible}" -eq 1 ]; then
    upgrade_e2e_timeout 20 docker info >/dev/null 2>&1 || return 1
    listed=$(upgrade_e2e_list_labeled_container_ids) || return 1
    candidates=$(
      printf '%s\n' "${candidate_container_ids[@]-}" "${owned_container_ids[@]-}"
      upgrade_e2e_collect_post_minus_preexisting container "${listed}"
    ) || return 1
    candidates=$(printf '%s\n' "${candidates}" | awk 'NF' | LC_ALL=C sort -u) || return 1
    upgrade_e2e_capture_candidate_ports "${candidates}" || return 1
    upgrade_e2e_stop_container_role edge "${candidates}" || return 1
  else
    candidates=''
  fi
  upgrade_e2e_stop_pid "${gateway_pid}" || return 1
  gateway_pid=''
  [ "${docker_resources_possible}" -eq 0 ] || upgrade_e2e_stop_container_role gateway "${candidates}" || return 1
  upgrade_e2e_stop_pid "${control_pid}" || return 1
  control_pid=''
  [ "${docker_resources_possible}" -eq 0 ] || upgrade_e2e_stop_container_role control "${candidates}" || return 1
  [ "${docker_resources_possible}" -eq 0 ] || upgrade_e2e_stop_container_role tls-proxy "${candidates}" || return 1
  upgrade_e2e_stop_pid "${license_pid}" || return 1
  license_pid=''
  if [ "${docker_resources_possible}" -eq 1 ]; then
    upgrade_e2e_stop_container_role license "${candidates}" || return 1
    upgrade_e2e_stop_container_role nats "${candidates}" || return 1
    upgrade_e2e_stop_container_role redis "${candidates}" || return 1
    upgrade_e2e_stop_container_role postgres "${candidates}" || return 1
  fi
}

upgrade_e2e_secret_scan() {
  local raw_pattern_file pattern_file report_file file_list name private_key file path pin_name hits scan_status
  local -a launcher_secret_value_names launcher_secret_file_input_names private_keys
  local -a secret_source_files scanner_excluded_files
  raw_pattern_file="${WORK_DIR}/certs/secret-patterns.raw"
  pattern_file="${WORK_DIR}/certs/secret-patterns"
  report_file="${WORK_DIR}/certs/secret-scan-report"
  file_list="${WORK_DIR}/certs/secret-scan-files"
  : >"${raw_pattern_file}"
  launcher_secret_value_names=(
    LICENSE_BILLING_PROVIDER_KEYS_JSON LICENSE_TOTP_KEYS_JSON LICENSE_CREDENTIAL_KEYS_JSON
    LICENSE_IDENTITY_TOKEN_KEYS_JSON LICENSE_SMTP_PASSWORD LICENSE_SIGNING_PRIVATE_KEY_BASE64
    LICENSE_SIGNER_REVOCATION_ATTEMPT_HMAC_KEY_BASE64 LICENSE_PKCS11_PIN
    ACCESS_TOKEN_SECRET ACCOUNT_RECOVERY_HMAC_KEY_BASE64 ACCOUNT_RECOVERY_KEK_KEYS_JSON
    API_KEY_PEPPER_BASE64 DNS_CREDENTIAL_KEY_BASE64 ACME_WRAPPING_KEY_BASE64
    ACME_DNS_HANDLE_ACTIVE_KEY_BASE64 ACME_DNS_HANDLE_VERIFY_ONLY_KEYS_JSON
    ANALYTICS_INGEST_ISOLATION_WRAPPING_KEY_BASE64 ANALYTICS_INGEST_NATS_PASSWORD
    ANALYTICS_INGEST_CLICKHOUSE_PASSWORD CLICKHOUSE_PASSWORD CACHE_CONTROL_RUNTIME_CURSOR_KEY_BASE64
    CUSTOM_RBAC_CURSOR_KEY_BASE64 JOB_QUERY_CURSOR_KEYS_JSON PLUGIN_WEBHOOK_SECRET_KEY_BASE64
    EDGE_PUBLISH_CURSOR_KEYS_JSON MFA_ENCRYPTION_KEYS_JSON ORIGIN_AUTH_ENCRYPTION_KEYS_JSON
    CHALLENGE_POLICY_CURSOR_KEY_BASE64 IDENTITY_VERIFICATION_CURSOR_KEY_BASE64
    TRAFFIC_PACKAGE_CURSOR_KEY_BASE64 PACKAGE_COMMERCE_CURSOR_KEY_BASE64
    ANALYTICS_LOGS_CURSOR_KEYS_JSON ANNOUNCEMENT_CURSOR_KEYS_JSON NOTIFICATION_SMTP_PASSWORD
    ERROR_PAGE_OBJECT_STORE_ACCESS_KEY_ID ERROR_PAGE_OBJECT_STORE_SECRET_ACCESS_KEY
    ERROR_PAGE_OBJECT_STORE_SESSION_TOKEN BOOTSTRAP_PASSWORD CONTROL_INSTALLATION_PRIVATE_KEY_BASE64
    CDNCA_NATS_URL CDNCA_TELEMETRY_NATS_URL CDNCA_TELEMETRY_NATS_USER
    CDNCA_TELEMETRY_NATS_PASSWORD CDNCA_PLUGIN_WEBHOOK_RUNTIME_NATS_URL EDGE_DEPLOYMENT_NATS_URL
    PLUGIN_WEBHOOK_NATS_URL PACKAGE_COMMERCE_WORKER_NATS_URL ANALYTICS_INGEST_NATS_URL
    CACHE_CONTROL_RUNTIME_NATS_URL NODE_PRESENCE_NATS_URL
    UPGRADE_E2E_ACTIVATION_CREDENTIAL UPGRADE_E2E_UPGRADE_GRANT UPGRADE_E2E_BEARER_TOKEN
    UPGRADE_E2E_DECRYPTED_SECRET UPGRADE_E2E_LICENSE_PROOF_HMAC_KEY
    UPGRADE_E2E_OPERATOR_SESSION UPGRADE_E2E_GENERATED_VALUES_JSON
  )
  launcher_secret_file_input_names=(
    CONTROL_ACTIVATION_CREDENTIAL_FILE CONTROL_INSTALLATION_PRIVATE_KEY_FILE
    CONTROL_INTERNAL_SERVER_PRIVATE_KEY_FILE NODE_CA_PRIVATE_KEY_FILE
    CONTROL_UPGRADE_CONTROL_SIGNING_PRIVATE_KEY_FILE CONTROL_UPGRADE_EDGE_SIGNING_PRIVATE_KEY_FILE
    EDGE_PUBLISH_SIGNING_PRIVATE_KEY_FILE PLUGIN_WEBHOOK_SECRET_KEY_FILE
    CDNCA_GATEWAY_TLS_KEY_FILE CDNCA_CONTROL_CLIENT_KEY_FILE
    EDGE_DEPLOYMENT_NATS_CREDS_FILE PLUGIN_WEBHOOK_NATS_CREDS_FILE
    PACKAGE_COMMERCE_WORKER_NATS_CREDS_FILE CDNCA_PLUGIN_WEBHOOK_RUNTIME_NATS_CREDS_FILE
    ACME_HTTP01_SIGNING_PRIVATE_KEY_FILE DNS_RECONCILE_WORKLOAD_MTLS_SERVER_PRIVATE_KEY_FILE
    TRAFFIC_PACKAGE_WORKLOAD_MTLS_SERVER_PRIVATE_KEY_FILE
    UPGRADE_E2E_GENERATED_SECRET_FILE
  )
  for name in "${launcher_secret_value_names[@]}"; do
    if [ -n "${!name-}" ]; then
      upgrade_e2e_append_secret_value "${raw_pattern_file}" "${!name}" || upgrade_e2e_fail 'secret-launcher-value-read'
    fi
  done
  pin_name=${LICENSE_PKCS11_PIN_ENV-}
  if [ -n "${pin_name}" ]; then
    [[ "${pin_name}" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || upgrade_e2e_fail 'secret-pkcs11-pin-env-name'
    if [ -n "${!pin_name-}" ]; then
      upgrade_e2e_append_secret_value "${raw_pattern_file}" "${!pin_name}" || upgrade_e2e_fail 'secret-pkcs11-pin-read'
    fi
  fi
  for name in "${launcher_secret_file_input_names[@]}"; do
    path=${!name-}
    [ -n "${path}" ] || continue
    upgrade_e2e_append_secret_file "${raw_pattern_file}" "${path}" || upgrade_e2e_fail 'secret-launcher-file-read'
  done

  private_keys=(
    "${WORK_DIR}/certs/ca.key"
    "${WORK_DIR}/certs/license-server.key"
    "${WORK_DIR}/certs/control-server.key"
    "${WORK_DIR}/certs/gateway-server.key"
    "${WORK_DIR}/certs/gateway-control-client.key"
    "${EDGE_IDENTITY_DIR}/client-key.pem"
    "${EDGE_IDENTITY_DIR}/artifact-x25519-key.bin"
  )
  secret_source_files=(
    "${CONTROL_INSTALLATION_KEY_SNAPSHOT}"
    "${CONTROL_ACTIVATION_CREDENTIAL_SNAPSHOT}"
    "${CONTROL_SIGNING_KEY_SNAPSHOT}"
    "${EDGE_SIGNING_KEY_SNAPSHOT}"
    "${private_keys[@]}"
  )
  for private_key in "${private_keys[@]}"; do
    upgrade_e2e_append_secret_file "${raw_pattern_file}" "${private_key}" || upgrade_e2e_fail 'secret-key-source-read'
  done
  LC_ALL=C sort -u "${raw_pattern_file}" >"${pattern_file}" || upgrade_e2e_fail 'secret-pattern-sort'
  awk '!/^[0-9a-f]+$/ || length($0) < 2 || length($0) % 2 {exit 1}' "${pattern_file}" || \
    upgrade_e2e_fail 'secret-pattern-format'

  upgrade_e2e_quiesce_writers || upgrade_e2e_fail 'secret-scan-quiesce'
  : >"${report_file}"
  : >"${file_list}"
  find "${WORK_DIR}" -type f -print0 >"${file_list}" || upgrade_e2e_fail 'secret-scan-enumerate'
  scanner_excluded_files=(
    "${raw_pattern_file}"
    "${pattern_file}"
    "${report_file}"
    "${file_list}"
    "${WORK_DIR}/bin/license-service"
    "${WORK_DIR}/bin/control-api"
    "${WORK_DIR}/bin/agent-gateway"
    "${WORK_DIR}/bin/cdnca-edge-agent"
    "${WORK_DIR}/bin/cdnca-edge-agent-helper"
  )
  hits=0
  if [ -s "${pattern_file}" ]; then
    while IFS= read -r -d '' file; do
      upgrade_e2e_exact_path_in "${file}" "${secret_source_files[@]}" && continue
      upgrade_e2e_exact_path_in "${file}" "${scanner_excluded_files[@]}" && continue
      [ -r "${file}" ] || upgrade_e2e_fail 'secret-scan-read'
      if upgrade_e2e_file_has_secret "${pattern_file}" "${file}"; then
        scan_status=0
      else
        scan_status=$?
      fi
      case "${scan_status}" in
        0)
          printf '%s\n' "${file#"${WORK_DIR}/"}" >>"${report_file}"
          hits=$((hits + 1))
          ;;
        1) ;;
        *) upgrade_e2e_fail 'secret-scan-read' ;;
      esac
    done <"${file_list}"
  fi
  [ "${hits}" -eq 0 ] || upgrade_e2e_fail 'runtime-secret-leak'
  secret_scan_completed=1
}

upgrade_e2e_static_control_fixture_contract() (
  local fixture valid missing duplicate variable
  fixture=$(mktemp -d "${TMPDIR:-/tmp}/cdnca-upgrade-e2e-static-control-fixture.XXXXXX") || return 1
  trap 'rm -rf -- "${fixture}"' EXIT HUP INT TERM
  fixture=$(cd -- "${fixture}" 2>/dev/null && pwd -P) || return 1
  valid="${fixture}/valid.sql"
  for variable in "${CONTROL_FIXTURE_IDENTITY_VARIABLES[@]}"; do
    printf "SELECT :'%s';\n" "${variable}" >>"${valid}" || return 1
  done
  upgrade_e2e_validate_control_authority_fixture "${valid}" || return 1
  for variable in "${CONTROL_FIXTURE_IDENTITY_VARIABLES[@]}"; do
    missing="${fixture}/missing-${variable}.sql"
    awk -v needle=":'${variable}'" 'index($0, needle) == 0 {print}' "${valid}" >"${missing}" || return 1
    ! upgrade_e2e_validate_control_authority_fixture "${missing}" || return 1
    duplicate="${fixture}/duplicate-${variable}.sql"
    { awk '1' "${valid}"; printf "SELECT :'%s';\n" "${variable}"; } >"${duplicate}" || return 1
    ! upgrade_e2e_validate_control_authority_fixture "${duplicate}" || return 1
  done
)

upgrade_e2e_static_edge_manifest_contract() (
  local fixture live_expected live_expected_sha live_three live_three_sha fake_root fake_edge complete
  local missing extra duplicate wrong unsafe unsafe_relative root_link nested_link fifo index name digest
  local source relative
  fixture=$(mktemp -d "${TMPDIR:-/tmp}/cdnca-upgrade-e2e-static-c.XXXXXX") || return 1
  trap 'rm -rf -- "${fixture}"' EXIT HUP INT TERM
  fixture=$(cd -- "${fixture}" 2>/dev/null && pwd -P) || return 1

  live_expected="${fixture}/live-expected.sha256"
  find "${REPO_ROOT}/agents/edge-agent" -type f -print0 |
    while IFS= read -r -d '' source; do
      relative=${source#"${REPO_ROOT}/"}
      digest=$(upgrade_e2e_sha256_regular_file "${source}") || exit 1
      printf '%s  %s\n' "${digest}" "${relative}"
    done | LC_ALL=C sort | awk 'NR <= 35' >"${live_expected}" || return 1
  [ "$(upgrade_e2e_count_lines <"${live_expected}")" -eq 35 ] || return 1
  live_expected_sha=$(upgrade_e2e_sha256_regular_file "${live_expected}") || return 1
  live_three="${fixture}/live-three.sha256"
  awk 'NR <= 3' "${live_expected}" >"${live_three}" || return 1
  [ "$(upgrade_e2e_count_lines <"${live_three}")" -eq 3 ] || return 1
  live_three_sha=$(upgrade_e2e_sha256_regular_file "${live_three}") || return 1
  (
    export UPGRADE_E2E_STATIC_C_MANIFEST=${live_expected}
    export UPGRADE_E2E_STATIC_C_MANIFEST_SHA256=${live_expected_sha}
    upgrade_e2e_validate_live_manifest c UPGRADE_E2E_STATIC_C_MANIFEST \
      UPGRADE_E2E_STATIC_C_MANIFEST_SHA256
  ) >/dev/null 2>&1 || return 1
  declare -F upgrade_e2e_validate_live_edge_manifest >/dev/null || return 1
  if (
    export UPGRADE_E2E_STATIC_C_MANIFEST=${live_expected}
    export UPGRADE_E2E_STATIC_C_MANIFEST_SHA256=${live_expected_sha}
    upgrade_e2e_validate_live_edge_manifest UPGRADE_E2E_STATIC_C_MANIFEST \
      UPGRADE_E2E_STATIC_C_MANIFEST_SHA256
  ) >/dev/null 2>&1; then
    return 1
  fi
  (
    export UPGRADE_E2E_STATIC_C_MANIFEST=${live_three}
    export UPGRADE_E2E_STATIC_C_MANIFEST_SHA256=${live_three_sha}
    upgrade_e2e_validate_live_manifest c UPGRADE_E2E_STATIC_C_MANIFEST \
      UPGRADE_E2E_STATIC_C_MANIFEST_SHA256
  ) >/dev/null 2>&1 || return 1
  if (
    export UPGRADE_E2E_STATIC_C_MANIFEST=${live_three}
    export UPGRADE_E2E_STATIC_C_MANIFEST_SHA256=${live_three_sha}
    upgrade_e2e_validate_live_edge_manifest UPGRADE_E2E_STATIC_C_MANIFEST \
      UPGRADE_E2E_STATIC_C_MANIFEST_SHA256
  ) >/dev/null 2>&1; then
    return 1
  fi

  fake_root="${fixture}/repo"
  fake_edge="${fake_root}/agents/edge-agent"
  mkdir -p -- "${fake_edge}" || return 1
  for ((index = 1; index <= 35; index++)); do
    printf -v name 'file-%02d.txt' "${index}"
    printf 'edge fixture %02d\n' "${index}" >"${fake_edge}/${name}" || return 1
  done
  complete="${fixture}/complete.sha256"
  upgrade_e2e_edge_inventory "${fake_root}" >"${complete}" || return 1
  [ "$(upgrade_e2e_count_lines <"${complete}")" -eq 35 ] || return 1
  LC_ALL=C sort -c -u "${complete}" >/dev/null 2>&1 || return 1
  awk '
    !/^[0-9a-f]{64}  agents\/edge-agent\/[A-Za-z0-9][A-Za-z0-9._\/-]*$/ {exit 1}
    END {if (NR != 35) exit 1}
  ' "${complete}" || return 1
  upgrade_e2e_edge_manifest_matches "${fake_root}" "${complete}" || return 1

  missing="${fixture}/missing.sha256"
  awk 'NR > 1' "${complete}" >"${missing}" || return 1
  ! upgrade_e2e_edge_manifest_matches "${fake_root}" "${missing}" || return 1

  printf 'outside edge\n' >"${fake_root}/extra.txt" || return 1
  digest=$(upgrade_e2e_sha256_regular_file "${fake_root}/extra.txt") || return 1
  extra="${fixture}/extra.sha256"
  { awk '1' "${complete}"; printf '%s  extra.txt\n' "${digest}"; } |
    LC_ALL=C sort >"${extra}" || return 1
  ! upgrade_e2e_edge_manifest_matches "${fake_root}" "${extra}" || return 1

  duplicate="${fixture}/duplicate.sha256"
  { awk '1' "${complete}"; awk 'NR == 1' "${complete}"; } |
    LC_ALL=C sort >"${duplicate}" || return 1
  ! upgrade_e2e_edge_manifest_matches "${fake_root}" "${duplicate}" || return 1

  wrong="${fixture}/wrong-digest.sha256"
  awk 'NR == 1 {sub(/^[0-9a-f]{64}/, "0000000000000000000000000000000000000000000000000000000000000000")} {print}' \
    "${complete}" >"${wrong}" || return 1
  ! upgrade_e2e_edge_manifest_matches "${fake_root}" "${wrong}" || return 1

  unsafe="${fixture}/unsafe-path.sha256"
  digest=$(upgrade_e2e_sha256_regular_file "${fake_edge}/file-01.txt") || return 1
  { awk 'NR > 1' "${complete}"; printf '%s  agents/edge-agent/../edge-agent/file-01.txt\n' "${digest}"; } |
    LC_ALL=C sort >"${unsafe}" || return 1
  ! upgrade_e2e_edge_manifest_matches "${fake_root}" "${unsafe}" || return 1
  for unsafe_relative in \
    '/agents/edge-agent/file-01.txt' \
    './agents/edge-agent/file-01.txt' \
    'agents//edge-agent/file-01.txt' \
    'agents/edge-agent/./file-01.txt'; do
    { awk 'NR > 1' "${complete}"; printf '%s  %s\n' "${digest}" "${unsafe_relative}"; } |
      LC_ALL=C sort >"${unsafe}" || return 1
    ! upgrade_e2e_edge_manifest_matches "${fake_root}" "${unsafe}" || return 1
  done

  root_link="${fixture}/repo-link"
  perl -e 'symlink $ARGV[0], $ARGV[1] or exit 1' "${fake_root}" "${root_link}" || return 1
  ! upgrade_e2e_edge_inventory "${root_link}" >/dev/null || return 1

  perl -e 'rename $ARGV[0], $ARGV[1] or exit 1; symlink $ARGV[2], $ARGV[0] or exit 1' \
    "${fake_edge}" "${fake_edge}-real" 'edge-agent-real' || return 1
  ! upgrade_e2e_edge_inventory "${fake_root}" >/dev/null || return 1
  rm -- "${fake_edge}" || return 1
  perl -e 'rename $ARGV[0], $ARGV[1] or exit 1' "${fake_edge}-real" "${fake_edge}" || return 1

  nested_link="${fake_edge}/nested-link"
  perl -e 'symlink $ARGV[0], $ARGV[1] or exit 1' 'file-01.txt' "${nested_link}" || return 1
  ! upgrade_e2e_edge_inventory "${fake_root}" >/dev/null || return 1
  rm -- "${nested_link}" || return 1

  fifo="${fake_edge}/non-regular.fifo"
  perl -MPOSIX -e 'POSIX::mkfifo($ARGV[0], 0600) == 0 or exit 1' "${fifo}" || return 1
  ! upgrade_e2e_edge_inventory "${fake_root}" >/dev/null || return 1
)

upgrade_e2e_static_contract() {
  local script readme implementation initialize cleanup_body scan_body scenarios_body main
  local preflight_body supply_preflight_body supply_snapshot_body native_manifest_body systemd_runtime_body
  local control_sql_body license_sql_body parent_chain_body edge_snapshot_body rollout_snapshot_body nats_verify_body
  local status_puback_body status_ack_body
  local edge_preflight_body edge_runtime_body edge_identity_body identity_validate_body pki_body
  local control_fixture_body apply_fixtures_body runtime_start_body identity_binding_body public_facts_body
  local nats_metadata_body nats_metadata_calls pki_identity_line pki_cert_line pki_main_line start_main_line
  local control_ready_line identity_binding_line gateway_start_line receipt_trust_line agent_enable_line variable contract prepare_inputs
  local fixture_observation_line fixture_retire_line fixture_nologin_line fixture_apply_line fixture_start_line
  local apply_fixtures_compact sequence_grant_count sequence_revoke_count table_revoke_count
  local start_body pending_line spawn_line
  local short_secret_patterns decoded_secret_patterns static_secret_source
  local nats_port_line redis_start_line reservation_line snapshot_line work_dir_line input_snapshot_line capture_line
  local edge_line gateway_line control_line license_line proxy_line nats_line redis_line postgres_line
  local quiesce_line enumerate_line evidence_line work_delete_line post_delete_probe_line reservation_release_line
  local contract_line preflight_line initialize_line runtime_line scenarios_line final_nats_verify_line
  local live_verify_line secret_scan_line build_body
  local status_ack_restart_equal_line status_ack_ledger_read_line
  script="${SCRIPT_DIR}/run.sh"
  readme="${SCRIPT_DIR}/README.md"
  contract="${SCRIPT_DIR}/contract.json"
  prepare_inputs="${SCRIPT_DIR}/prepare-inputs.sh"
  upgrade_e2e_require_file "${script}" run-script
  upgrade_e2e_require_file "${readme}" readme
  upgrade_e2e_require_file "${contract}" process-contract
  upgrade_e2e_require_file "${prepare_inputs}" prepare-inputs
  upgrade_e2e_static_control_fixture_contract || upgrade_e2e_fail 'static-control-fixture-template'
  upgrade_e2e_static_edge_manifest_contract || upgrade_e2e_fail 'static-c-manifest-complete-set'
  implementation=$(sed '/^upgrade_e2e_static_contract()/,$d' "${script}")
  initialize=$(sed -n '/^upgrade_e2e_initialize_task()/,/^}/p' <<<"${implementation}")
  cleanup_body=$(sed -n '/^upgrade_e2e_cleanup()/,/^}/p' <<<"${implementation}")
  scan_body=$(sed -n '/^upgrade_e2e_secret_scan()/,/^}/p' <<<"${implementation}")
  scenarios_body=$(sed -n '/^upgrade_e2e_assert_scenarios()/,/^}/p' <<<"${implementation}")
  control_sql_body=$(sed -n '/^upgrade_e2e_control_sql()/,/^}/p' <<<"${implementation}")
  license_sql_body=$(sed -n '/^upgrade_e2e_license_sql()/,/^}/p' <<<"${implementation}")
  parent_chain_body=$(sed -n '/^upgrade_e2e_assert_parent_chain()/,/^}/p' <<<"${implementation}")
  edge_snapshot_body=$(sed -n '/^upgrade_e2e_edge_fact_snapshot()/,/^}/p' <<<"${implementation}")
  rollout_snapshot_body=$(sed -n '/^upgrade_e2e_rollout_snapshot()/,/^}/p' <<<"${implementation}")
  status_puback_body=$(sed -n '/^upgrade_e2e_assert_status_puback_wire()/,/^}/p' <<<"${implementation}")
  status_ack_body=$(sed -n '/^upgrade_e2e_assert_edge_status_acks()/,/^}/p' <<<"${implementation}")
  nats_verify_body=$(sed -n '/^upgrade_e2e_verify_nats_server_state()/,/^}/p' <<<"${implementation}")
  edge_preflight_body=$(sed -n '/^upgrade_e2e_validate_edge_config_template()/,/^}/p' <<<"${implementation}")
  edge_runtime_body=$(sed -n '/^upgrade_e2e_write_edge_runtime_config()/,/^}/p' <<<"${implementation}")
  edge_identity_body=$(sed -n '/^upgrade_e2e_create_edge_identity()/,/^}/p' <<<"${implementation}")
  identity_validate_body=$(sed -n '/^upgrade_e2e_validate_edge_identity()/,/^}/p' <<<"${implementation}")
  pki_body=$(sed -n '/^upgrade_e2e_generate_pki()/,/^}/p' <<<"${implementation}")
  control_fixture_body=$(sed -n '/^upgrade_e2e_validate_control_authority_fixture()/,/^}/p' <<<"${implementation}")
  apply_fixtures_body=$(sed -n '/^upgrade_e2e_apply_migrations_and_fixtures()/,/^}/p' <<<"${implementation}")
  runtime_start_body=$(sed -n '/^upgrade_e2e_start_four_processes()/,/^}/p' <<<"${implementation}")
  build_body=$(sed -n '/^upgrade_e2e_build_binaries()/,/^}/p' <<<"${implementation}")
  preflight_body=$(sed -n '/^upgrade_e2e_preflight_external_inputs()/,/^}/p' <<<"${implementation}")
  supply_preflight_body=$(sed -n '/^upgrade_e2e_preflight_systemd_supply_chain()/,/^}/p' <<<"${implementation}")
  supply_snapshot_body=$(sed -n '/^upgrade_e2e_snapshot_systemd_supply_chain()/,/^}/p' <<<"${implementation}")
  native_manifest_body=$(sed -n '/^upgrade_e2e_validate_systemd_native_manifest()/,/^}/p' <<<"${implementation}")
  systemd_runtime_body=$(sed -n '/^upgrade_e2e_assert_systemd_runtime_supply_chain()/,/^}/p' <<<"${implementation}")
  identity_binding_body=$(sed -n '/^upgrade_e2e_assert_control_identity_fixture_binding()/,/^}/p' <<<"${implementation}")
  public_facts_body=$(sed -n '/^upgrade_e2e_edge_identity_public_facts()/,/^}/p' <<<"${implementation}")
  nats_metadata_body=$(sed -n '/^upgrade_e2e_strip_nats_server_metadata()/,/^}/p' <<<"${implementation}")
  start_body=$(sed -n '/^upgrade_e2e_start_owned_process()/,/^}/p' <<<"${implementation}")
  main=$(sed -n '/^# The final contract gate precedes every task mutation/,$p' "${script}")
  apply_fixtures_compact=$(tr '\n' ' ' <<<"${apply_fixtures_body}" | tr -s '[:space:]' ' ')
  [ "${LICENSE_MIGRATION_HEAD}" = '046' ] || upgrade_e2e_fail 'static-license-migration-head'
  [ "${CONTROL_MIGRATION_HEAD}" = '186' ] || upgrade_e2e_fail 'static-control-migration-head'
  [ "${#CONTROL_MIGRATION_MANIFEST_PATHS[@]}" -eq 21 ] || upgrade_e2e_fail 'static-control-manifest-member-count'
  upgrade_e2e_require_exact_control_migration_manifest <(
    printf '0  %s\n' "${CONTROL_MIGRATION_MANIFEST_PATHS[@]}"
  )
  if (upgrade_e2e_require_exact_control_migration_manifest <(
    printf '0  %s\n' "${CONTROL_MIGRATION_MANIFEST_PATHS[@]}" 'services/control-api/migrations/103_unfrozen.up.sql'
  ) >/dev/null 2>&1); then
    upgrade_e2e_fail 'static-control-manifest-extra-member'
  fi
  ! grep -F 'not-frozen' <<<"${implementation}" >/dev/null || upgrade_e2e_fail 'static-no-runtime-freeze-stop'
  grep -F 'upgrade_e2e_preflight_external_inputs()' <<<"${implementation}" >/dev/null || upgrade_e2e_fail 'static-external-preflight'
  jq -e '
    .systemd_image_evidence_schema == "cdnca.edge.systemd-image-evidence/v1" and
    .systemd_image_platforms == ["linux/amd64","linux/arm64"] and
    .systemd_attestation_predicate_types == {
      provenance:"https://slsa.dev/provenance/v0.2",
      spdx:"https://spdx.dev/Document"
    }
  ' "${contract}" >/dev/null || upgrade_e2e_fail 'static-systemd-supply-chain-contract'
  grep -F 'upgrade_e2e_preflight_systemd_supply_chain' <<<"${preflight_body}" >/dev/null || \
    upgrade_e2e_fail 'static-systemd-supply-chain-preflight'
  grep -F 'docker buildx imagetools inspect "${SYSTEMD_IMAGE}" --raw' <<<"${supply_preflight_body}" >/dev/null || \
    upgrade_e2e_fail 'static-systemd-exact-native-subjects'
  grep -F 'docker buildx imagetools inspect "${SYSTEMD_AMD64_SUBJECT}" --raw' <<<"${supply_preflight_body}" >/dev/null || \
    upgrade_e2e_fail 'static-systemd-amd64-manifest-read'
  grep -F 'docker buildx imagetools inspect "${SYSTEMD_ARM64_SUBJECT}" --raw' <<<"${supply_preflight_body}" >/dev/null || \
    upgrade_e2e_fail 'static-systemd-arm64-manifest-read'
  grep -F 'upgrade_e2e_validate_external_pair systemd-amd64-manifest' <<<"${supply_preflight_body}" >/dev/null || \
    upgrade_e2e_fail 'static-systemd-amd64-manifest-preflight'
  grep -F 'upgrade_e2e_validate_external_pair systemd-arm64-manifest' <<<"${supply_preflight_body}" >/dev/null || \
    upgrade_e2e_fail 'static-systemd-arm64-manifest-preflight'
  grep -F '.schemaVersion == 2' <<<"${native_manifest_body}" >/dev/null || \
    upgrade_e2e_fail 'static-systemd-native-manifest-schema'
  grep -F '.mediaType' <<<"${native_manifest_body}" >/dev/null || \
    upgrade_e2e_fail 'static-systemd-native-manifest-media-type'
  grep -F '.config' <<<"${native_manifest_body}" >/dev/null || \
    upgrade_e2e_fail 'static-systemd-native-manifest-config'
  grep -F '.layers' <<<"${native_manifest_body}" >/dev/null || \
    upgrade_e2e_fail 'static-systemd-native-manifest-layers'
  grep -F 'systemd-amd64-manifest-subject-digest' <<<"${supply_preflight_body}" >/dev/null || \
    upgrade_e2e_fail 'static-systemd-amd64-manifest-subject-digest'
  grep -F 'systemd-arm64-manifest-subject-digest' <<<"${supply_preflight_body}" >/dev/null || \
    upgrade_e2e_fail 'static-systemd-arm64-manifest-subject-digest'
  grep -F 'cosign verify --certificate-oidc-issuer "${SYSTEMD_COSIGN_ISSUER}" --certificate-identity "${SYSTEMD_COSIGN_IDENTITY}"' \
    <<<"${supply_preflight_body}" >/dev/null || upgrade_e2e_fail 'static-systemd-cosign-signature'
  grep -F 'cosign verify-attestation --type slsaprovenance' <<<"${supply_preflight_body}" >/dev/null || \
    upgrade_e2e_fail 'static-systemd-cosign-provenance'
  grep -F 'cosign verify-attestation --type spdxjson' <<<"${supply_preflight_body}" >/dev/null || \
    upgrade_e2e_fail 'static-systemd-cosign-spdx'
  grep -F 'upgrade_e2e_validate_external_pair systemd-amd64-inventory' <<<"${supply_preflight_body}" >/dev/null || \
    upgrade_e2e_fail 'static-systemd-amd64-inventory-preflight'
  grep -F 'upgrade_e2e_validate_external_pair systemd-arm64-inventory' <<<"${supply_preflight_body}" >/dev/null || \
    upgrade_e2e_fail 'static-systemd-arm64-inventory-preflight'
  grep -F 'upgrade_e2e_validate_external_pair systemd-amd64-provenance' <<<"${supply_preflight_body}" >/dev/null || \
    upgrade_e2e_fail 'static-systemd-amd64-provenance-preflight'
  grep -F 'upgrade_e2e_validate_external_pair systemd-arm64-provenance' <<<"${supply_preflight_body}" >/dev/null || \
    upgrade_e2e_fail 'static-systemd-arm64-provenance-preflight'
  grep -F 'upgrade_e2e_validate_external_pair systemd-spdx' <<<"${supply_preflight_body}" >/dev/null || \
    upgrade_e2e_fail 'static-systemd-spdx-preflight'
  grep -F 'upgrade_e2e_snapshot_input_pair systemd-amd64-inventory' <<<"${supply_snapshot_body}" >/dev/null || \
    upgrade_e2e_fail 'static-systemd-amd64-inventory-snapshot'
  grep -F 'upgrade_e2e_snapshot_input_pair systemd-arm64-inventory' <<<"${supply_snapshot_body}" >/dev/null || \
    upgrade_e2e_fail 'static-systemd-arm64-inventory-snapshot'
  grep -F 'upgrade_e2e_snapshot_input_pair systemd-amd64-provenance' <<<"${supply_snapshot_body}" >/dev/null || \
    upgrade_e2e_fail 'static-systemd-amd64-provenance-snapshot'
  grep -F 'upgrade_e2e_snapshot_input_pair systemd-arm64-provenance' <<<"${supply_snapshot_body}" >/dev/null || \
    upgrade_e2e_fail 'static-systemd-arm64-provenance-snapshot'
  grep -F 'upgrade_e2e_snapshot_input_pair systemd-spdx' <<<"${supply_snapshot_body}" >/dev/null || \
    upgrade_e2e_fail 'static-systemd-spdx-snapshot'
  grep -F 'upgrade_e2e_snapshot_input_pair systemd-amd64-manifest' <<<"${supply_snapshot_body}" >/dev/null || \
    upgrade_e2e_fail 'static-systemd-amd64-manifest-snapshot'
  grep -F 'upgrade_e2e_snapshot_input_pair systemd-arm64-manifest' <<<"${supply_snapshot_body}" >/dev/null || \
    upgrade_e2e_fail 'static-systemd-arm64-manifest-snapshot'
  grep -F '/opt/cdnca-upgrade-e2e/packaging/scripts/install.sh' <<<"${systemd_runtime_body}" >/dev/null || \
    upgrade_e2e_fail 'static-systemd-image-installer'
  grep -F 'cdnca-edge-agent-helper.socket' <<<"${systemd_runtime_body}" >/dev/null || \
    upgrade_e2e_fail 'static-systemd-helper-socket'
  grep -F 'for unit in cdnca-edge-agent.service cdnca-edge-agent-helper.service cdnca-edge-agent-helper.socket; do' \
    <<<"${systemd_runtime_body}" >/dev/null || upgrade_e2e_fail 'static-systemd-three-unit-byte-binding'
  grep -F 'cmp -s "/usr/lib/systemd/system/${unit}" "${image_packaging}/systemd/${unit}"' \
    <<<"${systemd_runtime_body}" >/dev/null || upgrade_e2e_fail 'static-systemd-loaded-unit-byte-binding'
  grep -F 'sha256sum "/usr/lib/systemd/system/${unit}"' <<<"${systemd_runtime_body}" >/dev/null || \
    upgrade_e2e_fail 'static-systemd-loaded-unit-hash-binding'
  grep -F 'systemctl is-enabled --quiet cdnca-edge-agent.service' <<<"${systemd_runtime_body}" >/dev/null || \
    upgrade_e2e_fail 'static-systemd-agent-enabled'
  grep -F 'systemctl is-active --quiet cdnca-edge-agent.service' <<<"${systemd_runtime_body}" >/dev/null || \
    upgrade_e2e_fail 'static-systemd-agent-active'
  grep -F 'systemctl is-enabled --quiet cdnca-edge-agent-helper.socket' <<<"${systemd_runtime_body}" >/dev/null || \
    upgrade_e2e_fail 'static-systemd-helper-socket-enabled'
  grep -F 'systemctl is-active --quiet cdnca-edge-agent-helper.socket' <<<"${systemd_runtime_body}" >/dev/null || \
    upgrade_e2e_fail 'static-systemd-helper-socket-active'
  grep -F 'test "$(systemctl is-enabled cdnca-edge-agent.service)" = enabled' <<<"${systemd_runtime_body}" >/dev/null || \
    upgrade_e2e_fail 'static-systemd-agent-enabled-exact'
  grep -F 'test "$(systemctl is-active cdnca-edge-agent.service)" = active' <<<"${systemd_runtime_body}" >/dev/null || \
    upgrade_e2e_fail 'static-systemd-agent-active-exact'
  grep -F 'test "$(systemctl is-enabled cdnca-edge-agent-helper.socket)" = enabled' <<<"${systemd_runtime_body}" >/dev/null || \
    upgrade_e2e_fail 'static-systemd-helper-socket-enabled-exact'
  grep -F 'test "$(systemctl is-active cdnca-edge-agent-helper.socket)" = active' <<<"${systemd_runtime_body}" >/dev/null || \
    upgrade_e2e_fail 'static-systemd-helper-socket-active-exact'
  grep -F 'systemctl is-enabled cdnca-edge-agent-helper.service' <<<"${systemd_runtime_body}" >/dev/null || \
    upgrade_e2e_fail 'static-systemd-helper-service-enabled-state'
  grep -F 'systemctl is-active cdnca-edge-agent-helper.service' <<<"${systemd_runtime_body}" >/dev/null || \
    upgrade_e2e_fail 'static-systemd-helper-service-active-state'
  grep -F 'systemctl show -p FragmentPath --value "${unit}"' <<<"${systemd_runtime_body}" >/dev/null || \
    upgrade_e2e_fail 'static-systemd-three-unit-fragment-paths'
  ! grep -F 'systemctl is-enabled --quiet cdnca-edge-agent-helper.socket cdnca-edge-agent.service' \
    <<<"${implementation}" >/dev/null || upgrade_e2e_fail 'static-systemd-no-multi-unit-enabled'
  ! grep -F 'systemctl is-active --quiet cdnca-edge-agent-helper.socket cdnca-edge-agent.service' \
    <<<"${implementation}" >/dev/null || upgrade_e2e_fail 'static-systemd-no-multi-unit-active'
  grep -F 'upgrade_e2e_assert_installing_journal' <<<"${scenarios_body}" >/dev/null || \
    upgrade_e2e_fail 'static-systemd-helper-journal'
  ! grep -F 'SYSTEMD_PROVENANCE_AMD64_SNAPSHOT' <<<"${scan_body}" >/dev/null || \
    upgrade_e2e_fail 'static-systemd-public-evidence-not-secret-excluded'
  grep -F 'upgrade_e2e_validate_live_manifest b UPGRADE_E2E_B_MANIFEST' <<<"${implementation}" >/dev/null || upgrade_e2e_fail 'static-b-manifest-preflight'
  grep -F 'upgrade_e2e_validate_live_manifest c "$1" "$2"' <<<"${implementation}" >/dev/null || upgrade_e2e_fail 'static-c-manifest-format-digest'
  grep -F 'upgrade_e2e_validate_live_edge_manifest UPGRADE_E2E_C_MANIFEST' <<<"${implementation}" >/dev/null || upgrade_e2e_fail 'static-c-complete-manifest-preflight'
  grep -F 'upgrade_e2e_snapshot_edge_manifest_matches "${c_manifest}"' <<<"${implementation}" >/dev/null || upgrade_e2e_fail 'static-c-complete-manifest-snapshot'
  grep -F 'agents/edge-agent/packaging/build/contract\.json' <<<"${implementation}" >/dev/null || upgrade_e2e_fail 'static-c-build-contract'
  grep -F 'EDGE_RELEASE_SOURCE_MANIFEST_SNAPSHOT' <<<"${implementation}" >/dev/null || upgrade_e2e_fail 'static-edge-release-source-snapshot'
  grep -F 'packaging/build/recipe.sh' <<<"${build_body}" >/dev/null || upgrade_e2e_fail 'static-edge-release-recipe'
  ! grep -F 'go build -trimpath -o "${WORK_DIR}/bin/cdnca-edge-agent"' <<<"${build_body}" >/dev/null || \
    upgrade_e2e_fail 'static-no-development-edge-build'
  grep -F "awk '\$2 ~ /^agents\\/edge-agent\\// {print}' \"\${SNAPSHOT_INVENTORY}\"" <<<"${implementation}" >/dev/null || \
    upgrade_e2e_fail 'static-c-snapshot-inventory-filter'
  grep -F 'upgrade_e2e_validate_nats_resources "${last_validated_external_file}"' <<<"${implementation}" >/dev/null || upgrade_e2e_fail 'static-nats-preflight'
  grep -F 'upgrade_e2e_snapshot_input_pair forward-bundle' <<<"${implementation}" >/dev/null || upgrade_e2e_fail 'static-forward-bundle-snapshot'
  grep -F 'upgrade_e2e_snapshot_input_pair rollback-bundle' <<<"${implementation}" >/dev/null || upgrade_e2e_fail 'static-rollback-bundle-snapshot'
  grep -F 'upgrade_e2e_bundle_executable_identity()' <<<"${implementation}" >/dev/null || upgrade_e2e_fail 'static-bundle-executable-parser'
  grep -F 'forward-bundle-built-binary-mismatch' <<<"${implementation}" >/dev/null || upgrade_e2e_fail 'static-forward-bundle-binary-binding'
  grep -F 'rollback-bundle-initial-binary-mismatch' <<<"${implementation}" >/dev/null || upgrade_e2e_fail 'static-rollback-bundle-binary-binding'
  grep -F 'nats-stream-readback-mismatch' <<<"${implementation}" >/dev/null || upgrade_e2e_fail 'static-nats-stream-readback'
  grep -F 'nats-consumer-readback-mismatch' <<<"${implementation}" >/dev/null || upgrade_e2e_fail 'static-nats-consumer-readback'
  grep -F "request --raw '\$JS.API.STREAM.NAMES'" <<<"${implementation}" >/dev/null || upgrade_e2e_fail 'static-nats-stream-enumeration'
  grep -F 'request --raw "\$JS.API.CONSUMER.NAMES.${stream}"' <<<"${implementation}" >/dev/null || upgrade_e2e_fail 'static-nats-consumer-enumeration'
  grep -F 'upgrade_e2e_verify_nats_server_state()' <<<"${implementation}" >/dev/null || upgrade_e2e_fail 'static-nats-final-verifier'
  grep -F 'stream info "${stream}" --json' <<<"${nats_verify_body}" >/dev/null || upgrade_e2e_fail 'static-nats-final-stream-readback'
  grep -F 'consumer info "${stream}" "${consumer}" --json' <<<"${nats_verify_body}" >/dev/null || upgrade_e2e_fail 'static-nats-final-consumer-readback'
	grep -F '{"_nats.level":"1","_nats.req.level":"0","_nats.ver":"2.11.4"}' <<<"${nats_metadata_body}" >/dev/null || upgrade_e2e_fail 'static-nats-server-metadata-contract'
	grep -F 'startswith("_nats.")' <<<"${nats_metadata_body}" >/dev/null || upgrade_e2e_fail 'static-nats-unknown-metadata-rejection'
	nats_metadata_calls=$(grep -c -F 'upgrade_e2e_strip_nats_server_metadata' <<<"${nats_verify_body}" || true)
	[ "${nats_metadata_calls}" -eq 2 ] || upgrade_e2e_fail 'static-nats-metadata-readback-coverage'
  grep -F 'cdnca.agent.deployment-status.upgrade-v2.*' <<<"${implementation}" >/dev/null || upgrade_e2e_fail 'static-nats-upgrade-v2-subject'
  grep -F 'stream:"AGENT_DEPLOYMENT_STATUS",filter:"",filters:[' <<<"${implementation}" >/dev/null || upgrade_e2e_fail 'static-nats-upgrade-dual-filter'
  grep -F 'license_e2e_fixture LOGIN NOINHERIT NOSUPERUSER' <<<"${implementation}" >/dev/null || upgrade_e2e_fail 'static-license-fixture-role'
  grep -F 'control_e2e_fixture LOGIN NOINHERIT NOSUPERUSER' <<<"${implementation}" >/dev/null || upgrade_e2e_fail 'static-control-fixture-role'
  grep -F 'GRANT INSERT ON access_scopes,node_enrollment_tokens,node_enrollment_authorizations, node_ca_key_epochs,node_certificates TO control_e2e_fixture;' \
    <<<"${apply_fixtures_compact}" >/dev/null || upgrade_e2e_fail 'static-control-fixture-identity-insert-grant'
  ! grep -E 'GRANT [^;]*(ALL|SELECT|UPDATE|DELETE|TRUNCATE|REFERENCES|TRIGGER)[^;]* ON [^;]*(access_scopes|node_enrollment_tokens|node_enrollment_authorizations|node_ca_key_epochs|node_certificates)' \
    <<<"${apply_fixtures_compact}" >/dev/null || upgrade_e2e_fail 'static-control-fixture-identity-insert-only'
  ! grep -E 'GRANT [^;]* ON ALL TABLES IN SCHEMA public TO (license|control)_e2e_fixture' \
    <<<"${apply_fixtures_compact}" >/dev/null || upgrade_e2e_fail 'static-fixture-no-all-table-grant'
  sequence_grant_count=$(grep -c -F 'GRANT USAGE,SELECT ON ALL SEQUENCES IN SCHEMA public TO ' \
    <<<"${apply_fixtures_body}" || true)
  sequence_revoke_count=$(grep -c -F 'REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public FROM ' \
    <<<"${apply_fixtures_body}" || true)
  table_revoke_count=$(grep -c -F 'REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM ' \
    <<<"${apply_fixtures_body}" || true)
  [ "${sequence_grant_count}" -eq 2 ] && [ "${sequence_revoke_count}" -eq 2 ] && \
    [ "${table_revoke_count}" -eq 2 ] || upgrade_e2e_fail 'static-fixture-direct-grant-revocation'
  for contract in \
    'REVOKE USAGE ON SCHEMA public FROM license_e2e_fixture;' \
    'REVOKE USAGE ON SCHEMA public FROM control_e2e_fixture;' \
    'REVOKE CONNECT ON DATABASE license_e2e FROM license_e2e_fixture;' \
    'REVOKE CONNECT ON DATABASE control_e2e FROM control_e2e_fixture;' \
    'ALTER ROLE license_e2e_fixture NOLOGIN;' \
    'ALTER ROLE control_e2e_fixture NOLOGIN;'; do
    grep -F "${contract}" <<<"${apply_fixtures_body}" >/dev/null || \
      upgrade_e2e_fail 'static-fixture-direct-grant-revocation'
  done
  fixture_observation_line=$(grep -n -F 'license-fixture-artifact-binding' <<<"${apply_fixtures_body}" | awk -F: 'NR==1 {print $1}')
  fixture_retire_line=$(grep -n -F 'REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public' \
    <<<"${apply_fixtures_body}" | awk -F: 'NR==1 {print $1}')
  fixture_nologin_line=$(grep -n -F 'ALTER ROLE control_e2e_fixture NOLOGIN' \
    <<<"${apply_fixtures_body}" | awk -F: 'NR==1 {print $1}')
  fixture_apply_line=$(grep -n -F 'upgrade_e2e_apply_migrations_and_fixtures' <<<"${main}" | awk -F: 'NR==1 {print $1}')
  fixture_start_line=$(grep -n -F 'upgrade_e2e_start_four_processes' <<<"${main}" | awk -F: 'NR==1 {print $1}')
  [ -n "${fixture_observation_line}" ] && [ -n "${fixture_retire_line}" ] && [ -n "${fixture_nologin_line}" ] && \
    [ "${fixture_observation_line}" -lt "${fixture_retire_line}" ] && \
    [ "${fixture_retire_line}" -lt "${fixture_nologin_line}" ] && \
    [ -n "${fixture_apply_line}" ] && [ -n "${fixture_start_line}" ] && \
    [ "${fixture_apply_line}" -lt "${fixture_start_line}" ] || \
    upgrade_e2e_fail 'static-fixture-direct-grant-revocation-order'
  grep -F 'revokes only the direct table, sequence, schema, and database connection grants issued by this driver' \
    "${readme}" >/dev/null || upgrade_e2e_fail 'static-fixture-direct-grant-revocation-readme'
  grep -F 'does not remove privileges inherited through `PUBLIC`' "${readme}" >/dev/null || \
    upgrade_e2e_fail 'static-fixture-public-privilege-boundary-readme'
  grep -F '`NOLOGIN` prevents direct login; it is not proof that the roles have no effective privileges' \
    "${readme}" >/dev/null || upgrade_e2e_fail 'static-fixture-nologin-boundary-readme'
  grep -F 'license-fixture-fabricated-runtime-facts' <<<"${implementation}" >/dev/null || upgrade_e2e_fail 'static-license-runtime-facts-empty'
  grep -F 'control-fixture-fabricated-runtime-facts' <<<"${implementation}" >/dev/null || upgrade_e2e_fail 'static-control-runtime-facts-empty'
  [ "${#CONTROL_FIXTURE_IDENTITY_VARIABLES[@]}" -eq 4 ] || upgrade_e2e_fail 'static-control-fixture-variable-count'
  grep -F 'literal_count' <<<"${control_fixture_body}" >/dev/null || \
    upgrade_e2e_fail 'static-control-fixture-literal-count'
  grep -F 'total_count' <<<"${control_fixture_body}" >/dev/null || \
    upgrade_e2e_fail 'static-control-fixture-unique-count'
  grep -F 'upgrade_e2e_validate_control_authority_fixture "${last_validated_external_file}"' \
    <<<"${implementation}" >/dev/null || upgrade_e2e_fail 'static-control-fixture-live-preflight'
  grep -F 'upgrade_e2e_validate_control_authority_fixture "${CONTROL_AUTHORITY_FIXTURE_SNAPSHOT}"' \
    <<<"${implementation}" >/dev/null || upgrade_e2e_fail 'static-control-fixture-snapshot-preflight'
  grep -F 'test fixture template, not enrollment' "${readme}" >/dev/null || \
    upgrade_e2e_fail 'static-control-fixture-readme-contract'
  for variable in "${CONTROL_FIXTURE_IDENTITY_VARIABLES[@]}"; do
    grep -F -- "-v ${variable}=\"\${" <<<"${apply_fixtures_body}" >/dev/null || \
      upgrade_e2e_fail "static-control-fixture-binding-${variable}"
  done
  grep -F 'upgrade_e2e_edge_identity_public_facts' <<<"${apply_fixtures_body}" >/dev/null || \
    upgrade_e2e_fail 'static-control-fixture-public-facts'
  grep -F 'upgrade_e2e_x25519_public_key_hex_from_raw' <<<"${public_facts_body}" >/dev/null || \
    upgrade_e2e_fail 'static-control-fixture-public-key'
  grep -F 'upgrade_e2e_control_sql "SELECT count(*)' <<<"${identity_binding_body}" >/dev/null || \
    upgrade_e2e_fail 'static-control-fixture-read-only-readback'
  for contract in \
    "certificate.rotation_status='current'" \
    'certificate.owner_scope_id=node.scope_id' \
    'state.active_artifact_key_id=artifact.id' \
    "artifact.status='active'" \
    "authorization.status='issued'"; do
    grep -F "${contract}" <<<"${identity_binding_body}" >/dev/null || \
      upgrade_e2e_fail 'static-control-fixture-production-binding'
  done
  control_ready_line=$(grep -n -F 'control-runtime-readiness' <<<"${runtime_start_body}" | awk -F: 'NR==1 {print $1}')
  identity_binding_line=$(grep -n -F 'upgrade_e2e_assert_control_identity_fixture_binding' <<<"${runtime_start_body}" | awk -F: 'NR==1 {print $1}')
  gateway_start_line=$(grep -n -F 'upgrade_e2e_run_container gateway' <<<"${runtime_start_body}" | awk -F: 'NR==1 {print $1}')
  [ -n "${control_ready_line}" ] && [ -n "${identity_binding_line}" ] && [ -n "${gateway_start_line}" ] && \
    [ "${control_ready_line}" -lt "${identity_binding_line}" ] && \
    [ "${identity_binding_line}" -lt "${gateway_start_line}" ] || \
    upgrade_e2e_fail 'static-control-fixture-readback-before-gateway'
  grep -F '/task/packaging/scripts/install.sh' <<<"${implementation}" >/dev/null || upgrade_e2e_fail 'static-edge-production-installer'
  grep -F '/usr/libexec/cdnca-edge-agent-helper key-init' <<<"${implementation}" >/dev/null || upgrade_e2e_fail 'static-edge-helper-key-init'
  grep -F 'systemctl enable --now cdnca-edge-agent-helper.socket' <<<"${implementation}" >/dev/null || upgrade_e2e_fail 'static-edge-helper-socket'
  grep -F 'systemctl enable --now cdnca-edge-agent.service' <<<"${implementation}" >/dev/null || upgrade_e2e_fail 'static-edge-agent-service'
  grep -F '.upgrade.installer_receipt_trust_file = "/etc/cdnca-edge-agent/trust/installer-receipt.json"' \
    <<<"${edge_runtime_body}" >/dev/null || upgrade_e2e_fail 'static-edge-receipt-trust-store-path'
  receipt_trust_line=$(grep -n -F 'install -o cdnca-edge -g cdnca-edge -m 0400 /dev/stdin /etc/cdnca-edge-agent/trust/installer-receipt.json' \
    <<<"${implementation}" | awk -F: 'NR==1 {print $1}')
  agent_enable_line=$(grep -n -F 'systemctl enable --now cdnca-edge-agent.service' <<<"${implementation}" | awk -F: 'NR==1 {print $1}')
  [ -n "${receipt_trust_line}" ] && [ -n "${agent_enable_line}" ] && [ "${receipt_trust_line}" -lt "${agent_enable_line}" ] || \
    upgrade_e2e_fail 'static-edge-receipt-trust-before-agent'
  grep -F '.identity_dir == "/etc/cdnca-edge-agent/identity"' <<<"${edge_preflight_body}" >/dev/null || \
    upgrade_e2e_fail 'static-edge-v2-identity-directory-preflight'
  grep -F 'has("node_id") | not' <<<"${edge_preflight_body}" >/dev/null || \
    upgrade_e2e_fail 'static-edge-v2-node-id-forbidden'
  grep -F 'has("client_certificate_file") | not' <<<"${edge_preflight_body}" >/dev/null || \
    upgrade_e2e_fail 'static-edge-v2-client-certificate-forbidden'
  grep -F 'has("client_private_key_file") | not' <<<"${edge_preflight_body}" >/dev/null || \
    upgrade_e2e_fail 'static-edge-v2-client-key-forbidden'
  ! grep -F '.gateway.client_certificate_file =' <<<"${edge_runtime_body}" >/dev/null || \
    upgrade_e2e_fail 'static-edge-runtime-no-legacy-client-certificate'
  ! grep -F '.gateway.client_private_key_file =' <<<"${edge_runtime_body}" >/dev/null || \
    upgrade_e2e_fail 'static-edge-runtime-no-legacy-client-key'
  grep -F '.identity_dir = "/etc/cdnca-edge-agent/identity"' <<<"${edge_runtime_body}" >/dev/null || \
    upgrade_e2e_fail 'static-edge-runtime-identity-directory'
  grep -F 'upgrade_e2e_create_edge_identity()' <<<"${edge_identity_body}" >/dev/null || \
    upgrade_e2e_fail 'static-edge-identity-creator'
  for name in identity.json client.pem client-key.pem artifact-x25519-key.bin; do
    grep -F "${name}" <<<"${edge_identity_body}" >/dev/null || \
      upgrade_e2e_fail "static-edge-identity-file-${name}"
  done
  grep -F 'chmod 0700' <<<"${edge_identity_body}" >/dev/null || upgrade_e2e_fail 'static-edge-identity-directory-mode'
  grep -F 'chmod 0600' <<<"${edge_identity_body}" >/dev/null || upgrade_e2e_fail 'static-edge-identity-file-mode'
  grep -F 'upgrade_e2e_fsync_path' <<<"${edge_identity_body}" >/dev/null || upgrade_e2e_fail 'static-edge-identity-fsync'
  grep -F 'upgrade_e2e_atomic_publish_identity' <<<"${edge_identity_body}" >/dev/null || \
    upgrade_e2e_fail 'static-edge-identity-atomic-publish'
  grep -F 'S_ISLNK' <<<"${identity_validate_body}" >/dev/null || upgrade_e2e_fail 'static-edge-identity-no-symlinks'
  grep -F '== 0700' <<<"${identity_validate_body}" >/dev/null || upgrade_e2e_fail 'static-edge-identity-exact-directory-mode'
  grep -F '== 0600' <<<"${identity_validate_body}" >/dev/null || upgrade_e2e_fail 'static-edge-identity-exact-file-mode'
  grep -F '"@actual" eq "@required"' <<<"${identity_validate_body}" >/dev/null || \
    upgrade_e2e_fail 'static-edge-identity-exact-file-set'
  grep -F 'keys == ["artifact_encryption_key_id"' <<<"${identity_validate_body}" >/dev/null || \
    upgrade_e2e_fail 'static-edge-identity-strict-schema'
  grep -F 'spiffe://cdn-platform/node/${node_id}' <<<"${identity_validate_body}" >/dev/null || \
    upgrade_e2e_fail 'static-edge-identity-spiffe-binding'
  grep -F 'openssl verify -purpose sslclient' <<<"${identity_validate_body}" >/dev/null || \
    upgrade_e2e_fail 'static-edge-identity-client-chain'
  grep -F 'certificate_public' <<<"${identity_validate_body}" >/dev/null || \
    upgrade_e2e_fail 'static-edge-identity-client-key-binding'
  grep -F 'upgrade_e2e_x25519_key_id_from_raw' <<<"${identity_validate_body}" >/dev/null || \
    upgrade_e2e_fail 'static-edge-identity-x25519-binding'
  grep -F 'upgrade_e2e_create_edge_identity' <<<"${pki_body}" >/dev/null || \
    upgrade_e2e_fail 'static-edge-identity-created-after-pki'
  grep -F -- '-v "${EDGE_IDENTITY_DIR}:/task/bootstrap/identity:ro"' <<<"${implementation}" >/dev/null || \
    upgrade_e2e_fail 'static-edge-identity-directory-mount'
  grep -F '/etc/cdnca-edge-agent/identity' <<<"${implementation}" >/dev/null || \
    upgrade_e2e_fail 'static-edge-identity-production-install'
  pki_cert_line=$(grep -n -F 'upgrade_e2e_issue_certificate edge-agent-client' <<<"${pki_body}" | awk -F: 'NR==1 {print $1}')
  pki_identity_line=$(grep -n -F 'upgrade_e2e_create_edge_identity' <<<"${pki_body}" | awk -F: 'NR==1 {print $1}')
  pki_main_line=$(grep -n -F 'upgrade_e2e_generate_pki' <<<"${main}" | awk -F: 'NR==1 {print $1}')
  start_main_line=$(grep -n -F 'upgrade_e2e_start_four_processes' <<<"${main}" | awk -F: 'NR==1 {print $1}')
  [ -n "${pki_cert_line}" ] && [ -n "${pki_identity_line}" ] && [ "${pki_cert_line}" -lt "${pki_identity_line}" ] && \
    [ -n "${pki_main_line}" ] && [ -n "${start_main_line}" ] && [ "${pki_main_line}" -lt "${start_main_line}" ] || \
    upgrade_e2e_fail 'static-edge-identity-before-container-start'
  grep -F 'EDGE_IDENTITY_DIR}/client-key.pem' <<<"${scan_body}" >/dev/null || \
    upgrade_e2e_fail 'static-edge-identity-client-key-secret-source'
  grep -F 'EDGE_IDENTITY_DIR}/artifact-x25519-key.bin' <<<"${scan_body}" >/dev/null || \
    upgrade_e2e_fail 'static-edge-identity-x25519-secret-source'
  grep -F 'SET default_transaction_read_only=on;' <<<"${control_sql_body}" >/dev/null || upgrade_e2e_fail 'static-control-observation-read-only'
  grep -F 'SET default_transaction_read_only=on;' <<<"${license_sql_body}" >/dev/null || upgrade_e2e_fail 'static-license-observation-read-only'
  ! grep -Eq '(INSERT|UPDATE|DELETE|TRUNCATE)[[:space:]]' <<<"${scenarios_body}" || upgrade_e2e_fail 'static-no-scenario-sql-mutation'
  grep -F 'operator-parent-receipt-chain' <<<"${scenarios_body}" >/dev/null || upgrade_e2e_fail 'static-operator-parent-chain'
  grep -F 'automatic-parent-receipt-chain' <<<"${scenarios_body}" >/dev/null || upgrade_e2e_fail 'static-automatic-parent-chain'
  grep -F 'success-parent-receipt-chain' <<<"${scenarios_body}" >/dev/null || upgrade_e2e_fail 'static-success-parent-chain'
  grep -F 'response_bytes=convert_to(format(' <<<"${parent_chain_body}" >/dev/null || upgrade_e2e_fail 'static-parent-response-canonical-bytes'
  grep -F 'array_agg(receipt.status ORDER BY receipt.receipt_sequence)' <<<"${parent_chain_body}" >/dev/null || upgrade_e2e_fail 'static-parent-control-exact-order'
  grep -F 'JOIN issued_upgrade_grants parent_grant ON parent_grant.id=receipt.grant_id' <<<"${parent_chain_body}" >/dev/null || upgrade_e2e_fail 'static-parent-license-grant-binding'
  grep -F 'JOIN issued_upgrade_command_grants command_grant ON command_grant.plan_id=' <<<"${parent_chain_body}" >/dev/null || upgrade_e2e_fail 'static-parent-command-artifact-binding'
  ! grep -F 'ON grant_record.id=receipt.grant_id' <<<"${parent_chain_body}" >/dev/null || upgrade_e2e_fail 'static-parent-no-command-grant-id-confusion'
  grep -F 'upgrade_e2e_rollout_snapshot()' <<<"${implementation}" >/dev/null || upgrade_e2e_fail 'static-full-replay-snapshot'
  grep -F 'upgrade_grant_receipts' <<<"${rollout_snapshot_body}" >/dev/null || upgrade_e2e_fail 'static-replay-license-facts'
  grep -F 'upgrade_e2e_edge_fact_snapshot' <<<"${rollout_snapshot_body}" >/dev/null || upgrade_e2e_fail 'static-replay-edge-snapshot-binding'
  grep -F '/state/upgrade-wire-v1' <<<"${edge_snapshot_body}" >/dev/null || upgrade_e2e_fail 'static-replay-edge-wire-facts'
  grep -F '/var/lib/cdnca-edge-agent-helper/transactions' <<<"${edge_snapshot_body}" >/dev/null || upgrade_e2e_fail 'static-replay-helper-transaction-facts'
  grep -F 'journal-*.json' <<<"${edge_snapshot_body}" >/dev/null || upgrade_e2e_fail 'static-replay-helper-journal-facts'
  grep -F -- '--tmpfs /var/lib/cdnca-edge-agent-helper:rw,noexec,nosuid,nodev,size=16m' \
    <<<"${implementation}" >/dev/null || upgrade_e2e_fail 'static-helper-bounded-tmpfs'
  grep -F 'upgrade_e2e_inject_helper_enospc()' <<<"${implementation}" >/dev/null || \
    upgrade_e2e_fail 'static-helper-enospc-injector'
  grep -F 'stat -f -c %T "${directory}"' <<<"${implementation}" >/dev/null || \
    upgrade_e2e_fail 'static-helper-tmpfs-readback'
  grep -F 'No space left on device' <<<"${implementation}" >/dev/null || \
    upgrade_e2e_fail 'static-helper-real-enospc'
  grep -F 'upgrade_e2e_edge_lkg_snapshot' <<<"${scenarios_body}" >/dev/null || \
    upgrade_e2e_fail 'static-enospc-lkg-snapshot'
  grep -F 'upgrade_e2e_helper_journal_snapshot' <<<"${scenarios_body}" >/dev/null || \
    upgrade_e2e_fail 'static-enospc-journal-snapshot'
  grep -F "state='installing'" <<<"${scenarios_body}" >/dev/null || \
    upgrade_e2e_fail 'static-enospc-no-installing'
  grep -F '[ "${lkg_before}" = "${lkg_during}" ]' <<<"${scenarios_body}" >/dev/null || \
    upgrade_e2e_fail 'static-enospc-lkg-unchanged'
  grep -F '[ "${journal_before}" = "${journal_during}" ]' <<<"${scenarios_body}" >/dev/null || \
    upgrade_e2e_fail 'static-enospc-journal-unchanged'
  grep -F 'systemctl kill --kill-who=main --signal=KILL' <<<"${implementation}" >/dev/null || \
    upgrade_e2e_fail 'static-edge-agent-sigkill'
  grep -F '[ "${after_pid}" != "${before_pid}" ]' <<<"${implementation}" >/dev/null || \
    upgrade_e2e_fail 'static-edge-agent-new-pid'
  grep -F '[ "${after_start_time}" != "${before_start_time}" ]' <<<"${implementation}" >/dev/null || \
    upgrade_e2e_fail 'static-edge-agent-new-start-identity'
  grep -F 'upgrade_e2e_remove_helper_enospc' <<<"${scenarios_body}" >/dev/null || \
    upgrade_e2e_fail 'static-helper-enospc-cleared'
  grep -F 'upgrade_e2e_sigkill_edge_agent_and_wait' <<<"${scenarios_body}" >/dev/null || \
    upgrade_e2e_fail 'static-enospc-sigkill-recovery'
  grep -F 'accepted,claimed,installing,healthy' <<<"${scenarios_body}" >/dev/null || upgrade_e2e_fail 'static-success-status-sequence'
  grep -F 'accepted,claimed,installing,rolling_back,rolled_back' <<<"${scenarios_body}" >/dev/null || upgrade_e2e_fail 'static-auto-rollback-status-sequence'
  grep -F 'upgrade_e2e_assert_status_puback_wire()' <<<"${implementation}" >/dev/null || upgrade_e2e_fail 'static-status-puback-wire-verifier'
  grep -F 'delivery_stream,delivery_consumer,delivery_sequence' <<<"${implementation}" >/dev/null || upgrade_e2e_fail 'static-status-puback-persisted-identity'
  grep -F 'stream get -j AGENT_DEPLOYMENT_STATUS "${sequence}"' <<<"${implementation}" >/dev/null || upgrade_e2e_fail 'static-status-puback-getmsg'
  grep -F 'gateway-upgrade-status-v2-${status_id}' <<<"${implementation}" >/dev/null || upgrade_e2e_fail 'static-status-puback-message-id'
  grep -F 'upgrade_e2e_assert_edge_status_acks()' <<<"${implementation}" >/dev/null || upgrade_e2e_fail 'static-edge-status-ack-verifier'
  grep -F 'upgrade_e2e_assert_edge_status_acks "${plan_id}"' <<<"${status_puback_body}" >/dev/null || upgrade_e2e_fail 'static-edge-status-ack-binding'
  grep -F '/state/upgrade-wire-v1/acked/${status_id}.json' <<<"${status_ack_body}" >/dev/null || upgrade_e2e_fail 'static-edge-status-ack-file-binding'
  grep -F '.version == 1' <<<"${status_ack_body}" >/dev/null || upgrade_e2e_fail 'static-edge-status-ack-version'
  grep -F '.receipt_required == true and .receipt_confirmed == true' <<<"${status_ack_body}" >/dev/null || upgrade_e2e_fail 'static-edge-status-ack-confirmed'
  grep -F '.encoded' <<<"${status_ack_body}" >/dev/null || upgrade_e2e_fail 'static-edge-status-ack-encoded'
  grep -F '.ack_sha256' <<<"${status_ack_body}" >/dev/null || upgrade_e2e_fail 'static-edge-status-ack-digest'
  grep -F 'cdnca.gateway.upgrade-status-ack-confirmation/v1' <<<"${status_ack_body}" >/dev/null || upgrade_e2e_fail 'static-edge-status-confirmation-schema'
  grep -F 'upgrade-proof.confirmed.${node_id}.${ack_digest}' <<<"${status_ack_body}" >/dev/null || upgrade_e2e_fail 'static-edge-status-confirmation-subject'
  grep -F 'cmp -s "${ack_encoded}" "${confirmation_ack}"' <<<"${status_ack_body}" >/dev/null || upgrade_e2e_fail 'static-edge-status-confirmation-byte-binding'
  grep -F 'upgrade_e2e_edge_status_ack_snapshot' <<<"${status_ack_body}" >/dev/null || upgrade_e2e_fail 'static-edge-status-ack-restart-snapshot'
  grep -F 'upgrade_e2e_restart_edge_agent' <<<"${status_ack_body}" >/dev/null || upgrade_e2e_fail 'static-edge-status-ack-restart'
  grep -F 'cdnca.gateway.upgrade-status-ack-ledger/v1' <<<"${status_ack_body}" >/dev/null || upgrade_e2e_fail 'static-edge-status-ledger-schema'
  grep -F '.pending | type == "array" and length == 0' <<<"${status_ack_body}" >/dev/null || upgrade_e2e_fail 'static-edge-status-ledger-empty'
  grep -F 'previous_sequence < ledger_sequence' <<<"${status_ack_body}" >/dev/null || upgrade_e2e_fail 'static-edge-status-ledger-order'
  grep -F 'gateway-upgrade-status-ack-ledger-v1-${ledger_digest}' <<<"${status_ack_body}" >/dev/null || upgrade_e2e_fail 'static-edge-status-ledger-message-id'
  status_ack_restart_equal_line=$(grep -n -F '[ "${snapshot_before}" = "${snapshot_after}" ]' <<<"${status_ack_body}" | awk -F: 'NR==1 {print $1}')
  status_ack_ledger_read_line=$(grep -n -F 'ledger_subject="cdnca.agent.deployment-status.upgrade-proof.pending.${node_id}"' <<<"${status_ack_body}" | awk -F: 'NR==1 {print $1}')
  [ -n "${status_ack_restart_equal_line}" ] && [ -n "${status_ack_ledger_read_line}" ] && \
    [ "${status_ack_restart_equal_line}" -lt "${status_ack_ledger_read_line}" ] || \
    upgrade_e2e_fail 'static-edge-status-ledger-after-restart'
  grep -F 'byte-identical Edge Ack files across an Agent restart' "${readme}" >/dev/null || upgrade_e2e_fail 'static-edge-status-ack-restart-doc'
  grep -F 'final empty pending ledger' "${readme}" >/dev/null || upgrade_e2e_fail 'static-edge-status-ledger-doc'
  grep -F 'upgrade_e2e_assert_status_puback_wire "${operator_plan}"' <<<"${scenarios_body}" >/dev/null || upgrade_e2e_fail 'static-status-puback-operator-binding'
  grep -F 'upgrade_e2e_assert_status_puback_wire "${auto_plan}"' <<<"${scenarios_body}" >/dev/null || upgrade_e2e_fail 'static-status-puback-automatic-binding'
  grep -F 'upgrade_e2e_assert_status_puback_wire "${success_plan}"' <<<"${scenarios_body}" >/dev/null || upgrade_e2e_fail 'static-status-puback-success-binding'
  grep -F 'upgrade_e2e_assert_installing_journal' <<<"${scenarios_body}" >/dev/null || upgrade_e2e_fail 'static-installing-journal-evidence'
  grep -F 'for state in accepted claimed installing; do' <<<"${scenarios_body}" >/dev/null || upgrade_e2e_fail 'static-restart-state-progression'
  grep -F 'completed upgraded' <<<"${scenarios_body}" >/dev/null || upgrade_e2e_fail 'static-success-progression'
  grep -F 'completed rolled_back' <<<"${scenarios_body}" >/dev/null || upgrade_e2e_fail 'static-rollback-progression'
  grep -F 'false-terminal-parent-receipt' <<<"${scenarios_body}" >/dev/null || upgrade_e2e_fail 'static-no-false-terminal'
  grep -F 'MaxDeliver=-1' "${readme}" >/dev/null || upgrade_e2e_fail 'static-unlimited-redelivery'
  grep -F 'TLS 1.3' "${readme}" >/dev/null || upgrade_e2e_fail 'static-tls13'
  [ "${GATEWAY_WORKLOAD_URI}" = 'spiffe://cdn-platform/gateway/control' ] || upgrade_e2e_fail 'static-gateway-uri'
  grep -F "upgrade_e2e_issue_certificate license-server 'DNS:license.internal' serverAuth" <<<"${implementation}" >/dev/null || upgrade_e2e_fail 'static-license-leaf'
  grep -F "upgrade_e2e_issue_certificate control-server 'DNS:control.internal' serverAuth" <<<"${implementation}" >/dev/null || upgrade_e2e_fail 'static-control-leaf'
  grep -F "upgrade_e2e_issue_certificate gateway-server 'DNS:gateway.internal' serverAuth" <<<"${implementation}" >/dev/null || upgrade_e2e_fail 'static-gateway-leaf'
  grep -F "upgrade_e2e_issue_certificate gateway-control-client \"URI:\${GATEWAY_WORKLOAD_URI}\" clientAuth" <<<"${implementation}" >/dev/null || upgrade_e2e_fail 'static-gateway-client-leaf'
  grep -F "upgrade_e2e_issue_certificate edge-agent-client \"URI:spiffe://cdn-platform/node/\${node_id}\" clientAuth" <<<"${implementation}" >/dev/null || upgrade_e2e_fail 'static-agent-client-leaf'
  grep -F "find \"\${WORK_DIR}\" -type f" <<<"${implementation}" >/dev/null || upgrade_e2e_fail 'static-recursive-secret-scan'
  grep -F 'upgrade_e2e_verify_container_label()' <<<"${implementation}" >/dev/null || upgrade_e2e_fail 'static-container-label-verifier'
  grep -F 'upgrade_e2e_verify_network_label()' <<<"${implementation}" >/dev/null || upgrade_e2e_fail 'static-network-label-verifier'
  grep -F 'owned_container_ids+=("${resource_id}")' <<<"${implementation}" >/dev/null || upgrade_e2e_fail 'static-owned-container-id'
  grep -F 'owned_network_ids+=("${resource_id}")' <<<"${implementation}" >/dev/null || upgrade_e2e_fail 'static-owned-network-id'
  ! grep -F 'rm -f "${TLS_PROXY_CONTAINER}"' <<<"${implementation}" >/dev/null || upgrade_e2e_fail 'static-no-name-container-cleanup'
  ! grep -F 'network rm "${NETWORK_NAME}"' <<<"${implementation}" >/dev/null || upgrade_e2e_fail 'static-no-name-network-cleanup'
  grep -F 'docker_resources_possible=1' <<<"${implementation}" >/dev/null || upgrade_e2e_fail 'static-docker-possible-state'
  grep -F 'docker_inspection_failed=1' <<<"${implementation}" >/dev/null || upgrade_e2e_fail 'static-docker-inspection-fail-closed'
  grep -F 'containers=-1' <<<"${implementation}" >/dev/null || upgrade_e2e_fail 'static-container-count-unknown'
  grep -F 'networks=-1' <<<"${implementation}" >/dev/null || upgrade_e2e_fail 'static-network-count-unknown'
  grep -F 'owned_ports+=("${nats_port}")' <<<"${implementation}" >/dev/null || upgrade_e2e_fail 'static-nats-port-independent'
  grep -F 'owned_ports+=("${redis_port}")' <<<"${implementation}" >/dev/null || upgrade_e2e_fail 'static-redis-port-independent'
  grep -F 'upgrade_e2e_capture_owned_ports' <<<"${implementation}" >/dev/null || upgrade_e2e_fail 'static-owned-port-recovery'
  nats_port_line=$(grep -n -F 'owned_ports+=("${nats_port}")' <<<"${implementation}" | awk -F: 'NR==1 {print $1}')
  redis_start_line=$(grep -n -F -- '--name "${REDIS_CONTAINER}"' <<<"${implementation}" | awk -F: 'NR==1 {print $1}')
  [ -n "${nats_port_line}" ] && [ -n "${redis_start_line}" ] && [ "${nats_port_line}" -lt "${redis_start_line}" ] || upgrade_e2e_fail 'static-nats-port-before-redis'
  grep -F 'scan_status=$?' <<<"${implementation}" >/dev/null || upgrade_e2e_fail 'static-grep-status'
  grep -F "*) upgrade_e2e_fail 'secret-scan-read'" <<<"${implementation}" >/dev/null || upgrade_e2e_fail 'static-grep-read-failure'
  grep -F '[ -r "${file}" ] || upgrade_e2e_fail' <<<"${implementation}" >/dev/null || upgrade_e2e_fail 'static-unreadable-file'
  ! grep -F '! -path "${WORK_DIR}/certs/*"' <<<"${implementation}" >/dev/null || upgrade_e2e_fail 'static-no-wide-cert-exclusion'
  ! grep -F '! -path "${WORK_DIR}/bin/*"' <<<"${implementation}" >/dev/null || upgrade_e2e_fail 'static-no-wide-bin-exclusion'
  grep -F 'UPGRADE_E2E_ACTIVATION_CREDENTIAL UPGRADE_E2E_UPGRADE_GRANT UPGRADE_E2E_BEARER_TOKEN' <<<"${implementation}" >/dev/null || upgrade_e2e_fail 'static-generated-secret-patterns'
  grep -F 'LICENSE_TOTP_KEYS_JSON LICENSE_CREDENTIAL_KEYS_JSON' <<<"${implementation}" >/dev/null || upgrade_e2e_fail 'static-runtime-secret-keyrings'
  grep -F 'LICENSE_IDENTITY_TOKEN_KEYS_JSON' <<<"${implementation}" >/dev/null || upgrade_e2e_fail 'static-runtime-secret-identity-keyring'
  ! grep -F 'cdnca.installation.upgrade-parent-receipt/v1' <<<"${implementation}" >/dev/null || upgrade_e2e_fail 'static-no-unfrozen-receipt-schema'
  grep -F 'expected_version="$(upgrade_e2e_require_env UPGRADE_E2E_PROCESS_CONTRACT_VERSION)"' <<<"${implementation}" >/dev/null || upgrade_e2e_fail 'static-final-process-version-input'
  grep -F 'expected_receipt="$(upgrade_e2e_require_env UPGRADE_E2E_LICENSE_PARENT_RECEIPT_SCHEMA)"' <<<"${implementation}" >/dev/null || upgrade_e2e_fail 'static-final-receipt-schema-input'
  grep -F 'upgrade_e2e_snapshot_preexisting_resources()' <<<"${implementation}" >/dev/null || upgrade_e2e_fail 'static-preexisting-resource-snapshot'
  grep -F 'upgrade_e2e_collect_post_minus_preexisting()' <<<"${implementation}" >/dev/null || upgrade_e2e_fail 'static-post-minus-preexisting-cleanup'
  grep -F 'upgrade_e2e_capture_candidate_ports' <<<"${implementation}" >/dev/null || upgrade_e2e_fail 'static-candidate-port-recovery'
  grep -F 'cleanup_probe_failed=1' <<<"${implementation}" >/dev/null || upgrade_e2e_fail 'static-cleanup-probe-fail-closed'
  ! grep -F '|| true' <<<"${cleanup_body}" >/dev/null || upgrade_e2e_fail 'static-no-unchecked-cleanup-probe'
  ! grep -F 'candidate_container_roles' <<<"${implementation}" >/dev/null || upgrade_e2e_fail 'static-no-container-role-fallback'
  grep -F 'registered_container_roles+=("${role}")' <<<"${implementation}" >/dev/null || upgrade_e2e_fail 'static-container-role-registration'
  grep -F 'upgrade_e2e_verify_registered_container_role' <<<"${implementation}" >/dev/null || upgrade_e2e_fail 'static-container-role-drift'
  grep -F 'upgrade_e2e_container_presence' <<<"${implementation}" >/dev/null || upgrade_e2e_fail 'static-container-presence-probe'
  grep -F 'upgrade_e2e_network_presence' <<<"${implementation}" >/dev/null || upgrade_e2e_fail 'static-network-presence-probe'
  ! grep -F 'inspect --type container "${resource_id}" >/dev/null 2>&1 || continue' <<<"${implementation}" >/dev/null || upgrade_e2e_fail 'static-no-silent-container-inspect'
  grep -F 'upgrade_e2e_cleanup_all_pids' <<<"${cleanup_body}" >/dev/null || upgrade_e2e_fail 'static-best-effort-all-pids'
  grep -F 'cleanup_failed=1' <<<"${cleanup_body}" >/dev/null || upgrade_e2e_fail 'static-best-effort-cleanup-accumulator'
  grep -F 'upgrade_e2e_append_secret_value()' <<<"${implementation}" >/dev/null || upgrade_e2e_fail 'static-secret-derived-patterns'
  grep -F '.. | strings | @base64' <<<"${implementation}" >/dev/null || upgrade_e2e_fail 'static-secret-structured-members'
  grep -F 'MIME::Base64=decode_base64,encode_base64' <<<"${implementation}" >/dev/null || upgrade_e2e_fail 'static-secret-encoded-decoded-forms'
  grep -F 'launcher_secret_file_input_names=(' <<<"${implementation}" >/dev/null || upgrade_e2e_fail 'static-secret-file-inputs'
  grep -F 'LICENSE_SIGNER_REVOCATION_ATTEMPT_HMAC_KEY_BASE64' <<<"${implementation}" >/dev/null || upgrade_e2e_fail 'static-secret-license-hmac'
  grep -F 'pin_name=${LICENSE_PKCS11_PIN_ENV-}' <<<"${implementation}" >/dev/null || upgrade_e2e_fail 'static-secret-pkcs11-pin'
  grep -F 'API_KEY_PEPPER_BASE64' <<<"${implementation}" >/dev/null || upgrade_e2e_fail 'static-secret-api-pepper'
  grep -F 'UPGRADE_E2E_GENERATED_VALUES_JSON' <<<"${implementation}" >/dev/null || upgrade_e2e_fail 'static-secret-generated-values'
  grep -F 'my $hex = unpack("H*", $form)' <<<"${implementation}" >/dev/null || upgrade_e2e_fail 'static-secret-raw-bytes'
  grep -F 'encode_base64($bytes, "")' <<<"${implementation}" >/dev/null || upgrade_e2e_fail 'static-secret-base64-forms'
  grep -F 'tr{+/}{-_}' <<<"${implementation}" >/dev/null || upgrade_e2e_fail 'static-secret-base64url-forms'
  grep -F 'uc(unpack("H*", $bytes))' <<<"${implementation}" >/dev/null || upgrade_e2e_fail 'static-secret-hex-forms'
  grep -F 'length($bytes) > 0' <<<"${implementation}" >/dev/null || upgrade_e2e_fail 'static-secret-short-values'
  grep -F 'length($hex) >= 2' <<<"${implementation}" >/dev/null || upgrade_e2e_fail 'static-secret-one-byte-patterns'
  grep -F 'EDGE_DEPLOYMENT_NATS_CREDS_FILE PLUGIN_WEBHOOK_NATS_CREDS_FILE' <<<"${implementation}" >/dev/null || upgrade_e2e_fail 'static-secret-nats-credential-files'
  grep -F 'PACKAGE_COMMERCE_WORKER_NATS_CREDS_FILE' <<<"${implementation}" >/dev/null || upgrade_e2e_fail 'static-secret-package-nats-credential-file'
  grep -F 'CDNCA_NATS_URL' <<<"${implementation}" >/dev/null || upgrade_e2e_fail 'static-secret-nats-url'
  ! grep -F 'printf '\''%s\n'\'' "${!name}"' <<<"${implementation}" >/dev/null || upgrade_e2e_fail 'static-no-plaintext-pattern-output'
  grep -F 'upgrade_e2e_quiesce_writers' <<<"${implementation}" >/dev/null || upgrade_e2e_fail 'static-secret-scan-quiesced'
  grep -F 'upgrade_e2e_register_pid()' <<<"${implementation}" >/dev/null || upgrade_e2e_fail 'static-pid-registration'
  grep -F 'upgrade_e2e_process_identity()' <<<"${implementation}" >/dev/null || upgrade_e2e_fail 'static-pid-start-identity'
  grep -F 'registered_pid_executables+=("${executable}")' <<<"${implementation}" >/dev/null || upgrade_e2e_fail 'static-pid-executable-registration'
  grep -F 'registered_pid_markers+=("${WORK_DIR}")' <<<"${implementation}" >/dev/null || upgrade_e2e_fail 'static-pid-marker-registration'
  grep -F 'registered_pid_starts+=("${started}")' <<<"${implementation}" >/dev/null || upgrade_e2e_fail 'static-pid-start-registration'
  grep -F 'registered_pid_pgids+=("${pgid}")' <<<"${implementation}" >/dev/null || upgrade_e2e_fail 'static-pgid-registration'
  grep -F 'kill -TERM -- "-${pgid}"' <<<"${implementation}" >/dev/null || upgrade_e2e_fail 'static-process-group-term'
  grep -F 'kill -KILL -- "-${pgid}"' <<<"${implementation}" >/dev/null || upgrade_e2e_fail 'static-process-group-kill'
  grep -F 'setpgid(0, 0)' <<<"${implementation}" >/dev/null || upgrade_e2e_fail 'static-private-process-group'
  grep -F 'upgrade_e2e_reserve_task_identity' <<<"${initialize}" >/dev/null || upgrade_e2e_fail 'static-task-reservation'
  ! grep -F 'docker_arch=$(docker info' <<<"${implementation}" >/dev/null || upgrade_e2e_fail 'static-no-unbounded-docker-info'
  grep -F "docker_arch=\$(upgrade_e2e_timeout 20 docker info --format" <<<"${implementation}" >/dev/null || upgrade_e2e_fail 'static-bounded-docker-architecture'
  grep -F 'secret_scan_completed=1' <<<"${scan_body}" >/dev/null || upgrade_e2e_fail 'static-secret-scan-completed-state'
  grep -F '[ "${status}" -eq 0 ] && [ "${secret_scan_completed}" -eq 1 ]' <<<"${cleanup_body}" >/dev/null || upgrade_e2e_fail 'static-abnormal-workdir-retention'
  grep -F 'rmdir -- "${RESERVATION_DIR}"' <<<"${cleanup_body}" >/dev/null || upgrade_e2e_fail 'static-owned-reservation-release'
  grep -F 'upgrade_e2e_copy_regular_file()' <<<"${implementation}" >/dev/null || upgrade_e2e_fail 'static-safe-input-copy'
  grep -F 'upgrade_e2e_canonical_repo_file()' <<<"${implementation}" >/dev/null || upgrade_e2e_fail 'static-canonical-repo-input'
  grep -F 'upgrade_e2e_snapshot_release_inputs()' <<<"${implementation}" >/dev/null || upgrade_e2e_fail 'static-immutable-input-snapshot'
  grep -F 'upgrade_e2e_verify_live_inputs_unchanged()' <<<"${implementation}" >/dev/null || upgrade_e2e_fail 'static-live-input-after-check'
  grep -F 'GOWORK=off' <<<"${implementation}" >/dev/null || upgrade_e2e_fail 'static-snapshot-build-workspace'
  grep -F 'cd "${INPUT_SNAPSHOT_DIR}/repo/services/control-api"' <<<"${implementation}" >/dev/null || upgrade_e2e_fail 'static-build-from-snapshot'
  grep -F 'CONTROL_MIGRATION_SNAPSHOT_DIR' <<<"${implementation}" >/dev/null || upgrade_e2e_fail 'static-migrations-from-snapshot'
  grep -F 'NATS_RESOURCES_SNAPSHOT' <<<"${implementation}" >/dev/null || upgrade_e2e_fail 'static-config-from-snapshot'
  ! grep -F 'snapshot_excluded_files' <<<"${implementation}" >/dev/null || upgrade_e2e_fail 'static-no-broad-snapshot-secret-exclusions'
  grep -F 'CONTROL_INSTALLATION_KEY_SNAPSHOT' <<<"${scan_body}" >/dev/null || upgrade_e2e_fail 'static-installation-key-source-exclusion'
  grep -F 'CONTROL_ACTIVATION_CREDENTIAL_SNAPSHOT' <<<"${scan_body}" >/dev/null || upgrade_e2e_fail 'static-activation-source-exclusion'
  grep -F 'CONTROL_SIGNING_KEY_SNAPSHOT' <<<"${scan_body}" >/dev/null || upgrade_e2e_fail 'static-control-signing-source-exclusion'
  grep -F 'EDGE_SIGNING_KEY_SNAPSHOT' <<<"${scan_body}" >/dev/null || upgrade_e2e_fail 'static-edge-signing-source-exclusion'
  grep -F 'upgrade_e2e_system_lock_root()' <<<"${implementation}" >/dev/null || upgrade_e2e_fail 'static-system-user-lock-root'
  grep -F 'upgrade_e2e_verify_reservation_owner()' <<<"${implementation}" >/dev/null || upgrade_e2e_fail 'static-reservation-owner-identity'
  ! grep -F 'RESERVATION_DIR="${TMPDIR:-/tmp}' <<<"${implementation}" >/dev/null || upgrade_e2e_fail 'static-reservation-independent-tmpdir'
  grep -F 'candidate_pid_pgids+=("${pid}")' <<<"${implementation}" >/dev/null || upgrade_e2e_fail 'static-candidate-pgid-registration'
  grep -F 'UPGRADE_E2E_PROCESS_GROUP_MARKER=' <<<"${implementation}" >/dev/null || upgrade_e2e_fail 'static-process-group-marker'
  grep -F 'upgrade_e2e_terminate_candidate_group' <<<"${implementation}" >/dev/null || upgrade_e2e_fail 'static-failed-spawn-group-cleanup'
  grep -F 'pending_group_markers+=("${group_marker}")' <<<"${implementation}" >/dev/null || upgrade_e2e_fail 'static-pending-spawn-marker'
  grep -F 'upgrade_e2e_list_marker_processes()' <<<"${implementation}" >/dev/null || upgrade_e2e_fail 'static-pending-process-discovery'
  grep -F 'upgrade_e2e_cleanup_pending_groups || failure=1' <<<"${implementation}" >/dev/null || upgrade_e2e_fail 'static-pending-group-cleanup'
  grep -F '[ "${pgid}" != "${shell_pgid}" ]' <<<"${implementation}" >/dev/null || upgrade_e2e_fail 'static-no-parent-process-group-signal'
  grep -F 'upgrade_e2e_wait_status_is_reapable "${wait_status}" || return 1' <<<"${implementation}" >/dev/null || \
    upgrade_e2e_fail 'static-pending-signal-wait-policy'
  upgrade_e2e_wait_status_is_reapable 143 || upgrade_e2e_fail 'static-pending-term-wait-status'
  upgrade_e2e_wait_status_is_reapable 137 || upgrade_e2e_fail 'static-pending-kill-wait-status'
  if upgrade_e2e_wait_status_is_reapable 127; then
    upgrade_e2e_fail 'static-pending-unowned-wait-status'
  fi
  pending_line=$(grep -n -F 'pending_group_markers+=("${group_marker}")' <<<"${start_body}" | awk -F: 'NR==1 {print $1}')
  spawn_line=$(grep -n -F 'UPGRADE_E2E_PROCESS_GROUP_MARKER="${group_marker}" perl' <<<"${start_body}" | awk -F: 'NR==1 {print $1}')
  [ -n "${pending_line}" ] && [ -n "${spawn_line}" ] && [ "${pending_line}" -lt "${spawn_line}" ] || \
    upgrade_e2e_fail 'static-pending-marker-before-spawn'
  grep -F 'upgrade_e2e_list_process_group_members()' <<<"${implementation}" >/dev/null || upgrade_e2e_fail 'static-surviving-group-enumeration'
  grep -F 'upgrade_e2e_group_member_identity()' <<<"${implementation}" >/dev/null || upgrade_e2e_fail 'static-group-member-identity'
  grep -F 'upgrade_e2e_write_cleanup_evidence' <<<"${cleanup_body}" >/dev/null || upgrade_e2e_fail 'static-cleanup-evidence-before-delete'
  grep -F 'upgrade_e2e_probe_cleanup_absent' <<<"${cleanup_body}" >/dev/null || upgrade_e2e_fail 'static-post-delete-cleanup-probe'
  grep -F 'upgrade_e2e_restore_reservation_metadata >/dev/null 2>&1 || cleanup_probe_failed=1' <<<"${cleanup_body}" >/dev/null || \
    upgrade_e2e_fail 'static-reservation-restore-fail-closed'
  snapshot_line=$(grep -n -F 'upgrade_e2e_snapshot_preexisting_resources' <<<"${initialize}" | awk -F: 'NR==1 {print $1}')
  reservation_line=$(grep -n -F 'upgrade_e2e_reserve_task_identity' <<<"${initialize}" | awk -F: 'NR==1 {print $1}')
  work_dir_line=$(grep -n -F 'WORK_DIR="$(mktemp -d' <<<"${initialize}" | awk -F: 'NR==1 {print $1}')
  input_snapshot_line=$(grep -n -F 'upgrade_e2e_snapshot_release_inputs' <<<"${initialize}" | awk -F: 'NR==1 {print $1}')
  [ -n "${reservation_line}" ] && [ -n "${work_dir_line}" ] && [ -n "${input_snapshot_line}" ] && [ -n "${snapshot_line}" ] && \
    [ "${reservation_line}" -lt "${work_dir_line}" ] && [ "${work_dir_line}" -lt "${input_snapshot_line}" ] && \
    [ "${input_snapshot_line}" -lt "${snapshot_line}" ] || \
    upgrade_e2e_fail 'static-reservation-before-input-snapshot-before-docker-snapshot'
  capture_line=$(grep -n -F 'upgrade_e2e_capture_candidate_ports' <<<"${cleanup_body}" | awk -F: 'NR==1 {print $1}')
  edge_line=$(grep -n -F 'upgrade_e2e_remove_container_role edge' <<<"${cleanup_body}" | awk -F: 'NR==1 {print $1}')
  gateway_line=$(grep -n -F 'upgrade_e2e_remove_container_role gateway' <<<"${cleanup_body}" | awk -F: 'NR==1 {print $1}')
  control_line=$(grep -n -F 'upgrade_e2e_remove_container_role control' <<<"${cleanup_body}" | awk -F: 'NR==1 {print $1}')
  license_line=$(grep -n -F 'upgrade_e2e_remove_container_role license' <<<"${cleanup_body}" | awk -F: 'NR==1 {print $1}')
  proxy_line=$(grep -n -F 'upgrade_e2e_remove_container_role tls-proxy' <<<"${cleanup_body}" | awk -F: 'NR==1 {print $1}')
  nats_line=$(grep -n -F 'upgrade_e2e_remove_container_role nats' <<<"${cleanup_body}" | awk -F: 'NR==1 {print $1}')
  redis_line=$(grep -n -F 'upgrade_e2e_remove_container_role redis' <<<"${cleanup_body}" | awk -F: 'NR==1 {print $1}')
  postgres_line=$(grep -n -F 'upgrade_e2e_remove_container_role postgres' <<<"${cleanup_body}" | awk -F: 'NR==1 {print $1}')
  [ "${capture_line}" -lt "${edge_line}" ] && [ "${edge_line}" -lt "${gateway_line}" ] && \
    [ "${gateway_line}" -lt "${control_line}" ] && [ "${control_line}" -lt "${proxy_line}" ] && \
    [ "${proxy_line}" -lt "${license_line}" ] && [ "${license_line}" -lt "${nats_line}" ] && \
    [ "${nats_line}" -lt "${redis_line}" ] && [ "${redis_line}" -lt "${postgres_line}" ] || \
    upgrade_e2e_fail 'static-reverse-dependency-cleanup-order'
  quiesce_line=$(grep -n -F 'upgrade_e2e_quiesce_writers' <<<"${scan_body}" | awk -F: 'NR==1 {print $1}')
  enumerate_line=$(grep -n -F 'find "${WORK_DIR}" -type f' <<<"${scan_body}" | awk -F: 'NR==1 {print $1}')
  [ -n "${quiesce_line}" ] && [ -n "${enumerate_line}" ] && [ "${quiesce_line}" -lt "${enumerate_line}" ] || upgrade_e2e_fail 'static-quiesce-before-enumeration'
  evidence_line=$(grep -n -F 'upgrade_e2e_write_cleanup_evidence' <<<"${cleanup_body}" | awk -F: 'NR==1 {print $1}')
  work_delete_line=$(grep -n -F 'find "${WORK_DIR}" -depth -delete' <<<"${cleanup_body}" | awk -F: 'NR==1 {print $1}')
  post_delete_probe_line=$(grep -n -F 'upgrade_e2e_probe_cleanup_absent' <<<"${cleanup_body}" | awk -F: 'NR==1 {print $1}')
  reservation_release_line=$(grep -n -F 'rmdir -- "${RESERVATION_DIR}"' <<<"${cleanup_body}" | awk -F: 'NR==1 {print $1}')
  [ -n "${evidence_line}" ] && [ -n "${work_delete_line}" ] && [ -n "${post_delete_probe_line}" ] && \
    [ -n "${reservation_release_line}" ] && [ "${evidence_line}" -lt "${work_delete_line}" ] && \
    [ "${work_delete_line}" -lt "${post_delete_probe_line}" ] && [ "${post_delete_probe_line}" -lt "${reservation_release_line}" ] || \
    upgrade_e2e_fail 'static-probe-before-reservation-release'
  contract_line=$(grep -n -F 'upgrade_e2e_require_final_contract' <<<"${main}" | awk -F: 'NR==1 {print $1}')
  preflight_line=$(grep -n -F 'upgrade_e2e_preflight_external_inputs' <<<"${main}" | awk -F: 'NR==1 {print $1}')
  initialize_line=$(grep -n -F 'upgrade_e2e_initialize_task' <<<"${main}" | awk -F: 'NR==1 {print $1}')
  runtime_line=$(grep -n -F 'upgrade_e2e_require_runtime' <<<"${main}" | awk -F: 'NR==1 {print $1}')
  scenarios_line=$(grep -n -F 'upgrade_e2e_assert_scenarios' <<<"${main}" | awk -F: 'NR==1 {print $1}')
  final_nats_verify_line=$(grep -n -F 'upgrade_e2e_verify_nats_server_state' <<<"${main}" | awk -F: 'NR==1 {print $1}')
  live_verify_line=$(grep -n -F "upgrade_e2e_verify_live_inputs_unchanged || upgrade_e2e_fail 'live-input-drift-after-run'" <<<"${main}" | awk -F: 'NR==1 {print $1}')
  secret_scan_line=$(grep -n -F 'upgrade_e2e_secret_scan' <<<"${main}" | awk -F: 'NR==1 {print $1}')
  [ -n "${contract_line}" ] && [ -n "${preflight_line}" ] && [ -n "${initialize_line}" ] && [ -n "${runtime_line}" ] && \
    [ -n "${scenarios_line}" ] && [ -n "${final_nats_verify_line}" ] && [ -n "${live_verify_line}" ] && [ -n "${secret_scan_line}" ] && \
    [ "${contract_line}" -lt "${preflight_line}" ] && [ "${preflight_line}" -lt "${initialize_line}" ] && \
    [ "${initialize_line}" -lt "${runtime_line}" ] && \
    [ "${runtime_line}" -lt "${scenarios_line}" ] && [ "${scenarios_line}" -lt "${final_nats_verify_line}" ] && \
    [ "${final_nats_verify_line}" -lt "${live_verify_line}" ] && \
    [ "${live_verify_line}" -lt "${secret_scan_line}" ] || upgrade_e2e_fail 'static-main-phase-order'
  grep -F 'post-minus-pre' "${readme}" >/dev/null || upgrade_e2e_fail 'static-cleanup-ownership-doc'
  grep -F 'reverse dependency order' "${readme}" >/dev/null || upgrade_e2e_fail 'static-cleanup-order-doc'
  grep -F 'PPID=1' "${readme}" >/dev/null || upgrade_e2e_fail 'static-cleanup'
  grep -F '## Batched validation' "${readme}" >/dev/null || upgrade_e2e_fail 'static-batched-validation-doc'
  grep -F 'immutable input snapshot' "${readme}" >/dev/null || upgrade_e2e_fail 'static-input-snapshot-doc'
  grep -F 'full `agents/edge-agent/` tree' "${readme}" >/dev/null || upgrade_e2e_fail 'static-c-complete-set-doc'
  grep -F 'not a runtime pass' "${readme}" >/dev/null || upgrade_e2e_fail 'static-static-not-runtime-doc'
  grep -F 'exactly the supplied `linux/amd64` and `linux/arm64` native subjects' "${readme}" >/dev/null || \
    upgrade_e2e_fail 'static-systemd-native-subject-doc'
  grep -F 'two real BuildKit SLSA predicates' "${readme}" >/dev/null || \
    upgrade_e2e_fail 'static-systemd-attestation-doc'
  grep -F 'requires each raw manifest SHA-256 to equal that subject digest' "${readme}" >/dev/null || \
    upgrade_e2e_fail 'static-systemd-native-manifest-doc'
  grep -F 'image-supplied production installer' "${readme}" >/dev/null || \
    upgrade_e2e_fail 'static-systemd-runtime-layout-doc'
  grep -F 'socket-activated helper service must independently remain disabled and inactive' "${readme}" >/dev/null || \
    upgrade_e2e_fail 'static-systemd-unit-state-doc'
  grep -F 'first asks the helper to durably move that journal' "${readme}" >/dev/null || \
    upgrade_e2e_fail 'static-systemd-journal-boundary-doc'
  grep -F 'canonical per-user system lock' "${readme}" >/dev/null || upgrade_e2e_fail 'static-lock-namespace-doc'
  grep -F 'surviving process-group members' "${readme}" >/dev/null || upgrade_e2e_fail 'static-surviving-group-doc'
  grep -F 'UPGRADE_PROCESS_E2E PASS license_head=046 control_head=186' "${readme}" >/dev/null || \
    upgrade_e2e_fail 'static-final-migration-status-doc'
  grep -F 'EXTERNAL_INPUT_NAMES=(' "${prepare_inputs}" >/dev/null || upgrade_e2e_fail 'static-prepare-external-inputs'
  grep -F 'LOCAL_INPUT_NAMES=(' "${prepare_inputs}" >/dev/null || upgrade_e2e_fail 'static-prepare-local-inputs'
  grep -F 'missing-external-input' "${prepare_inputs}" >/dev/null || upgrade_e2e_fail 'static-prepare-external-fail-closed'
  grep -F 'sha256' "${prepare_inputs}" >/dev/null || upgrade_e2e_fail 'static-prepare-canonical-sha'
  grep -F 'chmod 0600' "${prepare_inputs}" >/dev/null || upgrade_e2e_fail 'static-prepare-owner-only-env'
  grep -F 'No secret values are printed' "${prepare_inputs}" >/dev/null || upgrade_e2e_fail 'static-prepare-no-secret-output'
  ! grep -E 'printf[^\n]*UPGRADE_E2E_SYSTEMD_(IMAGE|COSIGN|AMD64_SUBJECT|ARM64_SUBJECT)' "${prepare_inputs}" >/dev/null || \
    upgrade_e2e_fail 'static-prepare-no-fake-external-artifact'
  grep -F 'canonical version-2 template' "${readme}" >/dev/null || upgrade_e2e_fail 'static-edge-v2-template-doc'
  grep -F 'atomically published, task-owned identity directory' "${readme}" >/dev/null || \
    upgrade_e2e_fail 'static-edge-identity-doc'
  short_secret_patterns=$(printf 'a' | upgrade_e2e_append_secret_bytes /dev/stdout) || upgrade_e2e_fail 'static-short-secret-pattern-run'
  grep -Fx '61' <<<"${short_secret_patterns}" >/dev/null || upgrade_e2e_fail 'static-short-secret-raw-pattern'
  grep -Fx '59513d3d' <<<"${short_secret_patterns}" >/dev/null || upgrade_e2e_fail 'static-short-secret-base64-pattern'
  grep -Fx '3631' <<<"${short_secret_patterns}" >/dev/null || upgrade_e2e_fail 'static-short-secret-hex-pattern'
  decoded_secret_patterns=$(printf 'YQ==' | upgrade_e2e_append_secret_bytes /dev/stdout) || upgrade_e2e_fail 'static-decoded-secret-pattern-run'
  grep -Fx '61' <<<"${decoded_secret_patterns}" >/dev/null || upgrade_e2e_fail 'static-decoded-secret-raw-pattern'
  static_secret_source='/input-snapshot/runtime/control-installation-key.pem'
  upgrade_e2e_exact_path_in "${static_secret_source}" "${static_secret_source}" || \
    upgrade_e2e_fail 'static-secret-source-exact-accept'
  ! upgrade_e2e_exact_path_in '/work/logs/copied-secret' "${static_secret_source}" || \
    upgrade_e2e_fail 'static-secret-copy-not-excluded'
  printf 'UPGRADE_PROCESS_E2E_STATIC PASS\n'
}

for command in awk basename chmod cmp curl date dirname docker find go grep id jq lsof mkdir mktemp openssl perl ps rm rmdir sed shasum sleep sort stat tr wc; do
  upgrade_e2e_require_command "${command}"
done

if [ "${UPGRADE_E2E_STATIC_ONLY:-0}" = '1' ]; then
  upgrade_e2e_static_contract
  exit 0
fi
[ "${UPGRADE_E2E_STATIC_ONLY:-0}" = '0' ] || upgrade_e2e_fail 'invalid-static-only'
upgrade_e2e_require_command cosign

# The final contract gate precedes every task mutation. Initialization then snapshots every live input before Docker mutation.
upgrade_e2e_require_final_contract
upgrade_e2e_preflight_external_inputs

# Every external byte and contract is validated before this first task-owned mutation.
upgrade_e2e_initialize_task
upgrade_e2e_require_runtime
upgrade_e2e_create_foundation
upgrade_e2e_build_binaries
upgrade_e2e_generate_pki
upgrade_e2e_precreate_nats
upgrade_e2e_apply_migrations_and_fixtures
upgrade_e2e_start_four_processes
upgrade_e2e_assert_scenarios
upgrade_e2e_verify_nats_server_state
upgrade_e2e_verify_live_inputs_unchanged || upgrade_e2e_fail 'live-input-drift-after-run'
upgrade_e2e_secret_scan
printf 'UPGRADE_PROCESS_E2E PASS license_head=%s control_head=%s\n' "${LICENSE_MIGRATION_HEAD}" "${CONTROL_MIGRATION_HEAD}"
