#!/bin/sh
# shellcheck disable=SC2016 # Contract strings intentionally match unexpanded shell source.
set -eu

script_dir=$(cd -- "$(dirname -- "$0")" && pwd)
entrypoint="${script_dir}/run.sh"
repo_root=$(cd -- "${script_dir}/../../.." && pwd)
infra_compose="${repo_root}/compose.yaml"
nats_config="${repo_root}/infra/nats/analytics-server.conf"
gateway_template="${repo_root}/infra/helm/cdnca/templates/agent-gateway.yaml"
helm_values="${repo_root}/infra/helm/cdnca/values.yaml"
helm_schema="${repo_root}/infra/helm/cdnca/values.schema.json"

if [ ! -x "${entrypoint}" ]; then
  echo "RED process E2E entrypoint is missing or not executable: ${entrypoint}" >&2
  exit 1
fi

fixture_pg='{"Name":"/fixture-pg","State":{"Running":true,"Status":"running"},"NetworkSettings":{"Ports":{"5432/tcp":[{"HostIp":"127.0.0.1","HostPort":"31001"}]}}}'
fixture_clickhouse='{"Name":"/fixture-clickhouse","State":{"Running":true,"Status":"running"},"NetworkSettings":{"Ports":{"8123/tcp":[{"HostIp":"127.0.0.1","HostPort":"31002"}]}}}'
fixture_nats='{"Name":"/fixture-nats","State":{"Running":true,"Status":"running"},"NetworkSettings":{"Ports":{"4222/tcp":[{"HostIp":"127.0.0.1","HostPort":"31003"}]}}}'
fixture_edge_nats='{"Name":"/fixture-edge-nats","State":{"Running":true,"Status":"running"},"NetworkSettings":{"Ports":{"4222/tcp":[{"HostIp":"127.0.0.1","HostPort":"31004"}]}}}'
fixture_redis='{"Name":"/fixture-redis","State":{"Running":true,"Status":"running"},"NetworkSettings":{"Ports":{"6379/tcp":[{"HostIp":"127.0.0.1","HostPort":"31005"}]}}}'
canonical_fixture="[${fixture_redis},${fixture_pg},${fixture_edge_nats},${fixture_clickhouse},${fixture_nats}]"
ready_expected=$(printf 'ready\t31001\t31002\t31003\t31004\t31005')
portmap_red=0

expect_portmap() {
  label=$1
  expected=$2
  fixture=$3
  actual=''
  status=0
  actual=$(printf '%s\n' "${fixture}" | "${entrypoint}" --core-port-fixture 2>/dev/null) || status=$?
  if [ "${status}" -ne 0 ] || [ "${actual}" != "${expected}" ]; then
    echo "RED portmap fixture failed: ${label}" >&2
    return 1
  fi
}

expect_portmap canonical-order "${ready_expected}" "${canonical_fixture}" || portmap_red=$((portmap_red + 1))

retry_fixture=$(printf '%s' "${canonical_fixture}" | sed 's/"5432\/tcp":\[{"HostIp":"127.0.0.1","HostPort":"31001"}\]/"5432\/tcp":null/')
expect_portmap transient-binding "$(printf 'retry\tport-binding-not-ready')" "${retry_fixture}" || portmap_red=$((portmap_red + 1))

empty_binding_fixture=$(printf '%s' "${canonical_fixture}" | sed 's/"5432\/tcp":\[{"HostIp":"127.0.0.1","HostPort":"31001"}\]/"5432\/tcp":[]/')
expect_portmap transient-empty-binding "$(printf 'retry\tport-binding-not-ready')" "${empty_binding_fixture}" || portmap_red=$((portmap_red + 1))

stopped_fixture=$(printf '%s' "${canonical_fixture}" | sed 's/"Running":true/"Running":false/')
starting_fixture=$(printf '%s' "${canonical_fixture}" | sed 's/"Running":true,"Status":"running"/"Running":false,"Status":"created"/')
bad_ports_shape_fixture=$(printf '%s' "${canonical_fixture}" | sed 's/"Ports":{"5432\/tcp":\[{"HostIp":"127.0.0.1","HostPort":"31001"}\]}/"Ports":[]/')
missing_network_settings_fixture=$(printf '%s' "${canonical_fixture}" | sed 's/,"NetworkSettings":{"Ports":{"5432\/tcp":\[{"HostIp":"127.0.0.1","HostPort":"31001"}\]}}//')
missing_ports_fixture=$(printf '%s' "${canonical_fixture}" | sed 's/"NetworkSettings":{"Ports":{"5432\/tcp":\[{"HostIp":"127.0.0.1","HostPort":"31001"}\]}}/"NetworkSettings":{}/')
missing_binding_fixture=$(printf '%s' "${canonical_fixture}" | sed 's/"Ports":{"5432\/tcp":\[{"HostIp":"127.0.0.1","HostPort":"31001"}\]}/"Ports":{}/')
mixed_malformed_fixture=$(printf '%s' "${retry_fixture}" | sed 's/"8123\/tcp":\[{"HostIp":"127.0.0.1","HostPort":"31002"}\]/"8123\/tcp":"not-an-array"/')
shape_contract=0
expect_portmap starting-container "$(printf 'retry\tcontainer-starting')" "${starting_fixture}" || shape_contract=1
expect_portmap stopped-container "$(printf 'fatal\tcontainer-not-running')" "${stopped_fixture}" || shape_contract=1
expect_portmap ports-shape "$(printf 'fatal\tinspect-shape')" "${bad_ports_shape_fixture}" || shape_contract=1
expect_portmap missing-network-settings "$(printf 'fatal\tinspect-shape')" "${missing_network_settings_fixture}" || shape_contract=1
expect_portmap missing-ports "$(printf 'fatal\tinspect-shape')" "${missing_ports_fixture}" || shape_contract=1
expect_portmap missing-binding "$(printf 'fatal\tbinding-shape')" "${missing_binding_fixture}" || shape_contract=1
expect_portmap mixed-pending-malformed "$(printf 'fatal\tbinding-shape')" "${mixed_malformed_fixture}" || shape_contract=1

missing_name_fixture="[${fixture_pg},${fixture_clickhouse},${fixture_nats},${fixture_edge_nats}]"
duplicate_name_fixture="[${fixture_pg},${fixture_clickhouse},${fixture_nats},${fixture_edge_nats},${fixture_redis},${fixture_redis}]"
name_contract=0
expect_portmap missing-name "$(printf 'fatal\tcontainer-name-cardinality')" "${missing_name_fixture}" || name_contract=1
expect_portmap duplicate-name "$(printf 'fatal\tcontainer-name-cardinality')" "${duplicate_name_fixture}" || name_contract=1
[ "${name_contract}" -eq 0 ] || portmap_red=$((portmap_red + 1))

bad_ip_fixture=$(printf '%s' "${canonical_fixture}" | sed 's/"HostIp":"127.0.0.1"/"HostIp":"0.0.0.0"/')
bad_range_fixture=$(printf '%s' "${canonical_fixture}" | sed 's/"HostPort":"31001"/"HostPort":"65536"/')
zero_port_fixture=$(printf '%s' "${canonical_fixture}" | sed 's/"HostPort":"31001"/"HostPort":"0"/')
noncanonical_port_fixture=$(printf '%s' "${canonical_fixture}" | sed 's/"HostPort":"31001"/"HostPort":"031001"/')
missing_host_port_fixture=$(printf '%s' "${canonical_fixture}" | sed 's/"HostPort":"31001"/"HostPort":null/')
duplicate_port_fixture=$(printf '%s' "${canonical_fixture}" | sed 's/"HostPort":"31002"/"HostPort":"31001"/')
port_contract=0
expect_portmap host-ip "$(printf 'fatal\thost-ip-mismatch')" "${bad_ip_fixture}" || port_contract=1
expect_portmap host-port-range "$(printf 'fatal\thost-port-invalid')" "${bad_range_fixture}" || port_contract=1
expect_portmap host-port-zero "$(printf 'fatal\thost-port-invalid')" "${zero_port_fixture}" || port_contract=1
expect_portmap host-port-noncanonical "$(printf 'fatal\thost-port-invalid')" "${noncanonical_port_fixture}" || port_contract=1
expect_portmap host-port-missing "$(printf 'fatal\thost-port-invalid')" "${missing_host_port_fixture}" || port_contract=1
expect_portmap host-port-unique "$(printf 'fatal\thost-port-duplicate')" "${duplicate_port_fixture}" || port_contract=1

for bounded_required in \
  'core-port-inspect.safe.json' \
  'obs_e2e_capture_core_port_snapshot "${safe_file}" "${inspect_timeout}"' \
  'inspect_timeout=$((remaining_seconds - 1))' \
  'obs_e2e_docker_timeout "${timeout_seconds}" inspect' \
  'deadline_epoch=$(( $(date +%s) + 15 ))' \
  'port-binding-not-ready' \
  'core-port-mapping-timeout'
do
  if ! grep -F -- "${bounded_required}" "${entrypoint}" >/dev/null; then
    echo "RED portmap bounded reader missing: ${bounded_required}" >&2
    portmap_red=$((portmap_red + 1))
    break
  fi
done

for nats_password in preprovision_password runtime_password publisher_password; do
  if ! grep -F -- "${nats_password}=\"obs_\$(obs_e2e_timeout 10 openssl rand -hex 24)\"" \
    "${entrypoint}" >/dev/null; then
    echo "RED NATS password lacks a parser-safe alphabetic prefix: ${nats_password}" >&2
    portmap_red=$((portmap_red + 1))
  fi
done

for required_identity in \
  'NATS_CONTROL_CONSUMER_USERNAME=runtime' \
  'NATS_CONTROL_CONSUMER_PASSWORD="${runtime_password}"' \
  'NATS_GATEWAY_PUBLISHER_USERNAME=publisher' \
  'NATS_GATEWAY_PUBLISHER_PASSWORD="${publisher_password}"'; do
  if ! grep -F -- "${required_identity}" "${entrypoint}" >/dev/null; then
    echo "RED process E2E omits dedicated analytics identity: ${required_identity%%=*}" >&2
    portmap_red=$((portmap_red + 1))
  fi
done
for legacy_identity in NATS_RUNTIME_USERNAME NATS_RUNTIME_PASSWORD NATS_PUBLISHER_USERNAME NATS_PUBLISHER_PASSWORD; do
  if grep -F -- "${legacy_identity}" "${entrypoint}" "${infra_compose}" "${nats_config}" >/dev/null; then
    echo "RED legacy analytics workload identity remains: ${legacy_identity}" >&2
    portmap_red=$((portmap_red + 1))
  fi
done

core_diagnostic_start=$(grep -n '^obs_e2e_emit_core_container_diagnostics()' "${entrypoint}" | sed -n '1s/:.*//p')
core_diagnostic_end=$(grep -n '^obs_e2e_capture_edge_nats_state()' "${entrypoint}" | sed -n '1s/:.*//p')
core_diagnostic_call=$(grep -n '^  obs_e2e_emit_core_container_diagnostics "${core_port_failure_stage}"' \
  "${entrypoint}" | sed -n '1s/:.*//p')
core_port_fail=$(grep -n '^  obs_e2e_fail "${core_port_failure_stage}"' "${entrypoint}" | sed -n '1s/:.*//p')
if [ -z "${core_diagnostic_start}" ] || [ -z "${core_diagnostic_end}" ] || \
  [ -z "${core_diagnostic_call}" ] || [ -z "${core_port_fail}" ] || \
  [ "${core_diagnostic_start}" -ge "${core_diagnostic_end}" ] || \
  [ "${core_diagnostic_call}" -ge "${core_port_fail}" ]; then
  echo 'RED exited core-container diagnostics must run before cleanup-triggering failure' >&2
  portmap_red=$((portmap_red + 1))
else
  core_diagnostic_block=$(sed -n "${core_diagnostic_start},${core_diagnostic_end}p" "${entrypoint}")
  for diagnostic_required in \
    '"Id":{{json .Id}}' \
    '"Name":{{json .Name}}' \
    '"Owner":{{json (index .Config.Labels "cdnca.obs-process-e2e")}}' \
    '.Name == $name and .Owner == $owner' \
    '.State.Running == false and (.State.Status == "exited" or .State.Status == "dead")' \
    'logs --tail 80 --timestamps "${container_id}"' \
    'obs_e2e_sanitize_diagnostic_stream' \
    'ANALYTICS_PROCESS_E2E_CORE_CONTAINER_LOG'
  do
    if ! printf '%s\n' "${core_diagnostic_block}" | grep -F -- "${diagnostic_required}" >/dev/null; then
      echo "RED core-container diagnostic contract missing: ${diagnostic_required}" >&2
      portmap_red=$((portmap_red + 1))
    fi
  done
  if printf '%s\n' "${core_diagnostic_block}" | grep -F '.Config.Env' >/dev/null; then
    echo 'RED core-container diagnostics expose raw container environment' >&2
    portmap_red=$((portmap_red + 1))
  fi
fi

if grep -F "last_reason='inspect-or-projection-unavailable'" "${entrypoint}" >/dev/null || \
  ! grep -F "reason=inspect-or-projection-unavailable" "${entrypoint}" >/dev/null; then
  echo 'RED portmap must fail closed immediately on inspect errors' >&2
  shape_contract=1
fi
if ! grep -F '($host_ports | map(tonumber) | unique | length) != 5' "${entrypoint}" >/dev/null; then
  echo 'RED portmap must compare canonical numeric ports' >&2
  port_contract=1
fi
[ "${shape_contract}" -eq 0 ] || portmap_red=$((portmap_red + 1))
[ "${port_contract}" -eq 0 ] || portmap_red=$((portmap_red + 1))

secret_fixture=$(printf '%s' "${canonical_fixture}" | sed 's/{"Name":"\/fixture-pg"/{"Config":{"Env":["PASSWORD=portmap-secret-sentinel"]},"Name":"\/fixture-pg"/')
secret_output=''
secret_status=0
secret_output=$(printf '%s\n' "${secret_fixture}" | "${entrypoint}" --core-port-fixture 2>&1) || secret_status=$?
if [ "${secret_status}" -ne 0 ] || [ "${secret_output}" != "${ready_expected}" ] || \
  printf '%s' "${secret_output}" | grep -F 'portmap-secret-sentinel' >/dev/null || \
  ! grep -F '"Name":{{json .Name}}' "${entrypoint}" >/dev/null || \
  ! grep -F '"Running":{{json .State.Running}}' "${entrypoint}" >/dev/null || \
  ! grep -F '"Ports":{{json .NetworkSettings.Ports}}' "${entrypoint}" >/dev/null; then
  echo 'RED portmap safe projection leaks or is missing' >&2
  portmap_red=$((portmap_red + 1))
fi

ownership_red=0
for ownership_required in \
  'readonly DISPLAY_TASK_ID="obs-process-e2e-${task_suffix}"' \
  'ownership_random="$(obs_e2e_timeout 10 openssl rand -hex 16)"' \
  'readonly OWNERSHIP_TOKEN="$$-${ownership_random}"' \
  'readonly TASK_ID="obs-process-e2e-${OWNERSHIP_TOKEN}"' \
  'readonly RESOURCE_LABEL_KEY=' \
  'readonly RESOURCE_LABEL="${RESOURCE_LABEL_KEY}=${TASK_ID}"' \
  'container_inspect="$(obs_e2e_docker_timeout 5 inspect' \
  '[ "${container_owner}" = "${TASK_ID}" ] || {'
do
  if ! grep -F -- "${ownership_required}" "${entrypoint}" >/dev/null; then
    echo "RED process E2E ownership isolation missing: ${ownership_required}" >&2
    ownership_red=$((ownership_red + 1))
    break
  fi
done
if grep -F 'readonly TASK_ID="obs-process-e2e-${task_suffix}"' "${entrypoint}" >/dev/null; then
  echo 'RED caller task suffix still controls cleanup ownership' >&2
  ownership_red=$((ownership_red + 1))
fi
[ "${ownership_red}" -eq 0 ] || portmap_red=$((portmap_red + 1))

cleanup_ownership_red=0
for cleanup_required in \
  'ps -aq --no-trunc --filter "label=${RESOURCE_LABEL}"' \
  '"Owner":{{json (index .Config.Labels "cdnca.obs-process-e2e")}}' \
  '[ "${inspected_container_id}" = "${container_id}" ] || {' \
  '[ "${container_owner}" = "${TASK_ID}" ] || {' \
  'network ls -q --no-trunc --filter "label=${RESOURCE_LABEL}"' \
  '[ "${inspected_network_id}" = "${network_id}" ] || {' \
  '[ "${inspected_network_name}" = "${NETWORK_NAME}" ] || {' \
  '[ "${network_owner}" = "${TASK_ID}" ] || {' \
  "obs_e2e_cleanup_refused 'container-identity-mismatch'" \
  "obs_e2e_cleanup_refused 'container-ownership-mismatch'" \
  "obs_e2e_cleanup_refused 'network-identity-mismatch'" \
  "obs_e2e_cleanup_refused 'network-ownership-mismatch'"
do
  if ! grep -F -- "${cleanup_required}" "${entrypoint}" >/dev/null; then
    echo "RED cleanup ownership verification missing: ${cleanup_required}" >&2
    cleanup_ownership_red=1
    break
  fi
done
if grep -F 'rm -f "${REDIS_CONTAINER}"' "${entrypoint}" >/dev/null || \
  grep -F 'network rm "${NETWORK_NAME}"' "${entrypoint}" >/dev/null; then
  echo 'RED cleanup deletes a named resource before exact ownership inspection' >&2
  cleanup_ownership_red=1
fi
[ "${cleanup_ownership_red}" -eq 0 ] || portmap_red=$((portmap_red + 1))

cleanup_name_red=0
for cleanup_name_required in \
  'case "${inspected_container_name}" in' \
  '"/${POSTGRES_CONTAINER}"|"/${CLICKHOUSE_CONTAINER}"|' \
  '"/${EDGE_NATS_CONTAINER}"|"/${NATS_CONTAINER}"|"/${REDIS_CONTAINER}"|' \
  '"/${EDGE_NATS_PROBE_CONTAINER}")' \
  "obs_e2e_cleanup_refused 'container-name-mismatch'"
do
  if ! grep -F -- "${cleanup_name_required}" "${entrypoint}" >/dev/null; then
    echo "RED cleanup exact container-name binding missing: ${cleanup_name_required}" >&2
    cleanup_name_red=1
    break
  fi
done
container_name_guard_line=$(grep -n "container-name-mismatch'" "${entrypoint}" | sed -n '1s/:.*//p')
container_delete_admit_line=$(grep -n 'owned_container_ids+=("${inspected_container_id}")' "${entrypoint}" | sed -n '1s/:.*//p')
if [ -z "${container_name_guard_line}" ] || [ -z "${container_delete_admit_line}" ] || \
  [ "${container_name_guard_line}" -ge "${container_delete_admit_line}" ]; then
  echo 'RED cleanup admits a container ID before exact expected-name verification' >&2
  cleanup_name_red=1
fi
[ "${cleanup_name_red}" -eq 0 ] || portmap_red=$((portmap_red + 1))

if [ "${portmap_red}" -ne 0 ]; then
  echo "RED process E2E portmap fixture contract failures=${portmap_red}" >&2
  exit 1
fi

edge_state_running='{"Running":true,"Status":"running","ExitCode":0,"OOMKilled":false,"Error":""}'
edge_info_response='{"type":"io.nats.jetstream.api.v1.account_info_response","memory":0,"storage":0,"streams":0,"consumers":0,"limits":{"max_memory":-1,"max_storage":-1,"max_streams":-1,"max_consumers":-1,"max_ack_pending":-1,"memory_max_stream_bytes":-1,"storage_max_stream_bytes":-1,"max_bytes_required":false},"api":{"level":1,"total":0,"errors":0}}'
edge_ready_fixture=$(jq -cn --arg response "${edge_info_response}" --argjson state "${edge_state_running}" \
  '{probe_exit:0,probe_stderr:"",response:$response,state:$state,store_writable:true}')
edge_readiness_red=0

edge_fixture_with_response() {
  jq -cn --arg response "$1" --argjson state "${edge_state_running}" \
    '{probe_exit:0,probe_stderr:"",response:$response,state:$state,store_writable:true}'
}

expect_edge_readiness() {
  label=$1
  expected=$2
  fixture=$3
  actual=''
  status=0
  actual=$(printf '%s\n' "${fixture}" | "${entrypoint}" --edge-nats-readiness-fixture 2>/dev/null) || status=$?
  if [ "${status}" -ne 0 ] || [ "${actual}" != "${expected}" ]; then
    echo "RED edge NATS readiness fixture failed: ${label}" >&2
    return 1
  fi
}

expect_edge_readiness ready "$(printf 'ready\tok')" "${edge_ready_fixture}" || edge_readiness_red=$((edge_readiness_red + 1))
expect_edge_readiness stopped "$(printf 'fatal\tcontainer-stopped')" \
  "$(printf '%s' "${edge_ready_fixture}" | sed 's/"Running":true/"Running":false/')" || \
  edge_readiness_red=$((edge_readiness_red + 1))
expect_edge_readiness oom "$(printf 'fatal\tcontainer-oom')" \
  "$(printf '%s' "${edge_ready_fixture}" | sed 's/"Running":true/"Running":false/; s/"OOMKilled":false/"OOMKilled":true/')" || \
  edge_readiness_red=$((edge_readiness_red + 1))
expect_edge_readiness store "$(printf 'fatal\tstore-unwritable')" \
  "$(printf '%s' "${edge_ready_fixture}" | sed 's/"store_writable":true/"store_writable":false/')" || \
  edge_readiness_red=$((edge_readiness_red + 1))
for probe_case in \
  'dns|lookup edge-nats: no such host|dns' \
  'connect|connection refused|connect' \
  'no-responder|nats: no responders available for request|no-responder'
do
  label=${probe_case%%|*}
  remainder=${probe_case#*|}
  probe_stderr=${remainder%%|*}
  expected_reason=${remainder##*|}
  fixture=$(printf '%s' "${edge_ready_fixture}" | sed \
    "s/\"probe_exit\":0/\"probe_exit\":1/; s/\"probe_stderr\":\"\"/\"probe_stderr\":\"${probe_stderr}\"/")
  expect_edge_readiness "${label}" "$(printf 'retry\t%s' "${expected_reason}")" "${fixture}" || \
    edge_readiness_red=$((edge_readiness_red + 1))
done
expect_edge_readiness js-api "$(printf 'fatal\tjs-api-error')" \
  "$(edge_fixture_with_response '{"type":"io.nats.jetstream.api.v1.account_info_response","error":{"code":503}}')" || \
  edge_readiness_red=$((edge_readiness_red + 1))
expect_edge_readiness malformed "$(printf 'fatal\tmalformed')" \
  "$(edge_fixture_with_response 'not-json')" || \
  edge_readiness_red=$((edge_readiness_red + 1))
expect_edge_readiness empty-info "$(printf 'fatal\tjs-info-invalid')" \
  "$(edge_fixture_with_response '{}')" || edge_readiness_red=$((edge_readiness_red + 1))
expect_edge_readiness wrong-info-type "$(printf 'fatal\tjs-info-invalid')" \
  "$(edge_fixture_with_response "$(printf '%s' "${edge_info_response}" | jq -c '.type="wrong"')")" || \
  edge_readiness_red=$((edge_readiness_red + 1))
expect_edge_readiness missing-info-fields "$(printf 'fatal\tjs-info-invalid')" \
  "$(edge_fixture_with_response "$(printf '%s' "${edge_info_response}" | jq -c 'del(.api)')")" || \
  edge_readiness_red=$((edge_readiness_red + 1))
expect_edge_readiness wrong-info-field-type "$(printf 'fatal\tjs-info-invalid')" \
  "$(edge_fixture_with_response "$(printf '%s' "${edge_info_response}" | jq -c '.streams="0"')")" || \
  edge_readiness_red=$((edge_readiness_red + 1))
expect_edge_readiness wrong-api-level "$(printf 'fatal\tjs-info-invalid')" \
  "$(edge_fixture_with_response "$(printf '%s' "${edge_info_response}" | jq -c '.api.level=0')")" || \
  edge_readiness_red=$((edge_readiness_red + 1))
expect_edge_readiness zero-limits "$(printf 'ready\tok')" \
  "$(edge_fixture_with_response "$(printf '%s' "${edge_info_response}" | jq -c '.limits |= with_entries(if (.value | type) == "number" then .value = 0 else . end)')")" || \
  edge_readiness_red=$((edge_readiness_red + 1))
expect_edge_readiness positive-limits "$(printf 'ready\tok')" \
  "$(edge_fixture_with_response "$(printf '%s' "${edge_info_response}" | jq -c '.limits |= with_entries(if (.value | type) == "number" then .value = 1 else . end)')")" || \
  edge_readiness_red=$((edge_readiness_red + 1))
for limit_field in \
  max_memory \
  max_storage \
  max_streams \
  max_consumers \
  max_ack_pending \
  memory_max_stream_bytes \
  storage_max_stream_bytes
do
  invalid_limit_response=$(printf '%s' "${edge_info_response}" | \
    jq -c --arg field "${limit_field}" '.limits[$field] = -2')
  expect_edge_readiness "limit-below-unlimited-${limit_field}" "$(printf 'fatal\tjs-info-invalid')" \
    "$(edge_fixture_with_response "${invalid_limit_response}")" || \
    edge_readiness_red=$((edge_readiness_red + 1))
done

if grep -F 'if [ "${1:-}" = --edge-nats-uid-fixture ]' "${entrypoint}" >/dev/null; then
  for uid_case in \
    'ready|1000|1000|ready|1000' \
    'invalid-leading-zero|01000|1000|fatal|runtime-uid-invalid' \
    'invalid-negative|-1|-1|fatal|runtime-uid-invalid' \
    'mismatch|1000|1001|fatal|runtime-uid-mismatch'
  do
    label=${uid_case%%|*}
    remainder=${uid_case#*|}
    pid1_uid=${remainder%%|*}
    remainder=${remainder#*|}
    exec_uid=${remainder%%|*}
    remainder=${remainder#*|}
    expected_state=${remainder%%|*}
    expected_reason=${remainder##*|}
    actual=''
    status=0
    actual=$("${entrypoint}" --edge-nats-uid-fixture "${pid1_uid}" "${exec_uid}" 2>/dev/null) || status=$?
    if [ "${status}" -ne 0 ] || \
      [ "${actual}" != "$(printf '%s\t%s' "${expected_state}" "${expected_reason}")" ]; then
      echo "RED edge NATS runtime UID fixture failed: ${label}" >&2
      edge_readiness_red=$((edge_readiness_red + 1))
    fi
  done
else
  echo 'RED edge NATS runtime UID fixture entrypoint is missing' >&2
  edge_readiness_red=$((edge_readiness_red + 1))
fi

if grep -F 'if [ "${1:-}" = --edge-nats-deadline-fixture ]' "${entrypoint}" >/dev/null; then
  for deadline_case in \
    'start-cap|41000000000|1000000000|5000|5000' \
    'one-millisecond|41000000000|40999000000|5000|1' \
    'sub-millisecond|41000000000|40999000001|5000|expired' \
    'at-deadline|41000000000|41000000000|5000|expired'
  do
    label=${deadline_case%%|*}
    remainder=${deadline_case#*|}
    deadline_nanos=${remainder%%|*}
    remainder=${remainder#*|}
    now_nanos=${remainder%%|*}
    remainder=${remainder#*|}
    cap_millis=${remainder%%|*}
    expected=${remainder##*|}
    actual=''
    status=0
    actual=$("${entrypoint}" --edge-nats-deadline-fixture \
      "${deadline_nanos}" "${now_nanos}" "${cap_millis}" 2>/dev/null) || status=$?
    if [ "${status}" -ne 0 ] || [ "${actual}" != "${expected}" ]; then
      echo "RED edge NATS deadline fixture failed: ${label}" >&2
      edge_readiness_red=$((edge_readiness_red + 1))
    fi
  done
else
  echo 'RED edge NATS deadline fixture entrypoint is missing' >&2
  edge_readiness_red=$((edge_readiness_red + 1))
fi

for edge_readiness_required in \
  'readonly EDGE_NATS_PROBE_CONTAINER="${TASK_ID}-edge-nats-probe"' \
  "readonly EDGE_NATS_NETWORK_ALIAS='edge-nats'" \
  "readonly EDGE_NATS_PROBE_NETWORK_ALIAS='edge-nats-probe'" \
  'edge_nats_probe_container_id=' \
  '--network "${NETWORK_NAME}" --network-alias "${EDGE_NATS_NETWORK_ALIAS}"' \
  '--name "${EDGE_NATS_PROBE_CONTAINER}"' \
  '--network-alias "${EDGE_NATS_PROBE_NETWORK_ALIAS}"' \
  '-e NATS_URL="nats://${EDGE_NATS_NETWORK_ALIAS}:4222"' \
  'obs_e2e_verify_edge_nats_store_writable' \
  'clock_gettime(CLOCK_MONOTONIC)' \
  'edge_nats_deadline_nanos=$(( $(obs_e2e_monotonic_nanos) + 40000000000 ))' \
  'obs_e2e_deadline_timeout_millis' \
  'obs_e2e_docker_timeout_millis' \
  'diagnostics-skipped-deadline' \
  'obs_e2e_emit_edge_nats_diagnostics "${edge_nats_last_reason}" "${edge_nats_deadline_nanos}"' \
  '/proc/1/status' \
  '--user "${edge_nats_pid1_euid}"' \
  'id -u' \
  'runtime-uid-invalid' \
  'runtime-uid-mismatch' \
  'io.nats.jetstream.api.v1.account_info_response' \
  'js-info-invalid' \
  'container-stopped' \
  'container-oom' \
  'store-unwritable' \
  'no-responder' \
  'js-api-error' \
  'malformed' \
  '"RestartCount":{{json .RestartCount}}' \
  'logs --tail 80 --timestamps' \
  'obs_e2e_sanitize_diagnostic_stream' \
  'obs_e2e_emit_process_diagnostic resource-absent "${WORK_DIR}/resource-absent.log"' \
  'EDGE_NATS_PROBE_STDERR_RAW' \
  'rm -f -- "${EDGE_NATS_PROBE_STDERR_RAW}"'
do
  if ! grep -F -- "${edge_readiness_required}" "${entrypoint}" >/dev/null; then
    echo "RED edge NATS readiness contract missing: ${edge_readiness_required}" >&2
    edge_readiness_red=$((edge_readiness_red + 1))
  fi
done
if grep -F '.Config.Env' "${entrypoint}" >/dev/null || \
  grep -F 'inspect "${EDGE_NATS_CONTAINER}"' "${entrypoint}" >/dev/null; then
  echo 'RED edge NATS diagnostics expose raw inspect or environment state' >&2
  edge_readiness_red=$((edge_readiness_red + 1))
fi
edge_nats_sleep_program=$(sed -n \
  "s/^[[:space:]]*perl -MTime::HiRes=usleep -e '\\([^']*\\)' \"\\\${edge_nats_sleep_millis}\"$/\\1/p" \
  "${entrypoint}")
if [ -z "${edge_nats_sleep_program}" ] || \
  ! perl -MTime::HiRes=usleep -e "${edge_nats_sleep_program}" 1 >/dev/null 2>&1; then
  echo 'RED edge NATS millisecond sleep program must accept its positional argument' >&2
  edge_readiness_red=$((edge_readiness_red + 1))
fi
[ "${edge_readiness_red}" -eq 0 ] || {
  echo "RED edge NATS readiness contract failures=${edge_readiness_red}" >&2
  exit 1
}

for required in \
  'nats:2.11.4-alpine' \
  'clickhouse/clickhouse-server:25.3.6.56-alpine' \
  'postgres:17.9-alpine' \
  'infra/nats/analytics-preprovision.sh' \
  'infra/nats/analytics-server.conf' \
  './cmd/control-api' \
  'migrate up' \
  '/health/detail' \
  'obs_e2e_timeout' \
  'obs_e2e_docker_timeout 55' \
  'obs_e2e_timeout 30 openssl req' \
  'obs_e2e_timeout 10 ruby' \
  'setpgid(0, 0)' \
  'obs_e2e_docker_count' \
  'container_residual=-1' \
  'obs_e2e_docker_timeout 5 inspect' \
  'core-port-mapping' \
  'docker-timeout-clickhouse-migration' \
  '--connect-timeout 2 --max-time 5' \
  "absent_pid=''" \
  "mismatch_pid=''" \
  "control_pid=''" \
  "gateway_pid=''" \
  'trap obs_e2e_cleanup EXIT' \
  "--label \"\${RESOURCE_LABEL}\"" \
  'control-api-graceful-stop-timeout' \
  'for command in cat date docker' \
  'local deadline_epoch current_epoch timeout_seconds' \
  "deadline_epoch=\$(( \$(date +%s) + 40 ))" \
  '/proc/1/cmdline' \
  'clickhouse-final-pid1' \
  'CREATE ROLE cdnca_control_app NOLOGIN' \
  'CREATE ROLE cdnca_plugin_webhook_runtime NOLOGIN' \
  'CREATE SCHEMA cdnca_e2e AUTHORIZATION cdnca' \
  'postgres-database-baseline' \
  'postgres-database-baseline-diagnostic-query' \
  'postgres-database-baseline-diagnostic-shape' \
  'ANALYTICS_PROCESS_E2E_UNKNOWN reason=postgres-database-baseline predicates=%s' \
  "('schema-acl-default'," \
  "('role-schema-acl-absent'," \
  "search_path=\${CONTROL_DATABASE_SCHEMA}" \
  'CONTROL_INSTALLATION_ID=70000000-0000-4000-8000-000000000002' \
  'API_KEY_PEPPER_VERSION=legacy-v1' \
  'IMPERSONATION_HMAC_KEY_BASE64=' \
  'OBSERVABILITY_LOG_CURSOR_KEY_BASE64=' \
  'MFA_ENABLED=true' \
  'MFA_ENCRYPTION_ACTIVE_KEY_ID=obs-process-e2e' \
  'MFA_ENCRYPTION_KEYS_JSON=' \
  'ORIGIN_AUTH_RUNTIME_ENABLED=false' \
  'EDGE_PUBLISH_RUNTIME_ENABLED=false' \
  'CDNCA_SECURITY_ACTIVATION_ENABLED=false' \
  'env -i "PATH=${PATH}" "TMPDIR=${TMPDIR:-/tmp}" "${control_env[@]}"' \
  'ANALYTICS_INGEST_ENABLED=true' \
  'ANALYTICS_INGEST_ISOLATION_WRAPPING_KEY_BASE64=' \
  'CONTROL_INTERNAL_SERVER_CERT_FILE=' \
  'CDNCA_GATEWAY_STARTUP_TIMEOUT=5s' \
  'SHUTDOWN_PERIOD=10s' \
  '090_package_offer_publication' \
  '091_notification_control_idempotency_receipts' \
  'migration-090-release-head-digest' \
  'migration-091-release-head-digest' \
  'package_offer_publication_090_integration_test.go' \
  'notification_control_idempotency_receipts_091_integration_test.go' \
  'd1c7490b78a9298e0380ec7a8258fbdbebb4a24c7ece1870a1b38f2dc6e4c5b0' \
  '1d1dc589b4dc08e04f72e61a459b0fd4096dab53f3135f55d146c02e1e6e3eb0' \
  '6b6004991baebda2e246edf287ef18ec2f441586782764541e55e02add7ba198' \
  '87ae89e034d20d2794e28ecc2a5e01968d3246fa382bf794482665a7f0317f79' \
  '179b3a7c2324403f4f1af4cd10b3c8dd27a584f6a797a1f06a6f7c32acb71c43' \
  '599a710f62eb6b8847449968ba09964eeec971974c85a7bea1766271f2b112ec' \
  'AGENT_COMMANDS' \
  'cdnca.agent.commands.*' \
  'cdnca.agent.commands.upgrade.*' \
  'cdnca.agent.commands.drain.*' \
  'cdnca.agent.commands.gateway-port.*' \
  'AGENT_DEPLOYMENT_STATUS' \
  'cdnca.agent.deployment-status.*' \
  'cdnca.agent.deployment-status.generic-v2.*.*' \
  'cdnca.agent.deployment-status.terminal-receipt.*.*' \
  'cdnca.agent.deployment-status.terminal-receipt-confirmation.*.*' \
  'cdnca.agent.deployment-status.terminal-receipt-confirmation-index.*' \
  'cdnca.agent.deployment-status.upgrade-v2.*' \
  'cdnca.agent.deployment-status.upgrade-proof.pending.*' \
  'cdnca.agent.deployment-status.upgrade-proof.confirmed.*.*' \
  'cdnca.agent.deployment-status.upgrade-proof.completed.*.*.*' \
  'cdnca.agent.deployment-status.upgrade-proof.status.*.*' \
  'cdnca.agent.deployment-status.drain.*' \
  'cdnca.agent.deployment-status.gateway-port.*' \
  'AGENT_HEARTBEATS' \
  'cdnca.agent.heartbeats.*' \
  'NODE_MONITORING_COMMANDS' \
  'cdnca.agent.node-monitoring.commands.*' \
  'NODE_MONITORING_STATUS' \
  'cdnca.agent.node-monitoring.status.*' \
  'edge_analytics_ingest_stream=$(jq -cn' \
  'name:"ANALYTICS_INGEST_V1", subjects:["cdnca.analytics.ingest.v1.*"]' \
  'edge_cc_coordination_stream=$(jq -cn' \
  'name:"SECURITY_CC_COORDINATION_V1", subjects:["cdnca.security.cccoord.v1.*.*"]' \
  'edge_l4_sessions_stream=$(jq -cn' \
  'name:"L4_SESSIONS_INGEST_V1", subjects:["cdnca.l4.sessions.v1.*.*.*"]' \
  'obs_e2e_ensure_edge_stream ANALYTICS_INGEST_V1 "${edge_analytics_ingest_stream}"' \
  'obs_e2e_ensure_edge_stream SECURITY_CC_COORDINATION_V1 "${edge_cc_coordination_stream}"' \
  'obs_e2e_ensure_edge_stream L4_SESSIONS_INGEST_V1 "${edge_l4_sessions_stream}"' \
  'control_api_edge_status' \
  'control_api_node_metrics' \
  'filter_subjects:["cdnca.agent.deployment-status.*",' \
  'filter_subject:"cdnca.agent.node-monitoring.status.*"' \
  'retention:"limits"' \
  'discard:"old"' \
  'ack_wait:120000000000' \
  'max_deliver:-1' \
  'max_ack_pending:256' \
  'max_waiting:32' \
  'max_batch:1' \
  'max_expires:5000000000' \
  'edge-nats-readiness' \
  'edge-nats-stream-configuration-mismatch' \
  'edge-nats-consumer-configuration-mismatch' \
  'duplicate_physical_rows_before' \
  'duplicate_physical_rows_after' \
  'outage_consumer_fetch_observed' \
  'outage_consumer_redelivery_observed' \
  'outage_ack_floor_after' \
  'nats consumer info -j ANALYTICS_INGEST_V1 control_api_analytics_ingest_v1' \
  'secret_names=(' \
  'secret_values=(' \
  'secret_plaintext_hits=0' \
  'private_key_material' \
  'ANALYTICS_PROCESS_E2E_SUMMARY'
do
  if ! grep -F -- "${required}" "${entrypoint}" >/dev/null; then
    echo "RED process E2E entrypoint is missing contract: ${required}" >&2
    exit 1
  fi
done

node_ca_red=0
for node_ca_required in \
  'openssl genpkey -algorithm RSA' \
  '-pkeyopt rsa_keygen_bits:2048 -out "${WORK_DIR}/certs/node-ca.key"' \
  'chmod 0600 "${WORK_DIR}/certs/node-ca.key"' \
  "-subj '/CN=CDNCA OBS Process E2E Node CA'" \
  '-key "${WORK_DIR}/certs/node-ca.key" -out "${WORK_DIR}/certs/node-ca.crt"' \
  "-addext 'basicConstraints=critical,CA:TRUE,pathlen:0'" \
  "-addext 'keyUsage=critical,keyCertSign,cRLSign'" \
  "-addext 'subjectKeyIdentifier=hash'" \
  'NODE_CA_CERTIFICATE_CHAIN_FILE=${WORK_DIR}/certs/node-ca.crt' \
  'NODE_CA_PRIVATE_KEY_FILE=${WORK_DIR}/certs/node-ca.key' \
  '"${WORK_DIR}/certs/node-ca.key" -type f -delete'
do
  if ! grep -F -- "${node_ca_required}" "${entrypoint}" >/dev/null; then
    echo "RED dedicated Node CA contract missing: ${node_ca_required}" >&2
    node_ca_red=$((node_ca_red + 1))
  fi
done
if grep -F 'NODE_CA_CERTIFICATE_CHAIN_FILE=${WORK_DIR}/certs/ca.crt' "${entrypoint}" >/dev/null || \
  grep -F 'NODE_CA_PRIVATE_KEY_FILE=${WORK_DIR}/certs/ca.key' "${entrypoint}" >/dev/null; then
  echo 'RED Node CA reuses the generic gRPC CA material' >&2
  node_ca_red=$((node_ca_red + 1))
fi
[ "${node_ca_red}" -eq 0 ] || {
  echo "RED dedicated Node CA contract failures=${node_ca_red}" >&2
  exit 1
}

history_red=0
for history_required in \
  'control_installation_entitlement(singleton,installation_id,last_status,created_at,updated_at)' \
  'ON CONFLICT(singleton) DO NOTHING' \
  'SET search_path TO ${CONTROL_DATABASE_SCHEMA};' \
  'control_installation_state' \
  'obs_e2e_run_analytics_preprovision analytics-history-a' \
  'obs_e2e_capture_analytics_generation a' \
  'nats stream info -j ANALYTICS_INGEST_V1' \
  'nats consumer info -j ANALYTICS_INGEST_V1 control_api_analytics_ingest_v1' \
  '.created | select(type == "string" and length > 0)' \
  'Time.iso8601' \
  'to_r * 1_000_000_000' \
  'stream_created_unix_nano,consumer_created_unix_nano,history_epoch' \
  'history_start_sequence,history_start_at,legacy_baseline_kind' \
  'legacy_baseline_at,legacy_baseline_sha256' \
  'WITH clock AS (SELECT clock_timestamp() AS now)' \
  'broker_consumer_ack_floor,broker_stream_ack_floor,prepared_stream_floor' \
  'SecureRandom.uuid' \
  'obs_e2e_reset_analytics_nats_store' \
  'stop "${NATS_CONTAINER}"' \
  'nats_container_state=' \
  'find "${WORK_DIR}/nats-store" -mindepth 1 -delete' \
  'start "${NATS_CONTAINER}"' \
  "nats request --raw --timeout 1s '\$JS.API.STREAM.INFO.ANALYTICS_INGEST_V1' '{}'" \
  'empty_stream_error' \
  '10059' \
  'NATS_USER=runtime' \
  'analytics-empty-runtime-stream-info.json' \
  'analytics-nats-empty-runtime-readiness' \
  'obs_e2e_refresh_nats_host_port' \
  'docker_timeout 5 port "${NATS_CONTAINER}" 4222/tcp' \
  'ANALYTICS_INGEST_NATS_URL=${ANALYTICS_NATS_URL}' \
  'obs_e2e_run_analytics_preprovision analytics-history-b' \
  'obs_e2e_capture_analytics_generation b' \
  'obs_e2e_retire_analytics_history_generation "${history_epoch_a}"' \
  'obs_e2e_insert_analytics_history_generation "${history_epoch_b}"'
do
  if ! grep -F -- "${history_required}" "${entrypoint}" >/dev/null; then
    echo "RED analytics history contract missing: ${history_required}" >&2
    history_red=$((history_red + 1))
  fi
done
history_schema_command_count=$(grep -F -c -- 'SET search_path TO ${CONTROL_DATABASE_SCHEMA};' "${entrypoint}" || true)
if [ "${history_schema_command_count}" -lt 4 ]; then
  echo 'RED analytics history SQL is not bound to the control schema on every command' >&2
  history_red=$((history_red + 1))
fi
history_a_line=$(grep -n -F 'obs_e2e_run_analytics_preprovision analytics-history-a' "${entrypoint}" | tail -n1 | cut -d: -f1)
history_a_capture_line=$(grep -n -F 'obs_e2e_capture_analytics_generation a' "${entrypoint}" | tail -n1 | cut -d: -f1)
history_a_seed_line=$(grep -n -F 'obs_e2e_insert_analytics_history_generation "${history_epoch_a}"' "${entrypoint}" | tail -n1 | cut -d: -f1)
history_reset_line=$(grep -n -F 'obs_e2e_reset_analytics_nats_store' "${entrypoint}" | tail -n1 | cut -d: -f1)
history_absent_line=$(grep -n -F "verify analytics ingest JetStream resources" "${entrypoint}" | sed -n '1p' | cut -d: -f1)
history_b_line=$(grep -n -F 'obs_e2e_run_analytics_preprovision analytics-history-b' "${entrypoint}" | tail -n1 | cut -d: -f1)
history_b_capture_line=$(grep -n -F 'obs_e2e_capture_analytics_generation b' "${entrypoint}" | tail -n1 | cut -d: -f1)
history_retire_line=$(grep -n -F 'obs_e2e_retire_analytics_history_generation "${history_epoch_a}"' "${entrypoint}" | tail -n1 | cut -d: -f1)
history_b_seed_line=$(grep -n -F 'obs_e2e_insert_analytics_history_generation "${history_epoch_b}"' "${entrypoint}" | tail -n1 | cut -d: -f1)
if [ -z "${history_a_line}${history_a_capture_line}${history_a_seed_line}${history_reset_line}${history_absent_line}${history_b_line}${history_b_capture_line}${history_retire_line}${history_b_seed_line}" ] || \
  ! [ "${history_a_line}" -lt "${history_a_capture_line}" ] || \
  ! [ "${history_a_capture_line}" -lt "${history_a_seed_line}" ] || \
  ! [ "${history_a_seed_line}" -lt "${history_reset_line}" ] || \
  ! [ "${history_reset_line}" -lt "${history_absent_line}" ] || \
  ! [ "${history_absent_line}" -lt "${history_b_line}" ] || \
  ! [ "${history_b_line}" -lt "${history_b_capture_line}" ] || \
  ! [ "${history_b_capture_line}" -lt "${history_retire_line}" ] || \
  ! [ "${history_retire_line}" -lt "${history_b_seed_line}" ]; then
  echo 'RED analytics history bootstrap order is not fail-closed A/absent/B order' >&2
  history_red=$((history_red + 1))
fi
[ "${history_red}" -eq 0 ] || {
  echo "RED analytics history contract failures=${history_red}" >&2
  exit 1
}

for clickhouse_migration in \
  '005_package_monitor_metrics.up.sql' \
  '006_access_event_state.up.sql' \
  '007_connections_ingest_receipts.up.sql' \
  '008_security_event_state.up.sql' \
  '009_site_realtime_monitoring.up.sql' \
  '010_global_firewall_events.up.sql' \
  '011_l4_session_facts.up.sql' \
  '012_analytics_log_query_projection.up.sql' \
  '013_connections_finalized_dimensions.up.sql'
do
  grep -F -- "infra/clickhouse/migrations/${clickhouse_migration}" "${entrypoint}" >/dev/null || {
    echo "RED ClickHouse ingest migration is missing: ${clickhouse_migration}" >&2
    exit 1
  }
done

for gateway_telemetry_required in \
  'CDNCA_TELEMETRY_NATS_URL=${EDGE_NATS_URL}' \
  'CDNCA_TELEMETRY_NATS_USER=' \
  'CDNCA_TELEMETRY_NATS_PASSWORD='
do
  grep -F -- "${gateway_telemetry_required}" "${entrypoint}" >/dev/null || {
    echo "RED Gateway telemetry publisher environment is missing: ${gateway_telemetry_required}" >&2
    exit 1
  }
done

for realtime_required in \
  'analytics_realtime_cursor_key="$(obs_e2e_timeout 10 openssl rand -base64 32)"' \
  'ANALYTICS_REALTIME_RUNTIME_ENABLED=true' \
  'ANALYTICS_REALTIME_CURSOR_KEY_BASE64=${analytics_realtime_cursor_key}' \
  'ANALYTICS_REALTIME_QUERY_TIMEOUT=1s' \
  'ANALYTICS_REALTIME_MAX_RESPONSE_BYTES=1048576'
do
  grep -F -- "${realtime_required}" "${entrypoint}" >/dev/null || {
    echo "RED realtime process composition is missing: ${realtime_required}" >&2
    exit 1
  }
done

gateway_values_block=$(sed -n '/^agentGateway:/,/^licenseService:/p' "${helm_values}")
for helm_value_required in \
  'telemetryNATSSecret:' \
  'existingSecret: cdnca-analytics-nats-publisher' \
  'url: nats-url' \
  'username: username' \
  'password: password'
do
  printf '%s\n' "${gateway_values_block}" | grep -F -- "${helm_value_required}" >/dev/null || {
    echo "RED Gateway telemetry publisher Helm value is missing: ${helm_value_required}" >&2
    exit 1
  }
done

for helm_env in URL USER PASSWORD; do
  grep -F -- "- name: CDNCA_TELEMETRY_NATS_${helm_env}" "${gateway_template}" >/dev/null || {
    echo "RED Gateway telemetry Helm environment is missing: ${helm_env}" >&2
    exit 1
  }
done
telemetry_secret_reference_count=$(grep -F -c -- \
  'name: {{ .Values.agentGateway.telemetryNATSSecret.existingSecret }}' "${gateway_template}" || true)
[ "${telemetry_secret_reference_count}" -eq 3 ] || {
  echo 'RED Gateway telemetry Helm environments must share the publisher-only Secret' >&2
  exit 1
}
for telemetry_secret_key in url username password; do
  grep -F -- "key: {{ .Values.agentGateway.telemetryNATSSecret.keys.${telemetry_secret_key} }}" \
    "${gateway_template}" >/dev/null || {
    echo "RED Gateway telemetry Helm Secret key is missing: ${telemetry_secret_key}" >&2
    exit 1
  }
done

jq -e '
  (.definitions.gatewayTelemetryNATSKeys.additionalProperties == false) and
  (.definitions.gatewayTelemetryNATSKeys.required == ["url", "username", "password"]) and
  ((.definitions.gatewayTelemetryNATSKeys.properties | keys) == ["password", "url", "username"]) and
  ([.definitions.agentGateway.required[] | select(. == "telemetryNATSSecret")] | length == 1) and
  (.definitions.agentGateway.properties.telemetryNATSSecret.additionalProperties == false) and
  (.definitions.agentGateway.properties.telemetryNATSSecret.required == ["existingSecret", "keys"]) and
  (.definitions.agentGateway.properties.telemetryNATSSecret.properties.keys["$ref"] == "#/definitions/gatewayTelemetryNATSKeys")
' "${helm_schema}" >/dev/null || {
  echo 'RED Gateway telemetry publisher Helm schema is not exact' >&2
  exit 1
}

for tls_validity_required in \
  'openssl req -x509 -newkey rsa:2048 -nodes -days 2' \
  'openssl req -new -x509 -days 2' \
  'openssl x509 -req -days 2 -in "${WORK_DIR}/certs/server.csr"' \
  'openssl x509 -req -days 2 -in "${WORK_DIR}/certs/gateway.csr"'
do
  if ! grep -F -- "${tls_validity_required}" "${entrypoint}" >/dev/null; then
    echo "RED process E2E TLS validity contract missing: ${tls_validity_required}" >&2
    exit 1
  fi
done
grep -F -- '"${NATS_BOX_IMAGE}" sh /contract/analytics-preprovision.sh' "${entrypoint}" >/dev/null || {
  echo 'RED analytics preprovision must invoke the repository text script through sh' >&2
  exit 1
}
if grep -F -- '-days 1' "${entrypoint}" >/dev/null; then
  echo 'RED process E2E TLS validity does not exceed the 24-hour runtime minimum' >&2
  exit 1
fi
for ca_extension in \
  "-addext 'basicConstraints=critical,CA:TRUE,pathlen:0'" \
  "-addext 'keyUsage=critical,keyCertSign,cRLSign'" \
  "-addext 'subjectKeyIdentifier=hash'"
do
  ca_extension_count="$(grep -F -c -- "${ca_extension}" "${entrypoint}" || true)"
  if [ "${ca_extension_count}" -lt 2 ]; then
    echo "RED Node and transport CA extension contract missing: ${ca_extension}" >&2
    exit 1
  fi
done

for disabled_runtime in \
  ACCOUNT_RECOVERY_ENABLED ACCOUNT_REGISTRATION_ENABLED ACME_RUNTIME_ENABLED \
  ANALYTICS_GEO_ARTIFACT_ENABLED \
  ANNOUNCEMENT_ENABLED CACHE_CONTROL_RUNTIME_ENABLED \
  CHALLENGE_POLICY_RUNTIME_ENABLED CONTROL_UPGRADE_PLAN_WRITER_ENABLED CONTROL_UPGRADE_RUNTIME_ENABLED \
  CONTROL_UPGRADE_SYSTEMD_PLAN_SOURCE_ENABLED CUSTOM_RBAC_RUNTIME_ENABLED DNS_RECONCILE_ENABLED \
  EDGE_AUTOMATIC_PUBLICATION_ENABLED ORIGIN_AUTH_RUNTIME_ENABLED EDGE_PUBLISH_RUNTIME_ENABLED \
  CDNCA_SECURITY_ACTIVATION_ENABLED ERROR_PAGE_RUNTIME_ENABLED HTTP_POLICY_RUNTIME_ENABLED \
  IDENTITY_VERIFICATION_RUNTIME_ENABLED JA4_BLOCK_RUNTIME_ENABLED JOB_QUERY_ENABLED \
  NODE_PORT_TRANSITION_RUNTIME_ENABLED NODE_SCHEDULING_RUNTIME_ENABLED NOTIFICATION_RUNTIME_ENABLED \
  PACKAGE_COMMERCE_RUNTIME_ENABLED PACKAGE_COMMERCE_WORKER_ENABLED PACKAGE_CYCLE_RUNTIME_ENABLED \
  PACKAGE_MONITOR_HTTP_ENABLED PACKAGE_MONITOR_RUNTIME_ENABLED PACKAGE_PERIOD_RESET_RUNTIME_ENABLED \
  PACKAGE_USAGE_RUNTIME_ENABLED PLUGIN_WEBHOOK_RUNTIME_ENABLED PROMOTION_HTTP_ENABLED \
  PAYMENT_CHANNELS_ENABLED SIGNER_REVOCATION_CONSUMER_ENABLED \
  SITE_STATUS_RECOVERY_RUNTIME_ENABLED SYSTEM_CONFIGURATION_RUNTIME_ENABLED \
  TRAFFIC_PACKAGE_RUNTIME_ENABLED TRAFFIC_PACKAGE_WORKLOAD_RUNTIME_ENABLED URL_AUTH_POLICY_RUNTIME_ENABLED
do
  grep -F -- "'${disabled_runtime}=false'" "${entrypoint}" >/dev/null || {
    echo "RED optional production runtime is not explicitly disabled: ${disabled_runtime}" >&2
    exit 1
  }
done
for connections_runtime_setting in \
  'ANALYTICS_CONNECTIONS_RUNTIME_ENABLED=true' \
  'ANALYTICS_CONNECTIONS_NATS_URL=${EDGE_NATS_URL}' \
  'ANALYTICS_CONNECTIONS_OPERATION_TIMEOUT=1s' \
  'ANALYTICS_CONNECTIONS_CONNECT_TIMEOUT=1s'
do
  grep -F -- "${connections_runtime_setting}" "${entrypoint}" >/dev/null || {
    echo "RED connections runtime is not bound to the isolated Edge NATS: ${connections_runtime_setting}" >&2
    exit 1
  }
done
for query_runtime_setting in \
  'ANALYTICS_QUERY_ENABLED=true' 'CLICKHOUSE_URL=' 'CLICKHOUSE_DATABASE=cdnca_analytics' \
  'CLICKHOUSE_USERNAME=analytics' 'CLICKHOUSE_PASSWORD='
do
  grep -F -- "${query_runtime_setting}" "${entrypoint}" >/dev/null || {
    echo "RED dashboard query runtime is not bound to the process E2E ClickHouse: ${query_runtime_setting}" >&2
    exit 1
  }
done
for disabled_endpoint in NODE_PRESENCE_NATS_URL NODE_PRESENCE_REDIS_URL; do
  grep -F -- "'${disabled_endpoint}='" "${entrypoint}" >/dev/null || {
    echo "RED optional presence dependency is not explicitly disabled: ${disabled_endpoint}" >&2
    exit 1
  }
done
if [ "$(grep -F -c 'env -i "PATH=${PATH}" "TMPDIR=${TMPDIR:-/tmp}" "${control_env[@]}"' "${entrypoint}")" -ne 4 ]; then
  echo 'RED every control-api process probe must use the hermetic environment' >&2
  exit 1
fi
if [ "$(grep -E -c '^obs_e2e_ensure_edge_stream (AGENT_COMMANDS|AGENT_DEPLOYMENT_STATUS|AGENT_HEARTBEATS|NODE_MONITORING_COMMANDS|NODE_MONITORING_STATUS) ' "${entrypoint}")" -ne 5 ] || \
  [ "$(grep -E -c '^obs_e2e_ensure_edge_consumer (AGENT_DEPLOYMENT_STATUS control_api_edge_status|NODE_MONITORING_STATUS control_api_node_metrics) ' "${entrypoint}")" -ne 2 ]; then
  echo 'RED exact Edge JetStream stream/consumer preprovisioning is incomplete' >&2
  exit 1
fi

if grep -E 'obs_e2e_docker_timeout [0-9]+ run --rm( -i)? --network' "${entrypoint}" >/dev/null; then
  echo 'RED process E2E has an unlabeled temporary container' >&2
  exit 1
fi
if grep -F 'SECONDS' "${entrypoint}" >/dev/null; then
  echo 'RED process E2E uses the Bash special SECONDS variable' >&2
  exit 1
fi
if grep -F 'docker port ' "${entrypoint}" >/dev/null; then
  echo 'RED process E2E uses per-container port queries' >&2
  exit 1
fi
if grep -E '^[[:space:]]*docker[[:space:]]' "${entrypoint}" >/dev/null; then
  echo 'RED process E2E uses a Docker call without an explicit timeout' >&2
  exit 1
fi
release_090_line=$(grep -n "migration-090-release-head-digest'" "${entrypoint}" | sed -n '1s/:.*//p')
release_091_line=$(grep -n "migration-091-release-head-digest'" "${entrypoint}" | sed -n '1s/:.*//p')
docker_info_line=$(grep -n 'docker-unavailable' "${entrypoint}" | sed -n '1s/:.*//p')
if [ -z "${release_090_line}" ] || [ -z "${release_091_line}" ] || [ -z "${docker_info_line}" ] || \
  [ "${release_090_line}" -ge "${docker_info_line}" ] || \
  [ "${release_091_line}" -ge "${docker_info_line}" ]; then
  echo 'RED process E2E must verify the exact migration 090/091 release heads before Docker access' >&2
  exit 1
fi
inspect_line=$(grep -n '^safe_ports_file=' "${entrypoint}" | sed -n '1s/:.*//p')
readiness_line=$(grep -n "postgres-readiness'" "${entrypoint}" | sed -n '1s/:.*//p')
if [ -z "${inspect_line}" ] || [ -z "${readiness_line}" ] || [ "${inspect_line}" -ge "${readiness_line}" ]; then
  echo 'RED process E2E must inspect ports before dependency readiness' >&2
  exit 1
fi
pid1_line=$(grep -n "clickhouse-final-pid1'" "${entrypoint}" | sed -n '1s/:.*//p')
clickhouse_readiness_line=$(grep -n "clickhouse-readiness'" "${entrypoint}" | sed -n '1s/:.*//p')
if [ -z "${pid1_line}" ] || [ -z "${clickhouse_readiness_line}" ] || \
  [ "${pid1_line}" -ge "${clickhouse_readiness_line}" ]; then
  echo 'RED process E2E must confirm final ClickHouse PID 1 before client readiness' >&2
  exit 1
fi
baseline_line=$(grep -n '^if \[ "${postgres_database_baseline}" != ' "${entrypoint}" | sed -n '1s/:.*//p')
migrate_line=$(grep -n 'control-api" migrate up' "${entrypoint}" | sed -n '1s/:.*//p')
if [ -z "${baseline_line}" ] || [ -z "${migrate_line}" ] || [ "${baseline_line}" -ge "${migrate_line}" ]; then
  echo 'RED process E2E must prove the PostgreSQL role/schema baseline before migration' >&2
  exit 1
fi

edge_setup_start=$(grep -n '^# Pre-create the shared edge JetStream resources' "${entrypoint}" | sed -n '1s/:.*//p')
edge_setup_end=$(grep -n "^printf 'edge NATS resources verified" "${entrypoint}" | sed -n '1s/:.*//p')
resource_absent_line=$(grep -n '^# Missing resources must fail closed' "${entrypoint}" | sed -n '1s/:.*//p')
first_control_serve_line=$(grep -n 'resource-absent.log' "${entrypoint}" | sed -n '1s/:.*//p')
if [ -z "${edge_setup_start}" ] || [ -z "${edge_setup_end}" ] || \
  [ -z "${resource_absent_line}" ] || [ -z "${first_control_serve_line}" ] || \
  [ "${edge_setup_start}" -ge "${edge_setup_end}" ] || \
  [ "${edge_setup_end}" -ge "${resource_absent_line}" ] || \
  [ "${edge_setup_end}" -ge "${first_control_serve_line}" ]; then
  echo 'RED edge JetStream resources must be verified before every control-api serve probe' >&2
  exit 1
fi
edge_setup_block=$(sed -n "${edge_setup_start},${edge_setup_end}p" "${entrypoint}")
for edge_required in \
  'obs_e2e_docker_timeout_millis "${timeout_millis}" exec "${edge_nats_probe_container_id}"' \
  "\$JS.API.INFO" \
  "\$JS.API.STREAM.CREATE.\${resource}" \
  "\$JS.API.CONSUMER.CREATE.\${stream}.\${durable}" \
  '.error.err_code // 0' \
  'edge_nats_deadline_nanos=' \
  'nats request --raw --timeout "${request_timeout_millis}ms"' \
  'storage:"file"' \
  'num_replicas:1' \
  'duplicate_window:120000000000' \
  'max_msg_size:1048576' \
  '.config.storage == $expected.storage' \
  '.config.num_replicas == $expected.num_replicas' \
  '.config.duplicate_window == $expected.duplicate_window' \
  '.config.max_msg_size == $expected.max_msg_size' \
  'deliver_policy:"all"' \
  'ack_policy:"explicit"' \
  'replay_policy:"instant"' \
  '(.config.filter_subject // "") == ($expected.config.filter_subject // "")' \
  '(.config.filter_subjects // []) == ($expected.config.filter_subjects // [])' \
  'edge-nats-stream-create-api-error' \
  'edge-nats-stream-info-api-error' \
  'edge-nats-consumer-create-api-error' \
  'edge-nats-consumer-info-api-error'
do
  printf '%s\n' "${edge_setup_block}" | grep -F -- "${edge_required}" >/dev/null || {
    echo "RED edge JetStream setup is missing exact contract: ${edge_required}" >&2
    exit 1
  }
done

if grep -E '^[[:space:]]*access_count=|duplicate_rows=\$\{access_count\}' "${entrypoint}" >/dev/null; then
  echo 'RED duplicate evidence reuses the pre-duplicate access_count variable' >&2
  exit 1
fi
duplicate_start=$(grep -n '^duplicate_physical_rows_before=' "${entrypoint}" | sed -n '1s/:.*//p')
duplicate_end=$(grep -n '^poison_message=' "${entrypoint}" | sed -n '1s/:.*//p')
if [ -z "${duplicate_start}" ] || [ -z "${duplicate_end}" ] || [ "${duplicate_start}" -ge "${duplicate_end}" ]; then
  echo 'RED duplicate evidence does not have independent before/after physical counts' >&2
  exit 1
fi
duplicate_block=$(sed -n "${duplicate_start},${duplicate_end}p" "${entrypoint}")
if printf '%s\n' "${duplicate_block}" | grep -F ' FINAL ' >/dev/null; then
  echo 'RED duplicate evidence uses FINAL instead of physical row counts' >&2
  exit 1
fi
printf '%s\n' "${duplicate_block}" | grep -F 'duplicate_physical_rows_after=' >/dev/null || {
  echo 'RED duplicate evidence does not query after duplicate publication' >&2
  exit 1
}

outage_start=$(grep -n '^# ClickHouse outage' "${entrypoint}" | sed -n '1s/:.*//p')
outage_end=$(grep -n '^# NATS restart' "${entrypoint}" | sed -n '1s/:.*//p')
if [ -z "${outage_start}" ] || [ -z "${outage_end}" ] || [ "${outage_start}" -ge "${outage_end}" ]; then
  echo 'RED ClickHouse outage evidence block is missing' >&2
  exit 1
fi
outage_block=$(sed -n "${outage_start},${outage_end}p" "${entrypoint}")
for outage_required in \
  'nats consumer info -j ANALYTICS_INGEST_V1 control_api_analytics_ingest_v1' \
  '.delivered.consumer_seq' \
  '.ack_floor.consumer_seq' \
  '.ack_floor.stream_seq' \
  '.num_ack_pending' \
  '.num_redelivered' \
  'outage_consumer_fetch_observed' \
  'outage_consumer_redelivery_observed' \
  'outage_ack_floor_after' \
  'outage_physical_rows_after'
do
  printf '%s\n' "${outage_block}" | grep -F -- "${outage_required}" >/dev/null || {
    echo "RED ClickHouse outage evidence is missing contract: ${outage_required}" >&2
    exit 1
  }
done
if printf '%s\n' "${outage_block}" | grep -F ' FINAL ' >/dev/null || \
  printf '%s\n' "${outage_block}" | grep -F 'sleep 1' >/dev/null; then
  echo 'RED ClickHouse outage evidence relies on FINAL or an unproved fixed sleep' >&2
  exit 1
fi

netrc_delete_line=$(grep -n "find \"\${WORK_DIR}/clickhouse.netrc\"" "${entrypoint}" | sed -n '1s/:.*//p')
secret_scan_line=$(grep -n '^secret_names=(' "${entrypoint}" | sed -n '1s/:.*//p')
if [ -z "${netrc_delete_line}" ] || [ -z "${secret_scan_line}" ] || \
  [ "${netrc_delete_line}" -ge "${secret_scan_line}" ]; then
  echo 'RED intentional secret holders must be deleted before the no-output scan' >&2
  exit 1
fi
secret_values_start=$(grep -n '^secret_values=(' "${entrypoint}" | sed -n '1s/:.*//p')
secret_values_end=$(awk -v start="${secret_values_start:-0}" 'NR > start && $0 == ")" {print NR; exit}' "${entrypoint}")
if [ -z "${secret_values_start}" ] || [ -z "${secret_values_end}" ] || \
  [ "${secret_values_start}" -ge "${secret_values_end}" ]; then
  echo 'RED generated secret values array is incomplete' >&2
  exit 1
fi
secret_values_block=$(sed -n "${secret_values_start},${secret_values_end}p" "${entrypoint}")
for secret_category in postgres_password clickhouse_password preprovision_password runtime_password \
  publisher_password access_secret isolation_wrapping_key api_key_pepper dns_credential_key \
  impersonation_hmac_key mfa_encryption_key observability_log_cursor_key analytics_realtime_cursor_key \
  enrollment_token
do
  secret_expansion="\${${secret_category}}"
  printf '%s\n' "${secret_values_block}" | grep -F -- "\"${secret_expansion}\"" >/dev/null || {
    echo "RED no-output scan is missing secret value expansion: ${secret_category}" >&2
    exit 1
  }
done
grep -F 'grep -R -a -F -q' "${entrypoint}" >/dev/null || {
  echo 'RED real-secret scan must suppress matching plaintext output' >&2
  exit 1
}

for analytics_cursor_required in \
  'ANALYTICS_LOGS_CURSOR_ACTIVE_KEY_ID=obs-process-e2e' \
  'ANALYTICS_LOGS_CURSOR_KEYS_JSON={\"obs-process-e2e\":\"${observability_log_cursor_key}\"}'
do
  grep -F -- "${analytics_cursor_required}" "${entrypoint}" >/dev/null || {
    echo "RED analytics logs cursor keyring environment is missing: ${analytics_cursor_required}" >&2
    exit 1
  }
done

fixture_source_line=$(grep -n "missing-edge-telemetry-fixture-source" "${entrypoint}" | sed -n '1s/:.*//p')
work_dir_line=$(grep -n '^WORK_DIR=' "${entrypoint}" | sed -n '1s/:.*//p')
fixture_build_line=$(grep -n 'go build -trimpath -o "${edge_fixture_command}" ./cmd/edge-telemetry-fixture' \
  "${entrypoint}" | sed -n '1s/:.*//p')
fixture_preflight_line=$(grep -n '"${edge_fixture_command}" --preflight-eventspool-mtls' \
  "${entrypoint}" | sed -n '1s/:.*//p')
network_create_line=$(grep -n 'network create --label' "${entrypoint}" | sed -n '1s/:.*//p')
if [ -z "${fixture_source_line}" ] || [ -z "${work_dir_line}" ] || [ -z "${fixture_build_line}" ] || \
  [ -z "${fixture_preflight_line}" ] || [ -z "${network_create_line}" ] || \
  [ "${fixture_source_line}" -ge "${work_dir_line}" ] || [ "${fixture_build_line}" -le "${work_dir_line}" ] || \
  [ "${fixture_build_line}" -ge "${network_create_line}" ] || \
  [ "${fixture_preflight_line}" -ge "${network_create_line}" ]; then
  echo 'RED Edge fixture source/build/preflight must fail closed before Docker mutation' >&2
  exit 1
fi

for edge_fixture_required in \
  'go build -trimpath -o "${WORK_DIR}/bin/edge-agent" ./cmd/edge-agent' \
  '"${WORK_DIR}/bin/edge-agent" enroll' \
  '--gateway-root-ca-file "${WORK_DIR}/certs/ca.crt"' \
  '--identity-dir "${WORK_DIR}/edge-identity"' \
  '--token-file "${WORK_DIR}/edge-enrollment-token"' \
  'CDNCA_GATEWAY_AGENT_CLIENT_CA_FILE=${WORK_DIR}/certs/node-ca.crt' \
  '"${edge_fixture_command}"' \
  '--spool-directory "${WORK_DIR}/edge-event-spool"' \
  '--gateway-address "127.0.0.1:${gateway_agent_port}"' \
  '--client-certificate-file "${fixture_client_certificate_file}"' \
  '--client-private-key-file "${fixture_client_private_key_file}"' \
  '.transport == "eventspool_mtls"' \
  '.acknowledged_source_watermark == $watermark' \
  'connections_ingest_receipts_v1 FINAL' \
  "state='broker_ack_observed'" \
  'puback_sequence>0' \
  'nats_stream_sequence=puback_sequence' \
  'gateway_to_control=PASS' \
  'edge_fixture_status=acknowledged' \
  'edge_fixture_transport=eventspool_mtls' \
  'connections_receipt_state=${connections_receipt_state}' \
  'connections_puback_sequence=${connections_puback_sequence}'
do
  grep -F -- "${edge_fixture_required}" "${entrypoint}" >/dev/null || {
    echo "RED real Edge telemetry fixture contract is missing: ${edge_fixture_required}" >&2
    exit 1
  }
done
if grep -F 'gateway_to_control=BLOCKED_EDGE_AGENT_FIXTURE' "${entrypoint}" >/dev/null || \
  grep -F "gateway_to_control='PARTIAL'" "${entrypoint}" >/dev/null || \
  grep -F "gateway_to_control='UNKNOWN'" "${entrypoint}" >/dev/null; then
  echo 'RED process summary still carries a non-evidence Edge telemetry status' >&2
  exit 1
fi
grep -F 'Direct NATS fixtures prove only publisher-to-Control durability; they never satisfy gateway_to_control.' \
  "${entrypoint}" >/dev/null || {
    echo 'RED direct NATS publisher fixtures are not explicitly excluded from gateway_to_control proof' >&2
    exit 1
  }

bash -n "${entrypoint}"
echo 'GREEN process E2E static contract'
