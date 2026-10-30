#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
server_config="$repo_root/infra/nats/analytics-server.conf"
preprovision_script="$repo_root/infra/nats/analytics-preprovision.sh"
probe="$repo_root/tests/analytics-observability/preprovision/acl_probe.go"

for required in "$server_config" "$preprovision_script" "$probe"; do
  if [[ ! -f "$required" ]]; then
    printf 'missing required OBS preprovision file: %s\n' "${required#"$repo_root/"}" >&2
    exit 1
  fi
done

task_id="cdnca-obs-preprovision-$$"
network_name="$task_id"
server_name="$task_id-nats"
mismatch_name="$task_id-mismatch"
republish_mismatch_name="$task_id-republish-mismatch"
transform_mismatch_name="$task_id-transform-mismatch"
lease_mismatch_name="$task_id-lease-mismatch"
active_lease_name="$task_id-active-lease"
toolbox_name="$task_id-cli"
tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/cdnca-obs-preprovision.XXXXXX")
preprovision_user="preprovision-$task_id"
preprovision_password="preprovision-password-$task_id"
runtime_user="runtime-$task_id"
runtime_password="runtime-password-$task_id"
publisher_user="publisher-$task_id"
publisher_password="publisher-password-$task_id"
docker_timeout=${OBS_DOCKER_TIMEOUT_SECONDS:-120}
cleanup_timeout=${OBS_DOCKER_CLEANUP_TIMEOUT_SECONDS:-30}
stage=setup
cleanup_running=0

for timeout_value in "$docker_timeout" "$cleanup_timeout"; do
  if [[ ! "$timeout_value" =~ ^[1-9][0-9]*$ ]]; then
    printf 'Docker timeout must be a positive integer\n' >&2
    exit 1
  fi
done

process_group_is_alive() {
  kill -0 -- "-$1" 2>/dev/null
}

wait_for_process_group_exit() {
  local pgid=$1 attempts=${2:-20}
  while [[ $attempts -gt 0 ]] && process_group_is_alive "$pgid"; do
    sleep 0.1
    attempts=$((attempts - 1))
  done
  if process_group_is_alive "$pgid"; then
    return 1
  fi
  return 0
}

run_hard_timeout() {
  local timeout_seconds=$1
  shift
  local monitor_was_enabled=0 command_pid watchdog_pid command_status timeout_marker
  timeout_marker=$(mktemp "${TMPDIR:-/tmp}/cdnca-obs-hard-timeout.XXXXXX")
  if [[ $(set -o | awk '$1 == "monitor" {print $2}') == on ]]; then
    monitor_was_enabled=1
  else
    set -m
  fi
  "$@" &
  command_pid=$!
  (
    sleep "$timeout_seconds"
    printf 'timeout\n' >"$timeout_marker"
    if process_group_is_alive "$command_pid"; then
      if kill -INT -- "-$command_pid" 2>/dev/null; then :; else :; fi
    fi
    if ! wait_for_process_group_exit "$command_pid" 20; then
      if process_group_is_alive "$command_pid"; then
        if kill -TERM -- "-$command_pid" 2>/dev/null; then :; else :; fi
      fi
      if ! wait_for_process_group_exit "$command_pid" 20; then
        if process_group_is_alive "$command_pid"; then
          if kill -KILL -- "-$command_pid" 2>/dev/null; then :; else :; fi
        fi
        if wait_for_process_group_exit "$command_pid" 20; then :; else :; fi
      fi
    fi
  ) &
  watchdog_pid=$!
  if [[ $monitor_was_enabled -eq 0 ]]; then
    set +m
  fi
  if wait "$command_pid"; then
    command_status=0
  else
    command_status=$?
  fi
  if [[ -s "$timeout_marker" ]]; then
    if wait "$watchdog_pid" 2>/dev/null; then :; else :; fi
    command_status=124
  else
    if kill -0 "$watchdog_pid" 2>/dev/null; then
      if kill -TERM -- "-$watchdog_pid" 2>/dev/null; then :; else :; fi
    fi
    if wait "$watchdog_pid" 2>/dev/null; then :; else :; fi
  fi
  rm -f "$timeout_marker"
  return "$command_status"
}


timeout_fixture_pids() {
  local token=$1 output status
  if output=$(pgrep -f "$token" 2>/dev/null); then
    printf '%s\n' "$output"
    return 0
  fi
  status=$?
  if [[ $status -eq 1 ]]; then
    return 0
  fi
  return "$status"
}

count_timeout_fixture_processes() {
  local output
  output=$(timeout_fixture_pids "$1")
  if [[ -z "$output" ]]; then
    printf '0\n'
  else
    printf '%s\n' "$output" | awk 'NF { count++ } END { print count + 0 }'
  fi
}

count_timeout_fixture_ppid1() {
  local token=$1 pids pid ppid count=0
  pids=$(timeout_fixture_pids "$token")
  for pid in $pids; do
    ppid=$(LC_ALL=C ps -o ppid= -p "$pid" 2>/dev/null | tr -d ' ')
    if [[ $ppid == 1 ]]; then
      count=$((count + 1))
    fi
  done
  printf '%s\n' "$count"
}

cleanup_timeout_fixture() {
  local token=$1 pids pid pgid self_pgid seen=" "
  self_pgid=$(LC_ALL=C ps -o pgid= -p $$ | tr -d ' ')
  pids=$(timeout_fixture_pids "$token")
  for pid in $pids; do
    pgid=$(LC_ALL=C ps -o pgid= -p "$pid" 2>/dev/null | tr -d ' ')
    if [[ "$pgid" =~ ^[1-9][0-9]*$ && $pgid != "$self_pgid" && "$seen" != *" $pgid "* ]]; then
      seen="$seen$pgid "
      if kill -TERM -- "-$pgid" 2>/dev/null; then :; else :; fi
    fi
  done
  sleep 0.2
  pids=$(timeout_fixture_pids "$token")
  seen=" "
  for pid in $pids; do
    pgid=$(LC_ALL=C ps -o pgid= -p "$pid" 2>/dev/null | tr -d ' ')
    if [[ "$pgid" =~ ^[1-9][0-9]*$ && $pgid != "$self_pgid" && "$seen" != *" $pgid "* ]]; then
      seen="$seen$pgid "
      if kill -KILL -- "-$pgid" 2>/dev/null; then :; else :; fi
    fi
  done
  for _ in $(seq 1 50); do
    if [[ $(count_timeout_fixture_processes "$token") == 0 ]]; then
      return 0
    fi
    sleep 0.1
  done
  return 1
}

run_timeout_selftest() {
  local fixture_name=$1 token pid_file int_file normal_status signal_status timeout_status process_count ppid1_count
  if run_hard_timeout 5 bash -c 'exit 37'; then normal_status=0; else normal_status=$?; fi
  if run_hard_timeout 5 bash -c 'kill -TERM $$'; then signal_status=0; else signal_status=$?; fi
  token="cdnca-obs-hard-timeout-$fixture_name-$$-$RANDOM"
  pid_file=$(mktemp "${TMPDIR:-/tmp}/cdnca-obs-timeout-pid.XXXXXX")
  int_file=$(mktemp "${TMPDIR:-/tmp}/cdnca-obs-timeout-int.XXXXXX")
  rm -f "$int_file"
  # shellcheck disable=SC2016 # The fixture body is Perl; shell expansion would corrupt it.
  if run_hard_timeout 1 perl -e '
    use strict;
    use warnings;
    my ($pid_file, $int_file, $token) = @ARGV;
    $0 = "$token-leader";
    $SIG{INT} = sub {
      open my $fh, ">", $int_file or die "open int marker: $!";
      print {$fh} "leader-int\n";
      close $fh or die "close int marker: $!";
      exit 0;
    };
    my $child = fork();
    die "fork: $!" unless defined $child;
    if ($child == 0) {
      $0 = "$token-descendant";
      $SIG{INT} = "IGNORE";
      while (1) { select undef, undef, undef, 1; }
    }
    open my $fh, ">", $pid_file or die "open pid file: $!";
    print {$fh} "$child\n";
    close $fh or die "close pid file: $!";
    waitpid($child, 0);
  ' "$pid_file" "$int_file" "$token"; then
    timeout_status=0
  else
    timeout_status=$?
  fi
  process_count=$(count_timeout_fixture_processes "$token")
  ppid1_count=$(count_timeout_fixture_ppid1 "$token")
  if [[ $normal_status != 37 || $signal_status != 143 || $timeout_status != 124 ||
    ! -s "$int_file" || $process_count != 0 || $ppid1_count != 0 ]]; then
    printf 'hard-timeout selftest failed: normal=%s signal=%s timeout=%s leader_int=%s processes=%s ppid1=%s\n' \
      "$normal_status" "$signal_status" "$timeout_status" \
      "$([[ -s "$int_file" ]] && printf 1 || printf 0)" "$process_count" "$ppid1_count" >&2
    if ! cleanup_timeout_fixture "$token"; then
      printf 'hard-timeout fixture cleanup failed\n' >&2
    fi
    process_count=$(count_timeout_fixture_processes "$token")
    ppid1_count=$(count_timeout_fixture_ppid1 "$token")
    rm -f "$pid_file" "$int_file"
    printf 'hard-timeout fixture cleanup: processes=%s ppid1=%s\n' "$process_count" "$ppid1_count" >&2
    return 1
  fi
  rm -f "$pid_file" "$int_file"
  printf 'hard-timeout selftest passed: normal=%s signal=%s timeout=%s processes=%s ppid1=%s\n' \
    "$normal_status" "$signal_status" "$timeout_status" "$process_count" "$ppid1_count"
}


query_task_container_ids() {
  run_hard_timeout "$cleanup_timeout" docker ps -aq \
    --filter "label=cdnca.obs-preprovision=$task_id"
}

query_task_network_ids() {
  run_hard_timeout "$cleanup_timeout" docker network ls -q \
    --filter "label=cdnca.obs-preprovision=$task_id" --filter "name=^${network_name}$"
}

count_ids() {
  if [[ -z "$1" ]]; then
    printf '0\n'
  else
    printf '%s\n' "$1" | awk 'NF { count++ } END { print count + 0 }'
  fi
}

cleanup() {
  local status=$?
  local cleanup_tmp_dir=${1:-$tmp_dir}
  local cleanup_status=0 container_output network_output id
  local -a container_ids=() network_ids=()
  if [[ $cleanup_running -eq 1 ]]; then
    return "$status"
  fi
  cleanup_running=1
  if container_output=$(query_task_container_ids); then
    while IFS= read -r id; do
      [[ -n "$id" ]] && container_ids[${#container_ids[@]}]="$id"
    done <<< "$container_output"
    if [[ ${#container_ids[@]} -gt 0 ]]; then
      if run_hard_timeout "$cleanup_timeout" docker rm -f "${container_ids[@]}" >/dev/null 2>&1; then
        :
      else
        printf 'failed to remove task-owned containers\n' >&2
        cleanup_status=1
      fi
    fi
  else
    printf 'task-owned container residue count: -1 (query failed)\n' >&2
    cleanup_status=1
  fi
  if network_output=$(query_task_network_ids); then
    while IFS= read -r id; do
      [[ -n "$id" ]] && network_ids[${#network_ids[@]}]="$id"
    done <<< "$network_output"
    if [[ ${#network_ids[@]} -gt 0 ]]; then
      if run_hard_timeout "$cleanup_timeout" docker network rm "${network_ids[@]}" >/dev/null 2>&1; then
        :
      else
        printf 'failed to remove task-owned network\n' >&2
        cleanup_status=1
      fi
    fi
  else
    printf 'task-owned network residue count: -1 (query failed)\n' >&2
    cleanup_status=1
  fi
  rm -rf "$cleanup_tmp_dir"
  if [[ $status -ne 0 ]]; then
    printf 'analytics NATS preprovision acceptance failed at stage: %s\n' "$stage" >&2
  fi
  if [[ $cleanup_status -ne 0 ]]; then
    return "$cleanup_status"
  fi
  return "$status"
}

run_cleanup_failure_selftest() {
  local query_log action_log query_status action_status
  query_log=$(mktemp "${TMPDIR:-/tmp}/cdnca-obs-cleanup-query.XXXXXX")
  action_log=$(mktemp "${TMPDIR:-/tmp}/cdnca-obs-cleanup-action.XXXXXX")
  if (
    fixture_tmp=$(mktemp -d "${TMPDIR:-/tmp}/cdnca-obs-cleanup-query-tmp.XXXXXX")
    cleanup_running=0
    # shellcheck disable=SC2329 # run_hard_timeout invokes the fixture function indirectly.
    docker() { return 73; }
    if cleanup "$fixture_tmp"; then query_status=0; else query_status=$?; fi
    [[ $query_status -ne 0 && ! -e "$fixture_tmp" ]]
  ) 2>"$query_log"; then
    :
  else
    rm -f "$query_log" "$action_log"
    printf 'cleanup query-failure selftest did not fail closed\n' >&2
    return 1
  fi
  if ! grep -Fq 'container residue count: -1' "$query_log" ||
    ! grep -Fq 'network residue count: -1' "$query_log"; then
    rm -f "$query_log" "$action_log"
    printf 'cleanup query-failure selftest did not preserve -1\n' >&2
    return 1
  fi
  if (
    fixture_tmp=$(mktemp -d "${TMPDIR:-/tmp}/cdnca-obs-cleanup-action-tmp.XXXXXX")
    cleanup_running=0
    # shellcheck disable=SC2329 # run_hard_timeout invokes the fixture function indirectly.
    docker() {
      if [[ $1 == ps ]]; then printf 'fixture-container\n'; return 0; fi
      if [[ $1 == network && $2 == ls ]]; then printf 'fixture-network\n'; return 0; fi
      return 74
    }
    if cleanup "$fixture_tmp"; then action_status=0; else action_status=$?; fi
    [[ $action_status -ne 0 && ! -e "$fixture_tmp" ]]
  ) 2>"$action_log"; then
    :
  else
    rm -f "$query_log" "$action_log"
    printf 'cleanup action-failure selftest did not fail closed\n' >&2
    return 1
  fi
  if ! grep -Fq 'failed to remove task-owned containers' "$action_log" ||
    ! grep -Fq 'failed to remove task-owned network' "$action_log"; then
    rm -f "$query_log" "$action_log"
    printf 'cleanup action-failure selftest lost failure evidence\n' >&2
    return 1
  fi
  rm -f "$query_log" "$action_log"
  printf 'cleanup failure selftest passed: query=-1 action=nonzero\n'
}

case ${OBS_PREPROVISION_SELFTEST:-} in
  timeout)
    if run_timeout_selftest run; then selftest_status=0; else selftest_status=$?; fi
    rm -rf "$tmp_dir"
    exit "$selftest_status"
    ;;
  cleanup-failure)
    if run_cleanup_failure_selftest; then selftest_status=0; else selftest_status=$?; fi
    rm -rf "$tmp_dir"
    exit "$selftest_status"
    ;;
  '') ;;
  *)
    rm -rf "$tmp_dir"
    printf 'unknown OBS preprovision selftest mode\n' >&2
    exit 2
    ;;
esac
trap cleanup EXIT INT TERM

mkdir -p "$tmp_dir/store" "$tmp_dir/mismatch-store" "$tmp_dir/republish-store" "$tmp_dir/transform-store" \
  "$tmp_dir/lease-mismatch-store" "$tmp_dir/active-lease-store"
chmod 700 "$tmp_dir" "$tmp_dir/store" "$tmp_dir/mismatch-store" "$tmp_dir/republish-store" \
  "$tmp_dir/transform-store" "$tmp_dir/lease-mismatch-store" "$tmp_dir/active-lease-store"
run_hard_timeout "$docker_timeout" docker network create \
  --label "cdnca.obs-preprovision=$task_id" "$network_name" >/dev/null
run_hard_timeout "$docker_timeout" docker run --detach --name "$toolbox_name" --network "$network_name" \
  --label "cdnca.obs-preprovision=$task_id" \
  --volume "$preprovision_script:/opt/cdnca/analytics-preprovision.sh:ro" \
  natsio/nats-box:0.19.1 sh -c 'while :; do sleep 60; done' >/dev/null
stage=reject-credential-url
if run_hard_timeout "$docker_timeout" docker exec \
  --env NATS_URL='nats://embedded-user:embedded-password@nats:4222' \
  --env NATS_PREPROVISION_USERNAME="$preprovision_user" \
  --env NATS_PREPROVISION_PASSWORD="$preprovision_password" \
  "$toolbox_name" sh /opt/cdnca/analytics-preprovision.sh >"$tmp_dir/credential-url.out" 2>&1; then
  printf 'preprovision accepted credentials embedded in NATS_URL\n' >&2
  exit 1
fi
if grep -Fq 'embedded-password' "$tmp_dir/credential-url.out"; then
  printf 'embedded NATS URL credential leaked in output\n' >&2
  exit 1
fi

start_server() {
  local name=$1 alias=$2 store=$3
  run_hard_timeout "$docker_timeout" docker run --detach --name "$name" --network "$network_name" --network-alias "$alias" \
    --label "cdnca.obs-preprovision=$task_id" --publish 127.0.0.1::4222 \
    --env NATS_STORE_DIR=/data \
    --env NATS_PREPROVISION_USERNAME="$preprovision_user" \
    --env NATS_PREPROVISION_PASSWORD="$preprovision_password" \
    --env NATS_CONTROL_CONSUMER_USERNAME="$runtime_user" \
    --env NATS_CONTROL_CONSUMER_PASSWORD="$runtime_password" \
    --env NATS_GATEWAY_PUBLISHER_USERNAME="$publisher_user" \
    --env NATS_GATEWAY_PUBLISHER_PASSWORD="$publisher_password" \
    --volume "$server_config:/etc/nats/analytics-server.conf:ro" \
    --volume "$store:/data" \
    nats:2.11.4-alpine -c /etc/nats/analytics-server.conf >/dev/null
  for _ in $(seq 1 60); do
    if run_hard_timeout "$docker_timeout" docker exec "$name" \
      wget -qO- 'http://127.0.0.1:8222/healthz?js-enabled-only=true' 2>/dev/null | grep -q '"status":"ok"'; then
      return 0
    fi
    sleep 0.25
  done
  printf 'NATS server did not become healthy\n' >&2
  return 1
}

run_preprovision() {
  local alias=$1 output=$2
  run_hard_timeout "$docker_timeout" docker exec \
    --env NATS_URL="nats://$alias:4222" \
    --env NATS_PREPROVISION_USERNAME="$preprovision_user" \
    --env NATS_PREPROVISION_PASSWORD="$preprovision_password" \
    "$toolbox_name" sh /opt/cdnca/analytics-preprovision.sh >"$output" 2>&1
}

request() {
  local alias=$1 subject=$2 payload=${3:-'{}'}
  run_hard_timeout "$docker_timeout" docker exec "$toolbox_name" nats --server "nats://$alias:4222" \
    --user "$preprovision_user" --password "$preprovision_password" \
    request --raw --timeout 3s "$subject" "$payload"
}

assert_no_credentials() {
  local output=$1 secret
  for secret in "$preprovision_user" "$preprovision_password" "$runtime_user" "$runtime_password" "$publisher_user" "$publisher_password"; do
    if grep -Fq "$secret" "$output"; then
      printf 'credential leaked in preprovision output\n' >&2
      return 1
    fi
  done
}

assert_streams() {
  # shellcheck disable=SC2016 # JetStream API subjects are literal strings.
  request nats '$JS.API.STREAM.INFO.ANALYTICS_INGEST_V1' | jq -e '
    .config.name == "ANALYTICS_INGEST_V1" and .config.subjects == ["cdnca.analytics.ingest.v1.*"] and
    .config.retention == "workqueue" and .config.max_consumers == 1 and .config.max_msgs == 10000000 and
    .config.max_bytes == 10737418240 and .config.discard == "new" and .config.max_age == 0 and
    .config.max_msgs_per_subject == -1 and .config.max_msg_size == 1048576 and .config.storage == "file" and
    .config.num_replicas == 1 and .config.duplicate_window == 600000000000' >/dev/null
  # shellcheck disable=SC2016 # JetStream API subjects are literal strings.
  request nats '$JS.API.STREAM.INFO.ANALYTICS_ISOLATION_V1' | jq -e '
    .config.name == "ANALYTICS_ISOLATION_V1" and .config.subjects == ["cdnca.analytics.isolation.v1"] and
    .config.retention == "limits" and .config.max_consumers == -1 and .config.max_msgs == 10000000 and
    .config.max_bytes == 1073741824 and .config.discard == "new" and .config.max_age == 2592000000000000 and
    .config.max_msgs_per_subject == -1 and .config.max_msg_size == 2097152 and .config.storage == "file" and
    .config.num_replicas == 1 and .config.duplicate_window == 600000000000' >/dev/null
  # shellcheck disable=SC2016 # JetStream API subjects are literal strings.
  request nats '$JS.API.STREAM.INFO.CONNECTIONS_INGEST_V1' | jq -e '
    .config.name == "CONNECTIONS_INGEST_V1" and .config.subjects == ["cdnca.connections.v1.*.*"] and
    .config.retention == "workqueue" and .config.max_consumers == 1 and .config.max_msgs == 1000000 and
    .config.max_bytes == 2147483648 and .config.discard == "new" and .config.discard_new_per_subject == true and
    .config.max_age == 0 and .config.max_msgs_per_subject == 1 and .config.max_msg_size == 65536 and
    .config.storage == "file" and .config.num_replicas == 1 and .config.duplicate_window == 600000000000' >/dev/null
  # shellcheck disable=SC2016 # JetStream API subjects are literal strings.
  request nats '$JS.API.STREAM.INFO.CONNECTIONS_DEAD_V1' | jq -e '
    .config.name == "CONNECTIONS_DEAD_V1" and .config.subjects == ["cdnca.connections.dead.v1"] and
    .config.retention == "limits" and .config.max_consumers == -1 and .config.max_msgs == 1000000 and
    .config.max_bytes == 1073741824 and .config.discard == "new" and .config.max_age == 2592000000000000 and
    .config.max_msgs_per_subject == -1 and .config.max_msg_size == 8192 and .config.storage == "file" and
    .config.num_replicas == 1 and .config.duplicate_window == 86400000000000' >/dev/null
  for bucket in AISTATE_2dcd3c381ead92f3 AILEASE_2dcd3c381ead92f3 AIEVIDENCE_2dcd3c381ead92f3; do
    request nats "\$JS.API.STREAM.INFO.KV_$bucket" >"$tmp_dir/$bucket.json"
  done
  jq -e '.config | .name == "KV_AISTATE_2dcd3c381ead92f3" and .subjects == ["$KV.AISTATE_2dcd3c381ead92f3.>"] and .max_msgs_per_subject == 1 and .max_bytes == 4194304 and .max_age == 0 and .max_msg_size == 1024 and .storage == "file" and .num_replicas == 1 and .discard == "new" and .deny_delete == true and .allow_rollup_hdrs == true and .allow_direct == true' "$tmp_dir/AISTATE_2dcd3c381ead92f3.json" >/dev/null
  jq -e '.config | .name == "KV_AILEASE_2dcd3c381ead92f3" and .subjects == ["$KV.AILEASE_2dcd3c381ead92f3.>"] and .max_msgs_per_subject == 1 and .max_bytes == 4194304 and .max_age == 40000000000 and .max_msg_size == 1024 and .storage == "file" and .num_replicas == 1 and .discard == "new" and .deny_delete == true and .allow_rollup_hdrs == true and .allow_direct == true' "$tmp_dir/AILEASE_2dcd3c381ead92f3.json" >/dev/null
  jq -e '.config | .name == "KV_AIEVIDENCE_2dcd3c381ead92f3" and .subjects == ["$KV.AIEVIDENCE_2dcd3c381ead92f3.>"] and .max_msgs_per_subject == 1 and .max_bytes == 1073741824 and .max_age == 0 and .max_msg_size == 2162688 and .storage == "file" and .num_replicas == 1 and .discard == "new" and .deny_delete == true and .allow_rollup_hdrs == true and .allow_direct == true' "$tmp_dir/AIEVIDENCE_2dcd3c381ead92f3.json" >/dev/null
  # shellcheck disable=SC2016 # JetStream API subjects are literal strings.
  request nats '$JS.API.CONSUMER.INFO.ANALYTICS_INGEST_V1.control_api_analytics_ingest_v1' | jq -e '
    .config.durable_name == "control_api_analytics_ingest_v1" and .config.deliver_policy == "all" and
    .config.ack_policy == "explicit" and .config.ack_wait == 120000000000 and .config.max_deliver == -1 and
    .config.filter_subject == "cdnca.analytics.ingest.v1.*" and .config.replay_policy == "instant" and
    .config.max_ack_pending == 256 and .config.max_waiting == 16 and .config.max_batch == 32 and
    .config.max_expires == 2000000000 and .config.max_bytes == 33554432' >/dev/null
  # shellcheck disable=SC2016 # JetStream API subjects are literal strings.
  request nats '$JS.API.CONSUMER.INFO.CONNECTIONS_INGEST_V1.control_api_connections' | jq -e '
    .config.durable_name == "control_api_connections" and .config.deliver_policy == "all" and
    .config.ack_policy == "explicit" and .config.ack_wait == 30000000000 and .config.max_deliver == 8 and
    .config.backoff == [30000000000,60000000000,120000000000,300000000000,600000000000,900000000000,1800000000000] and
    .config.filter_subject == "cdnca.connections.v1.*.*" and .config.replay_policy == "instant" and
    .config.max_ack_pending == 256 and .config.max_waiting == 16 and .config.max_batch == 1 and
    .config.max_expires == 5000000000 and .config.max_bytes == 65536' >/dev/null
}

stage=start-primary
start_server "$server_name" nats "$tmp_dir/store"
stage=preprovision-primary
run_preprovision nats "$tmp_dir/first.out"
run_preprovision nats "$tmp_dir/second.out"
assert_no_credentials "$tmp_dir/first.out"
assert_no_credentials "$tmp_dir/second.out"
stage=assert-resources
assert_streams

stage=legacy-lease-migration
# shellcheck disable=SC2016 # JetStream API subjects are literal strings.
request nats '$JS.API.STREAM.INFO.KV_AILEASE_2dcd3c381ead92f3' >"$tmp_dir/legacy-lease-current.json"
legacy_lease_config=$(jq -c '
  .config |
  .max_age = 12000000000 |
  .duplicate_window = 12000000000 |
  .metadata |= del(."_nats.ver", ."_nats.level")
' "$tmp_dir/legacy-lease-current.json")
# shellcheck disable=SC2016 # JetStream API subjects are literal strings.
request nats '$JS.API.STREAM.UPDATE.KV_AILEASE_2dcd3c381ead92f3' "$legacy_lease_config" >/dev/null
run_hard_timeout "$docker_timeout" docker exec "$toolbox_name" nats --server nats://nats:4222 \
  --user "$runtime_user" --password "$runtime_password" pub --jetstream \
  "\$KV.AILEASE_2dcd3c381ead92f3.active" legacy-lease-value >/dev/null
legacy_expired=0
for _ in $(seq 1 100); do
  # shellcheck disable=SC2016 # JetStream API subjects are literal strings.
  request nats '$JS.API.STREAM.INFO.KV_AILEASE_2dcd3c381ead92f3' >"$tmp_dir/legacy-lease-before.json"
  if jq -e '.state.messages == 0 and .state.last_seq > 0' "$tmp_dir/legacy-lease-before.json" >/dev/null; then
    legacy_expired=1
    break
  fi
  sleep 0.25
done
if [[ $legacy_expired -ne 1 ]]; then
  printf 'legacy lease migration fixture did not become idle\n' >&2
  exit 1
fi
legacy_lease_before_config=$(jq -S -c '.config | del(.max_age, .duplicate_window)' "$tmp_dir/legacy-lease-before.json")
legacy_lease_before_state=$(jq -S -c '.state' "$tmp_dir/legacy-lease-before.json")
legacy_lease_created=$(jq -er '.created' "$tmp_dir/legacy-lease-before.json")
legacy_lease_sequence=$(jq -er '.state.last_seq | select(. > 0)' "$tmp_dir/legacy-lease-before.json")
run_preprovision nats "$tmp_dir/legacy-lease-migration.out"
assert_no_credentials "$tmp_dir/legacy-lease-migration.out"
grep -Fq 'migrated legacy lease stream KV_AILEASE_2dcd3c381ead92f3 from 12s to 40s' \
  "$tmp_dir/legacy-lease-migration.out"
run_preprovision nats "$tmp_dir/legacy-lease-idempotent.out"
assert_no_credentials "$tmp_dir/legacy-lease-idempotent.out"
if grep -Fq 'migrated legacy lease stream' "$tmp_dir/legacy-lease-idempotent.out"; then
  printf 'legacy lease migration was not idempotent\n' >&2
  exit 1
fi
# shellcheck disable=SC2016 # JetStream API subjects are literal strings.
request nats '$JS.API.STREAM.INFO.KV_AILEASE_2dcd3c381ead92f3' >"$tmp_dir/legacy-lease-after.json"
jq -e --arg created "$legacy_lease_created" --argjson sequence "$legacy_lease_sequence" '
  .config.max_age == 40000000000 and .config.duplicate_window == 40000000000 and
  .config.metadata["_nats.req.level"] == "0" and .created == $created and
  .state.messages == 0 and .state.last_seq == $sequence
' "$tmp_dir/legacy-lease-after.json" >/dev/null
legacy_lease_after_config=$(jq -S -c '.config | del(.max_age, .duplicate_window)' "$tmp_dir/legacy-lease-after.json")
legacy_lease_after_state=$(jq -S -c '.state' "$tmp_dir/legacy-lease-after.json")
if [[ $legacy_lease_before_config != "$legacy_lease_after_config" ||
  $legacy_lease_before_state != "$legacy_lease_after_state" ]]; then
  printf 'legacy lease migration changed non-TTL configuration or state\n' >&2
  exit 1
fi
assert_streams

stage=legacy-lease-restart
run_hard_timeout "$docker_timeout" docker restart "$server_name" >/dev/null
restart_ready=0
for _ in $(seq 1 60); do
  if run_hard_timeout "$docker_timeout" docker exec "$server_name" \
    wget -qO- 'http://127.0.0.1:8222/healthz?js-enabled-only=true' 2>/dev/null | grep -q '"status":"ok"'; then
    restart_ready=1
    break
  fi
  sleep 0.25
done
if [[ $restart_ready -ne 1 ]]; then
  printf 'NATS server did not recover after lease migration restart\n' >&2
  exit 1
fi
# shellcheck disable=SC2016 # JetStream API subjects are literal strings.
request nats '$JS.API.STREAM.INFO.KV_AILEASE_2dcd3c381ead92f3' >"$tmp_dir/legacy-lease-restarted.json"
jq -e --arg created "$legacy_lease_created" --argjson sequence "$legacy_lease_sequence" '
  .config.max_age == 40000000000 and .config.duplicate_window == 40000000000 and
  .created == $created and .state.messages == 0 and .state.last_seq == $sequence
' "$tmp_dir/legacy-lease-restarted.json" >/dev/null

host_port=$(run_hard_timeout "$docker_timeout" docker port "$server_name" 4222/tcp | sed 's/.*://')
stage=publisher-acl
NATS_URL="nats://127.0.0.1:$host_port" NATS_TEST_USERNAME="$publisher_user" \
  NATS_TEST_PASSWORD="$publisher_password" NATS_TEST_MODE=publisher \
  go -C "$repo_root/services/control-api" run ../../tests/analytics-observability/preprovision/acl_probe.go
stage=runtime-acl
NATS_URL="nats://127.0.0.1:$host_port" NATS_TEST_USERNAME="$runtime_user" \
  NATS_TEST_PASSWORD="$runtime_password" NATS_TEST_MODE=runtime \
  go -C "$repo_root/services/control-api" run ../../tests/analytics-observability/preprovision/acl_probe.go

stage=preprovision-scope
# shellcheck disable=SC2016 # JetStream API subjects are literal strings.
request nats '$JS.API.STREAM.CREATE.NOT_OBS' '{"name":"NOT_OBS","subjects":["not.obs"]}' >"$tmp_dir/preprovision-denied.out" 2>&1 || true
if ! grep -Eqi 'permissions violation|permission denied' "$tmp_dir/preprovision-denied.out"; then
  printf 'preprovision identity did not receive a non-OBS permission denial\n' >&2
  exit 1
fi
if run_hard_timeout "$docker_timeout" docker exec "$server_name" \
  wget -qO- 'http://127.0.0.1:8222/jsz?streams=true' | jq -e \
  '[.account_details[].stream_detail[].name] | index("NOT_OBS") != null' >/dev/null; then
  printf 'preprovision identity created a non-OBS stream\n' >&2
  exit 1
fi
# shellcheck disable=SC2016 # The preprovision identity can update only the fixed lease stream.
request nats '$JS.API.STREAM.UPDATE.ANALYTICS_INGEST_V1' '{}' >"$tmp_dir/preprovision-update-denied.out" 2>&1 || true
if ! grep -Eqi 'permissions violation|permission denied' "$tmp_dir/preprovision-update-denied.out"; then
  printf 'preprovision identity updated a non-migratable stream\n' >&2
  exit 1
fi
for operation in DELETE PURGE; do
  operation_name=$(printf '%s' "$operation" | tr '[:upper:]' '[:lower:]')
  # shellcheck disable=SC2016 # The deployment identity has no destructive stream permissions.
  request nats "\$JS.API.STREAM.$operation.KV_AILEASE_2dcd3c381ead92f3" '{}' \
    >"$tmp_dir/preprovision-$operation_name-denied.out" 2>&1 || true
  if ! grep -Eqi 'permissions violation|permission denied' "$tmp_dir/preprovision-$operation_name-denied.out"; then
    printf 'preprovision identity received destructive %s permission\n' "$operation" >&2
    exit 1
  fi
done

stage=start-mismatch
start_server "$mismatch_name" nats-mismatch "$tmp_dir/mismatch-store"
# shellcheck disable=SC2016 # JetStream API subjects are literal strings.
request nats-mismatch '$JS.API.STREAM.CREATE.ANALYTICS_INGEST_V1' \
  '{"name":"ANALYTICS_INGEST_V1","subjects":["cdnca.analytics.ingest.v1.*"],"storage":"memory"}' >/dev/null
stage=reject-mismatch
if run_preprovision nats-mismatch "$tmp_dir/mismatch.out"; then
  printf 'preprovision accepted a mismatched resource\n' >&2
  exit 1
fi
assert_no_credentials "$tmp_dir/mismatch.out"

exact_ingest_config=$(jq -cn '{
  name:"ANALYTICS_INGEST_V1", subjects:["cdnca.analytics.ingest.v1.*"], retention:"workqueue",
  max_consumers:1, max_msgs:10000000, max_bytes:10737418240, discard:"new",
  max_age:0, max_msgs_per_subject:-1, max_msg_size:1048576, storage:"file",
  num_replicas:1, duplicate_window:600000000000, compression:"none",
  allow_direct:false, mirror_direct:false, allow_msg_ttl:false
}')

stage=reject-republish-mismatch
start_server "$republish_mismatch_name" nats-republish-mismatch "$tmp_dir/republish-store"
republish_config=$(printf '%s' "$exact_ingest_config" | jq -c \
  '. + {republish:{src:"cdnca.analytics.ingest.v1.*", dest:"cdnca.analytics.republished.v1"}}')
# shellcheck disable=SC2016 # JetStream API subjects are literal strings.
request nats-republish-mismatch '$JS.API.STREAM.CREATE.ANALYTICS_INGEST_V1' "$republish_config" >/dev/null
if run_preprovision nats-republish-mismatch "$tmp_dir/republish-mismatch.out"; then
  printf 'preprovision accepted a republish mismatch\n' >&2
  exit 1
fi
assert_no_credentials "$tmp_dir/republish-mismatch.out"

stage=reject-subject-transform-mismatch
start_server "$transform_mismatch_name" nats-transform-mismatch "$tmp_dir/transform-store"
transform_config=$(printf '%s' "$exact_ingest_config" | jq -c \
  '. + {subject_transform:{src:"cdnca.analytics.ingest.v1.*", dest:"cdnca.analytics.transformed.v1.{{wildcard(1)}}"}}')
# shellcheck disable=SC2016 # JetStream API subjects are literal strings.
request nats-transform-mismatch '$JS.API.STREAM.CREATE.ANALYTICS_INGEST_V1' "$transform_config" >/dev/null
if run_preprovision nats-transform-mismatch "$tmp_dir/transform-mismatch.out"; then
  printf 'preprovision accepted a subject transform mismatch\n' >&2
  exit 1
fi
assert_no_credentials "$tmp_dir/transform-mismatch.out"

stage=reject-legacy-lease-drift
start_server "$lease_mismatch_name" nats-lease-mismatch "$tmp_dir/lease-mismatch-store"
run_preprovision nats-lease-mismatch "$tmp_dir/lease-mismatch-baseline.out"
assert_no_credentials "$tmp_dir/lease-mismatch-baseline.out"
legacy_lease_drift=$(printf '%s' "$legacy_lease_config" | jq -c '.max_bytes = 4194305')
# shellcheck disable=SC2016 # JetStream API subjects are literal strings.
request nats-lease-mismatch '$JS.API.STREAM.UPDATE.KV_AILEASE_2dcd3c381ead92f3' "$legacy_lease_drift" >/dev/null
if run_preprovision nats-lease-mismatch "$tmp_dir/lease-mismatch.out"; then
  printf 'preprovision accepted non-TTL legacy lease drift\n' >&2
  exit 1
fi
assert_no_credentials "$tmp_dir/lease-mismatch.out"
# shellcheck disable=SC2016 # JetStream API subjects are literal strings.
request nats-lease-mismatch '$JS.API.STREAM.INFO.KV_AILEASE_2dcd3c381ead92f3' | jq -e '
  .config.max_bytes == 4194305 and .config.max_age == 12000000000 and
  .config.duplicate_window == 12000000000
' >/dev/null

stage=reject-nonlegacy-lease-ttl
nonlegacy_lease_ttl=$(printf '%s' "$legacy_lease_config" | jq -c '
  .max_age = 13000000000 | .duplicate_window = 13000000000
')
# shellcheck disable=SC2016 # JetStream API subjects are literal strings.
request nats-lease-mismatch '$JS.API.STREAM.UPDATE.KV_AILEASE_2dcd3c381ead92f3' "$nonlegacy_lease_ttl" >/dev/null
if run_preprovision nats-lease-mismatch "$tmp_dir/nonlegacy-lease-ttl.out"; then
  printf 'preprovision accepted a non-12s legacy lease TTL\n' >&2
  exit 1
fi
assert_no_credentials "$tmp_dir/nonlegacy-lease-ttl.out"
# shellcheck disable=SC2016 # JetStream API subjects are literal strings.
request nats-lease-mismatch '$JS.API.STREAM.INFO.KV_AILEASE_2dcd3c381ead92f3' | jq -e '
  .config.max_bytes == 4194304 and .config.max_age == 13000000000 and
  .config.duplicate_window == 13000000000
' >/dev/null

stage=reject-active-legacy-lease
start_server "$active_lease_name" nats-active-lease "$tmp_dir/active-lease-store"
run_preprovision nats-active-lease "$tmp_dir/active-lease-baseline.out"
assert_no_credentials "$tmp_dir/active-lease-baseline.out"
# shellcheck disable=SC2016 # JetStream API subjects are literal strings.
request nats-active-lease '$JS.API.STREAM.UPDATE.KV_AILEASE_2dcd3c381ead92f3' "$legacy_lease_config" >/dev/null
run_hard_timeout "$docker_timeout" docker exec "$toolbox_name" nats --server nats://nats-active-lease:4222 \
  --user "$runtime_user" --password "$runtime_password" pub --jetstream \
  "\$KV.AILEASE_2dcd3c381ead92f3.active" active-lease-value >/dev/null
if run_preprovision nats-active-lease "$tmp_dir/active-lease.out"; then
  printf 'preprovision migrated an active legacy lease stream\n' >&2
  exit 1
fi
assert_no_credentials "$tmp_dir/active-lease.out"
grep -Fq 'legacy lease stream KV_AILEASE_2dcd3c381ead92f3 is not idle' "$tmp_dir/active-lease.out"
# shellcheck disable=SC2016 # JetStream API subjects are literal strings.
request nats-active-lease '$JS.API.STREAM.INFO.KV_AILEASE_2dcd3c381ead92f3' | jq -e '
  .config.max_age == 12000000000 and .config.duplicate_window == 12000000000 and
  .state.messages == 1
' >/dev/null

stage=cleanup
cleanup
trap - EXIT INT TERM
if container_output=$(query_task_container_ids); then
  container_count=$(count_ids "$container_output")
else
  container_count=-1
fi
if [[ $container_count != 0 ]]; then
  printf 'task-owned container residue remains\n' >&2
  exit 1
fi
if network_output=$(query_task_network_ids); then
  network_count=$(count_ids "$network_output")
else
  network_count=-1
fi
if [[ $network_count != 0 ]]; then
  printf 'task-owned network residue remains\n' >&2
  exit 1
fi
printf 'analytics NATS preprovision acceptance passed (containers=%s networks=%s)\n' \
  "$container_count" "$network_count"
