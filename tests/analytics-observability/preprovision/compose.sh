#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
project="cdnca-obs-preprovision-$$"
tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/cdnca-obs-compose.XXXXXX")
docker_timeout=${OBS_DOCKER_TIMEOUT_SECONDS:-180}
cleanup_timeout=${OBS_DOCKER_CLEANUP_TIMEOUT_SECONDS:-30}
cleanup_running=0
final_container_count=-1
final_network_count=-1
final_volume_count=-1

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


compose() {
  POSTGRES_DB=cdnca POSTGRES_USER=cdnca POSTGRES_PASSWORD=compose-postgres \
  REDIS_PASSWORD=compose-redis CLICKHOUSE_DB=cdnca CLICKHOUSE_USER=cdnca \
  CLICKHOUSE_PASSWORD=compose-clickhouse NATS_CLIENT_PORT=0 NATS_MONITOR_PORT=0 \
  NATS_PREPROVISION_USERNAME=compose-preprovision \
  NATS_PREPROVISION_PASSWORD=compose-preprovision-password \
  NATS_CONTROL_CONSUMER_USERNAME=compose-runtime NATS_CONTROL_CONSUMER_PASSWORD=compose-runtime-password \
  NATS_GATEWAY_PUBLISHER_USERNAME=compose-publisher NATS_GATEWAY_PUBLISHER_PASSWORD=compose-publisher-password \
    run_hard_timeout "$docker_timeout" docker compose \
      --project-name "$project" --file "$repo_root/compose.yaml" "$@"
}

count_ids() {
  if [[ -z "$1" ]]; then
    printf '0\n'
  else
    printf '%s\n' "$1" | awk 'NF { count++ } END { print count + 0 }'
  fi
}

query_project_container_ids() {
  run_hard_timeout "$cleanup_timeout" docker ps -aq \
    --filter "label=com.docker.compose.project=$project"
}

query_project_network_ids() {
  run_hard_timeout "$cleanup_timeout" docker network ls -q \
    --filter "label=com.docker.compose.project=$project"
}

query_project_volume_ids() {
  run_hard_timeout "$cleanup_timeout" docker volume ls -q \
    --filter "label=com.docker.compose.project=$project"
}

cleanup() {
  local status=$?
  local cleanup_tmp_dir=${1:-$tmp_dir}
  local cleanup_status=0 resource_output
  if [[ $cleanup_running -eq 1 ]]; then
    return "$status"
  fi
  cleanup_running=1
  if compose down --volumes --remove-orphans >/dev/null 2>&1; then
    :
  else
    printf 'failed to remove task-owned Compose resources\n' >&2
    cleanup_status=1
  fi
  if resource_output=$(query_project_container_ids); then
    final_container_count=$(count_ids "$resource_output")
  else
    final_container_count=-1
    cleanup_status=1
  fi
  if resource_output=$(query_project_network_ids); then
    final_network_count=$(count_ids "$resource_output")
  else
    final_network_count=-1
    cleanup_status=1
  fi
  if resource_output=$(query_project_volume_ids); then
    final_volume_count=$(count_ids "$resource_output")
  else
    final_volume_count=-1
    cleanup_status=1
  fi
  if [[ $final_container_count != 0 || $final_network_count != 0 || $final_volume_count != 0 ]]; then
    printf 'Compose task residue remains (containers=%s networks=%s volumes=%s)\n' \
      "$final_container_count" "$final_network_count" "$final_volume_count" >&2
    cleanup_status=1
  fi
  rm -rf "$cleanup_tmp_dir"
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
    docker() {
      if [[ $1 == compose ]]; then return 0; fi
      return 73
    }
    if cleanup "$fixture_tmp"; then query_status=0; else query_status=$?; fi
    [[ $query_status -ne 0 && ! -e "$fixture_tmp" ]]
  ) 2>"$query_log"; then
    :
  else
    rm -f "$query_log" "$action_log"
    printf 'cleanup query-failure selftest did not fail closed\n' >&2
    return 1
  fi
  if ! grep -Fq 'containers=-1 networks=-1 volumes=-1' "$query_log"; then
    rm -f "$query_log" "$action_log"
    printf 'cleanup query-failure selftest did not preserve -1\n' >&2
    return 1
  fi
  if (
    fixture_tmp=$(mktemp -d "${TMPDIR:-/tmp}/cdnca-obs-cleanup-action-tmp.XXXXXX")
    cleanup_running=0
    # shellcheck disable=SC2329 # run_hard_timeout invokes the fixture function indirectly.
    docker() {
      if [[ $1 == compose ]]; then return 74; fi
      return 0
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
  if ! grep -Fq 'failed to remove task-owned Compose resources' "$action_log"; then
    rm -f "$query_log" "$action_log"
    printf 'cleanup action-failure selftest lost failure evidence\n' >&2
    return 1
  fi
  rm -f "$query_log" "$action_log"
  printf 'cleanup failure selftest passed: query=-1 action=nonzero\n'
}

case ${OBS_PREPROVISION_SELFTEST:-} in
  timeout)
    if run_timeout_selftest compose; then selftest_status=0; else selftest_status=$?; fi
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

compose up --abort-on-container-exit --exit-code-from nats-analytics-preprovision \
  nats-analytics-preprovision >"$tmp_dir/first.out" 2>&1
compose up --abort-on-container-exit --exit-code-from nats-analytics-preprovision \
  --force-recreate nats-analytics-preprovision >"$tmp_dir/second.out" 2>&1

for output in "$tmp_dir/first.out" "$tmp_dir/second.out"; do
  grep -Fq 'analytics NATS resources verified' "$output"
  for secret in compose-preprovision-password compose-runtime-password compose-publisher-password; do
    if grep -Fq "$secret" "$output"; then
      printf 'credential leaked in Compose preprovision output\n' >&2
      exit 1
    fi
  done
done

cleanup
trap - EXIT INT TERM
printf 'analytics NATS Compose preprovision passed (containers=%s networks=%s volumes=%s)\n' \
  "$final_container_count" "$final_network_count" "$final_volume_count"
