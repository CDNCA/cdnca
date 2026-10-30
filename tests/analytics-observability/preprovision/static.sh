#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/cdnca-obs-preprovision-static.XXXXXX")
task_id="cdnca-obs-preprovision-static-$$"
helm_default_name="$task_id-helm-default"
helm_disabled_name="$task_id-helm-disabled"
helm_lint_name="$task_id-helm-lint"
helm_template_name="$task_id-helm-template"
helm_invalid_name="$task_id-helm-invalid"
docker_timeout=${OBS_DOCKER_TIMEOUT_SECONDS:-120}
cleanup_timeout=${OBS_DOCKER_CLEANUP_TIMEOUT_SECONDS:-30}
cleanup_running=0
final_container_count=-1

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
    --filter "label=cdnca.obs-preprovision-static=$task_id"
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
  local cleanup_status=0 initial_query_ok=0 container_output id
  local -a container_ids=()
  if [[ $cleanup_running -eq 1 ]]; then
    return "$status"
  fi
  cleanup_running=1
  if container_output=$(query_task_container_ids); then
    initial_query_ok=1
    while IFS= read -r id; do
      [[ -n "$id" ]] && container_ids[${#container_ids[@]}]="$id"
    done <<< "$container_output"
    if [[ ${#container_ids[@]} -gt 0 ]]; then
      if run_hard_timeout "$cleanup_timeout" docker rm -f "${container_ids[@]}" >/dev/null 2>&1; then
        :
      else
        printf 'failed to remove task-owned static Helm containers\n' >&2
        cleanup_status=1
      fi
    fi
  else
    printf 'task-owned static container residue count: -1 (query failed)\n' >&2
    final_container_count=-1
    cleanup_status=1
  fi
  if [[ $initial_query_ok -eq 1 ]]; then
    if container_output=$(query_task_container_ids); then
      final_container_count=$(count_ids "$container_output")
    else
      final_container_count=-1
      cleanup_status=1
    fi
  fi
  if [[ $final_container_count != 0 ]]; then
    printf 'task-owned static container residue remains: %s\n' "$final_container_count" >&2
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
  if ! grep -Fq 'static container residue count: -1' "$query_log"; then
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
  if ! grep -Fq 'failed to remove task-owned static Helm containers' "$action_log"; then
    rm -f "$query_log" "$action_log"
    printf 'cleanup action-failure selftest lost failure evidence\n' >&2
    return 1
  fi
  rm -f "$query_log" "$action_log"
  printf 'cleanup failure selftest passed: query=-1 action=nonzero\n'
}

case ${OBS_PREPROVISION_SELFTEST:-} in
  timeout)
    if run_timeout_selftest static; then selftest_status=0; else selftest_status=$?; fi
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

jq empty "$repo_root/infra/helm/cdnca/values.schema.json" >/dev/null

POSTGRES_DB=cdnca POSTGRES_USER=cdnca POSTGRES_PASSWORD=static-postgres \
REDIS_PASSWORD=static-redis CLICKHOUSE_DB=cdnca CLICKHOUSE_USER=cdnca \
CLICKHOUSE_PASSWORD=static-clickhouse \
NATS_PREPROVISION_USERNAME=static-preprovision \
NATS_PREPROVISION_PASSWORD=static-preprovision-password \
NATS_CONTROL_CONSUMER_USERNAME=static-runtime NATS_CONTROL_CONSUMER_PASSWORD=static-runtime-password \
NATS_GATEWAY_PUBLISHER_USERNAME=static-publisher NATS_GATEWAY_PUBLISHER_PASSWORD=static-publisher-password \
  run_hard_timeout "$docker_timeout" docker compose \
    -f "$repo_root/compose.yaml" config >"$tmp_dir/compose.yaml"

run_hard_timeout "$docker_timeout" docker run --rm --name "$helm_default_name" \
  --label "cdnca.obs-preprovision-static=$task_id" \
  --volume "$repo_root/infra/helm/cdnca:/chart:ro" alpine/helm:3.18.4 \
  lint /chart >"$tmp_dir/helm-default.out"
run_hard_timeout "$docker_timeout" docker run --rm --name "$helm_disabled_name" \
  --label "cdnca.obs-preprovision-static=$task_id" \
  --volume "$repo_root/infra/helm/cdnca:/chart:ro" alpine/helm:3.18.4 \
  lint /chart --set analyticsNATSPreprovision.enabled=true \
  --set controlApi.analyticsIngest.enabled=false >"$tmp_dir/helm-disabled.out"
run_hard_timeout "$docker_timeout" docker run --rm --name "$helm_lint_name" \
  --label "cdnca.obs-preprovision-static=$task_id" \
  --volume "$repo_root/infra/helm/cdnca:/chart:ro" alpine/helm:3.18.4 \
  lint /chart --set analyticsNATSPreprovision.enabled=true \
  --set controlApi.analyticsIngest.enabled=true >"$tmp_dir/helm-lint.out"
run_hard_timeout "$docker_timeout" docker run --rm --name "$helm_template_name" \
  --label "cdnca.obs-preprovision-static=$task_id" \
  --volume "$repo_root/infra/helm/cdnca:/chart:ro" alpine/helm:3.18.4 \
  template static /chart --set analyticsNATSPreprovision.enabled=true \
  --set controlApi.analyticsIngest.enabled=true >"$tmp_dir/helm.yaml"

contract_failed=0
if run_hard_timeout "$docker_timeout" docker run --rm --name "$helm_invalid_name" \
  --label "cdnca.obs-preprovision-static=$task_id" \
  --volume "$repo_root/infra/helm/cdnca:/chart:ro" alpine/helm:3.18.4 \
  lint /chart --set analyticsNATSPreprovision.enabled=false \
  --set controlApi.analyticsIngest.enabled=true >"$tmp_dir/helm-invalid.out" 2>&1; then
  printf 'Helm schema accepted analytics ingest without NATS preprovision\n' >&2
  contract_failed=1
fi
for field in name description subjects retention max_consumers max_msgs max_bytes discard \
  discard_new_per_subject max_age max_msgs_per_subject max_msg_size storage num_replicas \
  no_ack template_owner duplicate_window placement mirror sources sealed deny_delete deny_purge allow_rollup_hdrs \
  compression first_seq subject_transform republish allow_direct mirror_direct consumer_limits \
  allow_msg_ttl subject_delete_marker_ttl metadata; do
  if ! grep -Fq "$field" "$repo_root/infra/nats/analytics-preprovision.sh"; then
    printf 'external preprovision verification omits StreamConfig field: %s\n' "$field" >&2
    contract_failed=1
  fi
done
for script in run.sh static.sh compose.sh; do
  if ! grep -Fq 'run_hard_timeout()' "$repo_root/tests/analytics-observability/preprovision/$script"; then
    printf 'Docker hard-timeout helper missing from %s\n' "$script" >&2
    contract_failed=1
  fi
  for signal in INT TERM KILL; do
    if ! grep -Fq "kill -$signal --" "$repo_root/tests/analytics-observability/preprovision/$script"; then
      printf 'Docker hard-timeout escalation omits %s in %s\n' "$signal" "$script" >&2
      contract_failed=1
    fi
  done
done
docker_word=docker
for script in run.sh static.sh compose.sh; do
  while IFS= read -r line; do
    if [[ "$line" == *"$docker_word "* && "$line" != *'run_hard_timeout '* ]]; then
      printf 'Docker call bypasses hard timeout in %s: %s\n' "$script" "$line" >&2
      contract_failed=1
    fi
  done <"$repo_root/tests/analytics-observability/preprovision/$script"
done
if [[ $contract_failed -ne 0 ]]; then
  exit 1
fi

ruby -ryaml -e '
  compose = YAML.load_file(ARGV.fetch(0))
  compose_source = File.binread(ARGV.fetch(1))
  nats = compose.dig("services", "nats") or abort "compose nats service missing"
  init = compose.dig("services", "nats-analytics-preprovision") or abort "compose preprovision service missing"
  abort "compose NATS image drift" unless nats["image"] == "nats:2.11.4-alpine"
  abort "compose preprovision image drift" unless init["image"] == "natsio/nats-box:0.19.1"
  abort "compose NATS config missing" unless nats.fetch("volumes").any? { |item| item["source"].end_with?("infra/nats/analytics-server.conf") }
  abort "compose script missing" unless init.fetch("volumes").any? { |item| item["source"].end_with?("infra/nats/analytics-preprovision.sh") }
  abort "compose NATS URL contains credentials" unless init.dig("environment", "NATS_URL") == "nats://nats:4222"
  abort "compose connections stream drift" unless init.dig("environment", "ANALYTICS_CONNECTIONS_STREAM") == "CONNECTIONS_INGEST_V1"
  abort "compose connections durable drift" unless init.dig("environment", "ANALYTICS_CONNECTIONS_DURABLE") == "control_api_connections"
  expected = {
    "NATS_PREPROVISION_USERNAME" => "static-preprovision",
    "NATS_PREPROVISION_PASSWORD" => "\"static-preprovision-password\"",
    "NATS_CONTROL_CONSUMER_USERNAME" => "static-runtime",
    "NATS_CONTROL_CONSUMER_PASSWORD" => "\"static-runtime-password\"",
    "NATS_GATEWAY_PUBLISHER_USERNAME" => "static-publisher",
    "NATS_GATEWAY_PUBLISHER_PASSWORD" => "\"static-publisher-password\""
  }
  abort "compose identities are not separated" unless expected.all? { |key, value| nats.fetch("environment")[key] == value }
  abort "compose retains a legacy workload identity fallback" if compose_source.match?(/NATS_(?:RUNTIME|PUBLISHER)_(?:USERNAME|PASSWORD)/)
' "$tmp_dir/compose.yaml" "$repo_root/compose.yaml"

ruby -ryaml -e '
  documents = YAML.load_stream(File.read(ARGV.fetch(0))).compact
  job = documents.find { |doc| doc["kind"] == "Job" && doc.dig("metadata", "name")&.end_with?("analytics-nats-preprovision") }
  deployment = documents.find { |doc| doc["kind"] == "Deployment" && doc.dig("metadata", "name")&.end_with?("control-api") }
  abort "Helm preprovision Job missing" unless job
  abort "Helm control-api Deployment missing" unless deployment
  container = job.dig("spec", "template", "spec", "containers", 0)
  abort "Helm preprovision image drift" unless container["image"] == "natsio/nats-box:0.19.1"
  env = container.fetch("env").to_h { |entry| [entry.fetch("name"), entry] }
  %w[NATS_URL NATS_PREPROVISION_USERNAME NATS_PREPROVISION_PASSWORD].each do |name|
    abort "Helm #{name} is not Secret-backed" unless env.dig(name, "valueFrom", "secretKeyRef")
  end
  script = container.fetch("args").fetch(0).lines.reject { |line| line.include?("CDNCA_ANALYTICS_PREPROVISION_SCRIPT_") }.join
  abort "Helm embedded preprovision script drift" unless script == File.binread(ARGV.fetch(1))
  control_env = deployment.dig("spec", "template", "spec", "containers", 0, "env").to_h { |entry| [entry.fetch("name"), entry] }
  url_ref = control_env.dig("ANALYTICS_INGEST_NATS_URL", "valueFrom", "secretKeyRef")
  user_ref = control_env.dig("ANALYTICS_INGEST_NATS_USER", "valueFrom", "secretKeyRef")
  password_ref = control_env.dig("ANALYTICS_INGEST_NATS_PASSWORD", "valueFrom", "secretKeyRef")
  abort "control-api NATS URL is not datastore Secret-backed" unless url_ref && url_ref["name"] == "cdnca-customer-datastores"
  abort "control-api NATS runtime credentials are not separated" unless user_ref && password_ref && user_ref["name"] == "cdnca-control-api-runtime" && password_ref["name"] == "cdnca-control-api-runtime"
' "$tmp_dir/helm.yaml" "$repo_root/infra/nats/analytics-preprovision.sh"

cleanup
trap - EXIT INT TERM
printf 'analytics NATS preprovision static gates passed (containers=%s)\n' "$final_container_count"
