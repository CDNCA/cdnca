#!/usr/bin/env bash
# shellcheck disable=SC2016 # NATS API subject fixtures intentionally use literal shell strings.
set -Eeuo pipefail
umask 077

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/../../.." && pwd)"
readonly REPO_ROOT
readonly NATS_IMAGE='nats:2.11.4-alpine'
readonly NATS_BOX_IMAGE='natsio/nats-box:0.19.1'
readonly CLICKHOUSE_IMAGE='clickhouse/clickhouse-server:25.3.6.56-alpine'
readonly POSTGRES_IMAGE='postgres:17.9-alpine'
readonly REDIS_IMAGE='redis:7.4.4-alpine'
readonly CONTROL_DATABASE_SCHEMA='cdnca_e2e'
readonly MIGRATION_090_ID='090_package_offer_publication'
readonly MIGRATION_091_ID='091_notification_control_idempotency_receipts'
readonly MIGRATION_090_UP="${REPO_ROOT}/services/control-api/migrations/${MIGRATION_090_ID}.up.sql"
readonly MIGRATION_090_DOWN="${REPO_ROOT}/services/control-api/migrations/${MIGRATION_090_ID}.down.sql"
readonly MIGRATION_090_TEST="${REPO_ROOT}/services/control-api/migrations/package_offer_publication_090_integration_test.go"
readonly MIGRATION_091_UP="${REPO_ROOT}/services/control-api/migrations/${MIGRATION_091_ID}.up.sql"
readonly MIGRATION_091_DOWN="${REPO_ROOT}/services/control-api/migrations/${MIGRATION_091_ID}.down.sql"
readonly MIGRATION_091_TEST="${REPO_ROOT}/services/control-api/internal/notificationcontrol/notification_control_idempotency_receipts_091_integration_test.go"
readonly MIGRATION_090_UP_RELEASE_SHA256='d1c7490b78a9298e0380ec7a8258fbdbebb4a24c7ece1870a1b38f2dc6e4c5b0'
readonly MIGRATION_090_DOWN_RELEASE_SHA256='1d1dc589b4dc08e04f72e61a459b0fd4096dab53f3135f55d146c02e1e6e3eb0'
readonly MIGRATION_090_TEST_RELEASE_SHA256='6b6004991baebda2e246edf287ef18ec2f441586782764541e55e02add7ba198'
readonly MIGRATION_091_UP_RELEASE_SHA256='87ae89e034d20d2794e28ecc2a5e01968d3246fa382bf794482665a7f0317f79'
readonly MIGRATION_091_DOWN_RELEASE_SHA256='179b3a7c2324403f4f1af4cd10b3c8dd27a584f6a797a1f06a6f7c32acb71c43'
readonly MIGRATION_091_TEST_RELEASE_SHA256='599a710f62eb6b8847449968ba09964eeec971974c85a7bea1766271f2b112ec'
readonly PREPROVISION_SCRIPT="${REPO_ROOT}/infra/nats/analytics-preprovision.sh"
readonly NATS_SERVER_CONFIG="${REPO_ROOT}/infra/nats/analytics-server.conf"
readonly EDGE_TELEMETRY_FIXTURE_SOURCE="${REPO_ROOT}/agents/edge-agent/cmd/edge-telemetry-fixture"

obs_e2e_fail() {
  printf 'ANALYTICS_PROCESS_E2E_FAIL stage=%s\n' "$1" >&2
  exit 1
}

obs_e2e_unknown() {
  printf 'ANALYTICS_PROCESS_E2E_UNKNOWN reason=%s\n' "$1" >&2
  exit 77
}

obs_e2e_classify_core_ports() {
  local postgres=$1 clickhouse=$2 nats=$3 edge_nats=$4 redis=$5
  jq -er \
    --arg postgres "${postgres}" --arg clickhouse "${clickhouse}" \
    --arg nats "${nats}" --arg edge_nats "${edge_nats}" --arg redis "${redis}" '
      def fatal($reason): "fatal\t" + $reason;
      def retry($reason): "retry\t" + $reason;
      if type != "array" then fatal("inspect-shape")
      elif length != 5 then fatal("container-name-cardinality")
      else
        (["/" + $postgres, "/" + $clickhouse, "/" + $nats, "/" + $edge_nats, "/" + $redis]) as $names
        | if any(.[]; (.Name | type) != "string") or
             ([.[] | .Name] | unique | length) != 5 or
             any(.[]; .Name as $name | ($names | index($name)) == null)
          then fatal("container-name-cardinality")
          else
            def one($name): [.[] | select(.Name == ("/" + $name))][0];
            [{container:one($postgres),port:"5432/tcp"},
             {container:one($clickhouse),port:"8123/tcp"},
             {container:one($nats),port:"4222/tcp"},
             {container:one($edge_nats),port:"4222/tcp"},
             {container:one($redis),port:"6379/tcp"}] as $targets
            | if any($targets[]; (.container.State | type) != "object") or
                 any($targets[]; (.container.State.Running | type) != "boolean")
              then fatal("inspect-shape")
              elif any($targets[]; .container.State.Running != true and
                (.container.State.Status == "created" or .container.State.Status == "restarting"))
              then retry("container-starting")
              elif any($targets[]; .container.State.Running != true)
              then fatal("container-not-running")
              elif any($targets[]; . as $target |
                ($target.container.NetworkSettings | type) != "object") or
                   any($targets[]; . as $target |
                ($target.container.NetworkSettings | has("Ports") | not)) or
                   any($targets[]; . as $target |
                ($target.container.NetworkSettings.Ports | type) != "object")
              then fatal("inspect-shape")
              elif any($targets[]; . as $target |
                ($target.container.NetworkSettings.Ports | has($target.port) | not))
              then fatal("binding-shape")
              elif any($targets[]; . as $target |
                $target.container.NetworkSettings.Ports[$target.port] as $binding |
                $binding != null and ($binding | type) != "array")
              then fatal("binding-shape")
              elif any($targets[]; . as $target |
                $target.container.NetworkSettings.Ports[$target.port] as $binding |
                $binding != null and ($binding | length) > 1)
              then fatal("binding-cardinality")
              elif any($targets[]; . as $target |
                $target.container.NetworkSettings.Ports[$target.port] as $binding |
                $binding != null and ($binding | length) == 1 and
                ($binding[0] | type) != "object")
              then fatal("binding-shape")
              elif any($targets[]; . as $target |
                $target.container.NetworkSettings.Ports[$target.port] as $binding |
                $binding != null and ($binding | length) == 1 and
                $binding[0].HostIp != "127.0.0.1")
              then fatal("host-ip-mismatch")
              elif any($targets[]; . as $target |
                $target.container.NetworkSettings.Ports[$target.port] as $binding |
                $binding != null and ($binding | length) == 1 and
                (($binding[0].HostPort | type) != "string" or $binding[0].HostPort == ""))
              then fatal("host-port-invalid")
              elif any($targets[]; . as $target |
                $target.container.NetworkSettings.Ports[$target.port] as $binding |
                $binding != null and ($binding | length) == 1 and
                ($binding[0].HostPort | test("^[1-9][0-9]{0,4}$") | not))
              then fatal("host-port-invalid")
              elif any($targets[]; . as $target |
                $target.container.NetworkSettings.Ports[$target.port] as $binding |
                $binding != null and ($binding | length) == 1 and
                (($binding[0].HostPort | tonumber) < 1 or ($binding[0].HostPort | tonumber) > 65535))
              then fatal("host-port-invalid")
              elif any($targets[]; . as $target |
                $target.container.NetworkSettings.Ports[$target.port] as $binding |
                $binding == null or ($binding | length) == 0)
              then retry("port-binding-not-ready")
              else
                [$targets[] | . as $target |
                  $target.container.NetworkSettings.Ports[$target.port][0].HostPort] as $host_ports
                | if ($host_ports | map(tonumber) | unique | length) != 5
                  then fatal("host-port-duplicate")
                  else "ready\t" + ($host_ports | join("\t"))
                  end
              end
          end
      end
    '
}

obs_e2e_classify_edge_nats_readiness() {
  jq -er '
    def fatal($reason): "fatal\t" + $reason;
    def retry($reason): "retry\t" + $reason;
    def integer: if type == "number" then . == floor else false end;
    def nonnegative_integer: if integer then . >= 0 else false end;
    def limit_integer: if integer then . >= -1 else false end;
    if type != "object" or
       keys != ["probe_exit","probe_stderr","response","state","store_writable"] or
       (.state | type) != "object" or
       (.state | keys) != ["Error","ExitCode","OOMKilled","Running","Status"] or
       (.state.Running | type) != "boolean" or
       (.state.Status | type) != "string" or
       (.state.ExitCode | type) != "number" or
       (.state.OOMKilled | type) != "boolean" or
       (.state.Error | type) != "string" or
       (.store_writable | type) != "boolean" or
       (.probe_exit | type) != "number" or
       (.probe_stderr | type) != "string" or
       (.response | type) != "string"
    then fatal("malformed")
    elif .state.Running != true
    then if .state.OOMKilled then fatal("container-oom") else fatal("container-stopped") end
    elif .store_writable != true then fatal("store-unwritable")
    elif .probe_exit != 0 then
      (.probe_stderr | ascii_downcase) as $error |
      if ($error | test("no responders")) then retry("no-responder")
      elif ($error | test("no such host|name resolution|temporary failure|server misbehaving"))
      then retry("dns")
      elif ($error | test("connection refused|i/o timeout|context deadline exceeded|no servers available|unable to connect|connection closed|timeout"))
      then retry("connect")
      else retry("probe-error")
      end
    else
      (try (.response | fromjson) catch null) as $response |
      if ($response | type) != "object" then fatal("malformed")
      elif $response.error != null then fatal("js-api-error")
      elif $response.type != "io.nats.jetstream.api.v1.account_info_response" or
           (($response.memory | nonnegative_integer) | not) or
           (($response.storage | nonnegative_integer) | not) or
           (($response.streams | nonnegative_integer) | not) or
           (($response.consumers | nonnegative_integer) | not) or
           ($response.limits | type) != "object" or
           (($response.limits.max_memory | limit_integer) | not) or
           (($response.limits.max_storage | limit_integer) | not) or
           (($response.limits.max_streams | limit_integer) | not) or
           (($response.limits.max_consumers | limit_integer) | not) or
           (($response.limits.max_ack_pending | limit_integer) | not) or
           (($response.limits.memory_max_stream_bytes | limit_integer) | not) or
           (($response.limits.storage_max_stream_bytes | limit_integer) | not) or
           ($response.limits.max_bytes_required | type) != "boolean" or
           ($response.api | type) != "object" or
           $response.api.level != 1 or
           (($response.api.total | nonnegative_integer) | not) or
           (($response.api.errors | nonnegative_integer) | not)
      then fatal("js-info-invalid")
      else "ready\tok"
      end
    end
  '
}

obs_e2e_classify_edge_nats_runtime_uid() {
  local pid1_euid=$1 exec_uid=$2 pid1_number exec_number
  if [[ ! "${pid1_euid}" =~ ^(0|[1-9][0-9]{0,9})$ ]] ||
     [[ ! "${exec_uid}" =~ ^(0|[1-9][0-9]{0,9})$ ]]; then
    printf 'fatal\truntime-uid-invalid\n'
    return 0
  fi
  pid1_number=$((10#${pid1_euid}))
  exec_number=$((10#${exec_uid}))
  if [ "${pid1_number}" -gt 4294967294 ] || [ "${exec_number}" -gt 4294967294 ]; then
    printf 'fatal\truntime-uid-invalid\n'
  elif [ "${pid1_number}" -ne "${exec_number}" ]; then
    printf 'fatal\truntime-uid-mismatch\n'
  else
    printf 'ready\t%s\n' "${pid1_euid}"
  fi
}

obs_e2e_deadline_budget_millis() {
  local deadline_nanos=$1 now_nanos=$2 cap_millis=$3 remaining_nanos remaining_millis
  [[ "${deadline_nanos}" =~ ^(0|[1-9][0-9]{0,18})$ ]] || return 1
  [[ "${now_nanos}" =~ ^(0|[1-9][0-9]{0,18})$ ]] || return 1
  [[ "${cap_millis}" =~ ^[1-9][0-9]{0,5}$ ]] || return 1
  [ "${cap_millis}" -le 60000 ] || return 1
  remaining_nanos=$((deadline_nanos - now_nanos))
  [ "${remaining_nanos}" -gt 0 ] || return 1
  remaining_millis=$((remaining_nanos / 1000000))
  [ "${remaining_millis}" -gt 0 ] || return 1
  [ "${remaining_millis}" -le "${cap_millis}" ] || remaining_millis=${cap_millis}
  printf '%s\n' "${remaining_millis}"
}

obs_e2e_capture_core_port_snapshot() {
  local output=$1 timeout_seconds=$2 temporary
  shift 2
  temporary="${output}.tmp"
  if ! obs_e2e_docker_timeout "${timeout_seconds}" inspect --type container \
    --format '{"Name":{{json .Name}},"State":{"Running":{{json .State.Running}},"Status":{{json .State.Status}}},"NetworkSettings":{"Ports":{{json .NetworkSettings.Ports}}}}' \
    "$@" | jq -s -ec '
      if type == "array" and length == 5 and all(.[]; type == "object")
      then . else error("unsafe inspect projection") end
    ' >"${temporary}"; then
    rm -f -- "${temporary}"
    return 1
  fi
  mv -- "${temporary}" "${output}"
}

obs_e2e_read_core_ports() {
  local safe_file=$1 postgres=$2 clickhouse=$3 nats=$4 edge_nats=$5 redis=$6
  local deadline_epoch current_epoch remaining_seconds inspect_timeout snapshot classification state detail
  local last_reason='port-binding-not-ready'
  deadline_epoch=$(( $(date +%s) + 15 ))
  while :; do
    current_epoch=$(date +%s)
    remaining_seconds=$((deadline_epoch - current_epoch))
    if [ "${remaining_seconds}" -le 1 ]; then
      core_port_failure_stage='core-port-mapping-timeout'
      printf 'ANALYTICS_PROCESS_E2E_PORTMAP reason=core-port-mapping-timeout detail=%s snapshot=%s\n' \
        "${last_reason}" "${safe_file}" >&2
      return 1
    fi
    inspect_timeout=$((remaining_seconds - 1))
    [ "${inspect_timeout}" -le 5 ] || inspect_timeout=5
    if obs_e2e_capture_core_port_snapshot "${safe_file}" "${inspect_timeout}" \
      "${postgres}" "${clickhouse}" "${nats}" "${edge_nats}" "${redis}"; then
      snapshot=$(cat -- "${safe_file}")
      if classification=$(obs_e2e_classify_core_ports \
        "${postgres}" "${clickhouse}" "${nats}" "${edge_nats}" "${redis}" <<<"${snapshot}"); then
        state=${classification%%$'\t'*}
        detail=${classification#*$'\t'}
        case "${state}" in
          ready)
            ports_tsv=${detail}
            return 0
            ;;
          retry) last_reason=${detail} ;;
          fatal)
            core_port_failure_stage='core-port-mapping'
            printf 'ANALYTICS_PROCESS_E2E_PORTMAP reason=%s snapshot=%s\n' \
              "${detail}" "${safe_file}" >&2
            return 1
            ;;
          *)
            core_port_failure_stage='core-port-mapping'
            printf 'ANALYTICS_PROCESS_E2E_PORTMAP reason=classification-shape snapshot=%s\n' \
              "${safe_file}" >&2
            return 1
            ;;
        esac
      else
        core_port_failure_stage='core-port-mapping'
        printf 'ANALYTICS_PROCESS_E2E_PORTMAP reason=classification-read snapshot=%s\n' \
          "${safe_file}" >&2
        return 1
      fi
    else
      core_port_failure_stage='core-port-mapping'
      printf 'ANALYTICS_PROCESS_E2E_PORTMAP reason=inspect-or-projection-unavailable snapshot=%s\n' \
        "${safe_file}" >&2
      return 1
    fi
    sleep 0.25
  done
}

if [ "${1:-}" = --core-port-fixture ]; then
  [ "$#" -eq 1 ] || obs_e2e_fail 'core-port-fixture-arguments'
  obs_e2e_classify_core_ports fixture-pg fixture-clickhouse fixture-nats fixture-edge-nats fixture-redis
  exit
fi

if [ "${1:-}" = --edge-nats-readiness-fixture ]; then
  [ "$#" -eq 1 ] || obs_e2e_fail 'edge-nats-readiness-fixture-arguments'
  obs_e2e_classify_edge_nats_readiness
  exit
fi

if [ "${1:-}" = --edge-nats-uid-fixture ]; then
  [ "$#" -eq 3 ] || obs_e2e_fail 'edge-nats-uid-fixture-arguments'
  obs_e2e_classify_edge_nats_runtime_uid "$2" "$3"
  exit
fi

if [ "${1:-}" = --edge-nats-deadline-fixture ]; then
  [ "$#" -eq 4 ] || obs_e2e_fail 'edge-nats-deadline-fixture-arguments'
  if obs_e2e_deadline_budget_millis "$2" "$3" "$4"; then
    exit
  fi
  printf 'expired\n'
  exit
fi

for command in cat date docker go curl jq openssl perl ruby shasum lsof awk env find grep mktemp ps sed sleep touch tr wc; do
  command -v "${command}" >/dev/null 2>&1 || obs_e2e_unknown "missing-command-${command}"
done
DOCKER_BIN="$(command -v docker)"
CURL_BIN="$(command -v curl)"
readonly DOCKER_BIN CURL_BIN
obs_e2e_timeout() {
  local timeout_seconds=$1
  shift
  perl -e '
    use POSIX qw(setpgid);
    my $timeout = shift @ARGV;
    my $pid = fork();
    die "fork command: $!\n" unless defined $pid;
    if ($pid == 0) {
      setpgid(0, 0) == 0 or exit 127;
      exec @ARGV;
      exit 127;
    }
    setpgid($pid, $pid);
    my $stop_child = sub {
      my ($signal, $exit_code) = @_;
      kill $signal, -$pid;
      for (1 .. 10) {
        last unless kill 0, -$pid;
        select undef, undef, undef, 0.05;
      }
      kill "KILL", -$pid if kill 0, -$pid;
      waitpid($pid, 0);
      exit $exit_code;
    };
    $SIG{ALRM} = sub { $stop_child->("TERM", 124) };
    $SIG{INT} = sub { $stop_child->("INT", 130) };
    $SIG{TERM} = sub { $stop_child->("TERM", 143) };
    alarm $timeout;
    waitpid($pid, 0);
    alarm 0;
    my $status = $?;
    if (kill 0, -$pid) {
      kill "TERM", -$pid;
      for (1 .. 10) {
        last unless kill 0, -$pid;
        select undef, undef, undef, 0.05;
      }
      kill "KILL", -$pid if kill 0, -$pid;
    }
    exit($status == -1 ? 127 : ($status & 127) ? 128 + ($status & 127) : $status >> 8);
  ' "${timeout_seconds}" "$@"
}
obs_e2e_docker_timeout() {
  local timeout_seconds=$1
  shift
  obs_e2e_timeout "${timeout_seconds}" "${DOCKER_BIN}" "$@"
}
obs_e2e_timeout_millis() {
  local timeout_millis=$1
  shift
  perl -MTime::HiRes=usleep -e '
    use POSIX qw(setpgid);
    my $timeout_millis = shift @ARGV;
    exit 125 unless defined($timeout_millis) && $timeout_millis =~ /^[1-9][0-9]*$/;
    my $pid = fork();
    die "fork command: $!\n" unless defined $pid;
    if ($pid == 0) {
      setpgid(0, 0) == 0 or exit 127;
      exec @ARGV;
      exit 127;
    }
    setpgid($pid, $pid);
    my $stop_child = sub {
      my ($signal, $exit_code) = @_;
      kill $signal, -$pid;
      for (1 .. 5) {
        last unless kill 0, -$pid;
        Time::HiRes::usleep(10_000);
      }
      kill "KILL", -$pid if kill 0, -$pid;
      waitpid($pid, 0);
      exit $exit_code;
    };
    $SIG{ALRM} = sub { $stop_child->("TERM", 124) };
    $SIG{INT} = sub { $stop_child->("INT", 130) };
    $SIG{TERM} = sub { $stop_child->("TERM", 143) };
    Time::HiRes::alarm($timeout_millis / 1000);
    waitpid($pid, 0);
    Time::HiRes::alarm(0);
    my $status = $?;
    if (kill 0, -$pid) {
      kill "TERM", -$pid;
      for (1 .. 5) {
        last unless kill 0, -$pid;
        Time::HiRes::usleep(10_000);
      }
      kill "KILL", -$pid if kill 0, -$pid;
    }
    exit($status == -1 ? 127 : ($status & 127) ? 128 + ($status & 127) : $status >> 8);
  ' "${timeout_millis}" "$@"
}
obs_e2e_docker_timeout_millis() {
  local timeout_millis=$1
  shift
  obs_e2e_timeout_millis "${timeout_millis}" "${DOCKER_BIN}" "$@"
}
obs_e2e_monotonic_nanos() {
  perl -MTime::HiRes=clock_gettime,CLOCK_MONOTONIC -e \
    'printf "%.0f\n", 1000000000 * clock_gettime(CLOCK_MONOTONIC)'
}
obs_e2e_deadline_timeout_millis() {
  local deadline_nanos=$1 cap_millis=$2 now_nanos
  now_nanos=$(obs_e2e_monotonic_nanos) || return 1
  obs_e2e_deadline_budget_millis "${deadline_nanos}" "${now_nanos}" "${cap_millis}"
}
obs_e2e_docker_count() {
  local output
  if ! output="$(obs_e2e_docker_timeout 15 "$@" 2>/dev/null)"; then
    printf '%s\n' -1
    return 1
  fi
  printf '%s\n' "${output}" | awk 'NF {count++} END {print count+0}'
}
curl() {
  "${CURL_BIN}" --connect-timeout 2 --max-time 5 "$@"
}
[ -r "${PREPROVISION_SCRIPT}" ] || obs_e2e_unknown 'missing-analytics-preprovision'
[ -r "${NATS_SERVER_CONFIG}" ] || obs_e2e_unknown 'missing-analytics-server-config'
[ -r "${EDGE_TELEMETRY_FIXTURE_SOURCE}/main.go" ] || obs_e2e_unknown 'missing-edge-telemetry-fixture-source'
[ -r "${MIGRATION_090_UP}" ] || obs_e2e_unknown 'missing-migration-090-up'
[ -r "${MIGRATION_090_DOWN}" ] || obs_e2e_unknown 'missing-migration-090-down'
[ -r "${MIGRATION_090_TEST}" ] || obs_e2e_unknown 'missing-migration-090-test'
[ -r "${MIGRATION_091_UP}" ] || obs_e2e_unknown 'missing-migration-091-up'
[ -r "${MIGRATION_091_DOWN}" ] || obs_e2e_unknown 'missing-migration-091-down'
[ -r "${MIGRATION_091_TEST}" ] || obs_e2e_unknown 'missing-migration-091-test'
migration_090_up_sha="$(shasum -a 256 "${MIGRATION_090_UP}" | awk '{print $1}')"
migration_090_down_sha="$(shasum -a 256 "${MIGRATION_090_DOWN}" | awk '{print $1}')"
migration_090_test_sha="$(shasum -a 256 "${MIGRATION_090_TEST}" | awk '{print $1}')"
migration_091_up_sha="$(shasum -a 256 "${MIGRATION_091_UP}" | awk '{print $1}')"
migration_091_down_sha="$(shasum -a 256 "${MIGRATION_091_DOWN}" | awk '{print $1}')"
migration_091_test_sha="$(shasum -a 256 "${MIGRATION_091_TEST}" | awk '{print $1}')"
readonly migration_090_up_sha migration_090_down_sha migration_090_test_sha
readonly migration_091_up_sha migration_091_down_sha migration_091_test_sha
if [ "${migration_090_up_sha}" != "${MIGRATION_090_UP_RELEASE_SHA256}" ] || \
  [ "${migration_090_down_sha}" != "${MIGRATION_090_DOWN_RELEASE_SHA256}" ] || \
  [ "${migration_090_test_sha}" != "${MIGRATION_090_TEST_RELEASE_SHA256}" ]; then
  obs_e2e_unknown 'migration-090-release-head-digest'
fi
if [ "${migration_091_up_sha}" != "${MIGRATION_091_UP_RELEASE_SHA256}" ] || \
  [ "${migration_091_down_sha}" != "${MIGRATION_091_DOWN_RELEASE_SHA256}" ] || \
  [ "${migration_091_test_sha}" != "${MIGRATION_091_TEST_RELEASE_SHA256}" ]; then
  obs_e2e_unknown 'migration-091-release-head-digest'
fi
obs_e2e_docker_timeout 55 info >/dev/null 2>&1 || obs_e2e_unknown 'docker-unavailable'
for image in "${NATS_IMAGE}" "${NATS_BOX_IMAGE}" "${CLICKHOUSE_IMAGE}" "${POSTGRES_IMAGE}" "${REDIS_IMAGE}"; do
  obs_e2e_docker_timeout 55 image inspect "${image}" >/dev/null 2>&1 || \
    obs_e2e_unknown "missing-image-${image//[:\/]/-}"
done

task_suffix="${ANALYTICS_PROCESS_E2E_TASK_SUFFIX:-$(date -u +%Y%m%d%H%M%S)-$$}"
case "${task_suffix}" in
  *[!a-zA-Z0-9_-]*) obs_e2e_fail 'invalid-task-suffix' ;;
esac
readonly DISPLAY_TASK_ID="obs-process-e2e-${task_suffix}"
ownership_random="$(obs_e2e_timeout 10 openssl rand -hex 16)" || obs_e2e_fail 'ownership-token-generation'
[[ "${ownership_random}" =~ ^[0-9a-f]{32}$ ]] || obs_e2e_fail 'ownership-token-shape'
readonly OWNERSHIP_TOKEN="$$-${ownership_random}"
readonly TASK_ID="obs-process-e2e-${OWNERSHIP_TOKEN}"
work_dir_candidate="$(mktemp -d "${TMPDIR:-/tmp}/cdnca-${TASK_ID}.XXXXXX")"
WORK_DIR="$(cd -- "${work_dir_candidate}" && pwd -P)"
readonly WORK_DIR
readonly NETWORK_NAME="cdnca-${TASK_ID}"
readonly POSTGRES_CONTAINER="${TASK_ID}-postgres"
readonly NATS_CONTAINER="${TASK_ID}-nats"
readonly EDGE_NATS_CONTAINER="${TASK_ID}-edge-nats"
readonly EDGE_NATS_PROBE_CONTAINER="${TASK_ID}-edge-nats-probe"
readonly EDGE_NATS_NETWORK_ALIAS='edge-nats'
readonly EDGE_NATS_PROBE_NETWORK_ALIAS='edge-nats-probe'
readonly CLICKHOUSE_CONTAINER="${TASK_ID}-clickhouse"
readonly REDIS_CONTAINER="${TASK_ID}-redis"
readonly RESOURCE_LABEL_KEY='cdnca.obs-process-e2e'
readonly RESOURCE_LABEL="${RESOURCE_LABEL_KEY}=${TASK_ID}"
readonly EDGE_NATS_STATE_SAFE="${WORK_DIR}/edge-nats-state.safe.json"
readonly EDGE_NATS_SERVER_LOG_SAFE="${WORK_DIR}/edge-nats-server.safe.log"
readonly EDGE_NATS_PROBE_STDERR_RAW="${WORK_DIR}/edge-nats-probe.stderr.raw"
readonly EDGE_NATS_PROBE_STDERR_SAFE="${WORK_DIR}/edge-nats-probe.stderr.safe.log"

control_pid=''
gateway_pid=''
absent_pid=''
mismatch_pid=''
edge_nats_container_id=''
edge_nats_probe_container_id=''
edge_nats_pid1_euid=''
edge_nats_store_reason=''
owned_ports=()
cleanup_reported=0

obs_e2e_stop_pid() {
  local pid=$1
  [ -n "${pid}" ] || return 0
  if kill -0 "${pid}" 2>/dev/null; then
    kill -TERM "${pid}" 2>/dev/null || true
    for _ in {1..40}; do
      kill -0 "${pid}" 2>/dev/null || break
      sleep 0.1
    done
    if kill -0 "${pid}" 2>/dev/null; then
      kill -KILL "${pid}" 2>/dev/null || true
    fi
  fi
  wait "${pid}" 2>/dev/null || true
}

obs_e2e_cleanup_refused() {
  printf 'ANALYTICS_PROCESS_E2E_CLEANUP_REFUSED reason=%s\n' "$1" >&2
}

obs_e2e_cleanup() {
  local status=$?
  local container_id container_ids_output container_inspect inspected_container_id inspected_container_name
  local container_owner network_id network_ids_output network_inspect inspected_network_id
  local inspected_network_name network_owner pid process_residual=0 orphan_residual=0 container_residual=0
  local network_residual=0 listener_residual=0 tmp_residual=0
  local container_query_failed=0 network_query_failed=0
  local -a owned_container_ids=() owned_network_ids=()
  trap - EXIT INT TERM
  set +e
  for pid in "${gateway_pid}" "${control_pid}" "${mismatch_pid}" "${absent_pid}"; do
    obs_e2e_stop_pid "${pid}"
  done
  for _ in {1..2}; do
    owned_container_ids=()
    if container_ids_output="$(obs_e2e_docker_timeout 15 ps -aq --no-trunc --filter "label=${RESOURCE_LABEL}" 2>/dev/null)"; then
      while IFS= read -r container_id; do
        [ -n "${container_id}" ] || continue
        if [[ ! "${container_id}" =~ ^[0-9a-f]{64}$ ]]; then
          obs_e2e_cleanup_refused 'container-identity-shape'
          container_query_failed=1
          continue
        fi
        if ! container_inspect="$(obs_e2e_docker_timeout 5 inspect --type container --format \
          '{"Id":{{json .Id}},"Name":{{json .Name}},"Owner":{{json (index .Config.Labels "cdnca.obs-process-e2e")}}}' \
          "${container_id}" 2>/dev/null)"; then
          obs_e2e_cleanup_refused 'container-inspect-unavailable'
          container_query_failed=1
          continue
        fi
        if ! inspected_container_id="$(jq -er '.Id | select(type == "string")' <<<"${container_inspect}")" ||
          ! inspected_container_name="$(jq -er '.Name | select(type == "string" and length > 1 and startswith("/"))' \
            <<<"${container_inspect}")"; then
          obs_e2e_cleanup_refused 'container-inspect-shape'
          container_query_failed=1
          continue
        fi
        container_owner="$(jq -r '.Owner // ""' <<<"${container_inspect}")"
        [ "${inspected_container_id}" = "${container_id}" ] || {
          obs_e2e_cleanup_refused 'container-identity-mismatch'
          container_query_failed=1
          continue
        }
        case "${inspected_container_name}" in
          "/${POSTGRES_CONTAINER}"|"/${CLICKHOUSE_CONTAINER}"|\
            "/${EDGE_NATS_CONTAINER}"|"/${NATS_CONTAINER}"|"/${REDIS_CONTAINER}"|\
            "/${EDGE_NATS_PROBE_CONTAINER}") ;;
          *)
            obs_e2e_cleanup_refused 'container-name-mismatch'
            container_query_failed=1
            continue
            ;;
        esac
        [ "${container_owner}" = "${TASK_ID}" ] || {
          obs_e2e_cleanup_refused 'container-ownership-mismatch'
          container_query_failed=1
          continue
        }
        owned_container_ids+=("${inspected_container_id}")
      done <<<"${container_ids_output}"
      if [ "${#owned_container_ids[@]}" -gt 0 ]; then
        obs_e2e_docker_timeout 20 rm -f "${owned_container_ids[@]}" >/dev/null 2>&1
      fi
    else
      container_query_failed=1
    fi
    sleep 0.5
  done
  owned_network_ids=()
  if network_ids_output="$(obs_e2e_docker_timeout 15 network ls -q --no-trunc --filter "label=${RESOURCE_LABEL}" 2>/dev/null)"; then
    while IFS= read -r network_id; do
      [ -n "${network_id}" ] || continue
      if [[ ! "${network_id}" =~ ^[0-9a-f]{64}$ ]]; then
        obs_e2e_cleanup_refused 'network-identity-shape'
        network_query_failed=1
        continue
      fi
      if ! network_inspect="$(obs_e2e_docker_timeout 5 network inspect --format \
        '{"Id":{{json .Id}},"Name":{{json .Name}},"Owner":{{json (index .Labels "cdnca.obs-process-e2e")}}}' \
        "${network_id}" 2>/dev/null)"; then
        obs_e2e_cleanup_refused 'network-inspect-unavailable'
        network_query_failed=1
        continue
      fi
      if ! inspected_network_id="$(jq -er '.Id | select(type == "string")' <<<"${network_inspect}")" ||
        ! inspected_network_name="$(jq -er '.Name | select(type == "string" and length > 0)' \
          <<<"${network_inspect}")"; then
        obs_e2e_cleanup_refused 'network-inspect-shape'
        network_query_failed=1
        continue
      fi
      network_owner="$(jq -r '.Owner // ""' <<<"${network_inspect}")"
      [ "${inspected_network_id}" = "${network_id}" ] || {
        obs_e2e_cleanup_refused 'network-identity-mismatch'
        network_query_failed=1
        continue
      }
      [ "${inspected_network_name}" = "${NETWORK_NAME}" ] || {
        obs_e2e_cleanup_refused 'network-identity-mismatch'
        network_query_failed=1
        continue
      }
      [ "${network_owner}" = "${TASK_ID}" ] || {
        obs_e2e_cleanup_refused 'network-ownership-mismatch'
        network_query_failed=1
        continue
      }
      owned_network_ids+=("${inspected_network_id}")
    done <<<"${network_ids_output}"
    if [ "${#owned_network_ids[@]}" -gt 0 ]; then
      obs_e2e_docker_timeout 20 network rm "${owned_network_ids[@]}" >/dev/null 2>&1
    fi
  else
    network_query_failed=1
  fi
  process_residual=$(ps -axo pid=,ppid=,command= | awk -v marker="${WORK_DIR}" \
    'index($0, marker) && $3 !~ /(^|\/)awk$/ {count++} END {print count+0}')
  orphan_residual=$(ps -axo pid=,ppid=,command= | awk -v marker="${WORK_DIR}" \
    'index($0, marker) && $2 == 1 && $3 !~ /(^|\/)awk$/ {count++} END {print count+0}')
  if ! container_residual="$(obs_e2e_docker_count ps -aq --filter "label=${RESOURCE_LABEL}")"; then
    container_query_failed=1
  fi
  if ! network_residual="$(obs_e2e_docker_count network ls -q --filter "label=${RESOURCE_LABEL}")"; then
    network_query_failed=1
  fi
  [ "${container_query_failed}" -eq 0 ] || container_residual=-1
  [ "${network_query_failed}" -eq 0 ] || network_residual=-1
  for port in "${owned_ports[@]-}"; do
    [ -n "${port}" ] || continue
    if lsof -nP -iTCP:"${port}" -sTCP:LISTEN >/dev/null 2>&1; then
      listener_residual=$((listener_residual + 1))
    fi
  done
  case "${WORK_DIR}" in
    */cdnca-obs-process-e2e-*) find "${WORK_DIR}" -depth -delete ;;
    *) tmp_residual=1 ;;
  esac
  [ ! -e "${WORK_DIR}" ] || tmp_residual=1
  cleanup_reported=1
  printf 'ANALYTICS_PROCESS_E2E_CLEANUP containers=%s networks=%s listeners=%s processes=%s ppid1=%s tmp=%s\n' \
    "${container_residual}" "${network_residual}" "${listener_residual}" \
    "${process_residual}" "${orphan_residual}" "${tmp_residual}"
  if [ "${container_residual}" -ne 0 ] || [ "${network_residual}" -ne 0 ] || \
    [ "${listener_residual}" -ne 0 ] || [ "${process_residual}" -ne 0 ] || \
    [ "${orphan_residual}" -ne 0 ] || [ "${tmp_residual}" -ne 0 ]; then
    exit 1
  fi
  exit "${status}"
}

trap obs_e2e_cleanup EXIT
trap 'exit 130' INT TERM

obs_e2e_wait_container() {
  local container=$1
  local deadline_epoch current_epoch timeout_seconds
  shift
  deadline_epoch=$(( $(date +%s) + 40 ))
  while :; do
    current_epoch=$(date +%s)
    [ "${current_epoch}" -lt "${deadline_epoch}" ] || return 1
    timeout_seconds=$((deadline_epoch - current_epoch))
    [ "${timeout_seconds}" -le 20 ] || timeout_seconds=20
    if obs_e2e_docker_timeout "${timeout_seconds}" exec "${container}" "$@" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.25
  done
}

obs_e2e_summary() {
  printf 'ANALYTICS_PROCESS_E2E_SUMMARY %s\n' "$1"
}

obs_e2e_sanitize_diagnostic_stream() {
  perl -e '
    use strict;
    use warnings;
    my $limit = 8192;
    my $output = "";
    while (<STDIN>) {
      s/[^\x09\x0a\x0d\x20-\x7e]//g;
      s{([a-z][a-z0-9+.-]*://)[^/@\s]+@}{${1}[REDACTED]@}ig;
      s{((?:password|token|authorization|credential|seed|private[ _-]?key)\s*[=:]\s*)\S+}{${1}[REDACTED]}ig;
      $output .= $_;
      last if length($output) >= $limit;
    }
    print substr($output, 0, $limit);
  '
}

obs_e2e_emit_process_diagnostic() {
  local stage=$1 source=$2
  [ -r "${source}" ] || return 0
  while IFS= read -r line || [ -n "${line}" ]; do
    printf 'ANALYTICS_PROCESS_E2E_PROCESS stage=%s %s\n' "${stage}" "${line}" >&2
  done < <(obs_e2e_sanitize_diagnostic_stream <"${source}")
}

obs_e2e_emit_core_container_diagnostics() {
  local stage=$1 expected_name inspect_json container_id safe_state line
  shift
  for expected_name in "$@"; do
    if ! inspect_json="$(obs_e2e_docker_timeout 5 inspect --type container --format \
      '{"Id":{{json .Id}},"Name":{{json .Name}},"Owner":{{json (index .Config.Labels "cdnca.obs-process-e2e")}},"RestartCount":{{json .RestartCount}},"State":{"Running":{{json .State.Running}},"Status":{{json .State.Status}},"ExitCode":{{json .State.ExitCode}},"OOMKilled":{{json .State.OOMKilled}},"Error":{{json .State.Error}}}}' \
      "${expected_name}" 2>/dev/null)"; then
      printf 'ANALYTICS_PROCESS_E2E_CORE_CONTAINER stage=%s name=/%s diagnostic=inspect-unavailable\n' \
        "${stage}" "${expected_name}" >&2
      continue
    fi
    if ! jq -e --arg name "/${expected_name}" --arg owner "${TASK_ID}" '
      keys == ["Id","Name","Owner","RestartCount","State"] and
      (.Id | type) == "string" and (.Id | test("^[0-9a-f]{64}$")) and
      .Name == $name and .Owner == $owner and (.RestartCount | type) == "number" and
      (.State | keys) == ["Error","ExitCode","OOMKilled","Running","Status"] and
      (.State.Running | type) == "boolean" and (.State.Status | type) == "string" and
      (.State.ExitCode | type) == "number" and (.State.OOMKilled | type) == "boolean" and
      (.State.Error | type) == "string"
    ' <<<"${inspect_json}" >/dev/null; then
      printf 'ANALYTICS_PROCESS_E2E_CORE_CONTAINER stage=%s name=/%s diagnostic=unsafe-inspect-rejected\n' \
        "${stage}" "${expected_name}" >&2
      continue
    fi
    if ! jq -e '.State.Running == false and (.State.Status == "exited" or .State.Status == "dead")' \
      <<<"${inspect_json}" >/dev/null; then
      continue
    fi
    container_id="$(jq -er '.Id' <<<"${inspect_json}")"
    safe_state="$(printf '%s\n' "${inspect_json}" | obs_e2e_sanitize_diagnostic_stream)"
    printf 'ANALYTICS_PROCESS_E2E_CORE_CONTAINER stage=%s state=%s\n' "${stage}" "${safe_state}" >&2
    while IFS= read -r line || [ -n "${line}" ]; do
      printf 'ANALYTICS_PROCESS_E2E_CORE_CONTAINER_LOG stage=%s id=%s %s\n' \
        "${stage}" "${container_id}" "${line}" >&2
    done < <({ obs_e2e_docker_timeout 5 logs --tail 80 --timestamps "${container_id}" 2>&1 || true; } |
      obs_e2e_sanitize_diagnostic_stream)
  done
}

obs_e2e_capture_edge_nats_state() {
  local timeout_millis=$1
  local temporary="${EDGE_NATS_STATE_SAFE}.tmp"
  rm -f -- "${EDGE_NATS_STATE_SAFE}" "${temporary}"
  [[ "${edge_nats_container_id}" =~ ^[0-9a-f]{64}$ ]] || return 1
  if ! obs_e2e_docker_timeout_millis "${timeout_millis}" inspect --type container --format \
    '{"Id":{{json .Id}},"Name":{{json .Name}},"Owner":{{json (index .Config.Labels "cdnca.obs-process-e2e")}},"RestartCount":{{json .RestartCount}},"State":{"Running":{{json .State.Running}},"Status":{{json .State.Status}},"ExitCode":{{json .State.ExitCode}},"OOMKilled":{{json .State.OOMKilled}},"Error":{{json .State.Error}}}}' \
    "${edge_nats_container_id}" >"${temporary}" 2>/dev/null; then
    rm -f -- "${temporary}"
    return 1
  fi
  if ! jq -ec --arg id "${edge_nats_container_id}" --arg name "/${EDGE_NATS_CONTAINER}" \
    --arg owner "${TASK_ID}" '
      keys == ["Id","Name","Owner","RestartCount","State"] and
      .Id == $id and .Name == $name and .Owner == $owner and
      (.RestartCount | type) == "number" and
      (.State | keys) == ["Error","ExitCode","OOMKilled","Running","Status"] and
      (.State.Running | type) == "boolean" and (.State.Status | type) == "string" and
      (.State.ExitCode | type) == "number" and (.State.OOMKilled | type) == "boolean" and
      (.State.Error | type) == "string"
    ' "${temporary}" >/dev/null; then
    rm -f -- "${temporary}"
    return 1
  fi
  mv -- "${temporary}" "${EDGE_NATS_STATE_SAFE}"
}

obs_e2e_classify_current_edge_nats() {
  local store_writable=$1 probe_exit=$2 response=$3
  jq -cn --slurpfile container "${EDGE_NATS_STATE_SAFE}" \
    --argjson store_writable "${store_writable}" --argjson probe_exit "${probe_exit}" \
    --rawfile probe_stderr "${EDGE_NATS_PROBE_STDERR_SAFE}" --arg response "${response}" '
      {state:$container[0].State,store_writable:$store_writable,probe_exit:$probe_exit,
       probe_stderr:$probe_stderr,response:$response}
    ' | obs_e2e_classify_edge_nats_readiness
}

obs_e2e_verify_edge_nats_store_writable() {
  local deadline_nanos=$1 timeout_millis exec_uid uid_classification uid_state
  edge_nats_store_reason='runtime-uid-read'
  timeout_millis="$(obs_e2e_deadline_timeout_millis "${deadline_nanos}" 3000)" || {
    edge_nats_store_reason=deadline
    return 1
  }
  # effective_uid expands inside the edge container.
  # shellcheck disable=SC2016
  if ! edge_nats_pid1_euid="$(obs_e2e_docker_timeout_millis "${timeout_millis}" \
    exec "${edge_nats_container_id}" sh -ec '
      effective_uid=$(sed -n "s/^Uid:[[:space:]]*[0-9][0-9]*[[:space:]]*\([0-9][0-9]*\)[[:space:]].*$/\1/p" /proc/1/status)
      [ -n "${effective_uid}" ] && printf "%s\n" "${effective_uid}"
    ' 2>/dev/null)"; then
    return 1
  fi
  uid_classification="$(obs_e2e_classify_edge_nats_runtime_uid \
    "${edge_nats_pid1_euid}" "${edge_nats_pid1_euid}")"
  uid_state=${uid_classification%%$'\t'*}
  edge_nats_store_reason=${uid_classification#*$'\t'}
  [ "${uid_state}" = ready ] || return 1

  timeout_millis="$(obs_e2e_deadline_timeout_millis "${deadline_nanos}" 3000)" || {
    edge_nats_store_reason=deadline
    return 1
  }
  edge_nats_store_reason='runtime-uid-exec'
  if ! exec_uid="$(obs_e2e_docker_timeout_millis "${timeout_millis}" exec \
    --user "${edge_nats_pid1_euid}" "${edge_nats_container_id}" id -u 2>/dev/null)"; then
    return 1
  fi
  uid_classification="$(obs_e2e_classify_edge_nats_runtime_uid \
    "${edge_nats_pid1_euid}" "${exec_uid}")"
  uid_state=${uid_classification%%$'\t'*}
  edge_nats_store_reason=${uid_classification#*$'\t'}
  [ "${uid_state}" = ready ] || return 1

  timeout_millis="$(obs_e2e_deadline_timeout_millis "${deadline_nanos}" 3000)" || {
    edge_nats_store_reason=deadline
    return 1
  }
  edge_nats_store_reason=store-unwritable
  # The probe variable expands inside the edge container.
  # shellcheck disable=SC2016
  obs_e2e_docker_timeout_millis "${timeout_millis}" exec \
    --user "${edge_nats_pid1_euid}" "${edge_nats_container_id}" sh -ec '
    probe=/data/.cdnca-readiness-write-probe
    (umask 077 && : >"${probe}") && rm -f "${probe}"
  ' >/dev/null 2>&1
}

obs_e2e_emit_edge_nats_diagnostics() {
  local reason=$1 deadline_nanos=$2 line timeout_millis logs_skipped=0
  if ! timeout_millis="$(obs_e2e_deadline_timeout_millis "${deadline_nanos}" 750)"; then
    printf 'ANALYTICS_PROCESS_E2E_EDGE_NATS_DIAGNOSTIC reason=%s diagnostic=diagnostics-skipped-deadline\n' \
      "${reason}" >&2
    return 0
  fi
  obs_e2e_capture_edge_nats_state "${timeout_millis}" || true
  if timeout_millis="$(obs_e2e_deadline_timeout_millis "${deadline_nanos}" 750)"; then
    { obs_e2e_docker_timeout_millis "${timeout_millis}" logs --tail 80 --timestamps \
      "${edge_nats_container_id}" 2>&1 || true; } | \
      obs_e2e_sanitize_diagnostic_stream >"${EDGE_NATS_SERVER_LOG_SAFE}"
  else
    : >"${EDGE_NATS_SERVER_LOG_SAFE}"
    logs_skipped=1
  fi
  printf 'ANALYTICS_PROCESS_E2E_EDGE_NATS_DIAGNOSTIC reason=%s' "${reason}" >&2
  if [ -s "${EDGE_NATS_STATE_SAFE}" ]; then
    printf ' state=%s' "$(cat -- "${EDGE_NATS_STATE_SAFE}")" >&2
  fi
  [ "${logs_skipped}" -eq 0 ] || printf ' logs=diagnostics-skipped-deadline' >&2
  printf '\n' >&2
  while IFS= read -r line || [ -n "${line}" ]; do
    printf 'ANALYTICS_PROCESS_E2E_EDGE_NATS_SERVER %s\n' "${line}" >&2
  done <"${EDGE_NATS_SERVER_LOG_SAFE}"
  while IFS= read -r line || [ -n "${line}" ]; do
    printf 'ANALYTICS_PROCESS_E2E_EDGE_NATS_PROBE %s\n' "${line}" >&2
  done <"${EDGE_NATS_PROBE_STDERR_SAFE}"
}

mkdir -p "${WORK_DIR}/bin" "${WORK_DIR}/certs" "${WORK_DIR}/nats-store" "${WORK_DIR}/edge-nats-store"
edge_fixture_command="${CDNCA_OBS_EDGE_AGENT_FIXTURE_COMMAND:-${WORK_DIR}/bin/edge-telemetry-fixture}"
if [ -n "${CDNCA_OBS_EDGE_AGENT_FIXTURE_COMMAND:-}" ]; then
  [ -f "${edge_fixture_command}" ] && [ -x "${edge_fixture_command}" ] || \
    obs_e2e_unknown 'edge-agent-eventspool-mtls-fixture-unavailable'
else
  (
    cd "${REPO_ROOT}/agents/edge-agent"
    obs_e2e_timeout 180 go build -trimpath -o "${edge_fixture_command}" ./cmd/edge-telemetry-fixture
  ) >"${WORK_DIR}/edge-telemetry-fixture-build.log" 2>&1 || \
    obs_e2e_unknown 'edge-agent-eventspool-mtls-fixture-unavailable'
fi
obs_e2e_timeout 10 "${edge_fixture_command}" --preflight-eventspool-mtls \
  >"${WORK_DIR}/edge-telemetry-fixture-preflight.json" 2>/dev/null || \
  obs_e2e_unknown 'edge-agent-eventspool-mtls-fixture-unavailable'
jq -e '.capability == "eventspool_mtls" and .status == "ready"' \
  "${WORK_DIR}/edge-telemetry-fixture-preflight.json" >/dev/null || \
  obs_e2e_unknown 'edge-agent-eventspool-mtls-fixture-unavailable'
edge_fixture_binary_sha="$(shasum -a 256 "${edge_fixture_command}" | awk '{print $1}')"
readonly edge_fixture_command edge_fixture_binary_sha

obs_e2e_docker_timeout 55 network create --label "${RESOURCE_LABEL}" "${NETWORK_NAME}" >/dev/null || \
  obs_e2e_fail 'network-create'

postgres_password="$(obs_e2e_timeout 10 openssl rand -hex 24)"
clickhouse_password="$(obs_e2e_timeout 10 openssl rand -hex 24)"
preprovision_password="obs_$(obs_e2e_timeout 10 openssl rand -hex 24)"
runtime_password="obs_$(obs_e2e_timeout 10 openssl rand -hex 24)"
publisher_password="obs_$(obs_e2e_timeout 10 openssl rand -hex 24)"
readonly postgres_password clickhouse_password preprovision_password runtime_password publisher_password

obs_e2e_docker_timeout 55 run -d --name "${POSTGRES_CONTAINER}" --network "${NETWORK_NAME}" \
  --label "${RESOURCE_LABEL}" \
  -p 127.0.0.1::5432 \
  -e POSTGRES_USER=cdnca -e POSTGRES_PASSWORD="${postgres_password}" -e POSTGRES_DB=cdnca \
  "${POSTGRES_IMAGE}" >/dev/null || obs_e2e_fail 'postgres-start'
obs_e2e_docker_timeout 55 run -d --name "${CLICKHOUSE_CONTAINER}" --network "${NETWORK_NAME}" \
  --label "${RESOURCE_LABEL}" \
  -p 127.0.0.1::8123 \
  -e CLICKHOUSE_DB=cdnca_analytics -e CLICKHOUSE_USER=analytics \
  -e CLICKHOUSE_PASSWORD="${clickhouse_password}" -e CLICKHOUSE_DEFAULT_ACCESS_MANAGEMENT=1 \
  "${CLICKHOUSE_IMAGE}" >/dev/null || obs_e2e_fail 'clickhouse-start'
obs_e2e_docker_timeout 55 run -d --name "${NATS_CONTAINER}" --network "${NETWORK_NAME}" \
  --label "${RESOURCE_LABEL}" \
  -p 127.0.0.1::4222 \
  -e NATS_STORE_DIR=/data \
  -e NATS_PREPROVISION_USERNAME=preprovision -e NATS_PREPROVISION_PASSWORD="${preprovision_password}" \
  -e NATS_CONTROL_CONSUMER_USERNAME=runtime -e NATS_CONTROL_CONSUMER_PASSWORD="${runtime_password}" \
  -e NATS_GATEWAY_PUBLISHER_USERNAME=publisher -e NATS_GATEWAY_PUBLISHER_PASSWORD="${publisher_password}" \
  -v "${NATS_SERVER_CONFIG}:/etc/nats/analytics-server.conf:ro" \
  -v "${WORK_DIR}/nats-store:/data" \
  "${NATS_IMAGE}" -c /etc/nats/analytics-server.conf >/dev/null || obs_e2e_fail 'analytics-nats-start'
edge_nats_container_id="$(obs_e2e_docker_timeout 55 run -d --name "${EDGE_NATS_CONTAINER}" \
  --network "${NETWORK_NAME}" --network-alias "${EDGE_NATS_NETWORK_ALIAS}" \
  --label "${RESOURCE_LABEL}" \
  -p 127.0.0.1::4222 -v "${WORK_DIR}/edge-nats-store:/data" \
  "${NATS_IMAGE}" -js --store_dir /data)" || obs_e2e_fail 'edge-nats-start'
[[ "${edge_nats_container_id}" =~ ^[0-9a-f]{64}$ ]] || obs_e2e_fail 'edge-nats-container-id'
obs_e2e_docker_timeout 55 run -d --name "${REDIS_CONTAINER}" --network "${NETWORK_NAME}" \
  --label "${RESOURCE_LABEL}" \
  -p 127.0.0.1::6379 "${REDIS_IMAGE}" redis-server --save '' --appendonly no >/dev/null || \
  obs_e2e_fail 'redis-start'

safe_ports_file="${WORK_DIR}/core-port-inspect.safe.json"
ports_tsv=''
core_port_failure_stage='core-port-mapping'
if ! obs_e2e_read_core_ports "${safe_ports_file}" \
  "${POSTGRES_CONTAINER}" "${CLICKHOUSE_CONTAINER}" "${NATS_CONTAINER}" \
  "${EDGE_NATS_CONTAINER}" "${REDIS_CONTAINER}"; then
  obs_e2e_emit_core_container_diagnostics "${core_port_failure_stage}" \
    "${POSTGRES_CONTAINER}" "${CLICKHOUSE_CONTAINER}" "${NATS_CONTAINER}" \
    "${EDGE_NATS_CONTAINER}" "${REDIS_CONTAINER}"
  obs_e2e_fail "${core_port_failure_stage}"
fi
IFS=$'\t' read -r postgres_port clickhouse_port nats_port edge_nats_port redis_port <<<"${ports_tsv}"
for published_port in "${postgres_port}" "${clickhouse_port}" "${nats_port}" "${edge_nats_port}" "${redis_port}"; do
  case "${published_port}" in
    ''|*[!0-9]*) obs_e2e_fail 'core-port-mapping' ;;
  esac
done
owned_ports+=("${postgres_port}" "${clickhouse_port}" "${nats_port}" "${edge_nats_port}" "${redis_port}")

obs_e2e_wait_container "${POSTGRES_CONTAINER}" pg_isready -U cdnca -d cdnca || obs_e2e_fail 'postgres-readiness'
obs_e2e_wait_container "${CLICKHOUSE_CONTAINER}" sh -ec "
  first_argv=\"\$(tr \"\000\" \"\n\" </proc/1/cmdline | sed -n \"1p\")\"
  [ \"\${first_argv##*/}\" = clickhouse-server ]
" || obs_e2e_unknown 'clickhouse-final-pid1'
obs_e2e_wait_container "${CLICKHOUSE_CONTAINER}" clickhouse-client --user analytics \
  --password "${clickhouse_password}" --query 'SELECT 1' || obs_e2e_fail 'clickhouse-readiness'
obs_e2e_wait_container "${REDIS_CONTAINER}" redis-cli ping || obs_e2e_fail 'redis-readiness'

obs_e2e_docker_timeout 20 exec "${POSTGRES_CONTAINER}" psql -v ON_ERROR_STOP=1 -U cdnca -d cdnca \
  --command 'CREATE ROLE cdnca_control_app NOLOGIN' >/dev/null || \
  obs_e2e_fail 'postgres-control-role-preprovision'
obs_e2e_docker_timeout 20 exec "${POSTGRES_CONTAINER}" psql -v ON_ERROR_STOP=1 -U cdnca -d cdnca \
  --command 'CREATE ROLE cdnca_plugin_webhook_runtime NOLOGIN' >/dev/null || \
  obs_e2e_fail 'postgres-runtime-role-preprovision'
obs_e2e_docker_timeout 20 exec "${POSTGRES_CONTAINER}" psql -v ON_ERROR_STOP=1 -U cdnca -d cdnca \
  --command 'CREATE SCHEMA cdnca_e2e AUTHORIZATION cdnca' >/dev/null || \
  obs_e2e_fail 'postgres-schema-preprovision'
postgres_database_baseline="$(obs_e2e_docker_timeout 20 exec "${POSTGRES_CONTAINER}" \
  psql -qAtX -v ON_ERROR_STOP=1 -U cdnca -d cdnca --command "
    SET search_path TO ${CONTROL_DATABASE_SCHEMA};
    SELECT current_schema() = '${CONTROL_DATABASE_SCHEMA}'
      AND (SELECT nspowner FROM pg_namespace
           WHERE oid = current_schema()::regnamespace) = current_user::regrole
      AND (SELECT COALESCE(nspacl, acldefault('n', nspowner))
                  IS NOT DISTINCT FROM acldefault('n', nspowner)
           FROM pg_namespace WHERE oid = current_schema()::regnamespace)
      AND (SELECT count(*) = 2 FROM pg_roles role
           WHERE role.oid IN (to_regrole('cdnca_control_app'),
                              to_regrole('cdnca_plugin_webhook_runtime'))
             AND NOT (role.rolcanlogin OR role.rolsuper OR role.rolcreatedb OR
                      role.rolcreaterole OR role.rolreplication OR role.rolbypassrls))
      AND current_user::regrole <> to_regrole('cdnca_control_app')
      AND current_user::regrole <> to_regrole('cdnca_plugin_webhook_runtime')
      AND NOT EXISTS (
        SELECT 1 FROM pg_default_acl default_acl
        WHERE default_acl.defaclrole = current_user::regrole
          AND default_acl.defaclnamespace IN (0, current_schema()::regnamespace)
          AND default_acl.defaclobjtype IN ('r', 'S', 'f', 'T'))
      AND NOT has_schema_privilege('cdnca_control_app', current_schema(), 'CREATE')
      AND NOT has_schema_privilege('cdnca_plugin_webhook_runtime', current_schema(), 'CREATE')
      AND NOT has_database_privilege('cdnca_control_app', current_database(), 'CREATE')
      AND NOT has_database_privilege('cdnca_plugin_webhook_runtime', current_database(), 'CREATE')
      AND NOT pg_has_role('cdnca_control_app', 'cdnca_plugin_webhook_runtime', 'MEMBER')
      AND NOT pg_has_role('cdnca_plugin_webhook_runtime', 'cdnca_control_app', 'MEMBER')
      AND NOT EXISTS (
        SELECT 1 FROM pg_namespace namespace
        CROSS JOIN LATERAL aclexplode(namespace.nspacl) acl
        WHERE namespace.oid = current_schema()::regnamespace
          AND acl.grantee IN (to_regrole('cdnca_control_app'),
                              to_regrole('cdnca_plugin_webhook_runtime')));
  ")" || obs_e2e_unknown 'postgres-database-baseline-query'
if [ "${postgres_database_baseline}" != 't' ]; then
  postgres_database_baseline_reasons="$(obs_e2e_docker_timeout 20 exec "${POSTGRES_CONTAINER}" \
    psql -qAtX -v ON_ERROR_STOP=1 -U cdnca -d cdnca --command "
      SET search_path TO ${CONTROL_DATABASE_SCHEMA};
      WITH checks(reason, ok) AS (VALUES
        ('control-role-present', to_regrole('cdnca_control_app') IS NOT NULL),
        ('runtime-role-present', to_regrole('cdnca_plugin_webhook_runtime') IS NOT NULL),
        ('schema-owner', (SELECT nspowner = current_user::regrole FROM pg_namespace
                          WHERE oid = current_schema()::regnamespace)),
        ('role-flags', (SELECT count(*) = 2 FROM pg_roles role
                        WHERE role.oid IN (to_regrole('cdnca_control_app'),
                                           to_regrole('cdnca_plugin_webhook_runtime'))
                          AND NOT (role.rolcanlogin OR role.rolsuper OR role.rolcreatedb OR
                                   role.rolcreaterole OR role.rolreplication OR role.rolbypassrls))),
        ('current-user-distinct', current_user::regrole NOT IN
          (to_regrole('cdnca_control_app'), to_regrole('cdnca_plugin_webhook_runtime'))),
        ('schema-acl-default', (SELECT COALESCE(nspacl, acldefault('n', nspowner))
                                      IS NOT DISTINCT FROM acldefault('n', nspowner)
                                FROM pg_namespace WHERE oid = current_schema()::regnamespace)),
        ('default-acl-absent', NOT EXISTS (
          SELECT 1 FROM pg_default_acl default_acl
          WHERE default_acl.defaclrole = current_user::regrole
            AND default_acl.defaclnamespace IN (0, current_schema()::regnamespace)
            AND default_acl.defaclobjtype IN ('r', 'S', 'f', 'T'))),
        ('control-schema-create-absent', NOT has_schema_privilege(
          to_regrole('cdnca_control_app'), current_schema(), 'CREATE')),
        ('runtime-schema-create-absent', NOT has_schema_privilege(
          to_regrole('cdnca_plugin_webhook_runtime'), current_schema(), 'CREATE')),
        ('control-database-create-absent', NOT has_database_privilege(
          to_regrole('cdnca_control_app'), current_database(), 'CREATE')),
        ('runtime-database-create-absent', NOT has_database_privilege(
          to_regrole('cdnca_plugin_webhook_runtime'), current_database(), 'CREATE')),
        ('control-runtime-membership-absent', NOT pg_has_role(
          to_regrole('cdnca_control_app'), to_regrole('cdnca_plugin_webhook_runtime'), 'MEMBER')),
        ('runtime-control-membership-absent', NOT pg_has_role(
          to_regrole('cdnca_plugin_webhook_runtime'), to_regrole('cdnca_control_app'), 'MEMBER')),
        ('role-schema-acl-absent', NOT EXISTS (
          SELECT 1 FROM pg_namespace namespace
          CROSS JOIN LATERAL aclexplode(namespace.nspacl) acl
          WHERE namespace.oid = current_schema()::regnamespace
            AND acl.grantee IN (to_regrole('cdnca_control_app'),
                                to_regrole('cdnca_plugin_webhook_runtime'))))
      )
      SELECT COALESCE(string_agg(reason, ',' ORDER BY reason), 'predicate-drift')
      FROM checks WHERE ok IS DISTINCT FROM true;
    ")" || obs_e2e_unknown 'postgres-database-baseline-diagnostic-query'
  case "${postgres_database_baseline_reasons}" in
    ''|*[!a-z0-9,-]*) obs_e2e_unknown 'postgres-database-baseline-diagnostic-shape' ;;
  esac
  printf 'ANALYTICS_PROCESS_E2E_UNKNOWN reason=postgres-database-baseline predicates=%s\n' \
    "${postgres_database_baseline_reasons}" >&2
  exit 77
fi

readonly DATABASE_URL="postgres://cdnca:${postgres_password}@127.0.0.1:${postgres_port}/cdnca?sslmode=disable&search_path=${CONTROL_DATABASE_SCHEMA}"
readonly CLICKHOUSE_URL="http://127.0.0.1:${clickhouse_port}/"
ANALYTICS_NATS_URL="nats://127.0.0.1:${nats_port}"
readonly EDGE_NATS_URL="nats://127.0.0.1:${edge_nats_port}"
readonly REDIS_URL="redis://127.0.0.1:${redis_port}/0"

# Pre-create the shared edge JetStream resources before any control-api process probe.
obs_e2e_edge_nats_request() {
  local subject=$1
  local payload=$2
  local timeout_millis=$3
  local request_timeout_millis=$4
  local status
  : >"${EDGE_NATS_PROBE_STDERR_RAW}"
  if obs_e2e_docker_timeout_millis "${timeout_millis}" exec "${edge_nats_probe_container_id}" \
    nats request --raw --timeout "${request_timeout_millis}ms" "${subject}" "${payload}" \
    2>"${EDGE_NATS_PROBE_STDERR_RAW}"; then
    status=0
  else
    status=$?
  fi
  obs_e2e_sanitize_diagnostic_stream <"${EDGE_NATS_PROBE_STDERR_RAW}" \
    >"${EDGE_NATS_PROBE_STDERR_SAFE}"
  rm -f -- "${EDGE_NATS_PROBE_STDERR_RAW}"
  return "${status}"
}

: >"${EDGE_NATS_PROBE_STDERR_SAFE}"
edge_nats_info_ready_response='{"type":"io.nats.jetstream.api.v1.account_info_response","memory":0,"storage":0,"streams":0,"consumers":0,"limits":{"max_memory":-1,"max_storage":-1,"max_streams":-1,"max_consumers":-1,"max_ack_pending":-1,"memory_max_stream_bytes":-1,"storage_max_stream_bytes":-1,"max_bytes_required":false},"api":{"level":1,"total":0,"errors":0}}'
edge_nats_deadline_nanos=$(( $(obs_e2e_monotonic_nanos) + 40000000000 ))
edge_nats_probe_deadline_nanos=$((edge_nats_deadline_nanos - 2000000000))
edge_nats_timeout_millis="$(obs_e2e_deadline_timeout_millis "${edge_nats_probe_deadline_nanos}" 5000)" || {
  obs_e2e_emit_edge_nats_diagnostics deadline "${edge_nats_deadline_nanos}"
  obs_e2e_fail 'edge-nats-readiness-deadline'
}
if ! obs_e2e_capture_edge_nats_state "${edge_nats_timeout_millis}"; then
  obs_e2e_emit_edge_nats_diagnostics state-unavailable "${edge_nats_deadline_nanos}"
  obs_e2e_fail 'edge-nats-readiness-state-unavailable'
fi
edge_nats_classification="$(obs_e2e_classify_current_edge_nats \
  true 0 "${edge_nats_info_ready_response}")" || \
  obs_e2e_fail 'edge-nats-readiness-classifier'
edge_nats_state=${edge_nats_classification%%$'\t'*}
edge_nats_last_reason=${edge_nats_classification#*$'\t'}
if [ "${edge_nats_state}" != ready ]; then
  obs_e2e_emit_edge_nats_diagnostics "${edge_nats_last_reason}" "${edge_nats_deadline_nanos}"
  obs_e2e_fail "edge-nats-readiness-${edge_nats_last_reason}"
fi

if ! obs_e2e_verify_edge_nats_store_writable "${edge_nats_probe_deadline_nanos}"; then
  edge_nats_last_reason=${edge_nats_store_reason}
  if edge_nats_timeout_millis="$(obs_e2e_deadline_timeout_millis \
    "${edge_nats_probe_deadline_nanos}" 1000)" &&
    obs_e2e_capture_edge_nats_state "${edge_nats_timeout_millis}"; then
    edge_nats_classification="$(obs_e2e_classify_current_edge_nats \
      false 0 "${edge_nats_info_ready_response}")" || \
      edge_nats_classification="$(printf 'fatal\tmalformed')"
    edge_nats_state=${edge_nats_classification%%$'\t'*}
    edge_nats_state_reason=${edge_nats_classification#*$'\t'}
    case "${edge_nats_store_reason}" in
      runtime-uid-invalid|runtime-uid-mismatch) ;;
      *)
        case "${edge_nats_state_reason}" in
          container-stopped|container-oom) edge_nats_last_reason=${edge_nats_state_reason} ;;
        esac
        ;;
    esac
  fi
  obs_e2e_emit_edge_nats_diagnostics "${edge_nats_last_reason}" "${edge_nats_deadline_nanos}"
  obs_e2e_fail "edge-nats-readiness-${edge_nats_last_reason}"
fi

edge_nats_timeout_millis="$(obs_e2e_deadline_timeout_millis "${edge_nats_probe_deadline_nanos}" 10000)" || {
  obs_e2e_emit_edge_nats_diagnostics deadline "${edge_nats_deadline_nanos}"
  obs_e2e_fail 'edge-nats-readiness-deadline'
}
edge_nats_probe_container_id="$(obs_e2e_docker_timeout_millis "${edge_nats_timeout_millis}" run -d \
  --name "${EDGE_NATS_PROBE_CONTAINER}" --network "${NETWORK_NAME}" \
  --network-alias "${EDGE_NATS_PROBE_NETWORK_ALIAS}" --label "${RESOURCE_LABEL}" \
  -e NATS_URL="nats://${EDGE_NATS_NETWORK_ALIAS}:4222" --entrypoint sh "${NATS_BOX_IMAGE}" \
  -ec 'trap "exit 0" TERM INT; while :; do sleep 3600 & wait "$!"; done')" || {
  obs_e2e_emit_edge_nats_diagnostics probe-container-start "${edge_nats_deadline_nanos}"
  obs_e2e_fail 'edge-nats-readiness-probe-container-start'
}
[[ "${edge_nats_probe_container_id}" =~ ^[0-9a-f]{64}$ ]] || {
  obs_e2e_emit_edge_nats_diagnostics probe-container-id "${edge_nats_deadline_nanos}"
  obs_e2e_fail 'edge-nats-readiness-probe-container-id'
}

edge_nats_ready=0
edge_nats_last_reason=connect
while edge_nats_timeout_millis="$(obs_e2e_deadline_timeout_millis \
  "${edge_nats_probe_deadline_nanos}" 5000)"; do
  if ! obs_e2e_capture_edge_nats_state "${edge_nats_timeout_millis}"; then
    edge_nats_last_reason='state-unavailable'
    break
  fi
  edge_nats_classification="$(obs_e2e_classify_current_edge_nats \
    true 0 "${edge_nats_info_ready_response}")" || \
    edge_nats_classification="$(printf 'fatal\tmalformed')"
  edge_nats_state=${edge_nats_classification%%$'\t'*}
  edge_nats_last_reason=${edge_nats_classification#*$'\t'}
  [ "${edge_nats_state}" = ready ] || break

  edge_nats_timeout_millis="$(obs_e2e_deadline_timeout_millis \
    "${edge_nats_probe_deadline_nanos}" 6000)" || break
  request_timeout_millis=${edge_nats_timeout_millis}
  [ "${request_timeout_millis}" -le 250 ] || \
    request_timeout_millis=$((request_timeout_millis - 100))
  edge_nats_probe_exit=0
  if edge_nats_response="$(obs_e2e_edge_nats_request "\$JS.API.INFO" '{}' \
    "${edge_nats_timeout_millis}" "${request_timeout_millis}")"; then
    edge_nats_probe_exit=0
  else
    edge_nats_probe_exit=$?
  fi
  edge_nats_classification="$(obs_e2e_classify_current_edge_nats \
    true "${edge_nats_probe_exit}" "${edge_nats_response}")" || \
    edge_nats_classification="$(printf 'fatal\tmalformed')"
  edge_nats_state=${edge_nats_classification%%$'\t'*}
  edge_nats_last_reason=${edge_nats_classification#*$'\t'}
  case "${edge_nats_state}" in
    ready)
      edge_nats_ready=1
      break
      ;;
    fatal) break ;;
    retry) ;;
    *)
      edge_nats_last_reason=malformed
      break
      ;;
  esac
  edge_nats_sleep_millis="$(obs_e2e_deadline_timeout_millis \
    "${edge_nats_probe_deadline_nanos}" 250)" || break
  perl -MTime::HiRes=usleep -e 'Time::HiRes::usleep($ARGV[0] * 1000)' "${edge_nats_sleep_millis}"
done
if [ "${edge_nats_ready}" -ne 1 ]; then
  obs_e2e_emit_edge_nats_diagnostics "${edge_nats_last_reason}" "${edge_nats_deadline_nanos}"
  obs_e2e_fail "edge-nats-readiness-${edge_nats_last_reason}"
fi

obs_e2e_edge_nats_api() {
  local subject=$1
  local payload=$2
  edge_nats_response="$(obs_e2e_edge_nats_request "${subject}" "${payload}" 6000 5000)" || \
    obs_e2e_fail 'edge-nats-api-request'
  printf '%s' "${edge_nats_response}" | jq -e 'type == "object"' >/dev/null 2>&1 || \
    obs_e2e_fail 'edge-nats-api-response'
}

obs_e2e_ensure_edge_stream() {
  local resource=$1
  local expected=$2
  local error_code
  obs_e2e_edge_nats_api "\$JS.API.STREAM.INFO.${resource}" '{}'
  error_code=$(printf '%s' "${edge_nats_response}" | jq -er '.error.err_code // 0') || \
    obs_e2e_fail 'edge-nats-stream-info-error-code'
  if [ "${error_code}" = 10059 ]; then
    obs_e2e_edge_nats_api "\$JS.API.STREAM.CREATE.${resource}" "${expected}"
    [ "$(printf '%s' "${edge_nats_response}" | jq -er '.error.err_code // 0')" = 0 ] || \
      obs_e2e_fail 'edge-nats-stream-create-api-error'
  elif [ "${error_code}" != 0 ]; then
    obs_e2e_fail 'edge-nats-stream-info-api-error'
  fi
  obs_e2e_edge_nats_api "\$JS.API.STREAM.INFO.${resource}" '{}'
  printf '%s' "${edge_nats_response}" | jq -e --argjson expected "${expected}" '
    (.config.subjects // []) as $subjects |
    .error == null and .config.name == $expected.name and
    ($subjects | sort) == ($expected.subjects | sort) and
    .config.retention == $expected.retention and
    .config.max_consumers == $expected.max_consumers and
    .config.max_msgs == $expected.max_msgs and .config.max_bytes == $expected.max_bytes and
    .config.discard == $expected.discard and .config.max_age == $expected.max_age and
    .config.max_msgs_per_subject == $expected.max_msgs_per_subject and
    (.config.discard_new_per_subject // false) == false and
    .config.storage == $expected.storage and .config.num_replicas == $expected.num_replicas and
    .config.duplicate_window == $expected.duplicate_window and
    .config.max_msg_size == $expected.max_msg_size
  ' >/dev/null || obs_e2e_fail 'edge-nats-stream-configuration-mismatch'
}

obs_e2e_ensure_edge_consumer() {
  local stream=$1
  local durable=$2
  local expected=$3
  local error_code
  obs_e2e_edge_nats_api "\$JS.API.CONSUMER.INFO.${stream}.${durable}" '{}'
  error_code=$(printf '%s' "${edge_nats_response}" | jq -er '.error.err_code // 0') || \
    obs_e2e_fail 'edge-nats-consumer-info-error-code'
  if [ "${error_code}" = 10014 ]; then
    obs_e2e_edge_nats_api "\$JS.API.CONSUMER.CREATE.${stream}.${durable}" "${expected}"
    [ "$(printf '%s' "${edge_nats_response}" | jq -er '.error.err_code // 0')" = 0 ] || \
      obs_e2e_fail 'edge-nats-consumer-create-api-error'
  elif [ "${error_code}" != 0 ]; then
    obs_e2e_fail 'edge-nats-consumer-info-api-error'
  fi
  obs_e2e_edge_nats_api "\$JS.API.CONSUMER.INFO.${stream}.${durable}" '{}'
  printf '%s' "${edge_nats_response}" | jq -e --argjson expected "${expected}" '
    .error == null and .stream_name == $expected.stream_name and
    .name == $expected.config.durable_name and
    .config.durable_name == $expected.config.durable_name and
    (.config.filter_subject // "") == ($expected.config.filter_subject // "") and
    (.config.filter_subjects // []) == ($expected.config.filter_subjects // []) and
    .config.deliver_policy == $expected.config.deliver_policy and
    .config.ack_policy == $expected.config.ack_policy and
    .config.ack_wait == $expected.config.ack_wait and
    .config.max_deliver == $expected.config.max_deliver and
    .config.replay_policy == $expected.config.replay_policy and
    .config.max_ack_pending == $expected.config.max_ack_pending and
    .config.max_waiting == $expected.config.max_waiting and
    .config.max_batch == $expected.config.max_batch and
    .config.max_expires == $expected.config.max_expires and
    ((.config.backoff // []) | length) == 0 and
    (.config.deliver_subject // "") == ""
  ' >/dev/null || obs_e2e_fail 'edge-nats-consumer-configuration-mismatch'
}

edge_command_stream=$(jq -cn '{
  name:"AGENT_COMMANDS",
  subjects:["cdnca.agent.commands.*","cdnca.agent.commands.acme-http01.*",
    "cdnca.agent.commands.cache.*","cdnca.agent.commands.cache-dlq.*",
    "cdnca.agent.commands.upgrade.*","cdnca.agent.commands.drain.*",
    "cdnca.agent.commands.gateway-port.*"],
  retention:"workqueue", max_consumers:-1, max_msgs:-1, max_bytes:-1, discard:"new",
  max_age:0, max_msgs_per_subject:-1, max_msg_size:1048576, storage:"file",
  num_replicas:1, duplicate_window:120000000000
}')
edge_status_stream=$(jq -cn '{
  name:"AGENT_DEPLOYMENT_STATUS",
  subjects:["cdnca.agent.deployment-status.*","cdnca.agent.deployment-status.generic-v2.*.*",
    "cdnca.agent.deployment-status.terminal-receipt.*.*",
    "cdnca.agent.deployment-status.terminal-receipt-confirmation.*.*",
    "cdnca.agent.deployment-status.terminal-receipt-confirmation-index.*",
    "cdnca.agent.deployment-status.acme-http01.*","cdnca.agent.deployment-status.cache.*","cdnca.agent.deployment-status.cache-dlq.*",
    "cdnca.agent.deployment-status.upgrade.*","cdnca.agent.deployment-status.upgrade-v2.*",
    "cdnca.agent.deployment-status.upgrade-proof.pending.*",
    "cdnca.agent.deployment-status.upgrade-proof.confirmed.*.*",
    "cdnca.agent.deployment-status.upgrade-proof.completed.*.*.*",
    "cdnca.agent.deployment-status.upgrade-proof.status.*.*",
    "cdnca.agent.deployment-status.drain.*","cdnca.agent.deployment-status.gateway-port.*"],
  retention:"limits", max_consumers:-1, max_msgs:-1, max_bytes:-1, discard:"old",
  max_age:0, max_msgs_per_subject:-1, max_msg_size:1048576, storage:"file",
  num_replicas:1, duplicate_window:120000000000
}')
edge_heartbeat_stream=$(jq -cn '{
  name:"AGENT_HEARTBEATS", subjects:["cdnca.agent.heartbeats.*"],
  retention:"workqueue", max_consumers:-1, max_msgs:-1, max_bytes:-1, discard:"new",
  max_age:0, max_msgs_per_subject:-1, max_msg_size:1048576, storage:"file",
  num_replicas:1, duplicate_window:120000000000
}')
edge_node_monitoring_command_stream=$(jq -cn '{
  name:"NODE_MONITORING_COMMANDS", subjects:["cdnca.agent.node-monitoring.commands.*"],
  retention:"workqueue", max_consumers:-1, max_msgs:-1, max_bytes:-1, discard:"new",
  max_age:0, max_msgs_per_subject:-1, max_msg_size:1048576, storage:"file",
  num_replicas:1, duplicate_window:120000000000
}')
edge_node_monitoring_status_stream=$(jq -cn '{
  name:"NODE_MONITORING_STATUS", subjects:["cdnca.agent.node-monitoring.status.*"],
  retention:"workqueue", max_consumers:-1, max_msgs:-1, max_bytes:-1, discard:"new",
  max_age:0, max_msgs_per_subject:-1, max_msg_size:1048576, storage:"file",
  num_replicas:1, duplicate_window:120000000000
}')
edge_analytics_ingest_stream=$(jq -cn '{
  name:"ANALYTICS_INGEST_V1", subjects:["cdnca.analytics.ingest.v1.*"],
  retention:"workqueue", max_consumers:1, max_msgs:10000000, max_bytes:10737418240,
  discard:"new", max_age:0, max_msgs_per_subject:-1, max_msg_size:1048576,
  storage:"file", num_replicas:1, duplicate_window:600000000000
}')
edge_cc_coordination_stream=$(jq -cn '{
  name:"SECURITY_CC_COORDINATION_V1", subjects:["cdnca.security.cccoord.v1.*.*"],
  retention:"workqueue", max_consumers:1, max_msgs:2000000, max_bytes:2147483648,
  discard:"new", max_age:86400000000000, max_msgs_per_subject:-1, max_msg_size:1048576,
  storage:"file", num_replicas:1, duplicate_window:600000000000
}')
edge_l4_sessions_stream=$(jq -cn '{
  name:"L4_SESSIONS_INGEST_V1", subjects:["cdnca.l4.sessions.v1.*.*.*"],
  retention:"workqueue", max_consumers:1, max_msgs:5000000, max_bytes:5368709120,
  discard:"new", max_age:2592000000000000, max_msgs_per_subject:-1,
  max_msg_size:1048576, storage:"file", num_replicas:1, duplicate_window:600000000000
}')
obs_e2e_ensure_edge_stream AGENT_COMMANDS "${edge_command_stream}"
obs_e2e_ensure_edge_stream AGENT_DEPLOYMENT_STATUS "${edge_status_stream}"
obs_e2e_ensure_edge_stream AGENT_HEARTBEATS "${edge_heartbeat_stream}"
obs_e2e_ensure_edge_stream NODE_MONITORING_COMMANDS "${edge_node_monitoring_command_stream}"
obs_e2e_ensure_edge_stream NODE_MONITORING_STATUS "${edge_node_monitoring_status_stream}"
obs_e2e_ensure_edge_stream ANALYTICS_INGEST_V1 "${edge_analytics_ingest_stream}"
obs_e2e_ensure_edge_stream SECURITY_CC_COORDINATION_V1 "${edge_cc_coordination_stream}"
obs_e2e_ensure_edge_stream L4_SESSIONS_INGEST_V1 "${edge_l4_sessions_stream}"

edge_status_consumer=$(jq -cn '{
  stream_name:"AGENT_DEPLOYMENT_STATUS",
  config:{durable_name:"control_api_edge_status", deliver_policy:"all", ack_policy:"explicit",
    ack_wait:120000000000, max_deliver:-1,
    filter_subjects:["cdnca.agent.deployment-status.*",
      "cdnca.agent.deployment-status.generic-v2.*.*"],
    replay_policy:"instant", max_ack_pending:256, max_waiting:32, max_batch:1,
    max_expires:5000000000}
}')
node_metrics_consumer=$(jq -cn '{
  stream_name:"NODE_MONITORING_STATUS",
  config:{durable_name:"control_api_node_metrics", deliver_policy:"all", ack_policy:"explicit",
    ack_wait:120000000000, max_deliver:-1,
    filter_subject:"cdnca.agent.node-monitoring.status.*", replay_policy:"instant",
    max_ack_pending:256, max_waiting:32, max_batch:1, max_expires:5000000000}
}')
obs_e2e_ensure_edge_consumer AGENT_DEPLOYMENT_STATUS control_api_edge_status "${edge_status_consumer}"
obs_e2e_ensure_edge_consumer NODE_MONITORING_STATUS control_api_node_metrics "${node_metrics_consumer}"
printf 'edge NATS resources verified\n' >"${WORK_DIR}/edge-nats-preprovision.log"

printf 'machine 127.0.0.1 login analytics password %s\n' "${clickhouse_password}" >"${WORK_DIR}/clickhouse.netrc"
# Retries are safe only here: all publishers start later, so the 003 backfill source tables are still empty.
clickhouse_migrated=0
for _ in {1..3}; do
  if obs_e2e_docker_timeout 55 exec -i "${CLICKHOUSE_CONTAINER}" clickhouse-client --user analytics \
    --password "${clickhouse_password}" --database cdnca_analytics --multiquery \
    < <(cat \
      "${REPO_ROOT}/infra/clickhouse/migrations/001_analytics.up.sql" \
      "${REPO_ROOT}/infra/clickhouse/migrations/002_analytics_authority_capture.up.sql" \
      "${REPO_ROOT}/infra/clickhouse/migrations/003_analytics_hourly_rollup.up.sql" \
      "${REPO_ROOT}/infra/clickhouse/migrations/004_analytics_version_evidence.up.sql" \
      "${REPO_ROOT}/infra/clickhouse/migrations/005_package_monitor_metrics.up.sql" \
      "${REPO_ROOT}/infra/clickhouse/migrations/006_access_event_state.up.sql" \
      "${REPO_ROOT}/infra/clickhouse/migrations/007_connections_ingest_receipts.up.sql" \
      "${REPO_ROOT}/infra/clickhouse/migrations/008_security_event_state.up.sql" \
      "${REPO_ROOT}/infra/clickhouse/migrations/009_site_realtime_monitoring.up.sql" \
      "${REPO_ROOT}/infra/clickhouse/migrations/010_global_firewall_events.up.sql" \
      "${REPO_ROOT}/infra/clickhouse/migrations/011_l4_session_facts.up.sql" \
      "${REPO_ROOT}/infra/clickhouse/migrations/012_analytics_log_query_projection.up.sql" \
      "${REPO_ROOT}/infra/clickhouse/migrations/013_connections_finalized_dimensions.up.sql") \
    >/dev/null; then
    clickhouse_migrated=1
    break
  else
    clickhouse_migration_status=$?
    [ "${clickhouse_migration_status}" -ne 124 ] || obs_e2e_unknown 'docker-timeout-clickhouse-migration'
    sleep 1
  fi
done
[ "${clickhouse_migrated}" -eq 1 ] || obs_e2e_fail 'clickhouse-migration'

(
  cd "${REPO_ROOT}/services/control-api"
  obs_e2e_timeout 180 go build -trimpath -o "${WORK_DIR}/bin/control-api" ./cmd/control-api
) >"${WORK_DIR}/control-build.log" 2>&1 || obs_e2e_fail 'control-api-build'
(
  cd "${REPO_ROOT}/services/agent-gateway"
  obs_e2e_timeout 180 go build -trimpath -o "${WORK_DIR}/bin/agent-gateway" ./cmd/agent-gateway
) >"${WORK_DIR}/gateway-build.log" 2>&1 || obs_e2e_fail 'agent-gateway-build'
(
  cd "${REPO_ROOT}/agents/edge-agent"
  obs_e2e_timeout 180 go build -trimpath -o "${WORK_DIR}/bin/edge-agent" ./cmd/edge-agent
) >"${WORK_DIR}/edge-agent-build.log" 2>&1 || obs_e2e_fail 'edge-agent-build'
control_binary_sha="$(shasum -a 256 "${WORK_DIR}/bin/control-api" | awk '{print $1}')"
gateway_binary_sha="$(shasum -a 256 "${WORK_DIR}/bin/agent-gateway" | awk '{print $1}')"
edge_agent_binary_sha="$(shasum -a 256 "${WORK_DIR}/bin/edge-agent" | awk '{print $1}')"

obs_e2e_timeout 120 env "DATABASE_URL=${DATABASE_URL}" "${WORK_DIR}/bin/control-api" migrate up \
  >"${WORK_DIR}/control-migrate.log" 2>&1 || obs_e2e_fail 'control-api-migrate-up'

obs_e2e_docker_timeout 20 exec "${POSTGRES_CONTAINER}" psql -v ON_ERROR_STOP=1 -U cdnca -d cdnca \
  --command "SET search_path TO ${CONTROL_DATABASE_SCHEMA}; INSERT INTO control_installation_entitlement(singleton,installation_id,last_status,created_at,updated_at)\
    VALUES(true,'70000000-0000-4000-8000-000000000002','uninstalled',clock_timestamp(),clock_timestamp())\
    ON CONFLICT(singleton) DO NOTHING" >/dev/null || obs_e2e_fail 'control-installation-preprovision'
control_installation_state="$(obs_e2e_docker_timeout 20 exec "${POSTGRES_CONTAINER}" \
  psql -qAtX -v ON_ERROR_STOP=1 -U cdnca -d cdnca --command \
  "SET search_path TO ${CONTROL_DATABASE_SCHEMA}; SELECT installation_id FROM control_installation_entitlement WHERE singleton=true")" || \
  obs_e2e_fail 'control-installation-read'
[ "${control_installation_state}" = '70000000-0000-4000-8000-000000000002' ] || \
  obs_e2e_fail 'control-installation-mismatch'

obs_e2e_timeout 30 openssl req -x509 -newkey rsa:2048 -nodes -days 2 \
  -subj '/CN=CDNCA OBS Process E2E CA' \
  -addext 'basicConstraints=critical,CA:TRUE,pathlen:0' \
  -addext 'keyUsage=critical,keyCertSign,cRLSign' \
  -addext 'subjectKeyIdentifier=hash' \
  -keyout "${WORK_DIR}/certs/ca.key" -out "${WORK_DIR}/certs/ca.crt" >/dev/null 2>&1
obs_e2e_timeout 30 openssl genpkey -algorithm RSA \
  -pkeyopt rsa_keygen_bits:2048 -out "${WORK_DIR}/certs/node-ca.key" >/dev/null 2>&1
chmod 0600 "${WORK_DIR}/certs/node-ca.key"
obs_e2e_timeout 30 openssl req -new -x509 -days 2 \
  -subj '/CN=CDNCA OBS Process E2E Node CA' \
  -key "${WORK_DIR}/certs/node-ca.key" -out "${WORK_DIR}/certs/node-ca.crt" \
  -addext 'basicConstraints=critical,CA:TRUE,pathlen:0' \
  -addext 'keyUsage=critical,keyCertSign,cRLSign' \
  -addext 'subjectKeyIdentifier=hash' >/dev/null 2>&1
obs_e2e_timeout 30 openssl req -newkey rsa:2048 -nodes -subj '/CN=localhost' \
  -keyout "${WORK_DIR}/certs/server.key" -out "${WORK_DIR}/certs/server.csr" >/dev/null 2>&1
printf 'subjectAltName=DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth\n' >"${WORK_DIR}/certs/server.ext"
obs_e2e_timeout 30 openssl x509 -req -days 2 -in "${WORK_DIR}/certs/server.csr" \
  -CA "${WORK_DIR}/certs/ca.crt" \
  -CAkey "${WORK_DIR}/certs/ca.key" -CAcreateserial -extfile "${WORK_DIR}/certs/server.ext" \
  -out "${WORK_DIR}/certs/server.crt" >/dev/null 2>&1
obs_e2e_timeout 30 openssl req -newkey rsa:2048 -nodes -subj '/CN=agent-gateway' \
  -keyout "${WORK_DIR}/certs/gateway.key" -out "${WORK_DIR}/certs/gateway.csr" >/dev/null 2>&1
printf 'subjectAltName=URI:spiffe://cdnca/obs-process-e2e/gateway\nextendedKeyUsage=clientAuth\n' >"${WORK_DIR}/certs/gateway.ext"
obs_e2e_timeout 30 openssl x509 -req -days 2 -in "${WORK_DIR}/certs/gateway.csr" \
  -CA "${WORK_DIR}/certs/ca.crt" \
  -CAkey "${WORK_DIR}/certs/ca.key" -CAcreateserial -extfile "${WORK_DIR}/certs/gateway.ext" \
  -out "${WORK_DIR}/certs/gateway.crt" >/dev/null 2>&1

node_id='30000000-0000-4000-8a00-000000000001'
tenant_id='10000000-0000-4000-8000-000000000001'
tenant_scope_id='11000000-0000-4000-8000-000000000001'
user_id='12000000-0000-4000-8000-000000000001'
site_id='20000000-0000-4000-8000-000000000001'
config_id='40000000-0000-4000-8000-000000000001'
package_subscription_id='50000000-0000-4000-8000-000000000001'
installation_id='70000000-0000-4000-8000-000000000002'
token_id='71000000-0000-4000-8000-000000000001'
ca_epoch_id='72000000-0000-4000-8000-000000000001'
ca_epoch_request_id='73000000-0000-4000-8000-000000000001'
enrollment_token="$(obs_e2e_timeout 10 ruby -rsecurerandom -e 'print SecureRandom.urlsafe_base64(32, false)')" || \
  obs_e2e_fail 'edge-enrollment-token-generation'
[[ "${enrollment_token}" =~ ^[A-Za-z0-9_-]{43}$ ]] || obs_e2e_fail 'edge-enrollment-token-shape'
enrollment_token_sha="$(printf '%s' "${enrollment_token}" | shasum -a 256 | awk '{print $1}')"
printf '%s\n' "${enrollment_token}" >"${WORK_DIR}/edge-enrollment-token"
printf 'obs-process-e2e-machine-%s\n' "${OWNERSHIP_TOKEN}" >"${WORK_DIR}/edge-machine-id"
chmod 0600 "${WORK_DIR}/edge-enrollment-token" "${WORK_DIR}/edge-machine-id"

canonical_snapshot="$(jq -cn \
  --arg scope "${tenant_scope_id}" --arg site "${site_id}" --arg subscription "${package_subscription_id}" \
  '{schema:"cdnca.edge.config-source/v1",configuration_scope_id:$scope,source_revision:1,
    sites:[{id:$site,package_subscription_id:$subscription,revision:1,domain:"obs.example.test",listen_port:443,
      origins:[{host:"192.0.2.20",port:80,weight:1}],balance:"round_robin",failover_tries:1,
      connect_timeout_ms:1000,read_timeout_ms:5000,websocket:true,range:true}],streams:[]}')" || \
  obs_e2e_fail 'edge-canonical-snapshot-build'
canonical_snapshot_sha="$(printf '%s' "${canonical_snapshot}" | shasum -a 256 | awk '{print $1}')"
canonical_snapshot_base64="$(printf '%s' "${canonical_snapshot}" | base64 | tr -d '\n')"
obs_e2e_timeout 10 openssl x509 -in "${WORK_DIR}/certs/node-ca.crt" -outform DER \
  -out "${WORK_DIR}/certs/node-ca.der" >/dev/null 2>&1 || obs_e2e_fail 'node-ca-der-export'
obs_e2e_timeout 10 openssl x509 -in "${WORK_DIR}/certs/node-ca.crt" -pubkey -noout \
  >"${WORK_DIR}/certs/node-ca-public.pem" 2>/dev/null || obs_e2e_fail 'node-ca-public-export'
obs_e2e_timeout 10 openssl pkey -pubin -in "${WORK_DIR}/certs/node-ca-public.pem" -outform DER \
  -out "${WORK_DIR}/certs/node-ca-public.der" >/dev/null 2>&1 || obs_e2e_fail 'node-ca-public-der-export'
node_ca_certificate_sha="$(shasum -a 256 "${WORK_DIR}/certs/node-ca.der" | awk '{print $1}')"
node_ca_public_key_sha="$(shasum -a 256 "${WORK_DIR}/certs/node-ca-public.der" | awk '{print $1}')"
node_ca_pem_base64="$(base64 <"${WORK_DIR}/certs/node-ca.crt" | tr -d '\n')"

obs_e2e_docker_timeout 20 exec "${POSTGRES_CONTAINER}" psql -v ON_ERROR_STOP=1 -U cdnca -d cdnca \
  --command "SET search_path TO ${CONTROL_DATABASE_SCHEMA}; BEGIN;
    INSERT INTO tenants(id,display_name) VALUES('${tenant_id}','OBS process tenant');
    INSERT INTO access_scopes(id,kind,tenant_id) VALUES('${tenant_scope_id}','tenant','${tenant_id}');
    INSERT INTO users(id,username,display_name,password_hash)
      VALUES('${user_id}','obs_fixture_user','OBS fixture user','test-only');
    INSERT INTO memberships(scope_id,user_id) VALUES('${tenant_scope_id}','${user_id}');
    INSERT INTO nodes(id,scope_id,name,admin_state,created_by_user_id,created_at,updated_at)
      VALUES('${node_id}','${tenant_scope_id}','obs-process-edge','pending','${user_id}',clock_timestamp(),clock_timestamp());
    INSERT INTO sites(id,scope_id,owner_user_id,domain,origins,origin_hosts,created_by_user_id,updated_by_user_id)
      VALUES('${site_id}','${tenant_scope_id}','${user_id}','obs.example.test',ARRAY['192.0.2.20:80'],ARRAY['192.0.2.20'],'${user_id}','${user_id}');
    INSERT INTO site_origin_pools(site_id,balance_method,failover_tries,connect_timeout_ms,read_timeout_ms)
      VALUES('${site_id}','round_robin',1,1000,5000);
    INSERT INTO site_origins(site_id,position,host,port,weight,enabled)
      VALUES('${site_id}',1,'192.0.2.20',80,1,true);
    INSERT INTO config_versions(id,configuration_scope_id,canonical_snapshot,canonical_snapshot_sha256,
      generator_name,generator_version,status,idempotency_key,request_digest,created_at,published_at)
      VALUES('${config_id}','${tenant_scope_id}',decode('${canonical_snapshot_base64}','base64'),
        decode('${canonical_snapshot_sha}','hex'),'analytics-process-e2e','1','releasable','obs-process-config',
        decode(repeat('31',32),'hex'),clock_timestamp(),clock_timestamp());
    INSERT INTO node_config_state(node_id,configuration_scope_id,current_config_version_id,revision,updated_at)
      VALUES('${node_id}','${tenant_scope_id}','${config_id}',1,clock_timestamp())
      ON CONFLICT (node_id) DO UPDATE SET configuration_scope_id=EXCLUDED.configuration_scope_id,
        current_config_version_id=EXCLUDED.current_config_version_id,
        revision=node_config_state.revision+1,updated_at=EXCLUDED.updated_at;
    INSERT INTO node_enrollment_tokens(id,node_id,purpose,token_hash,created_by_user_id,created_at,expires_at)
      VALUES('${token_id}','${node_id}','initial_enrollment',decode('${enrollment_token_sha}','hex'),'${user_id}',
        clock_timestamp(),clock_timestamp()+interval '1 hour');
    INSERT INTO node_ca_key_epochs(id,installation_id,epoch,key_id,ca_certificate_pem,ca_certificate_sha256,
      public_key_sha256,not_before,not_after,status,request_id,request_digest,created_by_scope_id,created_by_user_id,created_at)
      VALUES('${ca_epoch_id}','${installation_id}',1,'obs-process-node-ca',decode('${node_ca_pem_base64}','base64'),
        decode('${node_ca_certificate_sha}','hex'),decode('${node_ca_public_key_sha}','hex'),clock_timestamp()-interval '5 minutes',
        clock_timestamp()+interval '47 hours','active','${ca_epoch_request_id}',decode(repeat('32',32),'hex'),
        '${tenant_scope_id}','${user_id}',clock_timestamp());
    COMMIT;" >/dev/null || obs_e2e_fail 'edge-telemetry-authority-seed'
edge_authority_count="$(obs_e2e_docker_timeout 20 exec "${POSTGRES_CONTAINER}" \
  psql -qAtX -v ON_ERROR_STOP=1 -U cdnca -d cdnca --command \
  "SET search_path TO ${CONTROL_DATABASE_SCHEMA}; SELECT count(*) FROM nodes node
    JOIN node_config_state state ON state.node_id=node.id
    JOIN config_versions version ON version.id=state.current_config_version_id
    JOIN node_enrollment_tokens token ON token.node_id=node.id AND token.consumed_at IS NULL
    JOIN node_ca_key_epochs epoch ON epoch.installation_id='${installation_id}' AND epoch.status='active'
    WHERE node.id='${node_id}' AND node.scope_id='${tenant_scope_id}'
      AND state.current_config_version_id='${config_id}' AND version.canonical_snapshot_sha256=decode('${canonical_snapshot_sha}','hex')")" || \
  obs_e2e_fail 'edge-telemetry-authority-readback'
[ "${edge_authority_count}" = 1 ] || obs_e2e_fail 'edge-telemetry-authority-mismatch'

control_http_port="$(obs_e2e_timeout 10 ruby -rsocket -e 's=TCPServer.new("127.0.0.1",0); puts s.addr[1]')"
control_grpc_port="$(obs_e2e_timeout 10 ruby -rsocket -e 's=TCPServer.new("127.0.0.1",0); puts s.addr[1]')"
owned_ports+=("${control_http_port}" "${control_grpc_port}")
isolation_wrapping_key="$(obs_e2e_timeout 10 openssl rand -base64 32)"
api_key_pepper="$(obs_e2e_timeout 10 openssl rand -base64 32)"
dns_credential_key="$(obs_e2e_timeout 10 openssl rand -base64 32)"
impersonation_hmac_key="$(obs_e2e_timeout 10 openssl rand -base64 32)"
mfa_encryption_key="$(obs_e2e_timeout 10 openssl rand -base64 32)"
observability_log_cursor_key="$(obs_e2e_timeout 10 openssl rand -base64 32)"
analytics_realtime_cursor_key="$(obs_e2e_timeout 10 openssl rand -base64 32)"
access_secret="$(obs_e2e_timeout 10 openssl rand -hex 32)"
readonly isolation_wrapping_key api_key_pepper dns_credential_key impersonation_hmac_key
readonly mfa_encryption_key observability_log_cursor_key analytics_realtime_cursor_key access_secret

control_env=(
  "DATABASE_URL=${DATABASE_URL}"
  'CONTROL_INSTALLATION_ID=70000000-0000-4000-8000-000000000002'
  "HTTP_ADDR=127.0.0.1:${control_http_port}"
  "CONTROL_INTERNAL_GRPC_ADDR=127.0.0.1:${control_grpc_port}"
  "ACCESS_TOKEN_SECRET=${access_secret}"
  'API_KEY_PEPPER_VERSION=legacy-v1'
  "API_KEY_PEPPER_BASE64=${api_key_pepper}"
  "IMPERSONATION_HMAC_KEY_BASE64=${impersonation_hmac_key}"
  "OBSERVABILITY_LOG_CURSOR_KEY_BASE64=${observability_log_cursor_key}"
  'ANALYTICS_LOGS_CURSOR_ACTIVE_KEY_ID=obs-process-e2e'
  "ANALYTICS_LOGS_CURSOR_KEYS_JSON={\"obs-process-e2e\":\"${observability_log_cursor_key}\"}"
  'MFA_ENABLED=true'
  'MFA_ENCRYPTION_ACTIVE_KEY_ID=obs-process-e2e'
  "MFA_ENCRYPTION_KEYS_JSON={\"obs-process-e2e\":\"${mfa_encryption_key}\"}"
  'DNS_CREDENTIAL_KEY_ID=obs-process-e2e'
  "DNS_CREDENTIAL_KEY_BASE64=${dns_credential_key}"
  'ACCOUNT_RECOVERY_ENABLED=false'
  'ACCOUNT_REGISTRATION_ENABLED=false'
  'ACME_RUNTIME_ENABLED=false'
  'ANALYTICS_CONNECTIONS_RUNTIME_ENABLED=true'
  "ANALYTICS_CONNECTIONS_NATS_URL=${EDGE_NATS_URL}"
  'ANALYTICS_CONNECTIONS_OPERATION_TIMEOUT=1s'
  'ANALYTICS_CONNECTIONS_CONNECT_TIMEOUT=1s'
  'ANALYTICS_GEO_ARTIFACT_ENABLED=false'
  'ANALYTICS_QUERY_ENABLED=true'
  "CLICKHOUSE_URL=${CLICKHOUSE_URL}"
  'CLICKHOUSE_DATABASE=cdnca_analytics'
  'CLICKHOUSE_USERNAME=analytics'
  "CLICKHOUSE_PASSWORD=${clickhouse_password}"
  'ANALYTICS_REALTIME_RUNTIME_ENABLED=true'
  "ANALYTICS_REALTIME_CURSOR_KEY_BASE64=${analytics_realtime_cursor_key}"
  'ANALYTICS_REALTIME_QUERY_TIMEOUT=1s'
  'ANALYTICS_REALTIME_MAX_RESPONSE_BYTES=1048576'
  'ANNOUNCEMENT_ENABLED=false'
  'CACHE_CONTROL_RUNTIME_ENABLED=false'
  'CHALLENGE_POLICY_RUNTIME_ENABLED=false'
  'CONTROL_UPGRADE_PLAN_WRITER_ENABLED=false'
  'CONTROL_UPGRADE_RUNTIME_ENABLED=false'
  'CONTROL_UPGRADE_SYSTEMD_PLAN_SOURCE_ENABLED=false'
  'CUSTOM_RBAC_RUNTIME_ENABLED=false'
  'DNS_RECONCILE_ENABLED=false'
  'EDGE_AUTOMATIC_PUBLICATION_ENABLED=false'
  'ORIGIN_AUTH_RUNTIME_ENABLED=false'
  'EDGE_PUBLISH_RUNTIME_ENABLED=false'
  'CDNCA_SECURITY_ACTIVATION_ENABLED=false'
  'ERROR_PAGE_RUNTIME_ENABLED=false'
  'HTTP_POLICY_RUNTIME_ENABLED=false'
  'IDENTITY_VERIFICATION_RUNTIME_ENABLED=false'
  'JA4_BLOCK_RUNTIME_ENABLED=false'
  'JOB_QUERY_ENABLED=false'
  'NODE_PORT_TRANSITION_RUNTIME_ENABLED=false'
  'NODE_PRESENCE_NATS_URL='
  'NODE_PRESENCE_REDIS_URL='
  'NODE_SCHEDULING_RUNTIME_ENABLED=false'
  'NOTIFICATION_RUNTIME_ENABLED=false'
  'PACKAGE_COMMERCE_RUNTIME_ENABLED=false'
  'PACKAGE_COMMERCE_WORKER_ENABLED=false'
  'PACKAGE_CYCLE_RUNTIME_ENABLED=false'
  'PACKAGE_MONITOR_HTTP_ENABLED=false'
  'PACKAGE_MONITOR_RUNTIME_ENABLED=false'
  'PACKAGE_PERIOD_RESET_RUNTIME_ENABLED=false'
  'PACKAGE_USAGE_RUNTIME_ENABLED=false'
  'PLUGIN_WEBHOOK_RUNTIME_ENABLED=false'
  'PROMOTION_HTTP_ENABLED=false'
  'PAYMENT_CHANNELS_ENABLED=false'
  'SIGNER_REVOCATION_CONSUMER_ENABLED=false'
  'SITE_STATUS_RECOVERY_RUNTIME_ENABLED=false'
  'SYSTEM_CONFIGURATION_RUNTIME_ENABLED=false'
  'TRAFFIC_PACKAGE_RUNTIME_ENABLED=false'
  'TRAFFIC_PACKAGE_WORKLOAD_RUNTIME_ENABLED=false'
  'URL_AUTH_POLICY_RUNTIME_ENABLED=false'
  "EDGE_DEPLOYMENT_NATS_URL=${EDGE_NATS_URL}"
  "CONTROL_INTERNAL_SERVER_CERT_FILE=${WORK_DIR}/certs/server.crt"
  "CONTROL_INTERNAL_SERVER_PRIVATE_KEY_FILE=${WORK_DIR}/certs/server.key"
  "CONTROL_INTERNAL_GATEWAY_CLIENT_CA_FILE=${WORK_DIR}/certs/ca.crt"
  'CONTROL_INTERNAL_GATEWAY_WORKLOAD_URI_SAN=spiffe://cdnca/obs-process-e2e/gateway'
  "NODE_CA_CERTIFICATE_CHAIN_FILE=${WORK_DIR}/certs/node-ca.crt"
  "NODE_CA_PRIVATE_KEY_FILE=${WORK_DIR}/certs/node-ca.key"
  'ANALYTICS_INGEST_ENABLED=true'
  "ANALYTICS_INGEST_NATS_URL=${ANALYTICS_NATS_URL}"
  'ANALYTICS_INGEST_NATS_USER=runtime'
  "ANALYTICS_INGEST_NATS_PASSWORD=${runtime_password}"
  "ANALYTICS_INGEST_CLICKHOUSE_URL=${CLICKHOUSE_URL}"
  'ANALYTICS_INGEST_CLICKHOUSE_DATABASE=cdnca_analytics'
  'ANALYTICS_INGEST_CLICKHOUSE_USER=analytics'
  "ANALYTICS_INGEST_CLICKHOUSE_PASSWORD=${clickhouse_password}"
  'ANALYTICS_INGEST_ISOLATION_WRAPPING_KEY_ID=obs-process-e2e-kek-v1'
  "ANALYTICS_INGEST_ISOLATION_WRAPPING_KEY_BASE64=${isolation_wrapping_key}"
  'ANALYTICS_INGEST_CONNECT_TIMEOUT=1s'
  'ANALYTICS_INGEST_WRITE_TIMEOUT=1s'
  'ANALYTICS_INGEST_SUPERVISOR_BACKOFF_MIN=100ms'
  'ANALYTICS_INGEST_SUPERVISOR_BACKOFF_MAX=500ms'
  'ANALYTICS_INGEST_OPERATION_TIMEOUT=1s'
  'ANALYTICS_INGEST_FETCH_TIMEOUT=250ms'
  'ANALYTICS_INGEST_NAK_BASE_DELAY=100ms'
  'ANALYTICS_INGEST_NAK_MAX_DELAY=500ms'
  'SHUTDOWN_PERIOD=10s'
)

obs_e2e_run_analytics_preprovision() {
  local generation_name=$1
  if obs_e2e_docker_timeout 55 run --rm --label "${RESOURCE_LABEL}" --network "${NETWORK_NAME}" \
    -e NATS_URL="nats://${NATS_CONTAINER}:4222" \
    -e NATS_PREPROVISION_USERNAME=preprovision -e NATS_PREPROVISION_PASSWORD="${preprovision_password}" \
    -e ANALYTICS_INGEST_MAX_REQUEST_EXPIRES_NANOS=250000000 \
    -e ANALYTICS_INGEST_COORDINATION_LEASE_TTL_NANOS=4000000000 \
    -v "${PREPROVISION_SCRIPT}:/contract/analytics-preprovision.sh:ro" \
    "${NATS_BOX_IMAGE}" sh /contract/analytics-preprovision.sh \
    >"${WORK_DIR}/preprovision-${generation_name}.log" 2>&1; then
    return 0
  fi
  obs_e2e_emit_process_diagnostic "analytics-preprovision-${generation_name}" \
    "${WORK_DIR}/preprovision-${generation_name}.log"
  obs_e2e_fail "analytics-preprovision-${generation_name}"
}

obs_e2e_capture_analytics_generation() {
  local generation_name=$1
  local stream_info_file="${WORK_DIR}/analytics-stream-${generation_name}.json"
  local consumer_info_file="${WORK_DIR}/analytics-consumer-${generation_name}.json"
  local generation_file="${WORK_DIR}/analytics-generation-${generation_name}.tsv"
  local stream_created_iso consumer_created_iso stream_created_nano consumer_created_nano
  obs_e2e_docker_timeout 55 run --rm --label "${RESOURCE_LABEL}" --network "${NETWORK_NAME}" \
    -e NATS_URL="nats://${NATS_CONTAINER}:4222" -e NATS_USER=preprovision \
    -e NATS_PASSWORD="${preprovision_password}" "${NATS_BOX_IMAGE}" \
    nats stream info -j ANALYTICS_INGEST_V1 >"${stream_info_file}" 2>/dev/null || \
    obs_e2e_fail "analytics-stream-info-${generation_name}"
  obs_e2e_docker_timeout 55 run --rm --label "${RESOURCE_LABEL}" --network "${NETWORK_NAME}" \
    -e NATS_URL="nats://${NATS_CONTAINER}:4222" -e NATS_USER=preprovision \
    -e NATS_PASSWORD="${preprovision_password}" "${NATS_BOX_IMAGE}" \
    nats consumer info -j ANALYTICS_INGEST_V1 control_api_analytics_ingest_v1 \
    >"${consumer_info_file}" 2>/dev/null || obs_e2e_fail "analytics-consumer-info-${generation_name}"
  stream_created_iso="$(jq -er '.created | select(type == "string" and length > 0)' "${stream_info_file}")" || \
    obs_e2e_fail "analytics-stream-created-${generation_name}"
  consumer_created_iso="$(jq -er '.created | select(type == "string" and length > 0)' "${consumer_info_file}")" || \
    obs_e2e_fail "analytics-consumer-created-${generation_name}"
  stream_created_nano="$(obs_e2e_timeout 10 ruby -rtime -e \
    'value = (Time.iso8601(ARGV.fetch(0)).to_r * 1_000_000_000).to_i; abort unless value.positive?; puts value' \
    "${stream_created_iso}")" || obs_e2e_fail "analytics-stream-created-parse-${generation_name}"
  consumer_created_nano="$(obs_e2e_timeout 10 ruby -rtime -e \
    'value = (Time.iso8601(ARGV.fetch(0)).to_r * 1_000_000_000).to_i; abort unless value.positive?; puts value' \
    "${consumer_created_iso}")" || obs_e2e_fail "analytics-consumer-created-parse-${generation_name}"
  [ "${consumer_created_nano}" -ge "${stream_created_nano}" ] || \
    obs_e2e_fail "analytics-generation-order-${generation_name}"
  printf '%s\t%s\t%s\n' "${stream_created_nano}" "${consumer_created_nano}" "${consumer_created_iso}" \
    >"${generation_file}"
}

obs_e2e_insert_analytics_history_generation() {
  local history_epoch=$1 stream_created_nano=$2 consumer_created_nano=$3 history_start_at=$4
  obs_e2e_docker_timeout 20 exec "${POSTGRES_CONTAINER}" psql -v ON_ERROR_STOP=1 -U cdnca -d cdnca \
    --command "SET search_path TO ${CONTROL_DATABASE_SCHEMA}; WITH clock AS (SELECT clock_timestamp() AS now) INSERT INTO analytics_history_streams(\
      installation_id,nats_domain,stream_name,durable_name,\
      stream_created_unix_nano,consumer_created_unix_nano,history_epoch,\
      history_start_sequence,history_start_at,legacy_baseline_kind,\
      legacy_baseline_at,legacy_baseline_sha256,\
      broker_consumer_ack_floor,broker_stream_ack_floor,prepared_stream_floor,\
      revision,last_reconciled_at,created_at,updated_at\
    ) SELECT\
      '70000000-0000-4000-8000-000000000002','',\
      'ANALYTICS_INGEST_V1','control_api_analytics_ingest_v1',\
      ${stream_created_nano},${consumer_created_nano},'${history_epoch}',\
      1,'${history_start_at}'::timestamptz,'none',NULL,NULL,0,0,0,1,\
      clock.now,clock.now,clock.now FROM clock" >/dev/null || \
    obs_e2e_fail "analytics-history-seed-${history_epoch}"
}

obs_e2e_retire_analytics_history_generation() {
  local history_epoch=$1
  obs_e2e_docker_timeout 20 exec "${POSTGRES_CONTAINER}" psql -qAtX -v ON_ERROR_STOP=1 -U cdnca -d cdnca \
    --command "SET search_path TO ${CONTROL_DATABASE_SCHEMA}; WITH clock AS (SELECT clock_timestamp() AS now)\
      UPDATE analytics_history_streams AS history SET retired_at=clock.now,\
        revision=history.revision+1,last_reconciled_at=clock.now,updated_at=clock.now\
      FROM clock WHERE history.history_epoch='${history_epoch}' RETURNING 1" | \
    grep -Fx '1' >/dev/null || obs_e2e_fail "analytics-history-retire-${history_epoch}"
}

obs_e2e_reset_analytics_nats_store() {
  obs_e2e_docker_timeout 55 stop "${NATS_CONTAINER}" >/dev/null || obs_e2e_fail 'analytics-nats-stop-for-absent'
  nats_container_state="$(obs_e2e_docker_timeout 5 inspect -f '{{.State.Status}}' "${NATS_CONTAINER}")" || \
    obs_e2e_fail 'analytics-nats-stop-inspect'
  [ "${nats_container_state}" = 'exited' ] || obs_e2e_fail 'analytics-nats-not-stopped'
  find "${WORK_DIR}/nats-store" -mindepth 1 -delete
  obs_e2e_docker_timeout 55 start "${NATS_CONTAINER}" >/dev/null || obs_e2e_fail 'analytics-nats-start-empty'
  for _ in {1..30}; do
    if obs_e2e_docker_timeout 55 run --rm --label "${RESOURCE_LABEL}" --network "${NETWORK_NAME}" \
      -e NATS_URL="nats://${NATS_CONTAINER}:4222" -e NATS_USER=preprovision \
      -e NATS_PASSWORD="${preprovision_password}" "${NATS_BOX_IMAGE}" \
      nats request --raw --timeout 1s '$JS.API.STREAM.INFO.ANALYTICS_INGEST_V1' '{}' \
      >"${WORK_DIR}/analytics-empty-stream-info.json" 2>/dev/null; then
      empty_stream_error="$(jq -r '.error.err_code // 0' "${WORK_DIR}/analytics-empty-stream-info.json" 2>/dev/null || printf '0')"
    else
      empty_stream_error="$(jq -r '.error.err_code // 0' "${WORK_DIR}/analytics-empty-stream-info.json" 2>/dev/null || printf '0')"
    fi
    if [ "${empty_stream_error}" = '10059' ]; then
      for _ in {1..10}; do
        if obs_e2e_docker_timeout 55 run --rm --label "${RESOURCE_LABEL}" --network "${NETWORK_NAME}" \
          -e NATS_URL="nats://${NATS_CONTAINER}:4222" -e NATS_USER=runtime \
          -e NATS_PASSWORD="${runtime_password}" "${NATS_BOX_IMAGE}" \
          nats request --raw --timeout 1s '$JS.API.STREAM.INFO.ANALYTICS_INGEST_V1' '{}' \
          >"${WORK_DIR}/analytics-empty-runtime-stream-info.json" 2>/dev/null; then
          runtime_empty_stream_error="$(jq -r '.error.err_code // 0' "${WORK_DIR}/analytics-empty-runtime-stream-info.json" 2>/dev/null || printf '0')"
          [ "${runtime_empty_stream_error}" = '10059' ] && return 0
        fi
        sleep 0.1
      done
      obs_e2e_fail 'analytics-nats-empty-runtime-readiness'
    fi
    sleep 0.1
  done
  obs_e2e_fail 'analytics-nats-empty-readiness'
}

obs_e2e_refresh_nats_host_port() {
  local binding
  binding="$(obs_e2e_docker_timeout 5 port "${NATS_CONTAINER}" 4222/tcp | sed -n '1p')" || \
    obs_e2e_fail 'analytics-nats-host-port-read'
  case "${binding}" in
    127.0.0.1:[1-9][0-9]*) ;;
    *) obs_e2e_fail 'analytics-nats-host-port-shape' ;;
  esac
  nats_port="${binding##*:}"
  [ "${nats_port}" -ge 1 ] && [ "${nats_port}" -le 65535 ] || obs_e2e_fail 'analytics-nats-host-port-range'
  owned_ports+=("${nats_port}")
  ANALYTICS_NATS_URL="nats://127.0.0.1:${nats_port}"
  local index
  for index in "${!control_env[@]}"; do
    case "${control_env[index]}" in
      ANALYTICS_INGEST_NATS_URL=*) control_env[index]="ANALYTICS_INGEST_NATS_URL=${ANALYTICS_NATS_URL}" ;;
    esac
  done
}

obs_e2e_run_analytics_preprovision analytics-history-a
obs_e2e_capture_analytics_generation a
IFS=$'\t' read -r stream_created_a consumer_created_a consumer_created_at_a \
  <"${WORK_DIR}/analytics-generation-a.tsv"
history_epoch_a="$(obs_e2e_timeout 10 ruby -rsecurerandom -e 'puts SecureRandom.uuid')" || \
  obs_e2e_fail 'analytics-history-epoch-a'
obs_e2e_insert_analytics_history_generation "${history_epoch_a}" \
  "${stream_created_a}" "${consumer_created_a}" "${consumer_created_at_a}"
obs_e2e_reset_analytics_nats_store
obs_e2e_refresh_nats_host_port

# Missing resources must fail closed under the runtime identity; this is an actual process probe.
env -i "PATH=${PATH}" "TMPDIR=${TMPDIR:-/tmp}" "${control_env[@]}" \
  "${WORK_DIR}/bin/control-api" serve >"${WORK_DIR}/resource-absent.log" 2>&1 &
absent_pid=$!
for _ in {1..80}; do
  kill -0 "${absent_pid}" 2>/dev/null || break
  sleep 0.1
done
if kill -0 "${absent_pid}" 2>/dev/null; then
  obs_e2e_stop_pid "${absent_pid}"
  absent_pid=''
  obs_e2e_fail 'resource-absent-probe-did-not-fail-closed'
fi
if wait "${absent_pid}" 2>/dev/null; then
  absent_pid=''
  obs_e2e_fail 'resource-absent-probe-exited-zero'
fi
absent_pid=''
if ! grep -F 'verify analytics ingest JetStream resources' "${WORK_DIR}/resource-absent.log" >/dev/null; then
  obs_e2e_emit_process_diagnostic resource-absent "${WORK_DIR}/resource-absent.log"
  obs_e2e_fail 'resource-absent-probe-wrong-stage'
fi

obs_e2e_run_analytics_preprovision analytics-history-b
obs_e2e_capture_analytics_generation b
IFS=$'\t' read -r stream_created_b consumer_created_b consumer_created_at_b \
  <"${WORK_DIR}/analytics-generation-b.tsv"
history_epoch_b="$(obs_e2e_timeout 10 ruby -rsecurerandom -e 'puts SecureRandom.uuid')" || \
  obs_e2e_fail 'analytics-history-epoch-b'
obs_e2e_retire_analytics_history_generation "${history_epoch_a}"
obs_e2e_insert_analytics_history_generation "${history_epoch_b}" \
  "${stream_created_b}" "${consumer_created_b}" "${consumer_created_at_b}"

# A process with a mismatched evidence/isolation capacity must reject exact resources and leave them unchanged.
mismatch_http_port="$(obs_e2e_timeout 10 ruby -rsocket -e 's=TCPServer.new("127.0.0.1",0); puts s.addr[1]')"
mismatch_grpc_port="$(obs_e2e_timeout 10 ruby -rsocket -e 's=TCPServer.new("127.0.0.1",0); puts s.addr[1]')"
owned_ports+=("${mismatch_http_port}" "${mismatch_grpc_port}")
env -i "PATH=${PATH}" "TMPDIR=${TMPDIR:-/tmp}" "${control_env[@]}" \
  "HTTP_ADDR=127.0.0.1:${mismatch_http_port}" \
  "CONTROL_INTERNAL_GRPC_ADDR=127.0.0.1:${mismatch_grpc_port}" \
  'ANALYTICS_INGEST_ISOLATION_MAX_BYTES=1073741823' \
  "${WORK_DIR}/bin/control-api" serve >"${WORK_DIR}/resource-mismatch.log" 2>&1 &
mismatch_pid=$!
for _ in {1..80}; do
  kill -0 "${mismatch_pid}" 2>/dev/null || break
  sleep 0.1
done
if kill -0 "${mismatch_pid}" 2>/dev/null; then
  obs_e2e_stop_pid "${mismatch_pid}"
  mismatch_pid=''
  obs_e2e_fail 'resource-mismatch-probe-did-not-fail-closed'
fi
if wait "${mismatch_pid}" 2>/dev/null; then
  mismatch_pid=''
  obs_e2e_fail 'resource-mismatch-probe-exited-zero'
fi
mismatch_pid=''
if ! grep -F 'verify analytics ingest JetStream resources' "${WORK_DIR}/resource-mismatch.log" >/dev/null; then
  obs_e2e_emit_process_diagnostic resource-mismatch "${WORK_DIR}/resource-mismatch.log"
  obs_e2e_fail 'resource-mismatch-probe-wrong-stage'
fi

env -i "PATH=${PATH}" "TMPDIR=${TMPDIR:-/tmp}" "${control_env[@]}" \
  "${WORK_DIR}/bin/control-api" serve >"${WORK_DIR}/control.log" 2>&1 &
control_pid=$!
for _ in {1..80}; do
  if ! kill -0 "${control_pid}" 2>/dev/null; then
    obs_e2e_emit_process_diagnostic control "${WORK_DIR}/control.log"
    obs_e2e_fail 'control-api-exited-before-health'
  fi
  curl --silent --show-error "http://127.0.0.1:${control_http_port}/health/detail" \
    >"${WORK_DIR}/control-health.json" 2>/dev/null || true
  if jq -e '.analytics_ingest.enabled == true and (.analytics_ingest.state == "running" or .analytics_ingest.state == "degraded")' \
    "${WORK_DIR}/control-health.json" >/dev/null 2>&1; then
    break
  fi
  sleep 0.1
done
jq -e '.analytics_ingest.enabled == true' "${WORK_DIR}/control-health.json" >/dev/null || \
  obs_e2e_fail 'control-api-health-detail'

gateway_enrollment_port="$(obs_e2e_timeout 10 ruby -rsocket -e 's=TCPServer.new("127.0.0.1",0); puts s.addr[1]')"
gateway_agent_port="$(obs_e2e_timeout 10 ruby -rsocket -e 's=TCPServer.new("127.0.0.1",0); puts s.addr[1]')"
gateway_health_port="$(obs_e2e_timeout 10 ruby -rsocket -e 's=TCPServer.new("127.0.0.1",0); puts s.addr[1]')"
owned_ports+=("${gateway_enrollment_port}" "${gateway_agent_port}" "${gateway_health_port}")
env \
  "CDNCA_GATEWAY_ENROLLMENT_ADDR=127.0.0.1:${gateway_enrollment_port}" \
  "CDNCA_GATEWAY_AGENT_ADDR=127.0.0.1:${gateway_agent_port}" \
  "CDNCA_GATEWAY_HEALTH_ADDR=127.0.0.1:${gateway_health_port}" \
  'CDNCA_GATEWAY_INSTANCE_ID=70000000-0000-4000-8000-000000000001' \
  'CDNCA_GATEWAY_VERSION=obs-process-e2e' \
  "CDNCA_GATEWAY_TLS_CERT_FILE=${WORK_DIR}/certs/server.crt" \
  "CDNCA_GATEWAY_TLS_KEY_FILE=${WORK_DIR}/certs/server.key" \
  "CDNCA_GATEWAY_AGENT_CLIENT_CA_FILE=${WORK_DIR}/certs/node-ca.crt" \
  "CDNCA_CONTROL_ADDRESS=127.0.0.1:${control_grpc_port}" \
  'CDNCA_CONTROL_SERVER_NAME=localhost' \
  "CDNCA_CONTROL_CLIENT_CERT_FILE=${WORK_DIR}/certs/gateway.crt" \
  "CDNCA_CONTROL_CLIENT_KEY_FILE=${WORK_DIR}/certs/gateway.key" \
  "CDNCA_CONTROL_SERVER_CA_FILE=${WORK_DIR}/certs/ca.crt" \
  'CDNCA_CONTROL_CLIENT_WORKLOAD_URI_SAN=spiffe://cdnca/obs-process-e2e/gateway' \
  "CDNCA_REDIS_URL=${REDIS_URL}" "CDNCA_NATS_URL=${EDGE_NATS_URL}" \
  "CDNCA_TELEMETRY_NATS_URL=${EDGE_NATS_URL}" \
  'CDNCA_TELEMETRY_NATS_USER=' \
  'CDNCA_TELEMETRY_NATS_PASSWORD=' \
  'CDNCA_GATEWAY_STARTUP_TIMEOUT=5s' 'CDNCA_GATEWAY_SHUTDOWN_TIMEOUT=6s' \
  "${WORK_DIR}/bin/agent-gateway" >"${WORK_DIR}/gateway.log" 2>&1 &
gateway_pid=$!
for _ in {1..30}; do
  if ! kill -0 "${gateway_pid}" 2>/dev/null; then
    break
  fi
  if curl --silent --show-error "http://127.0.0.1:${gateway_health_port}/health/live" \
    >"${WORK_DIR}/gateway-health.json" 2>/dev/null; then
    break
  fi
  sleep 0.1
done
if ! kill -0 "${gateway_pid}" 2>/dev/null; then
  wait "${gateway_pid}" 2>/dev/null || true
  gateway_pid=''
  obs_e2e_emit_process_diagnostic gateway "${WORK_DIR}/gateway.log"
  obs_e2e_fail 'agent-gateway-exited-before-health'
fi
[ -s "${WORK_DIR}/gateway-health.json" ] || obs_e2e_fail 'agent-gateway-health'

obs_e2e_timeout 30 "${WORK_DIR}/bin/edge-agent" enroll \
  --gateway-address "127.0.0.1:${gateway_enrollment_port}" \
  --gateway-server-name localhost \
  --gateway-root-ca-file "${WORK_DIR}/certs/ca.crt" \
  --identity-dir "${WORK_DIR}/edge-identity" \
  --machine-id-file "${WORK_DIR}/edge-machine-id" \
  --token-file "${WORK_DIR}/edge-enrollment-token" \
  --openresty-version obs-process-e2e --timeout 20s \
  >"${WORK_DIR}/edge-enrollment.json" 2>"${WORK_DIR}/edge-enrollment.log" || {
    obs_e2e_emit_process_diagnostic edge-enrollment "${WORK_DIR}/edge-enrollment.log"
    obs_e2e_fail 'edge-agent-enrollment'
  }
fixture_client_certificate_file="$(jq -er '.client_certificate_file' "${WORK_DIR}/edge-enrollment.json")" || \
  obs_e2e_fail 'edge-agent-enrollment-certificate-path'
fixture_client_private_key_file="$(jq -er '.client_private_key_file' "${WORK_DIR}/edge-enrollment.json")" || \
  obs_e2e_fail 'edge-agent-enrollment-private-key-path'
fixture_artifact_private_key_file="$(jq -er '.artifact_encryption_private_key_file' "${WORK_DIR}/edge-enrollment.json")" || \
  obs_e2e_fail 'edge-agent-enrollment-artifact-key-path'
jq -e --arg node "${node_id}" --arg identity "${WORK_DIR}/edge-identity/identity.json" \
  --arg certificate "${WORK_DIR}/edge-identity/client.pem" --arg private_key "${WORK_DIR}/edge-identity/client-key.pem" \
  --arg artifact_key "${WORK_DIR}/edge-identity/artifact-x25519-key.bin" '
    .node_id == $node and .protocol_major == 1 and .protocol_minor == 0 and
    (.artifact_encryption_key_id | test("^x25519:[0-9a-f]{64}$")) and
    .identity_file == $identity and .client_certificate_file == $certificate and
    .client_private_key_file == $private_key and .artifact_encryption_private_key_file == $artifact_key
  ' "${WORK_DIR}/edge-enrollment.json" >/dev/null || obs_e2e_fail 'edge-agent-enrollment-receipt'
[ "${fixture_client_certificate_file}" = "${WORK_DIR}/edge-identity/client.pem" ] && \
  [ "${fixture_client_private_key_file}" = "${WORK_DIR}/edge-identity/client-key.pem" ] && \
  [ "${fixture_artifact_private_key_file}" = "${WORK_DIR}/edge-identity/artifact-x25519-key.bin" ] || \
  obs_e2e_fail 'edge-agent-enrollment-path-binding'
rm -f "${WORK_DIR}/edge-enrollment-token"

edge_fixture_event_id="obs-connection-${OWNERSHIP_TOKEN}"
edge_fixture_source_watermark=41
obs_e2e_timeout 30 "${edge_fixture_command}" \
  --node-id "${node_id}" --tenant-id "${tenant_id}" --site-id "${site_id}" \
  --installation-id "${installation_id}" --package-subscription-id "${package_subscription_id}" \
  --domain obs.example.test --listen-port 443 --spool-directory "${WORK_DIR}/edge-event-spool" \
  --gateway-address "127.0.0.1:${gateway_agent_port}" --gateway-server-name localhost \
  --gateway-ca-file "${WORK_DIR}/certs/ca.crt" \
  --client-certificate-file "${fixture_client_certificate_file}" \
  --client-private-key-file "${fixture_client_private_key_file}" \
  --event-id "${edge_fixture_event_id}" --connections 7 \
  --source-watermark "${edge_fixture_source_watermark}" --timeout 20s \
  >"${WORK_DIR}/edge-telemetry-fixture-receipt.json" 2>"${WORK_DIR}/edge-telemetry-fixture.log" || {
    obs_e2e_emit_process_diagnostic edge-telemetry-fixture "${WORK_DIR}/edge-telemetry-fixture.log"
    obs_e2e_fail 'edge-telemetry-fixture-delivery'
  }
jq -e --arg event "${edge_fixture_event_id}" --arg node "${node_id}" --arg tenant "${tenant_id}" \
  --arg installation "${installation_id}" --arg site "${site_id}" --arg subscription "${package_subscription_id}" \
  --argjson watermark "${edge_fixture_source_watermark}" '
    .status == "acknowledged" and .transport == "eventspool_mtls" and
    .sequence_kind == "source_watermark" and .event_id == $event and .node_id == $node and
    .tenant_id == $tenant and .installation_id == $installation and .site_id == $site and
    .package_subscription_id == $subscription and .domain == "obs.example.test" and .listen_port == 443 and
    .source_watermark == $watermark and .acknowledged_source_watermark == $watermark
  ' "${WORK_DIR}/edge-telemetry-fixture-receipt.json" >/dev/null || \
  obs_e2e_fail 'edge-telemetry-fixture-acknowledgement'

connections_receipt_count=''
for _ in {1..80}; do
  connections_receipt_count="$(curl --silent --show-error --fail --netrc-file "${WORK_DIR}/clickhouse.netrc" \
    --data-binary "SELECT count() FROM connections_ingest_receipts_v1 FINAL
      WHERE event_id='${edge_fixture_event_id}' AND tenant_id=toUUID('${tenant_id}')
        AND installation_id='${installation_id}' AND site_id=toUUID('${site_id}') AND node_id=toUUID('${node_id}')
        AND domain='obs.example.test' AND listen_port=443
        AND package_subscription_id=toUUID('${package_subscription_id}')
        AND source_watermark=${edge_fixture_source_watermark} AND connections=7
        AND nats_stream='CONNECTIONS_INGEST_V1' AND nats_durable='control_api_connections'
        AND state='broker_ack_observed' AND state_rank=3 AND puback_stream='CONNECTIONS_INGEST_V1'
        AND puback_sequence>0 AND nats_stream_sequence=puback_sequence AND nats_consumer_sequence>0
      FORMAT TabSeparatedRaw" "${CLICKHOUSE_URL}?database=cdnca_analytics" 2>/dev/null || true)"
  [ "${connections_receipt_count}" = 1 ] && break
  sleep 0.1
done
[ "${connections_receipt_count:-0}" = 1 ] || obs_e2e_fail 'edge-telemetry-clickhouse-receipt'
connections_receipt_tsv="$(curl --silent --show-error --fail --netrc-file "${WORK_DIR}/clickhouse.netrc" \
  --data-binary "SELECT receipt_id,batch_id,state,toString(state_rank),puback_stream,toString(puback_sequence),
      toString(nats_stream_sequence),toString(nats_consumer_sequence),toString(source_watermark)
    FROM connections_ingest_receipts_v1 FINAL
    WHERE event_id='${edge_fixture_event_id}' AND tenant_id=toUUID('${tenant_id}')
    FORMAT TabSeparatedRaw" "${CLICKHOUSE_URL}?database=cdnca_analytics")" || \
  obs_e2e_fail 'edge-telemetry-clickhouse-receipt-readback'
IFS=$'\t' read -r connections_receipt_id connections_batch_id connections_receipt_state \
  connections_state_rank connections_puback_stream connections_puback_sequence \
  connections_stream_sequence connections_consumer_sequence connections_source_watermark \
  <<<"${connections_receipt_tsv}"
[[ "${connections_receipt_id}" =~ ^conn_[0-9a-f]{64}$ ]] && \
  [[ "${connections_batch_id}" =~ ^conn_batch_[0-9a-f]{64}$ ]] && \
  [ "${connections_receipt_state}" = broker_ack_observed ] && [ "${connections_state_rank}" = 3 ] && \
  [ "${connections_puback_stream}" = CONNECTIONS_INGEST_V1 ] && \
  [ "${connections_puback_sequence}" -gt 0 ] && \
  [ "${connections_stream_sequence}" = "${connections_puback_sequence}" ] && \
  [ "${connections_consumer_sequence}" -gt 0 ] && \
  [ "${connections_source_watermark}" = "${edge_fixture_source_watermark}" ] || \
  obs_e2e_fail 'edge-telemetry-clickhouse-receipt-identity'

subject="cdnca.analytics.ingest.v1.${node_id}"
sentinel="CDNCA_OBS_E2E_PLAINTEXT_SENTINEL_${OWNERSHIP_TOKEN}"
sentinel_sha="$(printf '%s' "${sentinel}" | shasum -a 256 | awk '{print $1}')"
produced_at="$(date -u +%Y-%m-%dT%H:%M:%S.000000000Z)"
message_one="obs-process-${OWNERSHIP_TOKEN}-message-1"
jq -cn \
  --arg message "${message_one}" --arg produced "${produced_at}" --arg tenant "${tenant_id}" \
  --arg node "${node_id}" --arg site "${site_id}" --arg config "${config_id}" \
  '{schema_version:1,type:"access.v1",message_id:$message,produced_at:$produced,tenant_id:$tenant,node_id:$node,
    events:[{metric_version:1,event_id:("event-"+$message),occurred_at:$produced,tenant_id:$tenant,site_id:$site,node_id:$node,
      request_id:"request-1",trace_id:"trace-1",config_version_id:$config,host:"obs.example.test",path:"/e2e",
      client_ip:"192.0.2.10",country_code:"CN",carrier:"process-e2e",method:"GET",protocol:"HTTP/2",
      cache_status:"MISS",upstream_result:"ok",status_code:200,request_bytes:100,response_bytes:1000,duration_us:2500,
      task_id:null,ja4:null,origin_connect_us:null,origin_first_byte_us:null,origin_total_us:null}]}' \
  >"${WORK_DIR}/message-one.json"

# Direct NATS fixtures prove only publisher-to-Control durability; they never satisfy gateway_to_control.
obs_e2e_docker_timeout 55 run --rm -i --label "${RESOURCE_LABEL}" --network "${NETWORK_NAME}" \
  -e NATS_URL="nats://${NATS_CONTAINER}:4222" -e NATS_USER=publisher -e NATS_PASSWORD="${publisher_password}" \
  "${NATS_BOX_IMAGE}" nats pub -J --force-stdin \
  -H "Nats-Msg-Id:${message_one}" -H "Cdnca-Node-Id:${node_id}" -H "Cdnca-Tenant-Id:${tenant_id}" \
  -H "Cdnca-Site-Id:${site_id}" -H "Cdnca-Config-Version-Id:${config_id}" \
  -H "Cdnca-Installation-Id:${installation_id}" "${subject}" \
  <"${WORK_DIR}/message-one.json" >"${WORK_DIR}/publish-one.log" 2>&1 || obs_e2e_fail 'publish-valid-message'

duplicate_physical_rows_before=''
for _ in {1..40}; do
  duplicate_physical_rows_before=$(curl --silent --show-error --fail --netrc-file "${WORK_DIR}/clickhouse.netrc" \
    --data-binary "SELECT count() FROM access_events WHERE event_id='event-${message_one}' FORMAT TabSeparatedRaw" \
    "${CLICKHOUSE_URL}?database=cdnca_analytics" 2>/dev/null || true)
  [ "${duplicate_physical_rows_before}" = 1 ] && break
  sleep 0.1
done
[ "${duplicate_physical_rows_before:-0}" = 1 ] || obs_e2e_fail 'valid-message-clickhouse-query'

# JetStream duplicate suppression must keep the exact ClickHouse identity at one row.
obs_e2e_docker_timeout 55 run --rm -i --label "${RESOURCE_LABEL}" --network "${NETWORK_NAME}" \
  -e NATS_URL="nats://${NATS_CONTAINER}:4222" -e NATS_USER=publisher -e NATS_PASSWORD="${publisher_password}" \
  "${NATS_BOX_IMAGE}" nats pub -J --force-stdin \
  -H "Nats-Msg-Id:${message_one}" -H "Cdnca-Node-Id:${node_id}" -H "Cdnca-Tenant-Id:${tenant_id}" \
  -H "Cdnca-Site-Id:${site_id}" -H "Cdnca-Config-Version-Id:${config_id}" \
  -H "Cdnca-Installation-Id:${installation_id}" "${subject}" \
  <"${WORK_DIR}/message-one.json" >"${WORK_DIR}/publish-duplicate.log" 2>&1 || obs_e2e_fail 'publish-duplicate-message'

duplicate_physical_rows_after=''
for _ in {1..20}; do
  duplicate_physical_rows_current=$(curl --silent --show-error --fail --netrc-file "${WORK_DIR}/clickhouse.netrc" \
    --data-binary "SELECT count() FROM access_events WHERE event_id='event-${message_one}' FORMAT TabSeparatedRaw" \
    "${CLICKHOUSE_URL}?database=cdnca_analytics" 2>/dev/null || true)
  if [ -n "${duplicate_physical_rows_current}" ]; then
    [ "${duplicate_physical_rows_current}" = "${duplicate_physical_rows_before}" ] || \
      obs_e2e_fail 'duplicate-message-physical-row-growth'
    duplicate_physical_rows_after="${duplicate_physical_rows_current}"
  fi
  sleep 0.1
done
[ "${duplicate_physical_rows_after:-0}" = 1 ] || obs_e2e_fail 'duplicate-message-physical-row-query'

poison_message="obs-process-${OWNERSHIP_TOKEN}-poison"
printf '{"schema_version":1,"type":"wrong.v1","sentinel":"%s"}' "${sentinel}" >"${WORK_DIR}/poison.json"
obs_e2e_docker_timeout 55 run --rm -i --label "${RESOURCE_LABEL}" --network "${NETWORK_NAME}" \
  -e NATS_URL="nats://${NATS_CONTAINER}:4222" -e NATS_USER=publisher -e NATS_PASSWORD="${publisher_password}" \
  "${NATS_BOX_IMAGE}" nats pub -J --force-stdin \
  -H "Nats-Msg-Id:${poison_message}" -H "Cdnca-Node-Id:${node_id}" -H "Cdnca-Tenant-Id:${tenant_id}" \
  -H "Cdnca-Site-Id:${site_id}" -H "Cdnca-Config-Version-Id:${config_id}" \
  -H "Cdnca-Installation-Id:${installation_id}" "${subject}" \
  <"${WORK_DIR}/poison.json" >"${WORK_DIR}/publish-poison.log" 2>&1 || obs_e2e_fail 'publish-wrong-wire'
find "${WORK_DIR}/poison.json" -delete

for _ in {1..8}; do
  obs_e2e_docker_timeout 55 run --rm --label "${RESOURCE_LABEL}" --network "${NETWORK_NAME}" \
    -e NATS_URL="nats://${NATS_CONTAINER}:4222" -e NATS_USER=preprovision \
    -e NATS_PASSWORD="${preprovision_password}" "${NATS_BOX_IMAGE}" \
    nats stream info -j ANALYTICS_ISOLATION_V1 >"${WORK_DIR}/isolation-info.json" 2>/dev/null || true
  isolation_messages=$(jq -r '.state.messages // 0' "${WORK_DIR}/isolation-info.json" 2>/dev/null || printf '0')
  [ "${isolation_messages}" -ge 1 ] && break
  sleep 0.1
done
[ "${isolation_messages:-0}" -ge 1 ] || obs_e2e_fail 'wrong-wire-isolation'

obs_e2e_docker_timeout 55 run --rm --label "${RESOURCE_LABEL}" --network "${NETWORK_NAME}" \
  -e NATS_URL="nats://${NATS_CONTAINER}:4222" -e NATS_USER=runtime \
  -e NATS_PASSWORD="${runtime_password}" "${NATS_BOX_IMAGE}" \
  nats stream get -j ANALYTICS_ISOLATION_V1 1 >"${WORK_DIR}/isolation-record.json" 2>/dev/null || \
  obs_e2e_fail 'read-encrypted-isolation-record'
isolation_record_sha_before="$(shasum -a 256 "${WORK_DIR}/isolation-record.json" | awk '{print $1}')"
if grep -F -- "${sentinel}" "${WORK_DIR}/isolation-record.json" >/dev/null; then
  obs_e2e_fail 'plaintext-in-isolation-wire'
fi

# ClickHouse outage forces NAK/redelivery/backpressure; the actual process must recover without replacement.
obs_e2e_capture_ingest_consumer_info() {
  local output_file=$1
  obs_e2e_docker_timeout 55 run --rm --label "${RESOURCE_LABEL}" --network "${NETWORK_NAME}" \
    -e NATS_URL="nats://${NATS_CONTAINER}:4222" -e NATS_USER=preprovision \
    -e NATS_PASSWORD="${preprovision_password}" "${NATS_BOX_IMAGE}" \
    nats consumer info -j ANALYTICS_INGEST_V1 control_api_analytics_ingest_v1 >"${output_file}" 2>/dev/null
}

obs_e2e_capture_ingest_consumer_info "${WORK_DIR}/outage-consumer-before.json" || \
  obs_e2e_fail 'clickhouse-outage-consumer-baseline'
outage_delivered_before=$(jq -er '.delivered.consumer_seq | select(type == "number")' \
  "${WORK_DIR}/outage-consumer-before.json") || obs_e2e_fail 'clickhouse-outage-delivered-baseline'
outage_ack_consumer_before=$(jq -er '.ack_floor.consumer_seq | select(type == "number")' \
  "${WORK_DIR}/outage-consumer-before.json") || obs_e2e_fail 'clickhouse-outage-ack-consumer-baseline'
outage_ack_stream_before=$(jq -er '.ack_floor.stream_seq | select(type == "number")' \
  "${WORK_DIR}/outage-consumer-before.json") || obs_e2e_fail 'clickhouse-outage-ack-stream-baseline'
outage_pending_before=$(jq -er '.num_ack_pending | select(type == "number")' \
  "${WORK_DIR}/outage-consumer-before.json") || obs_e2e_fail 'clickhouse-outage-pending-baseline'
outage_redelivered_before=$(jq -er '.num_redelivered | select(type == "number")' \
  "${WORK_DIR}/outage-consumer-before.json") || obs_e2e_fail 'clickhouse-outage-redelivered-baseline'
[ "${outage_pending_before}" -eq 0 ] || obs_e2e_fail 'clickhouse-outage-consumer-baseline-pending'
[ "${outage_delivered_before}" -eq "${outage_ack_consumer_before}" ] || \
  obs_e2e_fail 'clickhouse-outage-consumer-baseline-unacked'

obs_e2e_docker_timeout 55 stop "${CLICKHOUSE_CONTAINER}" >/dev/null || obs_e2e_fail 'clickhouse-stop'
message_two="obs-process-${OWNERSHIP_TOKEN}-message-2"
sed "s/${message_one}/${message_two}/g; s/request-1/request-2/g" "${WORK_DIR}/message-one.json" >"${WORK_DIR}/message-two.json"
obs_e2e_docker_timeout 55 run --rm -i --label "${RESOURCE_LABEL}" --network "${NETWORK_NAME}" \
  -e NATS_URL="nats://${NATS_CONTAINER}:4222" -e NATS_USER=publisher -e NATS_PASSWORD="${publisher_password}" \
  "${NATS_BOX_IMAGE}" nats pub -J --force-stdin \
  -H "Nats-Msg-Id:${message_two}" -H "Cdnca-Node-Id:${node_id}" -H "Cdnca-Tenant-Id:${tenant_id}" \
  -H "Cdnca-Site-Id:${site_id}" -H "Cdnca-Config-Version-Id:${config_id}" \
  -H "Cdnca-Installation-Id:${installation_id}" "${subject}" \
  <"${WORK_DIR}/message-two.json" >"${WORK_DIR}/publish-during-clickhouse-outage.log" 2>&1 || \
  obs_e2e_fail 'publish-during-clickhouse-outage'
outage_consumer_fetch_observed=0
outage_consumer_redelivery_observed=0
for _ in {1..30}; do
  if obs_e2e_capture_ingest_consumer_info "${WORK_DIR}/outage-consumer-during.json"; then
    outage_consumer_tsv=$(jq -er '
      [.delivered.consumer_seq, .ack_floor.consumer_seq, .ack_floor.stream_seq,
       .num_ack_pending, .num_redelivered]
      | select(all(.[]; type == "number")) | @tsv
    ' "${WORK_DIR}/outage-consumer-during.json" 2>/dev/null || true)
    if [ -n "${outage_consumer_tsv}" ]; then
      IFS=$'\t' read -r outage_delivered_during outage_ack_consumer_during outage_ack_stream_during \
        outage_pending_during outage_redelivered_during <<<"${outage_consumer_tsv}"
      if [ "${outage_delivered_during}" -gt "${outage_delivered_before}" ] && \
        [ "${outage_delivered_during}" -gt "${outage_ack_consumer_during}" ] && \
        [ "${outage_pending_during}" -ge 1 ] && \
        [ "${outage_ack_stream_during}" -eq "${outage_ack_stream_before}" ]; then
        outage_consumer_fetch_observed=1
      fi
      if [ "${outage_delivered_during}" -ge "$((outage_delivered_before + 2))" ] && \
        [ "${outage_redelivered_during}" -gt "${outage_redelivered_before}" ] && \
        [ "${outage_ack_stream_during}" -eq "${outage_ack_stream_before}" ]; then
        outage_consumer_redelivery_observed=1
      fi
    fi
  fi
  if [ "${outage_consumer_fetch_observed}" -eq 1 ] && \
    [ "${outage_consumer_redelivery_observed}" -eq 1 ]; then
    break
  fi
  sleep 0.1
done
[ "${outage_consumer_fetch_observed}" -eq 1 ] || obs_e2e_fail 'clickhouse-outage-consumer-fetch'
[ "${outage_consumer_redelivery_observed}" -eq 1 ] || obs_e2e_fail 'clickhouse-outage-consumer-redelivery'

obs_e2e_docker_timeout 55 start "${CLICKHOUSE_CONTAINER}" >/dev/null || obs_e2e_fail 'clickhouse-restart'
obs_e2e_wait_container "${CLICKHOUSE_CONTAINER}" clickhouse-client --user analytics \
  --password "${clickhouse_password}" --query 'SELECT 1' || obs_e2e_fail 'clickhouse-restart-readiness'
outage_physical_rows_after=''
for _ in {1..60}; do
  outage_physical_rows_after=$(curl --silent --show-error --fail --netrc-file "${WORK_DIR}/clickhouse.netrc" \
    --data-binary "SELECT count() FROM access_events WHERE event_id='event-${message_two}' FORMAT TabSeparatedRaw" \
    "${CLICKHOUSE_URL}?database=cdnca_analytics" 2>/dev/null || true)
  [ "${outage_physical_rows_after}" = 1 ] && break
  sleep 0.1
done
[ "${outage_physical_rows_after:-0}" = 1 ] || obs_e2e_fail 'clickhouse-outage-redelivery-recovery'

outage_ack_floor_after=''
for _ in {1..30}; do
  if obs_e2e_capture_ingest_consumer_info "${WORK_DIR}/outage-consumer-after.json"; then
    outage_consumer_tsv=$(jq -er '
      [.ack_floor.stream_seq, .num_ack_pending]
      | select(all(.[]; type == "number")) | @tsv
    ' "${WORK_DIR}/outage-consumer-after.json" 2>/dev/null || true)
    if [ -n "${outage_consumer_tsv}" ]; then
      IFS=$'\t' read -r outage_ack_floor_current outage_pending_after <<<"${outage_consumer_tsv}"
      if [ "${outage_ack_floor_current}" -gt "${outage_ack_stream_before}" ] && \
        [ "${outage_pending_after}" -eq 0 ]; then
        outage_ack_floor_after="${outage_ack_floor_current}"
        break
      fi
    fi
  fi
  sleep 0.1
done
[ -n "${outage_ack_floor_after}" ] || obs_e2e_fail 'clickhouse-outage-consumer-ack-recovery'
outage_physical_rows_after=$(curl --silent --show-error --fail --netrc-file "${WORK_DIR}/clickhouse.netrc" \
  --data-binary "SELECT count() FROM access_events WHERE event_id='event-${message_two}' FORMAT TabSeparatedRaw" \
  "${CLICKHOUSE_URL}?database=cdnca_analytics") || obs_e2e_fail 'clickhouse-outage-final-physical-row-query'
[ "${outage_physical_rows_after}" = 1 ] || obs_e2e_fail 'clickhouse-outage-physical-row-growth'

# NATS restart must retain stream, durable consumer, and encrypted isolation record.
obs_e2e_docker_timeout 55 restart "${NATS_CONTAINER}" >/dev/null || obs_e2e_fail 'nats-restart'
for _ in {1..8}; do
  obs_e2e_docker_timeout 55 run --rm --label "${RESOURCE_LABEL}" --network "${NETWORK_NAME}" \
    -e NATS_URL="nats://${NATS_CONTAINER}:4222" -e NATS_USER=preprovision \
    -e NATS_PASSWORD="${preprovision_password}" "${NATS_BOX_IMAGE}" \
    nats stream info -j ANALYTICS_ISOLATION_V1 >"${WORK_DIR}/isolation-info-after-restart.json" 2>/dev/null && break
  sleep 0.1
done
obs_e2e_docker_timeout 55 run --rm --label "${RESOURCE_LABEL}" --network "${NETWORK_NAME}" \
  -e NATS_URL="nats://${NATS_CONTAINER}:4222" -e NATS_USER=runtime \
  -e NATS_PASSWORD="${runtime_password}" "${NATS_BOX_IMAGE}" \
  nats stream get -j ANALYTICS_ISOLATION_V1 1 >"${WORK_DIR}/isolation-record-after-restart.json" 2>/dev/null || \
  obs_e2e_fail 'isolation-record-after-nats-restart'
isolation_record_sha_after="$(shasum -a 256 "${WORK_DIR}/isolation-record-after-restart.json" | awk '{print $1}')"
[ "${isolation_record_sha_before}" = "${isolation_record_sha_after}" ] || obs_e2e_fail 'isolation-record-identity-after-restart'

# Prove the live control process reconnected to the restarted NATS dependency.
message_nats="obs-process-${OWNERSHIP_TOKEN}-message-nats-restart"
sed "s/${message_one}/${message_nats}/g; s/request-1/request-nats-restart/g" \
  "${WORK_DIR}/message-one.json" >"${WORK_DIR}/message-nats-restart.json"
obs_e2e_docker_timeout 55 run --rm -i --label "${RESOURCE_LABEL}" --network "${NETWORK_NAME}" \
  -e NATS_URL="nats://${NATS_CONTAINER}:4222" -e NATS_USER=publisher -e NATS_PASSWORD="${publisher_password}" \
  "${NATS_BOX_IMAGE}" nats pub -J --force-stdin \
  -H "Nats-Msg-Id:${message_nats}" -H "Cdnca-Node-Id:${node_id}" -H "Cdnca-Tenant-Id:${tenant_id}" \
  -H "Cdnca-Site-Id:${site_id}" -H "Cdnca-Config-Version-Id:${config_id}" \
  -H "Cdnca-Installation-Id:${installation_id}" "${subject}" \
  <"${WORK_DIR}/message-nats-restart.json" >"${WORK_DIR}/publish-after-nats-restart.log" 2>&1 || \
  obs_e2e_fail 'publish-after-nats-restart'
for _ in {1..60}; do
  nats_restart_count=$(curl --silent --show-error --fail --netrc-file "${WORK_DIR}/clickhouse.netrc" \
    --data-binary "SELECT count() FROM access_events FINAL WHERE event_id='event-${message_nats}' FORMAT TabSeparatedRaw" \
    "${CLICKHOUSE_URL}?database=cdnca_analytics" 2>/dev/null || true)
  [ "${nats_restart_count}" = 1 ] && break
  sleep 0.1
done
[ "${nats_restart_count:-0}" = 1 ] || obs_e2e_fail 'live-nats-reconnect-query'

# Restart the actual control-api binary and require the same durable identity to continue.
kill -TERM "${control_pid}" || obs_e2e_fail 'control-api-graceful-stop-signal'
for _ in {1..100}; do
  kill -0 "${control_pid}" 2>/dev/null || break
  sleep 0.1
done
if kill -0 "${control_pid}" 2>/dev/null; then
  obs_e2e_stop_pid "${control_pid}"
  control_pid=''
  obs_e2e_fail 'control-api-graceful-stop-timeout'
fi
if ! wait "${control_pid}"; then
  control_pid=''
  obs_e2e_fail 'control-api-graceful-stop'
fi
control_pid=''
env -i "PATH=${PATH}" "TMPDIR=${TMPDIR:-/tmp}" "${control_env[@]}" \
  "${WORK_DIR}/bin/control-api" serve >"${WORK_DIR}/control-after-restart.log" 2>&1 &
control_pid=$!
for _ in {1..80}; do
  if ! kill -0 "${control_pid}" 2>/dev/null; then
    obs_e2e_fail 'control-api-exited-after-restart'
  fi
  curl --silent --show-error "http://127.0.0.1:${control_http_port}/health/detail" \
    >"${WORK_DIR}/control-health-after-restart.json" 2>/dev/null || true
  jq -e '.analytics_ingest.enabled == true' "${WORK_DIR}/control-health-after-restart.json" >/dev/null 2>&1 && break
  sleep 0.1
done
jq -e '.analytics_ingest.enabled == true' "${WORK_DIR}/control-health-after-restart.json" >/dev/null || \
  obs_e2e_fail 'control-api-restart-health'

message_three="obs-process-${OWNERSHIP_TOKEN}-message-3"
sed "s/${message_one}/${message_three}/g; s/request-1/request-3/g" "${WORK_DIR}/message-one.json" >"${WORK_DIR}/message-three.json"
obs_e2e_docker_timeout 55 run --rm -i --label "${RESOURCE_LABEL}" --network "${NETWORK_NAME}" \
  -e NATS_URL="nats://${NATS_CONTAINER}:4222" -e NATS_USER=publisher -e NATS_PASSWORD="${publisher_password}" \
  "${NATS_BOX_IMAGE}" nats pub -J --force-stdin \
  -H "Nats-Msg-Id:${message_three}" -H "Cdnca-Node-Id:${node_id}" -H "Cdnca-Tenant-Id:${tenant_id}" \
  -H "Cdnca-Site-Id:${site_id}" -H "Cdnca-Config-Version-Id:${config_id}" \
  -H "Cdnca-Installation-Id:${installation_id}" "${subject}" \
  <"${WORK_DIR}/message-three.json" >"${WORK_DIR}/publish-after-control-restart.log" 2>&1 || \
  obs_e2e_fail 'publish-after-control-restart'
for _ in {1..60}; do
  final_count=$(curl --silent --show-error --fail --netrc-file "${WORK_DIR}/clickhouse.netrc" \
    --data-binary "SELECT count() FROM access_events FINAL WHERE event_id IN ('event-${message_one}','event-${message_two}','event-${message_nats}','event-${message_three}') FORMAT TabSeparatedRaw" \
    "${CLICKHOUSE_URL}?database=cdnca_analytics" 2>/dev/null || true)
  [ "${final_count}" = 4 ] && break
  sleep 0.1
done
[ "${final_count:-0}" = 4 ] || obs_e2e_fail 'final-clickhouse-identity-count'

# Read every current evidence KV value through the runtime identity and scan outputs/logs for plaintext.
obs_e2e_docker_timeout 55 run --rm --label "${RESOURCE_LABEL}" --network "${NETWORK_NAME}" \
  -e NATS_URL="nats://${NATS_CONTAINER}:4222" -e NATS_USER=runtime \
  -e NATS_PASSWORD="${runtime_password}" "${NATS_BOX_IMAGE}" \
  nats kv ls AIEVIDENCE_2dcd3c381ead92f3 --names \
  >"${WORK_DIR}/evidence-keys.log" 2>"${WORK_DIR}/evidence-keys.err" || {
    grep -Eiq 'no keys|no entries|not found' "${WORK_DIR}/evidence-keys.err" || \
      obs_e2e_fail 'list-evidence-kv-keys'
    : >"${WORK_DIR}/evidence-keys.log"
  }
touch "${WORK_DIR}/evidence-values.log"
while IFS= read -r evidence_key; do
  [ -n "${evidence_key}" ] || continue
  obs_e2e_docker_timeout 55 run --rm --label "${RESOURCE_LABEL}" --network "${NETWORK_NAME}" \
    -e NATS_URL="nats://${NATS_CONTAINER}:4222" -e NATS_USER=runtime \
    -e NATS_PASSWORD="${runtime_password}" "${NATS_BOX_IMAGE}" \
    nats kv get AIEVIDENCE_2dcd3c381ead92f3 "${evidence_key}" --raw \
    >>"${WORK_DIR}/evidence-values.log" 2>/dev/null || obs_e2e_fail 'read-evidence-kv-value'
done <"${WORK_DIR}/evidence-keys.log"
curl --silent --show-error --fail --netrc-file "${WORK_DIR}/clickhouse.netrc" \
  --data-binary 'SELECT event_id,request_id,trace_id,host,path,carrier,installation_id FROM access_events FINAL FORMAT JSONEachRow' \
  "${CLICKHOUSE_URL}?database=cdnca_analytics" >"${WORK_DIR}/clickhouse-plaintext-scan.json" || \
  obs_e2e_fail 'clickhouse-plaintext-scan-query'
find "${WORK_DIR}/clickhouse.netrc" "${WORK_DIR}/certs/ca.key" "${WORK_DIR}/certs/server.key" \
  "${WORK_DIR}/certs/gateway.key" "${WORK_DIR}/certs/node-ca.key" -type f -delete
find "${fixture_client_private_key_file}" "${fixture_artifact_private_key_file}" \
  "${WORK_DIR}/edge-enrollment-token" -type f -delete
plaintext_hits=$({ grep -R -a -F --exclude='message-one.json' --exclude='message-two.json' \
  --exclude='message-nats-restart.json' --exclude='message-three.json' \
  -- "${sentinel}" "${WORK_DIR}" 2>/dev/null || true; } | wc -l | tr -d ' ')
[ "${plaintext_hits}" -eq 0 ] || obs_e2e_fail 'plaintext-sentinel-scan'

secret_names=(
  postgres_password
  clickhouse_password
  preprovision_password
  runtime_password
  publisher_password
  access_secret
  isolation_wrapping_key
  api_key_pepper
  dns_credential_key
  impersonation_hmac_key
  mfa_encryption_key
  observability_log_cursor_key
  analytics_realtime_cursor_key
  enrollment_token
)
secret_values=(
  "${postgres_password}"
  "${clickhouse_password}"
  "${preprovision_password}"
  "${runtime_password}"
  "${publisher_password}"
  "${access_secret}"
  "${isolation_wrapping_key}"
  "${api_key_pepper}"
  "${dns_credential_key}"
  "${impersonation_hmac_key}"
  "${mfa_encryption_key}"
  "${observability_log_cursor_key}"
  "${analytics_realtime_cursor_key}"
  "${enrollment_token}"
)
secret_plaintext_hits=0
secret_plaintext_categories=()
for secret_index in "${!secret_names[@]}"; do
  if grep -R -a -F -q -- "${secret_values[$secret_index]}" "${WORK_DIR}" 2>/dev/null; then
    secret_plaintext_categories+=("${secret_names[$secret_index]}")
    secret_plaintext_hits=$((secret_plaintext_hits + 1))
  else
    secret_scan_status=$?
    [ "${secret_scan_status}" -eq 1 ] || obs_e2e_fail 'generated-secret-scan-read'
  fi
done
if grep -R -a -F -q -- 'PRIVATE KEY-----' "${WORK_DIR}" 2>/dev/null; then
  secret_plaintext_categories+=('private_key_material')
  secret_plaintext_hits=$((secret_plaintext_hits + 1))
else
  secret_scan_status=$?
  [ "${secret_scan_status}" -eq 1 ] || obs_e2e_fail 'private-key-material-scan-read'
fi
if [ "${secret_plaintext_hits}" -ne 0 ]; then
  secret_category_summary=$(IFS=,; printf '%s' "${secret_plaintext_categories[*]}")
  printf 'ANALYTICS_PROCESS_E2E_SECRET_SCAN categories=%s\n' "${secret_category_summary}" >&2
  obs_e2e_fail 'generated-secret-plaintext-scan'
fi

nats_version="$(obs_e2e_docker_timeout 20 exec "${NATS_CONTAINER}" nats-server --version | awk '{print $2}')" || \
  obs_e2e_fail 'summary-nats-version'
clickhouse_version="$(obs_e2e_docker_timeout 20 exec "${CLICKHOUSE_CONTAINER}" clickhouse-client --version | awk '{print $4}')" || \
  obs_e2e_fail 'summary-clickhouse-version'
control_health_state="$(jq -r '.analytics_ingest.state' "${WORK_DIR}/control-health-after-restart.json")" || \
  obs_e2e_fail 'summary-control-health'
control_restart_count="$(jq -r '.analytics_ingest.restart_count' "${WORK_DIR}/control-health-after-restart.json")" || \
  obs_e2e_fail 'summary-control-restart-count'
migration_head="$(obs_e2e_docker_timeout 20 exec "${POSTGRES_CONTAINER}" env \
  "PGOPTIONS=-csearch_path=${CONTROL_DATABASE_SCHEMA}" psql -U cdnca -d cdnca -Atqc \
  'SELECT COALESCE(max(version),0) FROM schema_migrations')" || obs_e2e_fail 'summary-migration-head'
preprovision_sha="$(shasum -a 256 "${PREPROVISION_SCRIPT}" | awk '{print $1}')"
server_config_sha="$(shasum -a 256 "${NATS_SERVER_CONFIG}" | awk '{print $1}')"

obs_e2e_summary "task=${DISPLAY_TASK_ID} publisher_to_control=PASS gateway_to_control=PASS edge_fixture_status=acknowledged edge_fixture_transport=eventspool_mtls edge_fixture_event_id=${edge_fixture_event_id} edge_fixture_source_watermark=${edge_fixture_source_watermark} connections_receipt_state=${connections_receipt_state} connections_puback_stream=${connections_puback_stream} connections_puback_sequence=${connections_puback_sequence} control_pid=${control_pid} control_listener=127.0.0.1:${control_http_port} control_health=/health/detail access_rows=${final_count} isolation_rows=${isolation_messages} duplicate_rows=${duplicate_physical_rows_after} migration_head=${migration_head} resource_absent_fail_closed=PASS resource_mismatch_fail_closed=PASS clickhouse_recovery=PASS outage_fetch=${outage_consumer_fetch_observed} outage_redelivery=${outage_consumer_redelivery_observed} outage_ack_floor=${outage_ack_floor_after} outage_rows=${outage_physical_rows_after} nats_restart=PASS control_restart=PASS evidence_persistence=PASS evidence_recovery=UNKNOWN plaintext_hits=${plaintext_hits} secret_plaintext_hits=${secret_plaintext_hits} control_state=${control_health_state} control_restart_count=${control_restart_count} nats=${nats_version} clickhouse=${clickhouse_version} control_binary_sha256=${control_binary_sha} gateway_binary_sha256=${gateway_binary_sha} edge_agent_binary_sha256=${edge_agent_binary_sha} edge_fixture_binary_sha256=${edge_fixture_binary_sha} preprovision_sha256=${preprovision_sha} server_config_sha256=${server_config_sha} sentinel_sha256=${sentinel_sha} bucket_full=UNKNOWN bucket_absent_exact=UNKNOWN"

[ "${cleanup_reported}" -eq 0 ] || obs_e2e_fail 'cleanup-called-early'
