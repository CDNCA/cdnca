#!/bin/sh
set -eu

repo_root="$(CDPATH='' cd -- "$(dirname -- "$0")/../../.." && pwd)"
# shellcheck disable=SC1091
. "${repo_root}/edge/openresty/runtime.env"

tmp_base="${TMPDIR:-/tmp}"
workdir="$(mktemp -d "${tmp_base%/}/cdnca-ccv2.XXXXXX")"
container="cdnca-ccv2-$(basename "${workdir}")"
race_exec_pid=""

cleanup() {
  cleanup_status=0
  if [ -n "${race_exec_pid}" ]; then
    kill "${race_exec_pid}" >/dev/null 2>&1 || true
    wait "${race_exec_pid}" 2>/dev/null || true
    race_exec_pid=""
  fi
  docker rm -f "${container}" >/dev/null 2>&1 || true
  if remaining_container_ids="$(docker ps -aq --filter "name=^/${container}$" 2>/dev/null)"; then
    if [ -n "${remaining_container_ids}" ]; then
      echo "cleanup: task container remains: ${container}" >&2
      cleanup_status=1
    fi
  else
    echo "cleanup: could not verify task container removal: ${container}" >&2
    cleanup_status=1
  fi
  case "${workdir}" in
    "${tmp_base%/}"/cdnca-ccv2.*) rm -rf -- "${workdir}" || true ;;
    *)
      echo "refusing to remove unexpected directory ${workdir}" >&2
      cleanup_status=1
      ;;
  esac
  if [ -e "${workdir}" ]; then
    echo "cleanup: task workdir remains: ${workdir}" >&2
    cleanup_status=1
  fi
  if process_table="$(ps -axo ppid=,command= 2>/dev/null)"; then
    if printf '%s\n' "${process_table}" | awk -v marker="${container}" '
      ($1 + 0) == 1 && index($0, marker) > 0 { found = 1 }
      END { exit(found ? 0 : 1) }
    '; then
      echo "cleanup: PPID=1 process retains task marker: ${container}" >&2
      cleanup_status=1
    fi
  else
    echo "cleanup: could not verify PPID=1 task processes: ${container}" >&2
    cleanup_status=1
  fi
  return "${cleanup_status}"
}

on_exit() {
  original_status="$1"
  trap - EXIT HUP INT TERM
  cleanup_status=0
  cleanup || cleanup_status=$?
  if [ "${original_status}" -ne 0 ]; then
    exit "${original_status}"
  fi
  exit "${cleanup_status}"
}

on_signal() {
  signal_status="$1"
  trap - EXIT HUP INT TERM
  cleanup || true
  exit "${signal_status}"
}

trap 'on_exit $?' EXIT
trap 'on_signal 129' HUP
trap 'on_signal 130' INT
trap 'on_signal 143' TERM

read_request_evidence() {
  request_label="$1"
  status="$(cat "${workdir}/logs/${request_label}.status")"
  worker_pid="$(awk 'tolower($1) == "x-cc-worker-pid:" { gsub(/\r/, "", $2); print $2 }' \
    "${workdir}/logs/${request_label}.headers" | tail -n 1)"
  case "${status}" in
    [0-9][0-9][0-9]) ;;
    *)
      echo "${request_label}: missing or invalid HTTP status evidence: ${status}" >&2
      exit 1
      ;;
  esac
  case "${worker_pid}" in
    ''|*[!0-9]*)
      echo "${request_label}: missing or invalid worker PID header" >&2
      exit 1
      ;;
  esac
}

validate_directed_request() {
  request_label="$1"
  expected_status="$2"
  expected_worker_pid="$3"
  read_request_evidence "${request_label}"
  test "${status}" = "${expected_status}" || {
    echo "${request_label}: expected status ${expected_status}, got ${status}" >&2
    exit 1
  }
  test "${worker_pid}" = "${expected_worker_pid}" || {
    echo "${request_label}: expected worker ${expected_worker_pid}, got ${worker_pid}" >&2
    exit 1
  }
}

run_directed_worker_phase() {
  worker_phase="$1"
  if ! docker exec "${container}" sh -c '
    detector_worker_pid="$1"
    warm_worker_pid="$2"
    worker_phase="$3"
    site_id="$4"
    seed_request_pid=""

    resume_all() {
      if [ -n "${seed_request_pid}" ]; then
        kill "${seed_request_pid}" 2>/dev/null || true
        wait "${seed_request_pid}" 2>/dev/null || true
        seed_request_pid=""
      fi
      kill -CONT "${detector_worker_pid}" 2>/dev/null || true
      kill -CONT "${warm_worker_pid}" 2>/dev/null || true
    }
    stop_worker() {
      target_worker_pid="$1"
      kill -STOP "${target_worker_pid}" || exit 1
      attempt=1
      while [ "${attempt}" -le 100 ]; do
        worker_state=$(awk "/^State:/ {print \$2}" "/proc/${target_worker_pid}/status" 2>/dev/null || true)
        case "${worker_state}" in T*|t*) return 0 ;; esac
        sleep 0.01
        attempt=$((attempt + 1))
      done
      echo "worker ${target_worker_pid}: failed to enter stopped state" >&2
      exit 1
    }
    continue_worker() {
      target_worker_pid="$1"
      kill -CONT "${target_worker_pid}" || exit 1
      attempt=1
      while [ "${attempt}" -le 100 ]; do
        worker_state=$(awk "/^State:/ {print \$2}" "/proc/${target_worker_pid}/status" 2>/dev/null || true)
        case "${worker_state}" in
          "") echo "worker ${target_worker_pid}: disappeared after CONT" >&2; exit 1 ;;
          T*|t*) ;;
          *) return 0 ;;
        esac
        sleep 0.01
        attempt=$((attempt + 1))
      done
      echo "worker ${target_worker_pid}: failed to resume" >&2
      exit 1
    }
    directed_request() {
      request_label="$1"
      request_port="$2"
      request_path="$3"
      expected_status="$4"
      expected_worker_pid="$5"
      curl -sS -D "/runtime/logs/${request_label}.headers" \
        -o "/runtime/logs/${request_label}.response" -w "%{http_code}" \
        "http://127.0.0.1:${request_port}${request_path}" \
        >"/runtime/logs/${request_label}.status" || exit 1
      actual_status=$(cat "/runtime/logs/${request_label}.status")
      actual_worker_pid=$(awk "tolower(\$1) == \"x-cc-worker-pid:\" {gsub(/\\r/, \"\", \$2); print \$2}" \
        "/runtime/logs/${request_label}.headers" | tail -n 1)
      test "${actual_status}" = "${expected_status}" || {
        echo "${request_label}: expected status ${expected_status}, got ${actual_status}" >&2
        exit 1
      }
      test "${actual_worker_pid}" = "${expected_worker_pid}" || {
        echo "${request_label}: expected worker ${expected_worker_pid}, got ${actual_worker_pid}" >&2
        exit 1
      }
    }

    trap resume_all EXIT
    trap "resume_all; exit 1" HUP INT TERM
    case "${worker_phase}" in
      baseline)
        stop_worker "${detector_worker_pid}"
        directed_request worker-baseline-warm 18080 /ready 200 "${warm_worker_pid}"
        continue_worker "${detector_worker_pid}"
        stop_worker "${warm_worker_pid}"
        directed_request worker-baseline-detector 18080 /ready 200 "${detector_worker_pid}"
        ;;
      local-integrity)
        stop_worker "${detector_worker_pid}"
        # The seed must be a full reload: it starts the cooldown the next two
        # requests are measured against. A paused read alone does not prove it,
        # the cooldown integrity check pauses too. Let the interval lapse first.
        sleep 1.1
        curl -fsS "http://127.0.0.1:18082/race-arm?pid=${warm_worker_pid}" >/dev/null
        (
          attempt=1
          while [ "${attempt}" -le 200 ]; do
            curl -sS -D /runtime/logs/local-integrity-seed.headers \
              -o /runtime/logs/local-integrity-seed.response -w "%{http_code}" \
              http://127.0.0.1:18080/ready \
              >/runtime/logs/local-integrity-seed.status || exit 1
            if grep -qi "^X-CC-Paused-Read: 1" /runtime/logs/local-integrity-seed.headers; then
              exit 0
            fi
            attempt=$((attempt + 1))
            sleep 0.01
          done
          echo "local integrity seed: bounded reload was not observed" >&2
          exit 1
        ) &
        seed_request_pid=$!
        observed_pid=""
        attempt=1
        while [ "${attempt}" -le 200 ]; do
          observed_pid=$(curl -fsS http://127.0.0.1:18082/race-read-complete 2>/dev/null || true)
          test "${observed_pid}" = "${warm_worker_pid}" && break
          attempt=$((attempt + 1))
          sleep 0.01
        done
        test "${observed_pid}" = "${warm_worker_pid}" || {
          echo "local integrity seed: controlled policy read was not observed" >&2
          exit 1
        }
        seed_read_observed=$(awk "{print \$1}" /proc/uptime)
        curl -fsS "http://127.0.0.1:18082/race-resume?pid=${warm_worker_pid}" >/dev/null
        if ! wait "${seed_request_pid}"; then
          seed_request_pid=""
          echo "local integrity seed: reload request failed" >&2
          exit 1
        fi
        seed_request_pid=""
        seed_status=$(cat /runtime/logs/local-integrity-seed.status)
        seed_worker_pid=$(awk "tolower(\$1) == \"x-cc-worker-pid:\" {gsub(/\\r/, \"\", \$2); print \$2}" \
          /runtime/logs/local-integrity-seed.headers | tail -n 1)
        test "${seed_status}" = 200 || {
          echo "local integrity seed: expected status 200, got ${seed_status}" >&2
          exit 1
        }
        test "${seed_worker_pid}" = "${warm_worker_pid}" || {
          echo "local integrity seed: expected worker ${warm_worker_pid}, got ${seed_worker_pid}" >&2
          exit 1
        }
        grep -qi "^X-CC-Full-Decode: 1" /runtime/logs/local-integrity-seed.headers || {
          echo "local integrity seed: the seed was not a full policy reload" >&2
          exit 1
        }

        curl -fsS "http://127.0.0.1:18082/race-arm?pid=${warm_worker_pid}" >/dev/null
        curl -fsS "http://127.0.0.1:18082/race-resume?pid=${warm_worker_pid}" >/dev/null
        directed_request local-integrity-cache-hit 18080 /ready 200 "${warm_worker_pid}"
        cache_hit_completed=$(awk "{print \$1}" /proc/uptime)
        setup_elapsed=$(awk -v start="${seed_read_observed}" -v finish="${cache_hit_completed}" \
          "BEGIN { printf \"%.6f\", finish - start }")
        printf "%s\n" "${setup_elapsed}" >/runtime/logs/local-integrity-setup.elapsed
        # Prove the cooldown path by what the worker did, not by wall-clock
        # thresholds that a loaded host breaks: a cache hit re-reads the bytes
        # (paused read) but never decodes them.
        grep -qi "^X-CC-Paused-Read: 1" /runtime/logs/local-integrity-cache-hit.headers || {
          echo "local integrity cache hit: cached integrity read was not observed" >&2
          exit 1
        }
        if grep -qi "^X-CC-Full-Decode: 1" /runtime/logs/local-integrity-cache-hit.headers; then
          echo "local integrity cache hit: policy was fully reloaded (${setup_elapsed}s after the seed read)" >&2
          exit 1
        fi
        cached_rejections=$(grep -c "cached policy integrity rejected" /runtime/logs/error.log || true)
        reload_rejections=$(grep -c "policy reload rejected" /runtime/logs/error.log || true)
        printf "%s\n" "{\"schema_version\":\"CCV2_LOCAL_INTEGRITY_MUST_NOT_LEAK\"}" \
          >"/runtime/security/${site_id}/cc.compiled.json"
        curl -sS -D /runtime/logs/local-integrity-allow.headers \
          -o /runtime/logs/local-integrity-allow.response -w "%{http_code}" \
          http://127.0.0.1:18080/ready \
          >/runtime/logs/local-integrity-allow.status || exit 1
        allow_completed=$(awk "{print \$1}" /proc/uptime)
        cooldown_elapsed=$(awk -v start="${seed_read_observed}" -v finish="${allow_completed}" \
          "BEGIN { printf \"%.6f\", finish - start }")
        printf "%s\n" "${cooldown_elapsed}" >/runtime/logs/local-integrity-cooldown.elapsed
        printf "local integrity cooldown elapsed: %ss\n" "${cooldown_elapsed}"
        # The tampered bytes must be caught by the cooldown integrity check
        # itself, not by a full reload after the interval.
        test "$(grep -c "cached policy integrity rejected" /runtime/logs/error.log || true)" -eq $((cached_rejections + 1)) || {
          echo "local integrity allow: cooldown integrity check did not reject the bytes (${cooldown_elapsed}s)" >&2
          exit 1
        }
        test "$(grep -c "policy reload rejected" /runtime/logs/error.log || true)" -eq "${reload_rejections}" || {
          echo "local integrity allow: rejected by a full reload instead of the cooldown check (${cooldown_elapsed}s)" >&2
          exit 1
        }
        if grep -qi "^X-CC-Full-Decode: 1" /runtime/logs/local-integrity-allow.headers; then
          echo "local integrity allow: policy was fully reloaded (${cooldown_elapsed}s)" >&2
          exit 1
        fi
        allow_status=$(cat /runtime/logs/local-integrity-allow.status)
        allow_worker_pid=$(awk "tolower(\$1) == \"x-cc-worker-pid:\" {gsub(/\\r/, \"\", \$2); print \$2}" \
          /runtime/logs/local-integrity-allow.headers | tail -n 1)
        test "${allow_status}" = 200 || {
          echo "local-integrity-allow: expected LKG status 200, got ${allow_status}" >&2
          exit 1
        }
        test "${allow_worker_pid}" = "${warm_worker_pid}" || {
          echo "local-integrity-allow: expected worker ${warm_worker_pid}, got ${allow_worker_pid}" >&2
          exit 1
        }
        directed_request local-integrity-fixed 18080 /fixed 429 "${warm_worker_pid}"
        if grep -F "CCV2_LOCAL_INTEGRITY_MUST_NOT_LEAK" \
          /runtime/logs/error.log /runtime/logs/local-integrity-*.response >/dev/null; then
          echo "local integrity fault: invalid configuration marker leaked" >&2
          exit 1
        fi

        cp "/runtime/security/${site_id}/cc.compiled.good" \
          "/runtime/security/${site_id}/cc.compiled.json"
        recovery_status=""
        attempt=1
        while [ "${attempt}" -le 200 ]; do
          curl -sS -D /runtime/logs/local-integrity-recovery.headers \
            -o /runtime/logs/local-integrity-recovery.response -w "%{http_code}" \
            http://127.0.0.1:18080/ready \
            >/runtime/logs/local-integrity-recovery.status || exit 1
          recovery_status=$(cat /runtime/logs/local-integrity-recovery.status)
          recovery_worker_pid=$(awk "tolower(\$1) == \"x-cc-worker-pid:\" {gsub(/\\r/, \"\", \$2); print \$2}" \
            /runtime/logs/local-integrity-recovery.headers | tail -n 1)
          test "${recovery_worker_pid}" = "${warm_worker_pid}" || {
            echo "local integrity recovery: expected worker ${warm_worker_pid}, got ${recovery_worker_pid}" >&2
            exit 1
          }
          test "${recovery_status}" = 200 || {
            echo "local integrity recovery: expected LKG status 200, got ${recovery_status}" >&2
            exit 1
          }
          if grep -qi "^X-CC-Full-Decode: 1" /runtime/logs/local-integrity-recovery.headers; then
            break
          fi
          attempt=$((attempt + 1))
          sleep 0.01
        done
        test "${recovery_status}" = 200 || {
          echo "local integrity recovery: valid bytes did not restore readiness" >&2
          exit 1
        }
        grep -qi "^X-CC-Paused-Read: 1" /runtime/logs/local-integrity-recovery.headers || {
          echo "local integrity recovery: full policy reload was not observed" >&2
          exit 1
        }
        grep -qi "^X-CC-Full-Decode: 1" /runtime/logs/local-integrity-recovery.headers || {
          echo "local integrity recovery: full policy decode was not observed" >&2
          exit 1
        }
        recovery_state=$(curl -fsS http://127.0.0.1:18082/state)
        test "${recovery_state}" = ok || {
          echo "local integrity recovery: expected shared state ok, got ${recovery_state}" >&2
          exit 1
        }
        ;;
      shared)
        stop_worker "${detector_worker_pid}"
        directed_request sibling-cooldown-warm 18081 /ready 200 "${warm_worker_pid}"
        warm_completed=$(awk "{print \$1}" /proc/uptime)
        printf "%s\n" "{\"schema_version\":\"tampered\"}" \
          >"/runtime/security/${site_id}/cc.compiled.json"
        directed_request shared-entry-detector 18080 /fixed 429 "${warm_worker_pid}"
        directed_request shared-sibling-rejection 18081 /fixed 429 "${warm_worker_pid}"
        allow_started=$(awk "{print \$1}" /proc/uptime)
        elapsed=$(awk -v start="${warm_completed}" -v finish="${allow_started}" "BEGIN { printf \"%.6f\", finish - start }")
        printf "%s\n" "${elapsed}" >/runtime/logs/shared-cooldown.elapsed
        awk -v elapsed="${elapsed}" "BEGIN { exit !(elapsed < 1) }" || {
          echo "shared cooldown interval: expected warm-to-allow under 1s, got ${elapsed}s" >&2
          exit 1
        }
        directed_request shared-sibling-allow 18081 /ready 200 "${warm_worker_pid}"
        continue_worker "${detector_worker_pid}"
        stop_worker "${warm_worker_pid}"
        directed_request shared-state-probe 18082 /state 200 "${detector_worker_pid}"
        probe_state=$(cat /runtime/logs/shared-state-probe.response)
        test "${probe_state}" = failed || {
          echo "shared-state-probe: expected failed, got ${probe_state}" >&2
          exit 1
        }
        probe_reason=$(curl -fsS http://127.0.0.1:18082/reason)
        test "${probe_reason}" = active_policy_unavailable || {
          echo "shared-reason-probe: expected active_policy_unavailable, got ${probe_reason}" >&2
          exit 1
        }
        ;;
      recovery)
        stop_worker "${detector_worker_pid}"
        directed_request shared-recovery-warm 18080 /ready 200 "${warm_worker_pid}"
        continue_worker "${detector_worker_pid}"
        stop_worker "${warm_worker_pid}"
        directed_request shared-recovery-detector 18080 /ready 200 "${detector_worker_pid}"
        ;;
      *) echo "unknown directed worker phase ${worker_phase}" >&2; exit 1 ;;
    esac
  ' sh "${detector_worker_pid}" "${warm_worker_pid}" "${worker_phase}" "${site_id}"; then
    echo "directed worker phase ${worker_phase} failed" >&2
    exit 1
  fi
}

run_graceful_reload_race() {
  # graceful-race-fixed needs the warmed rejection in a window that cannot
  # roll over during the race.
  prime_fixed_rejection graceful-race-precondition
  # Let every worker's reload interval lapse: the paused read then runs on the
  # locked reload path and siblings contend for the reload lock, instead of
  # depending on how long the preceding phases happened to take.
  sleep 1.1
  docker exec "${container}" kill -STOP "${detector_worker_pid}"
  docker exec "${container}" curl -fsS \
    "http://127.0.0.1:18082/race-arm?pid=${warm_worker_pid}" >/dev/null

  docker exec "${container}" sh -c '
    attempt=1
    while [ "${attempt}" -le 200 ]; do
      curl -sS -D /runtime/logs/graceful-race-old.headers \
        -o /runtime/logs/graceful-race-old.response -w "%{http_code}" \
        http://127.0.0.1:18080/ready \
        >/runtime/logs/graceful-race-old.status || exit 1
      if grep -qi "^X-CC-Paused-Read: 1" /runtime/logs/graceful-race-old.headers; then
        exit 0
      fi
      attempt=$((attempt + 1))
      sleep 0.01
    done
    echo "graceful reload race: old worker never entered the controlled read pause" >&2
    exit 1
  ' &
  race_exec_pid=$!

  if ! docker exec "${container}" sh -c '
    expected_pid="$1"
    attempt=1
    while [ "${attempt}" -le 200 ]; do
      observed_pid=$(curl -fsS http://127.0.0.1:18082/race-read-complete 2>/dev/null || true)
      test "${observed_pid}" = "${expected_pid}" && exit 0
      attempt=$((attempt + 1))
      sleep 0.01
    done
    exit 1
  ' sh "${warm_worker_pid}"; then
    docker exec "${container}" kill -CONT "${detector_worker_pid}" >/dev/null 2>&1 || true
    echo 'graceful reload race: controlled valid read was not observed' >&2
    exit 1
  fi

  docker exec "${container}" kill -STOP "${warm_worker_pid}"
  docker exec "${container}" kill -CONT "${detector_worker_pid}"
  printf '%s\n' '{"schema_version":"CCV2_GRACEFUL_RELOAD_INVALID_MUST_NOT_LEAK"}' \
    >"${workdir}/security/${site_id}/cc.compiled.json"
  docker exec "${container}" kill -HUP "${master_pid_before}"

  if ! docker exec "${container}" sh -c '
    detector_pid="$1"
    attempt=1
    while [ "${attempt}" -le 80 ]; do
      state=$(curl -fsS http://127.0.0.1:18082/state 2>/dev/null || true)
      test "${state}" = failed && break
      attempt=$((attempt + 1))
      sleep 0.01
    done
    test "${state}" = failed || {
      echo "graceful reload race: init did not publish failed" >&2
      exit 1
    }
    started=$(awk "{print \$1}" /proc/uptime)
    directed_request() {
      label="$1"
      port="$2"
      path="$3"
      expected_status="$4"
      curl -sS -D "/runtime/logs/${label}.headers" \
        -o "/runtime/logs/${label}.response" -w "%{http_code}" \
        "http://127.0.0.1:${port}${path}" \
        >"/runtime/logs/${label}.status" || exit 1
      actual_status=$(cat "/runtime/logs/${label}.status")
      actual_pid=$(awk "tolower(\$1) == \"x-cc-worker-pid:\" {gsub(/\\r/, \"\", \$2); print \$2}" \
        "/runtime/logs/${label}.headers" | tail -n 1)
      test "${actual_status}" = "${expected_status}" || {
        echo "${label}: expected status ${expected_status}, got ${actual_status}" >&2
        exit 1
      }
      test "${actual_pid}" = "${detector_pid}" || {
        echo "${label}: expected worker ${detector_pid}, got ${actual_pid}" >&2
        exit 1
      }
    }
    directed_request graceful-race-fixed 18080 /fixed 429
    directed_request graceful-race-sibling 18081 /ready 200
    directed_request graceful-race-state 18082 /state 200
    test "$(cat /runtime/logs/graceful-race-state.response)" = failed || {
      echo "graceful-race-state: expected exact failed" >&2
      exit 1
    }
    finished=$(awk "{print \$1}" /proc/uptime)
    elapsed=$(awk -v start="${started}" -v finish="${finished}" "BEGIN { printf \"%.6f\", finish - start }")
    printf "%s\n" "${elapsed}" >/runtime/logs/graceful-race.elapsed
    awk -v elapsed="${elapsed}" "BEGIN { exit !(elapsed < 1) }" || {
      echo "graceful reload race: failed-state observations exceeded 1s: ${elapsed}s" >&2
      exit 1
    }
  ' sh "${detector_worker_pid}"; then
    docker exec "${container}" kill -CONT "${warm_worker_pid}" >/dev/null 2>&1 || true
    echo 'graceful reload race: failed-state observation phase failed' >&2
    exit 1
  fi

  race_master_pid="$(docker exec "${container}" cat /runtime/nginx.pid)"
  race_worker_pids="$(docker exec "${container}" sh -c 'master_pid=$(cat /runtime/nginx.pid); cat "/proc/${master_pid}/task/${master_pid}/children"' | xargs)"
  test "${race_master_pid}" = "${master_pid_before}" || {
    echo "graceful reload race: master PID changed to ${race_master_pid}" >&2
    exit 1
  }
  test "${race_worker_pids}" = "${worker_pids_before}" || {
    echo "graceful reload race: worker PIDs changed to ${race_worker_pids}" >&2
    exit 1
  }

  docker exec "${container}" curl -fsS \
    "http://127.0.0.1:18082/race-resume?pid=${warm_worker_pid}" >/dev/null
  docker exec "${container}" kill -CONT "${warm_worker_pid}"
  race_wait_attempt=1
  while kill -0 "${race_exec_pid}" 2>/dev/null && [ "${race_wait_attempt}" -le 200 ]; do
    race_wait_attempt=$((race_wait_attempt + 1))
    sleep 0.01
  done
  if kill -0 "${race_exec_pid}" 2>/dev/null; then
    echo 'graceful reload race: old request did not resume within the bounded poll' >&2
    exit 1
  fi
  if ! wait "${race_exec_pid}"; then
    race_exec_pid=""
    echo 'graceful reload race: old request process failed' >&2
    exit 1
  fi
  race_exec_pid=""

  docker exec "${container}" kill -STOP "${warm_worker_pid}"
  docker exec "${container}" curl -sS -D /runtime/logs/graceful-race-after-old.headers \
    -o /runtime/logs/graceful-race-after-old.response -w '%{http_code}' \
    http://127.0.0.1:18082/state \
    >"${workdir}/logs/graceful-race-after-old.status"
  validate_directed_request graceful-race-after-old 200 "${detector_worker_pid}"
  test "$(cat "${workdir}/logs/graceful-race-after-old.response")" = failed || {
    observed_state="$(cat "${workdir}/logs/graceful-race-after-old.response")"
    echo "graceful reload race: old request overwrote failed with ${observed_state}" >&2
    exit 1
  }
  validate_directed_request graceful-race-old 200 "${warm_worker_pid}"
  if grep -F 'CCV2_GRACEFUL_RELOAD_INVALID_MUST_NOT_LEAK' \
    "${workdir}/logs/error.log" "${workdir}"/logs/graceful-race-*.response >/dev/null; then
    echo 'graceful reload race: invalid configuration marker leaked' >&2
    exit 1
  fi

  cp "${workdir}/security/${site_id}/cc.compiled.good" \
    "${workdir}/security/${site_id}/cc.compiled.json"
  docker exec "${container}" kill -CONT "${warm_worker_pid}"
  if ! docker exec "${container}" sh -c '
    attempt=1
    while [ "${attempt}" -le 200 ]; do
      status=$(curl -sS -o /dev/null -w "%{http_code}" http://127.0.0.1:18081/ready) || exit 1
      test "${status}" = 200 || {
        echo "graceful reload recovery: expected LKG status 200, got ${status}" >&2
        exit 1
      }
      state=$(curl -fsS http://127.0.0.1:18082/state) || exit 1
      test "${state}" = ok && exit 0
      test "${state}" = failed || {
        echo "graceful reload recovery: unexpected shared state ${state}" >&2
        exit 1
      }
      attempt=$((attempt + 1))
      sleep 0.01
    done
    exit 1
  '; then
    echo 'graceful reload recovery: valid bytes did not restore readiness' >&2
    exit 1
  fi
  recovery_state="$(docker exec "${container}" curl -fsS http://127.0.0.1:18082/state)"
  test "${recovery_state}" = ok || {
    echo "graceful reload recovery: expected shared state ok, got ${recovery_state}" >&2
    exit 1
  }
  status="$(docker exec "${container}" curl -sS -o /dev/null -w '%{http_code}' http://127.0.0.1:18080/fixed)"
  test "${status}" = 429 || {
    echo "graceful reload recovery: expected fixed status 429, got ${status}" >&2
    exit 1
  }
}

begin_fixed_window_group() {
  window_group="$1"
  window_remainder=$(($(date +%s) % 60))
  if [ "${window_remainder}" -gt 45 ]; then
    sleep $((61 - window_remainder))
  fi
  window_remainder=$(($(date +%s) % 60))
  test "${window_remainder}" -le 45 || {
    echo "${window_group}: could not establish a stable fixed-window interval" >&2
    exit 1
  }
}

run_sec11_matcher_evidence() {
  begin_fixed_window_group sec11-matchers
  if ! docker exec "${container}" sh -c '
    request() {
      label="$1"
      expected_status="$2"
      shift 2
      actual_status=$(curl -sS -D "/runtime/logs/${label}.headers" \
        -o "/runtime/logs/${label}.response" -w "%{http_code}" "$@") || exit 1
      printf "%s\n" "${actual_status}" >"/runtime/logs/${label}.status"
      test "${actual_status}" = "${expected_status}" || {
        echo "${label}: expected status ${expected_status}, got ${actual_status}" >&2
        exit 1
      }
    }
    expect_reason() {
      label="$1"
      expected_reason="$2"
      actual_reason=$(awk "tolower(\$1) == \"x-cc-reason:\" {gsub(/\\r/, \"\", \$2); print \$2}" \
        "/runtime/logs/${label}.headers" | tail -n 1)
      test "${actual_reason}" = "${expected_reason}" || {
        echo "${label}: expected X-CC-Reason ${expected_reason}, got ${actual_reason}" >&2
        exit 1
      }
    }
    expect_count() {
      kind="$1"
      expected_count="$2"
      actual_count=$(curl -fsS "http://127.0.0.1:18082/matcher-count?kind=${kind}") || exit 1
      test "${actual_count}" = "${expected_count}" || {
        echo "${kind}: expected matcher count ${expected_count}, got ${actual_count}" >&2
        exit 1
      }
    }

    expect_count ua 0
    request ua-missing 503 -H "User-Agent:" http://127.0.0.1:18080/ua
    expect_reason ua-missing invalid_user_agent
    request ua-multi-value 503 -H "User-Agent: multi-a" -H "User-Agent: multi-b" \
      http://127.0.0.1:18080/ua
    expect_reason ua-multi-value invalid_user_agent
    request ua-forged-case-duplicate 503 -H "User-Agent: forged-a" -H "uSeR-aGeNt: forged-b" \
      http://127.0.0.1:18080/ua
    expect_reason ua-forged-case-duplicate invalid_user_agent
    expect_count ua 0

    request ua-a 200 -H "uSeR-aGeNt: ua-a" http://127.0.0.1:18080/ua
    expect_count ua 1
    request ua-a-repeat 200 -H "User-Agent: ua-a" http://127.0.0.1:18080/ua
    expect_count ua 1
    request ua-b 200 -H "User-Agent: ua-b" http://127.0.0.1:18080/ua
    expect_count ua 2
    request ua-b-repeat 200 -H "User-Agent: ua-b" http://127.0.0.1:18080/ua
    expect_count ua 2
    request ua-c-threshold 200 -H "User-Agent: ua-c" http://127.0.0.1:18080/ua
    expect_count ua 3
    request ua-c-limited 429 -H "User-Agent: ua-c" http://127.0.0.1:18080/ua
    expect_count ua 3

    expect_count status404 0
    request status404-first 404 http://127.0.0.1:18080/status404
    expect_count status404 1
    request status404-second 404 http://127.0.0.1:18080/status404
    expect_count status404 2
    request status404-threshold-eligible 404 http://127.0.0.1:18080/status404
    expect_count status404 2
    request status404-limited 429 http://127.0.0.1:18080/status404
    expect_count status404 2

    expect_count combo_ua 0
    expect_count combo_404 0
    request combo-wrong-listener 404 -H "Host: localhost:18080" -H "User-Agent: combo-wrong" \
      http://127.0.0.1:18081/combo
    expect_count combo_ua 0
    expect_count combo_404 0
    ordered_rule="018f1000-0000-7000-8000-000000000041"
    logs_before=$(grep -c "cc v2 rate limit observed rule=${ordered_rule}" /runtime/logs/error.log || true)
    request combo-first 404 -H "User-Agent: combo-a" http://127.0.0.1:18080/combo
    expect_count combo_ua 1
    expect_count combo_404 1
    logs_after_first=$(grep -c "cc v2 rate limit observed rule=${ordered_rule}" /runtime/logs/error.log || true)
    test "${logs_after_first}" = "${logs_before}" || {
      echo "combo order: continue rule exceeded before its second request" >&2
      exit 1
    }
    request combo-threshold 404 -H "User-Agent: combo-b" http://127.0.0.1:18080/combo
    expect_count combo_ua 2
    expect_count combo_404 1
    logs_after_threshold=$(grep -c "cc v2 rate limit observed rule=${ordered_rule}" /runtime/logs/error.log || true)
    test "${logs_after_threshold}" -eq $((logs_before + 1)) || {
      echo "combo order: priority-11 continue rule did not run before priority-12 matcher" >&2
      exit 1
    }
    request combo-limited 429 -H "User-Agent: combo-b" http://127.0.0.1:18080/combo
    expect_count combo_ua 2
    expect_count combo_404 1

    curl -fsS http://127.0.0.1:18082/matcher-state-fault >/dev/null || exit 1
    request combo-state-failed 503 -H "User-Agent: combo-c" http://127.0.0.1:18080/combo
    expect_reason combo-state-failed matcher_state_unavailable
  '; then
    echo 'SEC-11 matcher runtime evidence failed' >&2
    exit 1
  fi
}

prime_fixed_rejection() {
  prime_label="$1"
  begin_fixed_window_group "${prime_label}"
  if ! docker exec "${container}" sh -c '
    label="$1"
    request_number=1
    while [ "${request_number}" -le 3 ]; do
      curl -sS -o /dev/null -w "%{http_code}" http://127.0.0.1:18080/fixed \
        >"/runtime/logs/${label}-${request_number}.status" || exit 1
      request_number=$((request_number + 1))
    done
  ' sh "${prime_label}"; then
    echo "${prime_label}: fixed-window precondition requests failed" >&2
    exit 1
  fi
  status="$(cat "${workdir}/logs/${prime_label}-3.status")"
  test "${status}" = 429 || {
    echo "${prime_label}: expected warmed /fixed status 429, got ${status}" >&2
    exit 1
  }
}

restore_active_policy() {
  recovery_label="$1"
  cp "${workdir}/security/${site_id}/cc.compiled.good" \
    "${workdir}/security/${site_id}/cc.compiled.json"
  if ! docker exec "${container}" sh -c '
    recovery_label="$1"
    attempt=1
    while [ "${attempt}" -le 200 ]; do
      curl -sS -D "/runtime/logs/${recovery_label}-recovery.headers" \
        -o "/runtime/logs/${recovery_label}-recovery.response" -w "%{http_code}" \
        http://127.0.0.1:18080/ready \
        >"/runtime/logs/${recovery_label}-recovery.status" || exit 1
      status=$(cat "/runtime/logs/${recovery_label}-recovery.status")
      case "${status}" in
        200)
          if ! grep -qi "^X-CC-Full-Decode: 1" "/runtime/logs/${recovery_label}-recovery.headers"; then
            attempt=$((attempt + 1))
            sleep 0.01
            continue
          fi
          state=$(curl -fsS http://127.0.0.1:18082/state) || exit 1
          test "${state}" = ok || {
            echo "${recovery_label}: expected shared state ok, got ${state}" >&2
            exit 1
          }
          exit 0
          ;;
        *)
          echo "${recovery_label}: expected LKG status 200, got ${status}" >&2
          exit 1
          ;;
      esac
      attempt=$((attempt + 1))
      sleep 0.01
    done
    echo "${recovery_label}: valid bytes did not recover through full policy decode" >&2
    exit 1
  ' sh "${recovery_label}"; then
    exit 1
  fi
}

run_active_file_fault() {
  fault_label="$1"
  fault_kind="$2"
  raw_marker="$3"
  concurrent_check="$4"
  active_policy="${workdir}/security/${site_id}/cc.compiled.json"
  good_policy="${workdir}/security/${site_id}/cc.compiled.good"

  prime_fixed_rejection "${fault_label}-precondition"
  case "${fault_kind}" in
    missing)
      rm -f "${active_policy}"
      ;;
    empty)
      : >"${active_policy}"
      ;;
    oversize)
      printf '%s' "${raw_marker}" >"${active_policy}"
      padding=$((1048577 - ${#raw_marker}))
      dd if=/dev/zero bs="${padding}" count=1 2>/dev/null | LC_ALL=C tr '\000' X >>"${active_policy}"
      actual_size="$(wc -c <"${active_policy}" | tr -d ' ')"
      test "${actual_size}" = 1048577 || {
        echo "${fault_label}: expected MAX_POLICY_BYTES+1, got ${actual_size}" >&2
        exit 1
      }
      ;;
    same-size)
      sed 's/cdnca\.edge\.cc\/v2/cdnca.edge.cc\/v9/' "${good_policy}" >"${active_policy}"
      good_size="$(wc -c <"${good_policy}" | tr -d ' ')"
      fault_size="$(wc -c <"${active_policy}" | tr -d ' ')"
      test "${fault_size}" = "${good_size}" || {
        echo "${fault_label}: tamper changed size from ${good_size} to ${fault_size}" >&2
        exit 1
      }
      good_digest="$(sha256sum "${good_policy}" | awk '{print $1}')"
      fault_digest="$(sha256sum "${active_policy}" | awk '{print $1}')"
      test "${fault_digest}" != "${good_digest}" || {
        echo "${fault_label}: tamper did not change digest" >&2
        exit 1
      }
      ;;
    *)
      echo "${fault_label}: unknown active fault kind ${fault_kind}" >&2
      exit 1
      ;;
  esac

  status="$(docker exec "${container}" curl -sS \
    -o "/runtime/logs/${fault_label}-allow.response" -w '%{http_code}' \
    http://127.0.0.1:18080/ready)"
  test "${status}" = 200 || {
    echo "${fault_label}: expected LKG allow status 200, got ${status}" >&2
    exit 1
  }
  state="$(docker exec "${container}" curl -fsS http://127.0.0.1:18082/state)"
  test "${state}" = failed || {
    echo "${fault_label}: expected shared state failed, got ${state}" >&2
    exit 1
  }
  reason="$(docker exec "${container}" curl -fsS http://127.0.0.1:18082/reason)"
  test "${reason}" = active_policy_unavailable || {
    echo "${fault_label}: expected stable reason active_policy_unavailable, got ${reason}" >&2
    exit 1
  }
  status="$(docker exec "${container}" curl -sS \
    -o "/runtime/logs/${fault_label}-fixed.response" -w '%{http_code}' \
    http://127.0.0.1:18080/fixed)"
  test "${status}" = 429 || {
    echo "${fault_label}: expected warmed fixed status 429, got ${status}" >&2
    exit 1
  }

  if [ "${concurrent_check}" = true ]; then
    if ! docker exec "${container}" sh -c '
      fault_label="$1"
      seq 1 24 | xargs -P 8 -I{} curl -sS \
        -o "/runtime/logs/${fault_label}-concurrent-{}.response" \
        -w "%{http_code}\n" http://127.0.0.1:18080/ready \
        >"/runtime/logs/${fault_label}-concurrent.statuses" || exit 1
      observed=$(wc -l <"/runtime/logs/${fault_label}-concurrent.statuses" | tr -d " ")
      test "${observed}" = 24 || {
        echo "${fault_label}: expected 24 concurrent statuses, got ${observed}" >&2
        exit 1
      }
      if grep -vx 200 "/runtime/logs/${fault_label}-concurrent.statuses" >/dev/null; then
        echo "${fault_label}: concurrent LKG allow status was not 200" >&2
        exit 1
      fi
    ' sh "${fault_label}"; then
      exit 1
    fi
  fi

  if [ -n "${raw_marker}" ] && grep -a -F "${raw_marker}" \
    "${workdir}/logs/error.log" \
    "${workdir}"/logs/"${fault_label}"-*.response >/dev/null; then
    echo "${fault_label}: active policy bytes leaked" >&2
    exit 1
  fi

  restore_active_policy "${fault_label}"
}

run_init_preflight() {
  preflight_name="$1"
  expected_error="$2"
  raw_marker="$3"
  preflight_dir="${workdir}/preflight-${preflight_name}"
  preflight_sha="$(sha256sum "${preflight_dir}/security/${site_id}/cc.compiled.json" | awk '{print $1}')"
  cat >"${preflight_dir}/nginx.conf" <<EOF
worker_processes 1;
error_log logs/error.log notice;
pid nginx.pid;
events { worker_connections 16; }
http {
  lua_package_path '/usr/local/share/cdnca/security/?.lua;;';
  lua_shared_dict cdnca_cc_v2_preflight 1m;
  init_by_lua_block {
    require("cc").init({state_dict="cdnca_cc_v2_preflight", release_root="/runtime/preflight-${preflight_name}", registry_json=[==[{"schema_version":"cdnca.edge.cc-registry/v1","config_version_id":"preflight-${preflight_name}","entries":[{"entry_id":"${entry_18080}","tenant_scope_id":"018f1000-0000-7000-8000-000000000001","site_id":"018f1000-0000-7000-8000-000000000002","hostname":"localhost","listen_port":18080,"protocol":"http","policy_id":"018f1000-0000-7000-8000-000000000020","policy_version":7,"binding_id":"018f1000-0000-7000-8000-000000000030","binding_revision":3,"publication_id":"018f1000-0000-7000-8000-000000000031","source_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","compiled_path":"security/018f1000-0000-7000-8000-000000000002/cc.compiled.json","compiled_sha256":"${preflight_sha}"}]}]==]})
  }
}
EOF
  if ! docker exec "${container}" openresty -t -p "/runtime/preflight-${preflight_name}/" -c nginx.conf \
    >"${workdir}/logs/preflight-${preflight_name}.syntax.output" 2>&1; then
    echo "${preflight_name}: generated preflight configuration failed syntax validation" >&2
    exit 1
  fi
  if docker exec "${container}" sh -c '
    preflight_name="$1"
    rm -f "/runtime/preflight-${preflight_name}/timed-out"
    openresty -g "daemon off; master_process off;" -p "/runtime/preflight-${preflight_name}/" -c nginx.conf &
    server_pid=$!
    attempt=1
    while [ "${attempt}" -le 300 ]; do
      test -r "/proc/${server_pid}/status" || break
      server_state=$(awk "\$1 == \"State:\" { print \$2; exit }" "/proc/${server_pid}/status")
      test "${server_state}" != Z || break
      attempt=$((attempt + 1))
      sleep 0.01
    done
    if [ -r "/proc/${server_pid}/status" ]; then
      server_state=$(awk "\$1 == \"State:\" { print \$2; exit }" "/proc/${server_pid}/status")
      if [ "${server_state}" != Z ] && kill -0 "${server_pid}" 2>/dev/null; then
        : >"/runtime/preflight-${preflight_name}/timed-out"
        kill -TERM "${server_pid}" 2>/dev/null || true
      fi
    fi
    wait "${server_pid}"
    server_status=$?
    exit "${server_status}"
  ' sh "${preflight_name}" >"${workdir}/logs/preflight-${preflight_name}.init.output" 2>&1; then
    echo "${preflight_name}: invalid policy unexpectedly passed real init preflight" >&2
    exit 1
  fi
  if [ -f "${preflight_dir}/timed-out" ]; then
    echo "${preflight_name}: real init preflight remained running and was terminated by its scoped watchdog" >&2
    exit 1
  fi
  if grep -F "${raw_marker}" \
    "${workdir}/logs/preflight-${preflight_name}.syntax.output" \
    "${workdir}/logs/preflight-${preflight_name}.init.output" \
    "${preflight_dir}/logs/error.log" >/dev/null; then
    echo "${preflight_name}: raw policy marker leaked from init preflight" >&2
    exit 1
  fi
  if ! grep -F "${expected_error}" \
    "${workdir}/logs/preflight-${preflight_name}.init.output" \
    "${preflight_dir}/logs/error.log" >/dev/null; then
    echo "${preflight_name}: expected stable error category not found" >&2
    exit 1
  fi
}

site_id="018f1000-0000-7000-8000-000000000002"
tenant_id="018f1000-0000-7000-8000-000000000001"
entry_18080="$(printf '%s\0%s\0%s\0%s\0%s' "${tenant_id}" "${site_id}" localhost 18080 http | sha256sum | awk '{print substr($1,1,32)}')"
entry_18081="$(printf '%s\0%s\0%s\0%s\0%s' "${tenant_id}" "${site_id}" localhost 18081 http | sha256sum | awk '{print substr($1,1,32)}')"
mkdir -p "${workdir}/security/${site_id}" "${workdir}/logs"
cat >"${workdir}/security/${site_id}/cc.compiled.json" <<'EOF'
{
  "schema_version":"cdnca.edge.cc/v2",
  "tenant_scope_id":"018f1000-0000-7000-8000-000000000001",
  "site_id":"018f1000-0000-7000-8000-000000000002",
  "policy_id":"018f1000-0000-7000-8000-000000000020",
  "policy_version":7,
  "binding_id":"018f1000-0000-7000-8000-000000000030",
  "binding_revision":3,
  "publication_id":"018f1000-0000-7000-8000-000000000031",
  "enabled":true,
  "trusted_proxies":[],
  "allowlist":[],
  "rules":[
    {"rule_id":"018f1000-0000-7000-8000-000000000021","priority":1,"flow":"continue","match":{"path":{"kind":"prefix","value":"/fixed"}},"dimension":"client_ip","limit":{"algorithm":"fixed_window","requests":1,"window_seconds":60},"action":{"kind":"log"}},
    {"rule_id":"018f1000-0000-7000-8000-000000000022","priority":2,"flow":"stop","match":{"path":{"kind":"prefix","value":"/fixed"}},"dimension":"client_ip","limit":{"algorithm":"fixed_window","requests":2,"window_seconds":60},"action":{"kind":"reject_429"}},
    {"rule_id":"018f1000-0000-7000-8000-000000000023","priority":3,"flow":"stop","match":{"path":{"kind":"prefix","value":"/leaky"}},"dimension":"client_ip","limit":{"algorithm":"leaky_bucket","rate_per_second":1,"burst":1},"action":{"kind":"reject_429"}},
    {"rule_id":"018f1000-0000-7000-8000-000000000024","priority":4,"flow":"stop","match":{"path":{"kind":"prefix","value":"/peer"},"source_cidr":"203.0.113.1/32"},"dimension":"client_ip","limit":{"algorithm":"fixed_window","requests":1,"window_seconds":60},"action":{"kind":"reject_429"}},
    {"rule_id":"018f1000-0000-7000-8000-000000000025","priority":5,"flow":"stop","match":{"path":{"kind":"prefix","value":"/peer-local"},"source_cidr":"127.0.0.1/32"},"dimension":"client_ip","limit":{"algorithm":"fixed_window","requests":1,"window_seconds":60},"action":{"kind":"reject_429"}},
    {"rule_id":"018f1000-0000-7000-8000-000000000026","priority":6,"flow":"stop","match":{"path":{"kind":"prefix","value":"/ban"},"source_cidr":"127.0.0.1/32"},"dimension":"client_ip","limit":{"algorithm":"fixed_window","requests":1,"window_seconds":60},"action":{"kind":"temporary_ban","ban_seconds":30}},
    {"rule_id":"018f1000-0000-7000-8000-000000000027","priority":7,"flow":"stop","match":{"port":18080,"path":{"kind":"prefix","value":"/port"}},"dimension":"client_ip","limit":{"algorithm":"fixed_window","requests":1,"window_seconds":60},"action":{"kind":"reject_429"}},
    {"rule_id":"018f1000-0000-7000-8000-000000000028","priority":8,"flow":"stop","match":{"path":{"kind":"prefix","value":"/.well-known/acme-challenge"}},"dimension":"client_ip","limit":{"algorithm":"fixed_window","requests":1,"window_seconds":60},"action":{"kind":"reject_429"}},
    {"rule_id":"018f1000-0000-7000-8000-000000000029","priority":9,"flow":"stop","match":{"path":{"kind":"exact","value":"/ua"},"distinct_user_agents":3},"dimension":"client_ip","limit":{"algorithm":"fixed_window","requests":1,"window_seconds":60},"action":{"kind":"reject_429"}},
    {"rule_id":"018f1000-0000-7000-8000-000000000040","priority":10,"flow":"stop","match":{"path":{"kind":"exact","value":"/status404"},"status_404_count":2},"dimension":"client_ip","limit":{"algorithm":"fixed_window","requests":1,"window_seconds":60},"action":{"kind":"reject_429"}},
    {"rule_id":"018f1000-0000-7000-8000-000000000041","priority":11,"flow":"continue","match":{"port":18080,"path":{"kind":"exact","value":"/combo"}},"dimension":"client_ip","limit":{"algorithm":"fixed_window","requests":1,"window_seconds":60},"action":{"kind":"log"}},
    {"rule_id":"018f1000-0000-7000-8000-000000000042","priority":12,"flow":"stop","match":{"port":18080,"path":{"kind":"exact","value":"/combo"},"distinct_user_agents":2,"status_404_count":1},"dimension":"client_ip","limit":{"algorithm":"fixed_window","requests":1,"window_seconds":60},"action":{"kind":"reject_429"}}
  ]
}
EOF
policy_sha="$(sha256sum "${workdir}/security/${site_id}/cc.compiled.json" | awk '{print $1}')"
cat >"${workdir}/nginx.conf" <<EOF
worker_processes 2;
error_log logs/error.log notice;
pid nginx.pid;
events { worker_connections 256; accept_mutex off; }
http {
  lua_package_path '/usr/local/share/cdnca/security/?.lua;;';
  lua_shared_dict cdnca_cc_v2_state 1m;
  log_by_lua_block {
    local cc = require("cc")
    cc.log()
    cc.log()
  }
  header_filter_by_lua_block {
    ngx.header["X-CC-Worker-Pid"] = tostring(ngx.worker.pid())
    if ngx.ctx.ccv2_smoke_paused_read then
      ngx.header["X-CC-Paused-Read"] = "1"
    end
    if ngx.ctx.ccv2_smoke_full_decode then
      ngx.header["X-CC-Full-Decode"] = "1"
    end
  }
  init_by_lua_block {
    local cjson_safe = require("cjson.safe")
    local original_decode = cjson_safe.decode
    cjson_safe.decode = function(raw, ...)
      local value, decode_error = original_decode(raw, ...)
      if ngx.get_phase() ~= "init" then
        ngx.ctx.ccv2_smoke_full_decode = true
      end
      return value, decode_error
    end
    local original_open = io.open
    io.open = function(path, mode)
      local file, open_error = original_open(path, mode)
      if not file or ngx.get_phase() == "init"
        or path ~= "/runtime/security/${site_id}/cc.compiled.json" then
        return file, open_error
      end
      return {
        read = function(_, ...)
          local raw = file:read(...)
          local dict = ngx.shared.cdnca_cc_v2_state
          local worker_pid = ngx.worker.pid()
          if dict:get("ccv2:smoke:pause-worker") == worker_pid then
            dict:set("ccv2:smoke:read-complete", worker_pid)
            local resumed = false
            for _ = 1, 200 do
              if dict:get("ccv2:smoke:resume-worker") == worker_pid then
                resumed = true
                break
              end
              ngx.sleep(0.01)
            end
            if not resumed then error("CC v2 smoke read pause timed out") end
            ngx.ctx.ccv2_smoke_paused_read = true
          end
          return raw
        end,
        close = function() return file:close() end,
      }
    end
    require("cc").init({state_dict="cdnca_cc_v2_state", release_root="/runtime", registry_json=[==[{"schema_version":"cdnca.edge.cc-registry/v1","config_version_id":"cfg-v1","entries":[{"entry_id":"${entry_18080}","tenant_scope_id":"018f1000-0000-7000-8000-000000000001","site_id":"018f1000-0000-7000-8000-000000000002","hostname":"localhost","listen_port":18080,"protocol":"http","policy_id":"018f1000-0000-7000-8000-000000000020","policy_version":7,"binding_id":"018f1000-0000-7000-8000-000000000030","binding_revision":3,"publication_id":"018f1000-0000-7000-8000-000000000031","source_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","compiled_path":"security/018f1000-0000-7000-8000-000000000002/cc.compiled.json","compiled_sha256":"${policy_sha}"},{"entry_id":"${entry_18081}","tenant_scope_id":"018f1000-0000-7000-8000-000000000001","site_id":"018f1000-0000-7000-8000-000000000002","hostname":"localhost","listen_port":18081,"protocol":"http","policy_id":"018f1000-0000-7000-8000-000000000020","policy_version":7,"binding_id":"018f1000-0000-7000-8000-000000000030","binding_revision":3,"publication_id":"018f1000-0000-7000-8000-000000000031","source_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","compiled_path":"security/018f1000-0000-7000-8000-000000000002/cc.compiled.json","compiled_sha256":"${policy_sha}"}]}]==]})
  }
  log_format ccv2_security_smoke escape=json '{"security_type":"\$cdnca_security_type","action":"\$cdnca_security_action","rule_id":"\$cdnca_security_rule_id","status":\$status}';
  server {
    listen 18080;
    set \$cdnca_security_emit 0;
    set \$cdnca_security_type "";
    set \$cdnca_security_action "";
    set \$cdnca_security_severity "";
    set \$cdnca_security_rule_id "";
    access_log /runtime/security.jsonl ccv2_security_smoke if=\$cdnca_security_emit;
    server_rewrite_by_lua_block { return require("cc").access("${entry_18080}") }
    location = /status404 { return 404 'missing\n'; }
    location = /combo { return 404 'combo missing\n'; }
    location / {
      return 200 'ok\n';
    }
  }
  server {
    listen 18081;
    server_rewrite_by_lua_block { return require("cc").access("${entry_18081}") }
    location = /status404 { return 404 'missing\n'; }
    location = /combo { return 404 'combo missing\n'; }
    location / {
      return 200 'ok\n';
    }
  }
  server {
    listen 18082;
    location = /race-arm {
      content_by_lua_block {
        local worker_pid = tonumber(ngx.var.arg_pid)
        if not worker_pid then return ngx.exit(ngx.HTTP_BAD_REQUEST) end
        local dict = ngx.shared.cdnca_cc_v2_state
        dict:delete("ccv2:smoke:read-complete")
        dict:delete("ccv2:smoke:resume-worker")
        local ok = dict:set("ccv2:smoke:pause-worker", worker_pid)
        if not ok then return ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR) end
        ngx.say("armed")
      }
    }
    location = /race-read-complete {
      content_by_lua_block {
        local worker_pid = ngx.shared.cdnca_cc_v2_state:get("ccv2:smoke:read-complete")
        if not worker_pid then return ngx.exit(ngx.HTTP_NOT_FOUND) end
        ngx.say(worker_pid)
      }
    }
    location = /race-resume {
      content_by_lua_block {
        local worker_pid = tonumber(ngx.var.arg_pid)
        if not worker_pid then return ngx.exit(ngx.HTTP_BAD_REQUEST) end
        local ok = ngx.shared.cdnca_cc_v2_state:set("ccv2:smoke:resume-worker", worker_pid)
        if not ok then return ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR) end
        ngx.say("resumed")
      }
    }
    location = /state {
      content_by_lua_block {
        local state = ngx.shared.cdnca_cc_v2_state:get("ccv2:policy-state:security/${site_id}/cc.compiled.json:${policy_sha}")
        if state == nil then
          ngx.status = ngx.HTTP_INTERNAL_SERVER_ERROR
          ngx.say("missing")
          return
        end
        ngx.say(state)
      }
    }
    location = /reason {
      content_by_lua_block {
        local reason = ngx.shared.cdnca_cc_v2_state:get("ccv2:policy-failure-reason:security/${site_id}/cc.compiled.json:${policy_sha}")
        if reason == nil then
          ngx.status = ngx.HTTP_NOT_FOUND
          ngx.say("missing")
          return
        end
        ngx.say(reason)
      }
    }
    location = /limit-state-fault {
      content_by_lua_block {
        local key = "bucket:018f1000-0000-7000-8000-000000000030:3:018f1000-0000-7000-8000-000000000023:127.0.0.1"
        local ok = ngx.shared.cdnca_cc_v2_state:set(key, "invalid")
        if not ok then return ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR) end
        ngx.say("armed")
      }
    }
    location = /limit-state-reset {
      content_by_lua_block {
        local key = "bucket:018f1000-0000-7000-8000-000000000030:3:018f1000-0000-7000-8000-000000000023:127.0.0.1"
        ngx.shared.cdnca_cc_v2_state:delete(key)
        ngx.say("reset")
      }
    }
    location = /matcher-count {
      content_by_lua_block {
        local rules = {
          ua = { id = "018f1000-0000-7000-8000-000000000029", kind = "ua-count" },
          status404 = { id = "018f1000-0000-7000-8000-000000000040", kind = "404-count" },
          combo_ua = { id = "018f1000-0000-7000-8000-000000000042", kind = "ua-count" },
          combo_404 = { id = "018f1000-0000-7000-8000-000000000042", kind = "404-count" },
        }
        local selected = rules[ngx.var.arg_kind]
        if not selected then return ngx.exit(ngx.HTTP_BAD_REQUEST) end
        local prefix = table.concat({ "sec11", "018f1000-0000-7000-8000-000000000020", "7",
          "018f1000-0000-7000-8000-000000000030", "3", selected.id, "127.0.0.1" }, ":")
        local bucket = prefix .. ":" .. math.floor(ngx.now() / 60)
        ngx.say(ngx.shared.cdnca_cc_v2_state:get(selected.kind .. ":" .. bucket) or 0)
      }
    }
    location = /matcher-state-fault {
      content_by_lua_block {
        local rule_id = "018f1000-0000-7000-8000-000000000042"
        local prefix = table.concat({ "sec11", "018f1000-0000-7000-8000-000000000020", "7",
          "018f1000-0000-7000-8000-000000000030", "3", rule_id, "127.0.0.1" }, ":")
        local ok = ngx.shared.cdnca_cc_v2_state:set("stat-failed:" .. prefix, true)
        if not ok then return ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR) end
        ngx.say("armed")
      }
    }
  }
}
EOF

docker run -d --name "${container}" --network none \
  --cpus 1 --memory 256m --pids-limit 128 \
  --volume "${repo_root}/edge/openresty/ccv2/engine.lua:/usr/local/share/cdnca/security/cc.lua:ro" \
  --volume "${workdir}:/runtime" --workdir /runtime \
  "${OPENRESTY_IMAGE}" openresty -g 'daemon off;' -p /runtime/ -c nginx.conf >/dev/null

for _ in $(seq 1 100); do
  if docker exec "${container}" curl -fsS http://127.0.0.1:18080/ready >/dev/null 2>&1; then
    break
  fi
  sleep 0.05
done
docker exec "${container}" curl -fsS http://127.0.0.1:18080/ready >/dev/null
cp "${workdir}/security/${site_id}/cc.compiled.json" "${workdir}/security/${site_id}/cc.compiled.good"

for preflight_name in malformed-json invalid-schema identity-mismatch; do
  mkdir -p "${workdir}/preflight-${preflight_name}/security/${site_id}" \
    "${workdir}/preflight-${preflight_name}/logs"
  : >"${workdir}/preflight-${preflight_name}/logs/error.log"
done
printf '%s\n' '{"schema_version":"cdnca.edge.cc/v2","marker":"CCV2_MALFORMED_PREFLIGHT_MUST_NOT_LEAK"' \
  >"${workdir}/preflight-malformed-json/security/${site_id}/cc.compiled.json"
printf '%s\n' '{"schema_version":"CCV2_INVALID_SCHEMA_PREFLIGHT_MUST_NOT_LEAK"}' \
  >"${workdir}/preflight-invalid-schema/security/${site_id}/cc.compiled.json"
sed 's/"tenant_scope_id":"018f1000-0000-7000-8000-000000000001"/"tenant_scope_id":"018f1000-0000-7000-8000-000000000009"/' \
  "${workdir}/security/${site_id}/cc.compiled.good" \
  >"${workdir}/preflight-identity-mismatch/security/${site_id}/cc.compiled.json"
run_init_preflight malformed-json 'load CC v2 policy: decode policy:' 'CCV2_MALFORMED_PREFLIGHT_MUST_NOT_LEAK'
run_init_preflight invalid-schema 'load CC v2 policy: invalid policy envelope' 'CCV2_INVALID_SCHEMA_PREFLIGHT_MUST_NOT_LEAK'
run_init_preflight identity-mismatch 'load CC v2 policy: invalid policy envelope' '018f1000-0000-7000-8000-000000000009'

master_pid_before="$(docker exec "${container}" cat /runtime/nginx.pid)"
worker_pids_before="$(docker exec "${container}" sh -c 'master_pid=$(cat /runtime/nginx.pid); cat "/proc/${master_pid}/task/${master_pid}/children"' | xargs)"
worker_count_before="$(printf '%s\n' "${worker_pids_before}" | awk '{print NF}')"
test "${worker_count_before}" = 2 || {
  echo "worker baseline: expected 2 workers, got ${worker_count_before}: ${worker_pids_before}" >&2
  exit 1
}
detector_worker_pid="$(printf '%s\n' "${worker_pids_before}" | awk '{print $1}')"
warm_worker_pid="$(printf '%s\n' "${worker_pids_before}" | awk '{print $2}')"
run_directed_worker_phase baseline
validate_directed_request worker-baseline-warm 200 "${warm_worker_pid}"
validate_directed_request worker-baseline-detector 200 "${detector_worker_pid}"

prime_fixed_rejection initial-fixed

begin_fixed_window_group port-rule
docker exec "${container}" sh -c '
  status=$(curl -sS -o /dev/null -w "%{http_code}" -H "Host: localhost:18081" http://127.0.0.1:18080/port)
  test "${status}" = 200 || { echo "port-rule first 18080 listener request: expected 200, got ${status}" >&2; exit 1; }
  status=$(curl -sS -o /dev/null -w "%{http_code}" -H "Host: localhost:18081" http://127.0.0.1:18080/port)
  test "${status}" = 429 || { echo "port-rule second 18080 listener request: expected 429, got ${status}" >&2; exit 1; }
  status=$(curl -sS -o /dev/null -w "%{http_code}" -H "Host: localhost:18080" http://127.0.0.1:18081/port)
  test "${status}" = 200 || { echo "port-rule first 18081 listener request: expected 200, got ${status}" >&2; exit 1; }
  status=$(curl -sS -o /dev/null -w "%{http_code}" -H "Host: localhost:18080" http://127.0.0.1:18081/port)
  test "${status}" = 200 || { echo "port-rule second 18081 listener request: expected 200, got ${status}" >&2; exit 1; }
'

run_sec11_matcher_evidence

begin_fixed_window_group acme-rule
docker exec "${container}" sh -c '
  status=$(curl -sS -o /dev/null -w "%{http_code}" http://127.0.0.1:18080/.well-known/acme-challenge/token)
  test "${status}" = 200 || { echo "acme-rule first request: expected 200, got ${status}" >&2; exit 1; }
  status=$(curl -sS -o /dev/null -w "%{http_code}" http://127.0.0.1:18080/.well-known/acme-challenge/token)
  test "${status}" = 429 || { echo "acme-rule second request: expected 429, got ${status}" >&2; exit 1; }
'

docker exec "${container}" sh -c '
  status=$(curl -sS -o /dev/null -w "%{http_code}" http://127.0.0.1:18080/leaky)
  test "${status}" = 200 || { echo "leaky-bucket first request: expected 200, got ${status}" >&2; exit 1; }
  status=$(curl -sS -o /dev/null -w "%{http_code}" http://127.0.0.1:18080/leaky)
  test "${status}" = 429 || { echo "leaky-bucket second request: expected 429, got ${status}" >&2; exit 1; }
'

begin_fixed_window_group peer-rules
docker exec "${container}" sh -c '
  status=$(curl -sS -o /dev/null -w "%{http_code}" -H "X-Forwarded-For: 203.0.113.1" http://127.0.0.1:18080/peer)
  test "${status}" = 200 || { echo "untrusted forwarded peer first request: expected 200, got ${status}" >&2; exit 1; }
  status=$(curl -sS -o /dev/null -w "%{http_code}" -H "X-Forwarded-For: 203.0.113.1" http://127.0.0.1:18080/peer)
  test "${status}" = 200 || { echo "untrusted forwarded peer second request: expected 200, got ${status}" >&2; exit 1; }
  status=$(curl -sS -o /dev/null -w "%{http_code}" http://127.0.0.1:18080/peer-local)
  test "${status}" = 200 || { echo "local peer first request: expected 200, got ${status}" >&2; exit 1; }
  status=$(curl -sS -o /dev/null -w "%{http_code}" http://127.0.0.1:18080/peer-local)
  test "${status}" = 429 || { echo "local peer second request: expected 429, got ${status}" >&2; exit 1; }
'

begin_fixed_window_group temporary-ban
docker exec "${container}" sh -c '
  status=$(curl -sS -o /dev/null -w "%{http_code}" http://127.0.0.1:18080/ban)
  test "${status}" = 200 || { echo "temporary-ban first request: expected 200, got ${status}" >&2; exit 1; }
  status=$(curl -sS -o /dev/null -w "%{http_code}" http://127.0.0.1:18080/ban)
  test "${status}" = 429 || { echo "temporary-ban activation request: expected 429, got ${status}" >&2; exit 1; }
  status=$(curl -sS -o /dev/null -w "%{http_code}" http://127.0.0.1:18080/ban)
  test "${status}" = 429 || { echo "temporary-ban retained request: expected 429, got ${status}" >&2; exit 1; }
'
# FX36/NF34: the ban activation is recorded once in the security log as a
# cc/temporary_ban event; the retained-ban rejections are not.
ban_events=$(grep -c '"security_type":"cc","action":"temporary_ban","rule_id":"018f1000-0000-7000-8000-000000000026","status":429' "${workdir}/security.jsonl" || true)
test "${ban_events}" = 1 || { echo "temporary-ban security events: expected 1, got ${ban_events}" >&2; cat "${workdir}/security.jsonl" >&2 || true; exit 1; }

prime_fixed_rejection cache-hit-precondition
run_directed_worker_phase local-integrity
validate_directed_request local-integrity-cache-hit 200 "${warm_worker_pid}"
validate_directed_request local-integrity-fixed 429 "${warm_worker_pid}"
validate_directed_request local-integrity-allow 200 "${warm_worker_pid}"
validate_directed_request local-integrity-recovery 200 "${warm_worker_pid}"

sleep 1.1
run_directed_worker_phase shared
validate_directed_request sibling-cooldown-warm 200 "${warm_worker_pid}"
validate_directed_request shared-entry-detector 429 "${warm_worker_pid}"
validate_directed_request shared-sibling-rejection 429 "${warm_worker_pid}"
validate_directed_request shared-sibling-allow 200 "${warm_worker_pid}"
validate_directed_request shared-state-probe 200 "${detector_worker_pid}"
printf '%s\n' failed >"${workdir}/logs/shared-state-probe.expected"
if ! cmp -s "${workdir}/logs/shared-state-probe.expected" "${workdir}/logs/shared-state-probe.response"; then
  printf '%s\n' 'shared-state-probe: expected exact body failed\n' >&2
  exit 1
fi
if ! grep -F 'retaining LKG' "${workdir}/logs/error.log" >/dev/null; then
  echo 'shared compiled-path fault: retaining LKG diagnostic not found' >&2
  exit 1
fi
if grep -F '{"schema_version":"tampered"}' "${workdir}/logs/error.log" "${workdir}"/logs/shared-*.response >/dev/null; then
  echo 'active digest-mismatch bytes leaked to response or log' >&2
  exit 1
fi

cp "${workdir}/security/${site_id}/cc.compiled.good" "${workdir}/security/${site_id}/cc.compiled.json"
sleep 1.1
run_directed_worker_phase recovery
validate_directed_request shared-recovery-warm 200 "${warm_worker_pid}"
validate_directed_request shared-recovery-detector 200 "${detector_worker_pid}"
run_graceful_reload_race
status="$(docker exec "${container}" curl -sS -D /runtime/logs/combo-state-after-hup.headers \
  -o /runtime/logs/combo-state-after-hup.response -w '%{http_code}' \
  -H 'User-Agent: combo-after-hup' http://127.0.0.1:18080/combo)"
test "${status}" = 503 || {
  echo "combo matcher state after bad-policy HUP: expected 503, got ${status}" >&2
  exit 1
}
reason="$(awk 'tolower($1) == "x-cc-reason:" {gsub(/\r/, "", $2); print $2}' \
  "${workdir}/logs/combo-state-after-hup.headers" | tail -n 1)"
test "${reason}" = matcher_state_unavailable || {
  echo "combo matcher state after bad-policy HUP: expected matcher_state_unavailable, got ${reason}" >&2
  exit 1
}
run_active_file_fault active-missing missing '' false
run_active_file_fault active-empty empty '' false
run_active_file_fault active-oversize oversize CCV2_OVERSIZE_MUST_NOT_LEAK false
run_active_file_fault active-same-size same-size cdnca.edge.cc/v9 true
prime_fixed_rejection active-digest-precondition

# The active registry still pins the good digest, so these bytes are a digest
# mismatch even though their JSON resembles an invalid schema.
printf '%s\n' '{"schema_version":"tampered"}' >"${workdir}/security/${site_id}/cc.compiled.json"
sleep 1.1
status="$(docker exec "${container}" curl -sS -o /dev/null -w '%{http_code}' http://127.0.0.1:18080/fixed)"
test "${status}" = 429 || {
  echo "cache-hit then active digest mismatch on rejected path: expected 429, got ${status}" >&2
  exit 1
}
status="$(docker exec "${container}" curl -sS -o /runtime/logs/active-digest-mismatch.response -w '%{http_code}' http://127.0.0.1:18080/ready)"
test "${status}" = 200 || {
  echo "active digest mismatch on otherwise allowed path: expected LKG status 200, got ${status}" >&2
  exit 1
}
if ! grep -F 'policy digest mismatch' "${workdir}/logs/error.log" >/dev/null; then
  echo 'active digest mismatch: stable digest diagnostic not found' >&2
  exit 1
fi
if grep -F '{"schema_version":"tampered"}' "${workdir}/logs/error.log" "${workdir}/logs/active-digest-mismatch.response" >/dev/null; then
  echo 'active digest-mismatch bytes leaked to response or log' >&2
  exit 1
fi

cp "${workdir}/security/${site_id}/cc.compiled.good" "${workdir}/security/${site_id}/cc.compiled.json"
sleep 1.1
status="$(docker exec "${container}" curl -sS -o /dev/null -w '%{http_code}' http://127.0.0.1:18080/ready)"
test "${status}" = 200 || {
  echo "unchanged cache hit: expected 200, got ${status}" >&2
  exit 1
}
sleep 1.1
status="$(docker exec "${container}" curl -sS -o /dev/null -w '%{http_code}' http://127.0.0.1:18080/ready)"
test "${status}" = 200 || {
  echo "unchanged cache reload: expected 200, got ${status}" >&2
  exit 1
}

prime_fixed_rejection malformed-looking-digest-precondition
printf '%s\n' '{"schema_version":"cdnca.edge.cc/v2","private_marker":"CCV2_MALFORMED_MUST_NOT_LEAK"' >"${workdir}/security/${site_id}/cc.compiled.json"
sleep 1.1
status="$(docker exec "${container}" curl -sS -o /dev/null -w '%{http_code}' http://127.0.0.1:18080/fixed)"
test "${status}" = 429 || {
  echo "active digest mismatch with malformed-looking bytes on rejected path: expected 429, got ${status}" >&2
  exit 1
}
status="$(docker exec "${container}" curl -sS -o /runtime/logs/malformed-json.response -w '%{http_code}' http://127.0.0.1:18080/ready)"
test "${status}" = 200 || {
  echo "active digest mismatch with malformed-looking bytes on otherwise allowed path: expected LKG status 200, got ${status}" >&2
  exit 1
}
if grep -F 'CCV2_MALFORMED_MUST_NOT_LEAK' "${workdir}/logs/error.log" "${workdir}/logs/malformed-json.response" >/dev/null; then
  echo 'malformed JSON bytes leaked to response or log' >&2
  exit 1
fi

cp "${workdir}/security/${site_id}/cc.compiled.good" "${workdir}/security/${site_id}/cc.compiled.json"
sleep 1.1
status="$(docker exec "${container}" curl -sS -o /dev/null -w '%{http_code}' http://127.0.0.1:18080/ready)"
test "${status}" = 200 || {
  echo "malformed-looking digest mismatch recovery: expected 200, got ${status}" >&2
  exit 1
}

prime_fixed_rejection valid-json-digest-precondition
printf ' ' >>"${workdir}/security/${site_id}/cc.compiled.json"
sleep 1.1
status="$(docker exec "${container}" curl -sS -o /dev/null -w '%{http_code}' http://127.0.0.1:18080/fixed)"
test "${status}" = 429 || {
  echo "digest mismatch on rejected path: expected 429, got ${status}" >&2
  exit 1
}
status="$(docker exec "${container}" curl -sS -o /runtime/logs/digest-mismatch.response -w '%{http_code}' http://127.0.0.1:18080/ready)"
test "${status}" = 200 || {
  echo "digest mismatch on otherwise allowed path: expected LKG status 200, got ${status}" >&2
  exit 1
}
if ! grep -F 'policy digest mismatch' "${workdir}/logs/error.log" >/dev/null; then
  echo 'valid JSON digest mismatch: stable digest diagnostic not found' >&2
  exit 1
fi

mv "${workdir}/security/${site_id}/cc.compiled.good" "${workdir}/security/${site_id}/cc.compiled.json"
sleep 1.1
status="$(docker exec "${container}" curl -sS -o /dev/null -w '%{http_code}' http://127.0.0.1:18080/ready)"
test "${status}" = 200 || {
  echo "digest mismatch recovery: expected 200, got ${status}" >&2
  exit 1
}
docker exec "${container}" curl -fsS http://127.0.0.1:18082/limit-state-fault >/dev/null
status="$(docker exec "${container}" curl -sS -o /dev/null -w '%{http_code}' http://127.0.0.1:18080/leaky)"
test "${status}" = 503 || {
  echo "limit state dependency failure: expected 503, got ${status}" >&2
  exit 1
}
docker exec "${container}" curl -fsS http://127.0.0.1:18082/limit-state-reset >/dev/null
container_running="$(docker inspect -f '{{.State.Running}}' "${container}")"
test "${container_running}" = true || {
  echo "container liveness after faults: expected true, got ${container_running}" >&2
  exit 1
}

master_pid_after="$(docker exec "${container}" cat /runtime/nginx.pid)"
worker_pids_after="$(docker exec "${container}" sh -c 'master_pid=$(cat /runtime/nginx.pid); cat "/proc/${master_pid}/task/${master_pid}/children"' | xargs)"
worker_count_after="$(printf '%s\n' "${worker_pids_after}" | awk '{print NF}')"
test "${master_pid_after}" = "${master_pid_before}" || {
  echo "master PID changed across faults: before ${master_pid_before}, after ${master_pid_after}" >&2
  exit 1
}
test "${worker_count_after}" = "${worker_count_before}" || {
  echo "worker count changed across faults: before ${worker_count_before}, after ${worker_count_after}" >&2
  exit 1
}
test "${worker_pids_after}" = "${worker_pids_before}" || {
  echo "worker PIDs changed across faults: before ${worker_pids_before}, after ${worker_pids_after}" >&2
  exit 1
}

docker exec "${container}" sh -c 'seq 1 16 | xargs -P 16 -I{} curl -sS -o /dev/null http://127.0.0.1:18080/leaky'
if grep -F 'state lock timeout' "${workdir}/logs/error.log" >/dev/null; then
  echo 'concurrent leaky-bucket gate: unexpected state lock timeout; last CC log lines:' >&2
  tail -n 20 "${workdir}/logs/error.log" >&2
  exit 1
fi

cleanup_status=0
cleanup || cleanup_status=$?
trap - EXIT HUP INT TERM
if [ "${cleanup_status}" -ne 0 ]; then
  exit "${cleanup_status}"
fi
echo 'CC v2 OpenResty smoke: PASS'
