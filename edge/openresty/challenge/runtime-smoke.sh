#!/bin/sh
set -eu

repo_root="$(CDPATH='' cd -- "$(dirname -- "$0")/../../.." && pwd)"
# shellcheck source=edge/openresty/runtime.env
# shellcheck disable=SC1091
. "${repo_root}/edge/openresty/runtime.env"

engine_sha256="81da1037bb0cf85e17949b271026e08733b80fdb4f00f6bab1ea471865bcd7ee"
crypto_sha256="f3198f31e12cb5700d78a80ca4f038e97db949e847f3e8d27e228b4263dc0367"
ip_sha256="02372567c92ceea47959291959b2381e13836a2011a4819c52805f8f57324631"
runtime_root="/usr/local/share/cdnca/challenge"
tmp_base="${TMPDIR:-/tmp}"
workdir="$(mktemp -d "${tmp_base%/}/cdnca-challenge-runtime.XXXXXX")"
chmod 0700 "${workdir}"
suffix="$(basename "${workdir}" | sed 's/^cdnca-challenge-runtime\.//')"
task_marker="cdnca-challenge-runtime-${suffix}"
image="cdnca/openresty-runtime:challenge-${suffix}"
baseline_container="${task_marker}-baseline"
tampered_engine_container="${task_marker}-tampered-engine"
tampered_crypto_container="${task_marker}-tampered-crypto"
tampered_ip_container="${task_marker}-tampered-ip"
rollback_container="${task_marker}-rollback"
owned_containers="${baseline_container} ${tampered_engine_container} ${tampered_crypto_container} ${tampered_ip_container} ${rollback_container}"

cleanup() {
  cleanup_status=0
  for owned_container in ${owned_containers}; do
    docker rm -f "${owned_container}" >/dev/null 2>&1 || true
  done
  docker image rm "${image}" >/dev/null 2>&1 || true

  for owned_container in ${owned_containers}; do
    remaining="$(docker ps -aq --filter "name=^/${owned_container}$" 2>/dev/null)" || {
      echo "cleanup: could not inspect task container ${owned_container}" >&2
      cleanup_status=1
      continue
    }
    if [ -n "${remaining}" ]; then
      echo "cleanup: task container remains: ${owned_container}" >&2
      cleanup_status=1
    fi
  done
  if docker image inspect "${image}" >/dev/null 2>&1; then
    echo "cleanup: task image remains: ${image}" >&2
    cleanup_status=1
  fi

  case "${workdir}" in
    "${tmp_base%/}"/cdnca-challenge-runtime.*)
      chmod -R u+w "${workdir}" 2>/dev/null || true
      rm -rf -- "${workdir}" || cleanup_status=1
      ;;
    *)
      echo "cleanup: refusing unexpected workdir ${workdir}" >&2
      cleanup_status=1
      ;;
  esac
  if [ -e "${workdir}" ]; then
    echo "cleanup: task workdir remains: ${workdir}" >&2
    cleanup_status=1
  fi

  if process_table="$(ps -axo ppid=,command= 2>/dev/null)"; then
    if printf '%s\n' "${process_table}" | awk -v marker="${task_marker}" '
      ($1 + 0) == 1 && index($0, marker) > 0 { found = 1 }
      END { exit(found ? 0 : 1) }
    '; then
      echo "cleanup: PPID=1 process retains task marker: ${task_marker}" >&2
      cleanup_status=1
    fi
  else
    echo "cleanup: could not verify PPID=1 task processes" >&2
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

prepare_state() {
  state_root="$1"
  release="${state_root}/releases/smoke-v1"
  mkdir -p "${release}" "${state_root}/shared"
  cat >"${release}/nginx.conf" <<EOF
worker_processes 1;
pid /var/lib/cdnca-edge/shared/nginx.pid;
error_log stderr notice;
events { worker_connections 64; }
http {
  access_log off;
  server {
    listen 18080;
    location = /ready { return 200 "ready\n"; }
  }
}
EOF
  ln -s releases/smoke-v1 "${state_root}/current"
}

start_candidate() {
  candidate_name="$1"
  state_root="$2"
  shift 2
  docker run --detach --name "${candidate_name}" --label "com.cdnca.test.marker=${task_marker}" \
    --network none --read-only --security-opt no-new-privileges \
    --pids-limit 128 --memory 256m --cpus 1 \
    --tmpfs /tmp:rw,noexec,nosuid,size=16m \
    --tmpfs /var/run:rw,noexec,nosuid,size=1m \
    --volume "${state_root}:/var/lib/cdnca-edge" \
    "$@" "${image}" >/dev/null
}

assert_no_published_listener() {
  candidate_name="$1"
  published="$(docker port "${candidate_name}" 2>/dev/null || true)"
  test -z "${published}" || {
    echo "${candidate_name}: unexpected published listener: ${published}" >&2
    return 1
  }
}

wait_ready() {
  candidate_name="$1"
  attempt=0
  while [ "${attempt}" -lt 100 ]; do
    running="$(docker inspect --format '{{.State.Running}}' "${candidate_name}" 2>/dev/null || true)"
    if [ "${running}" != true ]; then
      docker logs "${candidate_name}" >&2 || true
      echo "${candidate_name}: exited before readiness" >&2
      return 1
    fi
    if docker exec "${candidate_name}" curl --fail --silent --show-error \
      http://127.0.0.1:18080/ready >/dev/null 2>&1; then
      return 0
    fi
    attempt=$((attempt + 1))
    sleep 0.1
  done
  docker logs "${candidate_name}" >&2 || true
  echo "${candidate_name}: readiness timed out" >&2
  return 1
}

wait_healthy() {
  candidate_name="$1"
  attempt=0
  while [ "${attempt}" -lt 200 ]; do
    health="$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{end}}' \
      "${candidate_name}" 2>/dev/null || true)"
    case "${health}" in
      healthy) return 0 ;;
      unhealthy)
        docker inspect --format '{{json .State.Health}}' "${candidate_name}" >&2 || true
        echo "${candidate_name}: Docker healthcheck became unhealthy" >&2
        return 1
        ;;
    esac
    attempt=$((attempt + 1))
    sleep 0.1
  done
  echo "${candidate_name}: Docker healthcheck timed out" >&2
  return 1
}

assert_runtime_file() {
  candidate_name="$1"
  file_name="$2"
  expected_sha256="$3"
  runtime_path="${runtime_root}/${file_name}.lua"
  if ! docker exec "${candidate_name}" test -f "${runtime_path}"; then
    echo "runtime image missing ${runtime_path}" >&2
    return 1
  fi
  docker exec "${candidate_name}" sh -ceu \
    'printf "%s  %s\n" "$1" "$2" | sha256sum -c - >/dev/null' \
    challenge-runtime "${expected_sha256}" "${runtime_path}"
  mode="$(docker exec "${candidate_name}" stat -c '%a' "${runtime_path}")"
  test "${mode}" = 444 || {
    echo "runtime ${file_name} mode: expected 444, got ${mode}" >&2
    return 1
  }
}

assert_runtime_contract() {
  candidate_name="$1"
  assert_runtime_file "${candidate_name}" engine "${engine_sha256}"
  assert_runtime_file "${candidate_name}" crypto "${crypto_sha256}"
  assert_runtime_file "${candidate_name}" ip "${ip_sha256}"
  docker exec "${candidate_name}" /usr/local/openresty/bin/resty -e \
    "package.path=\"${runtime_root}/?.lua;\"..package.path; local engine=require(\"engine\"); assert(type(engine.init)==\"function\"); assert(type(engine.access)==\"function\")"
  docker exec "${candidate_name}" /usr/local/openresty/bin/resty -e \
    'local f=assert(io.open("/var/run/cdnca/security-runtime.ready","rb")); local v=assert(require("cjson.safe").decode(assert(f:read("*a")))); f:close(); local expected={schema_version=true,waf_sha256=true,cc_sha256=true,adaptive_sha256=true,config_sha256=true,cc_api_version=true}; local count=0; for key in pairs(v) do assert(expected[key],"unexpected ready key: "..tostring(key)); count=count+1 end; assert(count==6,"ready key count changed"); for key in pairs(expected) do assert(v[key]~=nil,"missing ready key: "..key) end; assert(v.challenge_sha256==nil,"challenge field changed ready v1"); assert(v.schema_version=="cdnca.security-runtime-ready/v1")'
}

assert_tampered_rejected() {
  candidate_name="$1"
  state_root="$2"
  runtime_path="$3"
  start_candidate "${candidate_name}" "${state_root}" \
    --volume "${workdir}/tampered.lua:${runtime_path}:ro"
  assert_no_published_listener "${candidate_name}"
  attempt=0
  while [ "${attempt}" -lt 50 ]; do
    running="$(docker inspect --format '{{.State.Running}}' "${candidate_name}")"
    [ "${running}" = false ] && break
    attempt=$((attempt + 1))
    sleep 0.1
  done
  running="$(docker inspect --format '{{.State.Running}}' "${candidate_name}")"
  if [ "${running}" != false ]; then
    echo "${candidate_name}: tampered candidate remained running" >&2
    return 1
  fi
  tampered_exit_code="$(docker inspect --format '{{.State.ExitCode}}' "${candidate_name}")"
  test "${tampered_exit_code}" -ne 0 || {
    echo "${candidate_name}: tampered candidate exited successfully" >&2
    return 1
  }
  printf '%s' "${tampered_exit_code}"
}

trap 'on_exit $?' EXIT
trap 'on_signal 129' HUP
trap 'on_signal 130' INT
trap 'on_signal 143' TERM

prepare_state "${workdir}/baseline-state"
prepare_state "${workdir}/tampered-engine-state"
prepare_state "${workdir}/tampered-crypto-state"
prepare_state "${workdir}/tampered-ip-state"
prepare_state "${workdir}/rollback-state"
printf '%s\n' 'return { tampered = true }' >"${workdir}/tampered.lua"
chmod 0444 "${workdir}/tampered.lua"

if ! CDNCA_EDGE_REVISION="${task_marker}" \
  "${repo_root}/scripts/edge-runtime-build.sh" "${image}" \
  >"${workdir}/build.log" 2>&1; then
  cat "${workdir}/build.log" >&2
  exit 1
fi

start_candidate "${baseline_container}" "${workdir}/baseline-state"
assert_no_published_listener "${baseline_container}"
wait_ready "${baseline_container}"
assert_runtime_contract "${baseline_container}"
wait_healthy "${baseline_container}"

engine_exit_code="$(assert_tampered_rejected "${tampered_engine_container}" \
  "${workdir}/tampered-engine-state" "${runtime_root}/engine.lua")"
wait_ready "${baseline_container}"
wait_healthy "${baseline_container}"

crypto_exit_code="$(assert_tampered_rejected "${tampered_crypto_container}" \
  "${workdir}/tampered-crypto-state" "${runtime_root}/crypto.lua")"
wait_ready "${baseline_container}"
wait_healthy "${baseline_container}"

ip_exit_code="$(assert_tampered_rejected "${tampered_ip_container}" \
  "${workdir}/tampered-ip-state" "${runtime_root}/ip.lua")"
wait_ready "${baseline_container}"
wait_healthy "${baseline_container}"

start_candidate "${rollback_container}" "${workdir}/rollback-state"
assert_no_published_listener "${rollback_container}"
wait_ready "${rollback_container}"
assert_runtime_contract "${rollback_container}"
wait_healthy "${rollback_container}"

printf 'CHALLENGE_RUNTIME_SMOKE={"status":"pass","engine_sha256":"%s","crypto_sha256":"%s","ip_sha256":"%s","mode":"0444","require_init_access":true,"ready_contract_unchanged":true,"tampered_exit_codes":{"engine":%s,"crypto":%s,"ip":%s},"baseline_survived":true,"rollback_healthy":true,"published_listeners":0}\n' \
  "${engine_sha256}" "${crypto_sha256}" "${ip_sha256}" \
  "${engine_exit_code}" "${crypto_exit_code}" "${ip_exit_code}"
