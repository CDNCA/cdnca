#!/bin/sh
set -eu

repo_root="$(CDPATH='' cd -- "$(dirname -- "$0")/../../.." && pwd)"
# shellcheck source=edge/openresty/runtime.env
# shellcheck disable=SC1091
. "${repo_root}/edge/openresty/runtime.env"

expected_sha256="d528c1309c2bfa0c9c48348185c1966d8a764a67164099cf6a522955667f7fdc"
runtime_path="/usr/local/share/cdnca/range/guard.lua"
dockerfile="${repo_root}/edge/openresty/Dockerfile"
entrypoint="${repo_root}/edge/openresty/entrypoint.sh"

static_status=0
if ! grep -F 'COPY --chmod=0444 edge/openresty/range/guard.lua /usr/local/share/cdnca/range/guard.lua' "${dockerfile}" >/dev/null; then
  echo "static preflight: Dockerfile does not install the Range runtime as mode 0444" >&2
  static_status=1
fi
healthcheck="$(sed -n '/^HEALTHCHECK /,/^ENTRYPOINT /p' "${dockerfile}")"
if ! printf '%s\n' "${healthcheck}" | grep -F "${expected_sha256}" >/dev/null ||
  ! printf '%s\n' "${healthcheck}" | grep -F "${runtime_path}" >/dev/null; then
  echo "static preflight: Dockerfile HEALTHCHECK does not bind the Range runtime path and digest" >&2
  static_status=1
fi
# shellcheck disable=SC2016
if ! grep -F "range_sha256=\"${expected_sha256}\"" "${entrypoint}" >/dev/null ||
  ! grep -F '"${range_sha256}" /usr/local/share/cdnca/range/guard.lua' "${entrypoint}" >/dev/null; then
  echo "static preflight: entrypoint does not verify the Range runtime digest" >&2
  static_status=1
fi
if ! grep -F 'require("range.guard")' "${entrypoint}" >/dev/null; then
  echo "static preflight: entrypoint does not require the Range runtime" >&2
  static_status=1
fi
if [ "${static_status}" -ne 0 ]; then
  exit "${static_status}"
fi

tmp_base="${TMPDIR:-/tmp}"
workdir="$(mktemp -d "${tmp_base%/}/cdnca-range-runtime.XXXXXX")"
chmod 0700 "${workdir}"
status_chain_harness="${workdir}/range-status-chain.lua"
suffix="$(basename "${workdir}" | sed 's/^cdnca-range-runtime\.//')"
task_marker="cdnca-range-runtime-${suffix}"
image="cdnca/openresty-runtime:range-${suffix}"
baseline_container="${task_marker}-baseline"
tampered_container="${task_marker}-tampered"
rollback_container="${task_marker}-rollback"
owned_containers="${baseline_container} ${tampered_container} ${rollback_container}"

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
    "${tmp_base%/}"/cdnca-range-runtime.*)
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
  chmod 0700 "${state_root}" "${state_root}/releases" "${release}" "${state_root}/shared"
  cat >"${release}/nginx.conf" <<'EOF'
worker_processes 1;
pid /var/lib/cdnca-edge/shared/nginx.pid;
error_log stderr notice;
events { worker_connections 64; }
http {
  access_log off;
  lua_package_path "/usr/local/share/cdnca/?.lua;;";
  server {
    listen 18080;
    location = /ready { return 200 "ready\n"; }
  }
  server {
    listen 127.0.0.1:18082;
    location / { return 204; }
  }
  server {
    listen 18081;
    set $range_cache_guard_no_store 0;
    location / {
      access_by_lua_block { require("range.guard").access({ max_range_bytes = 1024, max_if_range_bytes = 1024, max_ranges = 16, max_range_span_bytes = 67108864 }) }
      header_filter_by_lua_block { require("range.guard").header_filter({ max_header_bytes = 8192 }) }
      body_filter_by_lua_block { require("range.guard").body_filter() }
      proxy_pass http://127.0.0.1:18082;
    }
  }
}
EOF
  chmod 0444 "${release}/nginx.conf"
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

bounded_logs() {
  docker logs "$1" 2>&1 | tail -n 80 >&2 || true
}

wait_ready() {
  candidate_name="$1"
  attempt=0
  while [ "${attempt}" -lt 100 ]; do
    running="$(docker inspect --format '{{.State.Running}}' "${candidate_name}" 2>/dev/null || true)"
    if [ "${running}" != true ]; then
      bounded_logs "${candidate_name}"
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
  bounded_logs "${candidate_name}"
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

assert_image_healthcheck() {
  healthcheck_test="$(docker image inspect "${image}" --format '{{json .Config.Healthcheck.Test}}')"
  case "${healthcheck_test}" in
    *"${expected_sha256}"*"${runtime_path}"*|*"${runtime_path}"*"${expected_sha256}"*) ;;
    *)
      echo "image HEALTHCHECK does not bind ${runtime_path} to ${expected_sha256}" >&2
      return 1
      ;;
  esac
}

assert_runtime_contract() {
  candidate_name="$1"
  docker exec "${candidate_name}" test -f "${runtime_path}" || {
    echo "runtime image missing ${runtime_path}" >&2
    return 1
  }
  docker exec "${candidate_name}" sh -ceu \
    'printf "%s  %s\n" "$1" "$2" | sha256sum -c - >/dev/null' \
    range-runtime "${expected_sha256}" "${runtime_path}"
  mode="$(docker exec "${candidate_name}" stat -c '%a' "${runtime_path}")"
  test "${mode}" = 444 || {
    echo "runtime guard mode: expected 444, got ${mode}" >&2
    return 1
  }
  docker exec "${candidate_name}" /usr/local/openresty/bin/resty -e \
    'package.path="/usr/local/share/cdnca/?.lua;"..package.path; local guard=require("range.guard"); assert(type(guard.access)=="function"); assert(type(guard.header_filter)=="function"); assert(type(guard.body_filter)=="function")'
  docker exec "${candidate_name}" /usr/local/openresty/bin/resty -e '
    local file=assert(io.open("/var/run/cdnca/security-runtime.ready","rb"))
    local ready=assert(require("cjson.safe").decode(assert(file:read("*a"))))
    file:close()
    local expected={schema_version=true,waf_sha256=true,cc_sha256=true,adaptive_sha256=true,config_sha256=true,cc_api_version=true}
    local count=0
    for key in pairs(ready) do assert(expected[key],"unexpected ready key: "..tostring(key)); count=count+1 end
    assert(count==6,"ready key count changed")
    for key in pairs(expected) do assert(ready[key]~=nil,"missing ready key: "..key) end
    assert(ready.range_sha256==nil,"Range field changed ready v1")
    assert(ready.schema_version=="cdnca.security-runtime-ready/v1")
  '
  docker exec "${candidate_name}" grep -F \
    'access_by_lua_block { require("range.guard").access({ max_range_bytes = 1024, max_if_range_bytes = 1024, max_ranges = 16, max_range_span_bytes = 67108864 }) }' \
    /var/lib/cdnca-edge/current/nginx.conf >/dev/null
  docker exec "${candidate_name}" grep -F \
    'header_filter_by_lua_block { require("range.guard").header_filter({ max_header_bytes = 8192 }) }' \
    /var/lib/cdnca-edge/current/nginx.conf >/dev/null
  docker exec "${candidate_name}" grep -F \
    'body_filter_by_lua_block { require("range.guard").body_filter() }' \
    /var/lib/cdnca-edge/current/nginx.conf >/dev/null
}

request_status() {
  candidate_name="$1"
  range_value="$2"
  if ! status="$(docker exec "${candidate_name}" curl --silent --show-error --output /dev/null \
    --write-out '%{http_code}' --header "Range: ${range_value}" \
    http://127.0.0.1:18081/resource)"; then
    echo "${candidate_name}: Range request failed for ${range_value}, status=${status:-<empty>}" >&2
    bounded_logs "${candidate_name}"
    return 1
  fi
  printf '%s' "${status}"
}

assert_range_requests() {
  candidate_name="$1"
  status="$(request_status "${candidate_name}" 'bytes=0-9')"
  test "${status}" = 204 || {
    echo "valid Range did not continue to content handler: status=${status}" >&2
    return 1
  }
  status="$(request_status "${candidate_name}" 'bytes=0-9,20-29')"
  test "${status}" = 204 || {
    echo "valid multi-range did not continue to content handler: status=${status}" >&2
    return 1
  }
  status="$(request_status "${candidate_name}" 'bytes=0-9,5-14')"
  test "${status}" = 416 || {
    echo "overlapping multi-range was not rejected: status=${status}" >&2
    return 1
  }
  status="$(request_status "${candidate_name}" 'bytes=0-67108864')"
  test "${status}" = 416 || {
    echo "over-budget range was not rejected: status=${status}" >&2
    return 1
  }
}

prepare_status_chain_harness() {
  cat >"${status_chain_harness}" <<'LUA'
package.path = "/usr/local/share/cdnca/?.lua;" .. package.path
local guard = require("range.guard")

local cases = {
  { name = "retry then 206", upstream_status = "502, 206", status = 206,
    upstream_range = "bytes 0-9/100", upstream_length = "10", slice_range = "bytes=0-9",
    content_range = "bytes 0-9/100", content_length = "10", want_status = 206, want_no_store = "0" },
  { name = "retry then misaligned 206", upstream_status = "502, 206", status = 206,
    upstream_range = "bytes 1-9/100", upstream_length = "9", slice_range = "bytes=0-9",
    content_range = "bytes 0-9/100", content_length = "10", want_status = 502, want_no_store = "1", want_drop = true },
  { name = "retry then length-conflict 206", upstream_status = "502, 206", status = 206,
    upstream_range = "bytes 0-9/100", upstream_length = "9", slice_range = "bytes=0-9",
    content_range = "bytes 0-9/100", content_length = "10", want_status = 502, want_no_store = "1", want_drop = true },
  { name = "retry then 416", upstream_status = "502, 416", status = 416,
    upstream_range = "bytes */100", slice_range = "bytes=100-199",
    content_range = "bytes */100", want_status = 416, want_no_store = "0" },
  { name = "retry then invalid 416", upstream_status = "502, 416", status = 416,
    upstream_range = "bytes 0-9/100", slice_range = "bytes=100-199",
    content_range = "bytes */100", want_status = 502, want_no_store = "1", want_drop = true },
  { name = "forged satisfiable 416", upstream_status = "416", status = 416,
    upstream_range = "bytes */100", slice_range = "bytes=0-99",
    content_range = "bytes */100", want_status = 502, want_no_store = "1", want_drop = true },
  { name = "conflicting downstream 416 total", upstream_status = "416", status = 416,
    upstream_range = "bytes */100", slice_range = "bytes=100-199",
    content_range = "bytes */101", want_status = 502, want_no_store = "1", want_drop = true },
  { name = "empty object 416", upstream_status = "416", status = 416,
    upstream_range = "bytes */0", slice_range = "bytes=0-65535",
    content_range = "bytes */0", want_status = 416, want_no_store = "0" },
  { name = "client range 416 without slice", upstream_status = "416", status = 416,
    upstream_range = "bytes */100", request_range = "bytes=100-",
    content_range = "bytes */100", want_status = 416, want_no_store = "0" },
  { name = "forged client satisfiable 416 without slice", upstream_status = "416", status = 416,
    upstream_range = "bytes */100", request_range = "bytes=0-99",
    content_range = "bytes */100", want_status = 502, want_no_store = "1", want_drop = true },
  { name = "retry then 200", upstream_status = "502, 200", status = 200,
    want_status = 200, want_no_store = "1" },
  { name = "empty upstream status", upstream_status = "", status = 200,
    want_status = 200, want_no_store = "0" },
  { name = "single 200", upstream_status = "200", status = 200,
    want_status = 200, want_no_store = "1" },
  { name = "single 206", upstream_status = "206", status = 206,
    upstream_range = "bytes 0-9/100", upstream_length = "10", slice_range = "bytes=0-9",
    content_range = "bytes 0-9/100", content_length = "10", want_status = 206, want_no_store = "0" },
  { name = "single 416", upstream_status = "416", status = 416,
    upstream_range = "bytes */100", slice_range = "bytes=100-199",
    content_range = "bytes */100", want_status = 416, want_no_store = "0" },
}

for _, test in ipairs(cases) do
  local response_headers = {}
  local output_headers = {}
  if test.content_range then
    response_headers["content-range"] = test.content_range
    output_headers["Content-Range"] = test.content_range
  end
  if test.content_length then
    response_headers["content-length"] = test.content_length
    output_headers["Content-Length"] = test.content_length
  end
  _G.ngx = {
    ERR = "ERR",
    status = test.status,
    arg = { "body", false },
    ctx = { range_cache_request = test.request_range },
    header = output_headers,
    var = {
      range_cache_guard_no_store = "0",
      upstream_status = test.upstream_status,
      upstream_http_content_range = test.upstream_range,
      upstream_http_content_length = test.upstream_length,
      slice_range = test.slice_range,
    },
    resp = { get_headers = function() return response_headers end },
    log = function() end,
  }
  guard.header_filter({ max_header_bytes = 8192 })
  guard.body_filter()
  assert(ngx.status == test.want_status,
    test.name .. ": status=" .. tostring(ngx.status) .. " want=" .. tostring(test.want_status))
  assert(ngx.var.range_cache_guard_no_store == test.want_no_store,
    test.name .. ": no_store=" .. tostring(ngx.var.range_cache_guard_no_store) .. " want=" .. test.want_no_store)
  assert((ngx.ctx.range_cache_drop_body == true) == (test.want_drop == true),
    test.name .. ": drop_body=" .. tostring(ngx.ctx.range_cache_drop_body))
  if test.want_drop then
    assert(ngx.arg[1] == nil, test.name .. ": rejected response body was retained")
    assert(ngx.header["Content-Range"] == nil and ngx.header["Content-Length"] == nil,
      test.name .. ": rejected response metadata was retained")
  else
    assert(ngx.arg[1] == "body", test.name .. ": accepted response body was dropped")
  end
end

io.write("RANGE_STATUS_CHAIN=pass cases=15\n")
LUA
  chmod 0444 "${status_chain_harness}"
}

assert_range_status_chain() {
  candidate_name="$1"
  result="$(docker exec "${candidate_name}" /usr/local/openresty/bin/resty /cdnca-range-status-chain.lua)"
  test "${result}" = "RANGE_STATUS_CHAIN=pass cases=15" || {
    echo "${candidate_name}: unexpected Range status-chain result: ${result}" >&2
    return 1
  }
}

assert_tampered_rejected() {
  start_candidate "${tampered_container}" "${workdir}/tampered-state" \
    --volume "${workdir}/guard.tampered.lua:${runtime_path}:ro"
  assert_no_published_listener "${tampered_container}"
  attempt=0
  while [ "${attempt}" -lt 50 ]; do
    running="$(docker inspect --format '{{.State.Running}}' "${tampered_container}" 2>/dev/null || true)"
    [ "${running}" = false ] && break
    attempt=$((attempt + 1))
    sleep 0.1
  done
  running="$(docker inspect --format '{{.State.Running}}' "${tampered_container}")"
  if [ "${running}" != false ]; then
    echo "tampered candidate remained running" >&2
    return 1
  fi
  tampered_exit_code="$(docker inspect --format '{{.State.ExitCode}}' "${tampered_container}")"
  test "${tampered_exit_code}" -ne 0 || {
    echo "tampered candidate exited successfully" >&2
    return 1
  }
  printf '%s' "${tampered_exit_code}"
}

trap 'on_exit $?' EXIT
trap 'on_signal 129' HUP
trap 'on_signal 130' INT
trap 'on_signal 143' TERM

prepare_state "${workdir}/baseline-state"
prepare_state "${workdir}/tampered-state"
prepare_state "${workdir}/rollback-state"
prepare_status_chain_harness
printf '%s\n' 'return { tampered = true }' >"${workdir}/guard.tampered.lua"
chmod 0444 "${workdir}/guard.tampered.lua"

if ! CDNCA_EDGE_REVISION="${task_marker}" \
  "${repo_root}/scripts/edge-runtime-build.sh" "${image}" \
  >"${workdir}/build.log" 2>&1; then
  tail -n 120 "${workdir}/build.log" >&2
  exit 1
fi
assert_image_healthcheck

start_candidate "${baseline_container}" "${workdir}/baseline-state" \
  --volume "${status_chain_harness}:/cdnca-range-status-chain.lua:ro"
assert_no_published_listener "${baseline_container}"
wait_ready "${baseline_container}"
assert_runtime_contract "${baseline_container}"
assert_range_requests "${baseline_container}"
assert_range_status_chain "${baseline_container}"
wait_healthy "${baseline_container}"

tampered_exit_code="$(assert_tampered_rejected)"
wait_ready "${baseline_container}"
assert_range_requests "${baseline_container}"
assert_range_status_chain "${baseline_container}"
wait_healthy "${baseline_container}"

start_candidate "${rollback_container}" "${workdir}/rollback-state" \
  --volume "${status_chain_harness}:/cdnca-range-status-chain.lua:ro"
assert_no_published_listener "${rollback_container}"
wait_ready "${rollback_container}"
assert_runtime_contract "${rollback_container}"
assert_range_requests "${rollback_container}"
assert_range_status_chain "${rollback_container}"
wait_healthy "${rollback_container}"

printf 'RANGE_RUNTIME_SMOKE={"status":"pass","guard_sha256":"%s","mode":"0444","healthcheck_bound":true,"require_access_header_body":true,"ready_contract_unchanged":true,"valid_range":204,"valid_multi_range":204,"overlapping_range":416,"over_budget_range":416,"status_chain_cases":15,"tampered_exit_code":%s,"baseline_survived":true,"rollback_healthy":true,"published_listeners":0}\n' \
  "${expected_sha256}" "${tampered_exit_code}"
