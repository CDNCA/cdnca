#!/bin/sh
set -eu

repo_root="$(CDPATH='' cd -- "$(dirname -- "$0")/../../.." && pwd)"
# shellcheck source=edge/openresty/runtime.env
. "${repo_root}/edge/openresty/runtime.env"

expected_sha256="93405cdcf5e2a7edef1198cc3e09c6f1584cca6bd351e8561cb1c96c0aaa0bcc"
runtime_path="/usr/local/share/cdnca/security/url_auth.lua"
tmp_base="${TMPDIR:-/tmp}"
workdir="$(mktemp -d "${tmp_base%/}/cdnca-urlauth-runtime.XXXXXX")"
chmod 0700 "${workdir}"
suffix="$(basename "${workdir}" | sed 's/^cdnca-urlauth-runtime\.//')"
task_marker="cdnca-urlauth-runtime-${suffix}"
image="cdnca/openresty-runtime:urlauth-${suffix}"
baseline_container="${task_marker}-baseline"
tampered_container="${task_marker}-tampered"
rollback_container="${task_marker}-rollback"
tenant_id="11111111-1111-4111-8111-111111111111"
site_id="33333333-3333-4333-8333-333333333333"
policy_id="55555555-5555-4555-8555-555555555555"
key_id="runtime-key-v1"
key_secret="SENSITIVE_CREDENTIAL_0123456789abcdef"
sensitive_path="/download/private-SENSITIVE_PATH"
sensitive_query="SENSITIVE_QUERY"
sensitive_ip="198.51.100.77"
sensitive_ua="SENSITIVE_USER_AGENT"
valid_trace="00-0123456789abcdef0123456789abcdef-0123456789abcdef-01"
expires="$(( $(date +%s) + 300 ))"
key_sha256="$(printf '%s' "${key_secret}" | sha256sum | awk '{print $1}')"
canonical="CDNCA-URL-AUTH/1
tenant_id=${tenant_id}
site_id=${site_id}
method=GET
path=%2Fdownload%2Fprivate-SENSITIVE_PATH
query=marker=${sensitive_query}
expires=${expires}
key_id=${key_id}
client_ip=
"
signature="$(printf '%s' "${canonical}" | openssl dgst -sha256 -hmac "${key_secret}" | awk '{print $NF}')"

cleanup() {
  cleanup_status=0
  docker rm -f "${baseline_container}" "${tampered_container}" \
    "${rollback_container}" >/dev/null 2>&1 || true
  docker image rm "${image}" >/dev/null 2>&1 || true

  for owned_container in "${baseline_container}" "${tampered_container}" \
    "${rollback_container}"; do
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
    "${tmp_base%/}"/cdnca-urlauth-runtime.*)
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
  policy_dir="${state_root}/urlauth/policies/${policy_id}"
  key_dir="${state_root}/urlauth/keys"
  audit_dir="${state_root}/shared/telemetry/cfg-runtime-v1/${site_id}"
  mkdir -p "${release}" "${state_root}/shared" "${policy_dir}" "${key_dir}" \
    "${audit_dir}/18081" "${audit_dir}/18082"
  printf '%s' "${key_secret}" >"${key_dir}/${key_id}.key"
  chmod 0600 "${key_dir}/${key_id}.key"
  cat >"${workdir}/policy-v1.json" <<EOF
{"schema_version":"cdnca.edge.urlauth/v1","policy_version":1,"tenant_id":"${tenant_id}","site_id":"${site_id}","algorithm":"hmac-sha256","signature_parameter":"sig","expiration_parameter":"expires","key_id_parameter":"key","bind_client_ip":false,"max_clock_skew_seconds":5,"max_validity_seconds":600,"max_signature_uses":0,"excluded_query_parameters":[],"trusted_proxies":[{"family":4,"network":[127,0,0,0],"prefix_length":8}],"current_key":{"key_id":"${key_id}","key_file":"/var/lib/cdnca-edge/urlauth/keys/${key_id}.key","key_sha256":"${key_sha256}"}}
EOF
  cp "${workdir}/policy-v1.json" "${policy_dir}/current.json"
  chmod 0444 "${policy_dir}/current.json"
  cat >"${release}/nginx.conf" <<EOF
worker_processes 1;
pid /var/lib/cdnca-edge/shared/nginx.pid;
error_log stderr notice;
events { worker_connections 64; }
http {
  access_log off;
  lua_package_path "/usr/local/share/cdnca/security/?.lua;;";
  lua_shared_dict cdnca_url_auth_state 16m;
  log_format cdnca_url_auth_json escape=json '{"schema_version":1,"type":"security.url_auth.v1","occurred_at":"\$time_iso8601","tenant_id":"\$cdnca_tenant_id","site_id":"\$cdnca_site_id","node_id":"\$cdnca_node_id","config_version_id":"\$cdnca_config_version_id","request_id":"\$request_id","trace_id":"\$cdnca_urlauth_trace_id","action":"\$cdnca_urlauth_action","reason":"\$cdnca_urlauth_reason","status":\$cdnca_urlauth_status,"policy_version":\$cdnca_urlauth_policy_version,"policy_event":"\$cdnca_urlauth_policy_event"}';
  init_by_lua_block {
    require("url_auth").init({
      state_dict = "cdnca_url_auth_state",
      reload_interval = 0.05,
      bindings = {
        { tenant_id = "${tenant_id}", site_id = "${site_id}", listen_port = 18081, policy_path = "/var/lib/cdnca-edge/urlauth/policies/${policy_id}/current.json" },
        { tenant_id = "${tenant_id}", site_id = "${site_id}", listen_port = 18082, policy_path = "/var/lib/cdnca-edge/urlauth/policies/${policy_id}/current.json" },
      },
    })
  }
  init_worker_by_lua_block { require("url_auth").init_worker() }
  server {
    listen 18080;
    location = /ready { return 200 "ready\n"; }
  }
  server {
    listen 18081;
    server_name edge.example.test;
    set \$cdnca_tenant_id "${tenant_id}";
    set \$cdnca_site_id "${site_id}";
    set \$cdnca_node_id "";
    set \$cdnca_config_version_id "cfg-runtime-v1";
    set \$cdnca_urlauth_emit 0;
    set \$cdnca_urlauth_trace_id "";
    set \$cdnca_urlauth_action "";
    set \$cdnca_urlauth_reason "";
    set \$cdnca_urlauth_status 0;
    set \$cdnca_urlauth_policy_version 0;
    set \$cdnca_urlauth_policy_event "";
    access_log "/var/lib/cdnca-edge/shared/telemetry/cfg-runtime-v1/${site_id}/18081/security.jsonl" cdnca_url_auth_json if=\$cdnca_urlauth_emit;
    location = /dependency {
      access_by_lua_block { return require("url_auth").access({ tenant_id = "${tenant_id}", site_id = "44444444-4444-4444-8444-444444444444", listen_port = 18081 }) }
      content_by_lua_block { return ngx.exit(204) }
    }
    location / {
      access_by_lua_block { return require("url_auth").access({ tenant_id = "${tenant_id}", site_id = "${site_id}", listen_port = 18081 }) }
      content_by_lua_block { return ngx.exit(204) }
    }
  }
  server {
    listen 18082;
    server_name edge.example.test;
    set \$cdnca_tenant_id "${tenant_id}";
    set \$cdnca_site_id "${site_id}";
    set \$cdnca_node_id "";
    set \$cdnca_config_version_id "cfg-runtime-v1";
    set \$cdnca_urlauth_emit 0;
    set \$cdnca_urlauth_trace_id "";
    set \$cdnca_urlauth_action "";
    set \$cdnca_urlauth_reason "";
    set \$cdnca_urlauth_status 0;
    set \$cdnca_urlauth_policy_version 0;
    set \$cdnca_urlauth_policy_event "";
    access_log "/var/lib/cdnca-edge/shared/telemetry/cfg-runtime-v1/${site_id}/18082/security.jsonl" cdnca_url_auth_json if=\$cdnca_urlauth_emit;
    location = /misbound {
      access_by_lua_block { return require("url_auth").access({ tenant_id = "${tenant_id}", site_id = "${site_id}", listen_port = 18081 }) }
      content_by_lua_block { return ngx.exit(204) }
    }
    location / {
      access_by_lua_block { return require("url_auth").access({ tenant_id = "${tenant_id}", site_id = "${site_id}", listen_port = 18082 }) }
      content_by_lua_block { return ngx.exit(204) }
    }
  }
}
EOF
  ln -s releases/smoke-v1 "${state_root}/current"
}

start_candidate() {
  candidate_name="$1"
  state_root="$2"
  shift 2
  docker run --detach --name "${candidate_name}" --network none --read-only \
    --security-opt no-new-privileges --pids-limit 128 --memory 256m --cpus 1 \
    --tmpfs /tmp:rw,noexec,nosuid,size=16m \
    --tmpfs /var/run:rw,noexec,nosuid,size=1m \
    --volume "${state_root}:/var/lib/cdnca-edge" \
    "$@" "${image}" >/dev/null
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

assert_runtime_contract() {
  candidate_name="$1"
  if ! docker exec "${candidate_name}" test -f "${runtime_path}"; then
    echo "runtime image missing ${runtime_path}" >&2
    return 1
  fi
  docker exec "${candidate_name}" sh -ceu \
    'printf "%s  %s\n" "$1" "$2" | sha256sum -c - >/dev/null' \
    urlauth-runtime "${expected_sha256}" "${runtime_path}"
  mode="$(docker exec "${candidate_name}" stat -c '%a' "${runtime_path}")"
  test "${mode}" = 444 || {
    echo "runtime engine mode: expected 444, got ${mode}" >&2
    return 1
  }
  docker exec "${candidate_name}" /usr/local/openresty/bin/resty -e \
    'package.path = "/usr/local/share/cdnca/security/?.lua;" .. package.path; local url_auth = require("url_auth"); assert(type(url_auth.init) == "function"); assert(type(url_auth.init_worker) == "function"); assert(type(url_auth.access) == "function")'
  if docker exec "${candidate_name}" grep -n 'ngx\.log' "${runtime_path}"; then
    echo "URL-auth runtime uses request-context ngx.log" >&2
    return 1
  fi
  docker exec "${candidate_name}" /usr/local/openresty/bin/resty -e \
    'local f=assert(io.open("/var/run/cdnca/security-runtime.ready","rb")); local v=assert(require("cjson.safe").decode(assert(f:read("*a")))); f:close(); local expected={schema_version=true,waf_sha256=true,cc_sha256=true,adaptive_sha256=true,config_sha256=true,cc_api_version=true}; local count=0; for key in pairs(v) do assert(expected[key],"unexpected ready key: "..tostring(key)); count=count+1 end; assert(count==6,"ready key count changed"); for key in pairs(expected) do assert(v[key]~=nil,"missing ready key: "..key) end; assert(v.schema_version=="cdnca.security-runtime-ready/v1")'
}

request_status() {
  candidate_name="$1"
  request_path="$2"
  trace="$3"
  port="${4:-18081}"
  docker exec "${candidate_name}" curl --silent --show-error --output /dev/null \
    --write-out '%{http_code}' --user-agent "${sensitive_ua}" \
    --header "Host: edge.example.test" --header "X-Forwarded-For: ${sensitive_ip}" \
    --header "traceparent: ${trace}" "http://127.0.0.1:${port}${request_path}"
}

wait_audit_lines() {
  candidate_name="$1"
  expected="$2"
  port="${3:-18081}"
  audit_path="/var/lib/cdnca-edge/shared/telemetry/cfg-runtime-v1/${site_id}/${port}/security.jsonl"
  attempt=0
  while [ "${attempt}" -lt 50 ]; do
    count="$(docker exec "${candidate_name}" sh -c 'test -f "$1" && wc -l <"$1" || true' audit-lines "${audit_path}" | tr -d ' ')"
    [ "${count}" = "${expected}" ] && return 0
    attempt=$((attempt + 1))
    sleep 0.1
  done
  docker exec "${candidate_name}" sh -c 'test ! -f "$1" || cat "$1"' audit-lines "${audit_path}" >&2
  echo "audit line count did not reach ${expected}" >&2
  return 1
}

assert_port_audit_contract() {
  candidate_name="$1"
  audit_path="/var/lib/cdnca-edge/shared/telemetry/cfg-runtime-v1/${site_id}/18082/security.jsonl"
  docker exec --env "AUDIT_PATH=${audit_path}" "${candidate_name}" /usr/local/openresty/bin/resty -e '
    local cjson = require("cjson.safe")
    local file = assert(io.open(assert(os.getenv("AUDIT_PATH")), "rb"))
    local events = {}
    for line in file:lines() do events[#events + 1] = assert(cjson.decode(line)) end
    file:close()
    assert(#events == 2, "port event count=" .. #events)
    assert(events[1].action == "allow" and events[1].reason == "signature_valid" and events[1].status == 0 and events[1].policy_version == 1)
    assert(events[2].action == "block" and events[2].reason == "listen_port_mismatch" and events[2].status == 403 and events[2].policy_version == 1)
  '
}

assert_audit_contract() {
  candidate_name="$1"
  audit_path="/var/lib/cdnca-edge/shared/telemetry/cfg-runtime-v1/${site_id}/18081/security.jsonl"
  docker exec --env "AUDIT_PATH=${audit_path}" "${candidate_name}" /usr/local/openresty/bin/resty -e '
    local cjson = require("cjson.safe")
    local path = assert(os.getenv("AUDIT_PATH"))
    local file = assert(io.open(path, "rb"))
    local events = {}
    for line in file:lines() do events[#events + 1] = assert(cjson.decode(line)) end
    file:close()
    assert(#events == 5, "event count=" .. #events)
    local allowed = {schema_version=true,type=true,occurred_at=true,tenant_id=true,site_id=true,node_id=true,config_version_id=true,request_id=true,trace_id=true,action=true,reason=true,status=true,policy_version=true,policy_event=true}
    for _, event in ipairs(events) do
      local count = 0
      for key in pairs(event) do assert(allowed[key], "unexpected field=" .. tostring(key)); count = count + 1 end
      assert(count == 14, "field count=" .. count)
      assert(event.schema_version == 1 and event.type == "security.url_auth.v1")
      assert(event.tenant_id == "11111111-1111-4111-8111-111111111111")
      assert(event.site_id == "33333333-3333-4333-8333-333333333333")
      assert(event.config_version_id == "cfg-runtime-v1")
      assert(type(event.request_id) == "string" and #event.request_id == 32)
      assert(type(event.trace_id) == "string" and #event.trace_id <= 55)
    end
    assert(events[1].action == "allow" and events[1].reason == "signature_valid" and events[1].status == 0 and events[1].policy_version == 1 and events[1].policy_event == "")
    assert(events[1].trace_id == "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01")
    assert(events[2].action == "block" and events[2].reason == "signature_invalid" and events[2].status == 403 and events[2].policy_version == 1 and events[2].policy_event == "")
    assert(events[2].trace_id == "")
    assert(events[3].action == "error" and events[3].reason == "context_unavailable" and events[3].status == 503 and events[3].policy_version == 0 and events[3].policy_event == "")
    assert(events[4].action == "allow" and events[4].reason == "signature_valid" and events[4].status == 0 and events[4].policy_version == 1 and events[4].policy_event == "policy_rejected")
    assert(events[5].action == "allow" and events[5].reason == "signature_valid" and events[5].status == 0 and events[5].policy_version == 1 and events[5].policy_event == "")
  '
  for sentinel in "${sensitive_path}" "${sensitive_query}" "${signature}" "${key_secret}" \
    "${sensitive_ip}" "${sensitive_ua}" "SENSITIVE_POLICY"; do
    if docker exec "${candidate_name}" grep -F -- "${sentinel}" "${audit_path}"; then
      echo "URL-auth audit leaked sensitive sentinel" >&2
      return 1
    fi
  done
}

trap 'on_exit $?' EXIT
trap 'on_signal 129' HUP
trap 'on_signal 130' INT
trap 'on_signal 143' TERM

prepare_state "${workdir}/baseline-state"
prepare_state "${workdir}/tampered-state"
prepare_state "${workdir}/rollback-state"
printf '%s\n' 'return { tampered = true }' >"${workdir}/url_auth.tampered.lua"
chmod 0444 "${workdir}/url_auth.tampered.lua"

if ! CDNCA_EDGE_REVISION="${task_marker}" \
  "${repo_root}/scripts/edge-runtime-build.sh" "${image}" \
  >"${workdir}/build.log" 2>&1; then
  cat "${workdir}/build.log" >&2
  exit 1
fi

start_candidate "${baseline_container}" "${workdir}/baseline-state"
wait_ready "${baseline_container}"
assert_runtime_contract "${baseline_container}"
wait_healthy "${baseline_container}"

valid_request="${sensitive_path}?marker=${sensitive_query}&sig=${signature}&expires=${expires}&key=${key_id}"
invalid_signature="0000000000000000000000000000000000000000000000000000000000000000"
invalid_request="${sensitive_path}?marker=${sensitive_query}&sig=${invalid_signature}&expires=${expires}&key=${key_id}"
status="$(request_status "${baseline_container}" "${valid_request}" "${valid_trace}")"
test "${status}" = 204 || { echo "valid signature status=${status}" >&2; exit 1; }
status="$(request_status "${baseline_container}" "${valid_request}" "" 18082)"
test "${status}" = 204 || { echo "second-port valid signature status=${status}" >&2; exit 1; }
status="$(request_status "${baseline_container}" "/misbound" "" 18082)"
test "${status}" = 403 || { echo "misbound listen port status=${status}" >&2; exit 1; }
status="$(request_status "${baseline_container}" "${invalid_request}" "SENSITIVE_TRACE_HEADER")"
test "${status}" = 403 || { echo "invalid signature status=${status}" >&2; exit 1; }
status="$(request_status "${baseline_container}" "/dependency" "")"
test "${status}" = 503 || { echo "dependency failure status=${status}" >&2; exit 1; }
policy_path="${workdir}/baseline-state/urlauth/policies/${policy_id}/current.json"
chmod 0644 "${policy_path}"
printf '%s\n' '{"schema_version":"cdnca.edge.urlauth/v1","policy_version":2,"tampered":"SENSITIVE_POLICY"}' >"${policy_path}"
chmod 0444 "${policy_path}"
sleep 0.1
status="$(request_status "${baseline_container}" "${valid_request}" "")"
test "${status}" = 204 || { echo "LKG request status=${status}" >&2; exit 1; }
chmod 0644 "${policy_path}"
cp "${workdir}/policy-v1.json" "${policy_path}"
chmod 0444 "${policy_path}"
sleep 0.1
status="$(request_status "${baseline_container}" "${valid_request}" "")"
test "${status}" = 204 || { echo "policy rollback status=${status}" >&2; exit 1; }
wait_audit_lines "${baseline_container}" 5
wait_audit_lines "${baseline_container}" 2 18082
assert_audit_contract "${baseline_container}"
assert_port_audit_contract "${baseline_container}"

start_candidate "${tampered_container}" "${workdir}/tampered-state" \
  --volume "${workdir}/url_auth.tampered.lua:${runtime_path}:ro"
attempt=0
while [ "${attempt}" -lt 50 ]; do
  running="$(docker inspect --format '{{.State.Running}}' "${tampered_container}")"
  [ "${running}" = false ] && break
  attempt=$((attempt + 1))
  sleep 0.1
done
running="$(docker inspect --format '{{.State.Running}}' "${tampered_container}")"
if [ "${running}" != false ]; then
  echo "tampered candidate remained running" >&2
  exit 1
fi
exit_code="$(docker inspect --format '{{.State.ExitCode}}' "${tampered_container}")"
test "${exit_code}" -ne 0 || {
  echo "tampered candidate exited successfully" >&2
  exit 1
}

wait_ready "${baseline_container}"
wait_healthy "${baseline_container}"

start_candidate "${rollback_container}" "${workdir}/rollback-state"
wait_ready "${rollback_container}"
assert_runtime_contract "${rollback_container}"
wait_healthy "${rollback_container}"

printf 'URLAUTH_RUNTIME_SMOKE={"status":"pass","engine_sha256":"%s","mode":"0444","require":true,"ready_contract_unchanged":true,"allow":204,"second_port_allow":204,"misbound_port_reject":403,"misbound_reason":"listen_port_mismatch","reject":403,"dependency_failure":503,"audit_events":7,"lkg_policy_rejected":true,"sensitive_leaks":0,"tampered_exit_code":%s,"baseline_survived":true,"rollback_healthy":true}\n' \
  "${expected_sha256}" "${exit_code}"
