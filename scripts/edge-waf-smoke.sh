#!/bin/sh
set -eu

repo_root="$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)"
# shellcheck source=edge/openresty/runtime.env
# shellcheck disable=SC1091
. "${repo_root}/edge/openresty/runtime.env"

tmp_base="${TMPDIR:-/tmp}"
case "${tmp_base}" in
  /*) ;;
  *) echo "TMPDIR must be absolute" >&2; exit 64 ;;
esac
tmp_base="$(CDPATH='' cd -- "${tmp_base}" && pwd -P)"
workdir="$(mktemp -d "${tmp_base%/}/cdnca-edge-waf.XXXXXX")"
suffix="$(basename "${workdir}" | sed 's/^cdnca-edge-waf\.//')"
container="cdnca-edge-waf-${suffix}"

cleanup() {
  docker rm -f "${container}" >/dev/null 2>&1 || true
  case "${workdir}" in
    "${tmp_base%/}"/cdnca-edge-waf.*)
      chmod -R u+w "${workdir}" 2>/dev/null || true
      rm -rf -- "${workdir}"
      ;;
    *) echo "refusing to remove unexpected path: ${workdir}" >&2 ;;
  esac
}
trap cleanup EXIT HUP INT TERM

mkdir -p "${workdir}/policy" "${workdir}/bad" "${workdir}/clock" \
  "${workdir}/undersized-clock" "${workdir}/undersized-locks"
chmod 700 "${workdir}/policy" "${workdir}/bad" "${workdir}/clock" \
  "${workdir}/undersized-clock" "${workdir}/undersized-locks"
(
  cd "${repo_root}/agents/edge-agent"
  GOWORK=off CGO_ENABLED=0 go build -trimpath -ldflags '-s -w -buildid=' \
    -o "${workdir}/waf-compile" ./internal/waf/cmd/waf-compile
  GOWORK=off CGO_ENABLED=0 go build -trimpath -ldflags '-s -w -buildid=' \
    -o "${workdir}/waf-evaluate" ./internal/waf/cmd/waf-evaluate
)
waf_compile_sha256="$(shasum -a 256 "${workdir}/waf-compile" | awk '{print $1}')"
waf_evaluate_sha256="$(shasum -a 256 "${workdir}/waf-evaluate" | awk '{print $1}')"
waf_publisher_source_sha256="$(shasum -a 256 "${repo_root}/agents/edge-agent/internal/waf/publisher.go" | awk '{print $1}')"

state_snapshot() {
  state_root="$1"
  for path in "${state_root}/current.json" "${state_root}/fallback.json" "${state_root}"/versions/*.json; do
    if [ ! -e "${path}" ] && [ ! -L "${path}" ]; then
      printf 'waf_state path=%s state=missing\n' "${path}"
      continue
    fi
    if metadata="$(stat -f '%Lp:%l' "${path}" 2>/dev/null)"; then
      :
    else
      metadata="$(stat -c '%a:%h' "${path}" 2>/dev/null || printf '%s' unavailable)"
    fi
    digest="$(shasum -a 256 "${path}" 2>/dev/null | awk '{print $1}' || true)"
    [ -n "${digest}" ] || digest=unavailable
    file_type=regular
    [ -L "${path}" ] && file_type=symlink
    printf 'waf_state path=%s state=present type=%s mode_nlink=%s sha256=%s\n' \
      "${path}" "${file_type}" "${metadata}" "${digest}"
  done
}

publish_waf() {
  stage="$1"
  input="$2"
  output="$3"
  state_root="$4"
  error_file="${workdir}/${stage}.stderr"
  provenance_file="${output}.provenance"
  if "${workdir}/waf-compile" -input "${input}" -state-root "${state_root}" \
    >"${output}" 2>"${error_file}"; then
    printf 'waf_publish_stage=%s\nwaf_compile_sha256=%s\nwaf_evaluate_sha256=%s\nwaf_publisher_source_sha256=%s\n' \
      "${stage}" "${waf_compile_sha256}" "${waf_evaluate_sha256}" "${waf_publisher_source_sha256}" \
      >"${provenance_file}"
    return 0
  fi
  printf 'waf_publish_stage=%s\nwaf_compile_sha256=%s\nwaf_evaluate_sha256=%s\nwaf_publisher_source_sha256=%s\n' \
    "${stage}" "${waf_compile_sha256}" "${waf_evaluate_sha256}" "${waf_publisher_source_sha256}" >&2
  state_snapshot "${state_root}" >&2
  cat "${error_file}" >&2 || true
  return 1
}

cat >"${workdir}/policy-v1.json" <<'EOF'
{
  "schema_version": "cdnca.edge.waf/v1",
  "policy_version": 1,
  "rules": [
    {"rule_id":"allow-office","priority":500,"action":"allow","flow":"continue","match":{"header":{"name":"X-Allow","operator":"exact","value":"yes"}}},
    {"rule_id":"block-allow","priority":1,"action":"block","flow":"continue","match":{"path":{"kind":"exact","value":"/allow"}}},
    {"rule_id":"log-allow","priority":2,"action":"log","flow":"continue","match":{"query":{"name":"audit","operator":"exact","value":"1"}}},
    {"rule_id":"allow-stop","priority":600,"action":"allow","flow":"stop","match":{"path":{"kind":"exact","value":"/allow-stop"}}},
    {"rule_id":"block-before-allow","priority":0,"action":"block","flow":"continue","match":{"path":{"kind":"exact","value":"/allow-stop"}}},
    {"rule_id":"log-stop","priority":10,"action":"log","flow":"stop","match":{"path":{"kind":"exact","value":"/stop"}}},
    {"rule_id":"later-block","priority":11,"action":"block","flow":"stop","match":{"path":{"kind":"exact","value":"/stop"}}},
    {"rule_id":"continue-block","priority":20,"action":"block","flow":"continue","match":{"path":{"kind":"exact","value":"/continue"}}},
    {"rule_id":"continue-log-stop","priority":21,"action":"log","flow":"stop","match":{"path":{"kind":"exact","value":"/continue"}}},
    {"rule_id":"fields","priority":30,"action":"block","flow":"stop","match":{"path":{"kind":"exact","value":"/fields"},"query":{"name":"token","operator":"exact","value":"ok"},"header":{"name":"X-Mode","operator":"exact","value":"strict"}}},
    {"rule_id":"host-port","priority":40,"action":"block","flow":"stop","match":{"host":"waf.example.test","port":18081,"path":{"kind":"exact","value":"/port"}}},
    {"rule_id":"ipv4","priority":50,"action":"block","flow":"stop","match":{"path":{"kind":"exact","value":"/ipv4"},"source_cidr":"127.0.0.0/8"}},
    {"rule_id":"ipv6","priority":51,"action":"block","flow":"stop","match":{"path":{"kind":"exact","value":"/ipv6"},"source_cidr":"::1/128"}}
  ]
}
EOF

cat >"${workdir}/invalid.json" <<'EOF'
{"schema_version":"cdnca.edge.waf/v1","policy_version":2,"rules":[{"rule_id":"bad","priority":1,"action":"block","flow":"stop","match":{"path":{"kind":"exact","value":"/safe/../escape"}}}]}
EOF

publish_waf publish-v1 "${workdir}/policy-v1.json" "${workdir}/publish-v1.txt" "${workdir}/policy"
v1_digest="$(sed -n 's/^sha256=//p' "${workdir}/publish-v1.txt")"
if "${workdir}/waf-compile" -input "${workdir}/invalid.json" -state-root "${workdir}/policy" >"${workdir}/invalid.out" 2>"${workdir}/invalid.err"; then
  echo "invalid WAF candidate was accepted" >&2
  exit 1
fi
test "$(shasum -a 256 "${workdir}/policy/current.json" | awk '{print $1}')" = "${v1_digest}"
test "$(shasum -a 256 "${workdir}/policy/fallback.json" | awk '{print $1}')" = "${v1_digest}"

printf '%s\n' '{"broken":true}' >"${workdir}/bad/current.json"
cat >"${workdir}/nginx.conf" <<'EOF'
worker_processes 2;
error_log /work/error.log notice;
pid /work/nginx.pid;

events {
  worker_connections 1024;
}

http {
  lua_package_path "/opt/cdnca/lua/?.lua;;";
  lua_shared_dict cdnca_waf_clock 1m;
  lua_shared_dict cdnca_waf_locks 1m;
  access_log off;
  header_filter_by_lua_block {
    ngx.header["X-CDNCA-WAF-Worker-PID"] = tostring(ngx.worker.pid())
  }

  server {
    listen 18081;
    listen [::]:18081 ipv6only=on;
    server_name _;
    location / {
      access_by_lua_block {
        return require("cdnca_waf").access({policy_path = "/work/policy/current.json"})
      }
      content_by_lua_block {
        ngx.header["Content-Type"] = "text/plain"
        ngx.say("origin-ok")
      }
    }
  }

  server {
    listen 18082;
    server_name _;
    location / {
      access_by_lua_block {
        return require("cdnca_waf").access({policy_path = "/work/policy/current.json"})
      }
      content_by_lua_block {
        ngx.header["Content-Type"] = "text/plain"
        ngx.say("origin-ok")
      }
    }
  }

  server {
    listen 18083;
    server_name _;
    location / {
      access_by_lua_block {
        return require("cdnca_waf").access({policy_path = "/work/bad/current.json"})
      }
      content_by_lua_block {
        ngx.say("must-not-run")
      }
    }
  }

  server {
    listen 18084;
    server_name _;
    location / {
      access_by_lua_block {
        local original_time = ngx.time
        local test_time = tonumber(ngx.var.http_x_waf_test_now)
        if test_time then
          ngx.time = function() return test_time end
        end
        local result = require("cdnca_waf").access({policy_path = "/work/clock/current.json"})
        ngx.time = original_time
        return result
      }
      content_by_lua_block {
        ngx.say("origin-ok")
      }
    }
  }

  server {
    listen [::]:18085 ipv6only=off;
    server_name _;
    location / {
      access_by_lua_block {
        return require("cdnca_waf").access({policy_path = "/work/policy/current.json"})
      }
      content_by_lua_block {
        ngx.say("origin-ok")
      }
    }
  }
}
EOF

cat >"${workdir}/undersized-clock/nginx.conf" <<'EOF'
worker_processes 1;
error_log /work/undersized-clock/error.log notice;
pid /work/undersized-clock/nginx.pid;
events { worker_connections 64; }
http {
  lua_package_path "/opt/cdnca/lua/?.lua;;";
  lua_shared_dict cdnca_waf_clock 64k;
  lua_shared_dict cdnca_waf_locks 1m;
  access_log off;
  server {
    listen 18086;
    location / {
      access_by_lua_block {
        return require("cdnca_waf").access({policy_path = "/work/policy/current.json"})
      }
      content_by_lua_block { ngx.say("must-not-run") }
    }
  }
}
EOF

cat >"${workdir}/undersized-locks/nginx.conf" <<'EOF'
worker_processes 1;
error_log /work/undersized-locks/error.log notice;
pid /work/undersized-locks/nginx.pid;
events { worker_connections 64; }
http {
  lua_package_path "/opt/cdnca/lua/?.lua;;";
  lua_shared_dict cdnca_waf_clock 1m;
  lua_shared_dict cdnca_waf_locks 64k;
  access_log off;
  server {
    listen 18087;
    location / {
      access_by_lua_block {
        return require("cdnca_waf").access({policy_path = "/work/policy/current.json"})
      }
      content_by_lua_block { ngx.say("must-not-run") }
    }
  }
}
EOF

docker run --detach \
  --name "${container}" \
  --volume "${workdir}:/work" \
  --volume "${repo_root}/edge/openresty/lua:/opt/cdnca/lua:ro" \
  --entrypoint /usr/local/openresty/bin/openresty \
  "${OPENRESTY_IMAGE}" \
  -g 'daemon off;' -p /work/ -c nginx.conf >/dev/null

attempt=0
while ! docker exec "${container}" curl --noproxy '*' --silent --fail http://127.0.0.1:18081/ready >/dev/null 2>&1; do
  attempt=$((attempt + 1))
  if [ "${attempt}" -ge 40 ]; then
    docker logs "${container}" >&2 || true
    cat "${workdir}/error.log" >&2 || true
    exit 1
  fi
  sleep 0.1
done

request() {
  expected="$1"
  shift
  status="$(docker exec "${container}" curl --noproxy '*' --silent --show-error \
    --connect-timeout 2 --max-time 5 --output /tmp/cdnca-waf-body --write-out '%{http_code}' "$@")"
  if [ "${status}" != "${expected}" ]; then
    echo "request $* returned ${status}, want ${expected}" >&2
    docker exec "${container}" cat /tmp/cdnca-waf-body >&2 || true
    exit 1
  fi
  if [ "${expected}" = 403 ]; then
    body="$(docker exec "${container}" cat /tmp/cdnca-waf-body)"
    test "${body}" = "Request blocked"
    case "${body}" in
      *rule*|*policy*|*priority*) echo "block body leaked policy details" >&2; exit 1 ;;
    esac
  fi
}

request_pid() {
  expected="$1"
  shift
  status="$(docker exec "${container}" curl --noproxy '*' --silent --show-error \
    --connect-timeout 2 --max-time 5 --dump-header /tmp/cdnca-waf-headers \
    --output /tmp/cdnca-waf-body --write-out '%{http_code}' "$@")"
  if [ "${status}" != "${expected}" ]; then
    echo "request $* returned ${status}, want ${expected}" >&2
    docker exec "${container}" cat /tmp/cdnca-waf-body >&2 || true
    exit 1
  fi
  if [ "${expected}" = 403 ]; then
    body="$(docker exec "${container}" cat /tmp/cdnca-waf-body)"
    test "${body}" = "Request blocked"
    case "${body}" in
      *rule*|*policy*|*priority*) echo "block body leaked policy details" >&2; exit 1 ;;
    esac
  fi
  pid="$(docker exec "${container}" awk -F ': ' \
    '$1 == "X-CDNCA-WAF-Worker-PID" {gsub("\\r", "", $2); print $2}' \
    /tmp/cdnca-waf-headers | tail -n 1)"
  case "${pid}" in
    ''|*[!0-9]*) echo "response did not expose an exact worker PID: ${pid}" >&2; exit 1 ;;
  esac
  printf '%s\n' "${pid}"
}

request_different_pid() {
  expected="$1"
  excluded_pid="$2"
  shift 2
  attempt=0
  while [ "${attempt}" -lt 40 ]; do
    pid="$(request_pid "${expected}" "$@")"
    if [ "${pid}" != "${excluded_pid}" ]; then
      printf '%s\n' "${pid}"
      return 0
    fi
    attempt=$((attempt + 1))
  done
  echo "did not reach a worker other than ${excluded_pid} after ${attempt} attempts" >&2
  exit 1
}

probe_status_pid() {
  status="$(docker exec "${container}" curl --noproxy '*' --silent --connect-timeout 2 --max-time 5 \
    --dump-header /tmp/cdnca-waf-probe-headers --output /dev/null --write-out '%{http_code}' "$@" || true)"
  case "${status}" in
    [0-9][0-9][0-9]) ;;
    *) return 1 ;;
  esac
  pid="$(docker exec "${container}" awk -F ': ' \
    '$1 == "X-CDNCA-WAF-Worker-PID" {gsub("\\r", "", $2); print $2}' \
    /tmp/cdnca-waf-probe-headers | tail -n 1)"
  case "${pid}" in
    ''|*[!0-9]*) return 1 ;;
  esac
  printf '%s|%s\n' "${status}" "${pid}"
}

wait_status_on_two_workers() {
  expected="$1"
  shift
  wait_pid_one=''
  wait_pid_two=''
  last_status='unavailable'
  last_pid='unavailable'
  attempt=0
  while [ "${attempt}" -lt 40 ]; do
    probe="$(probe_status_pid "$@" || true)"
    case "${probe}" in
      *'|'*)
        last_status="${probe%%|*}"
        last_pid="${probe#*|}"
        if [ "${last_status}" = "${expected}" ]; then
          if [ -z "${wait_pid_one}" ]; then
            wait_pid_one="${last_pid}"
          elif [ "${last_pid}" != "${wait_pid_one}" ]; then
            wait_pid_two="${last_pid}"
            return 0
          fi
        fi
        ;;
    esac
    attempt=$((attempt + 1))
    sleep 0.1
  done
  echo "request $* did not reach two workers at status ${expected}; first PID ${wait_pid_one:-none}; last status ${last_status}; last PID ${last_pid}" >&2
  exit 1
}

wait_status_once() {
  expected="$1"
  shift
  last_status='unavailable'
  attempt=0
  while [ "${attempt}" -lt 40 ]; do
    last_status="$(docker exec "${container}" curl --noproxy '*' --silent --connect-timeout 2 --max-time 5 \
      --output /dev/null --write-out '%{http_code}' "$@" || true)"
    [ "${last_status}" = "${expected}" ] && return 0
    attempt=$((attempt + 1))
    sleep 0.1
  done
  echo "request $* did not reach status ${expected}; last status ${last_status}" >&2
  cat "${workdir}/undersized-clock/error.log" >&2 2>/dev/null || true
  cat "${workdir}/undersized-locks/error.log" >&2 2>/dev/null || true
  exit 1
}

wait_event_since() {
  first_line="$1"
  expected="$(printf '%s\t%s\t%s' "$2" "$3" "$4")"
  attempt=0
  while [ "${attempt}" -lt 30 ]; do
    docker exec "${container}" curl --noproxy '*' --silent --connect-timeout 2 --max-time 5 \
      --output /dev/null -H 'Host: waf.example.test' http://127.0.0.1:18081/no-match >/dev/null 2>&1 || true
    if tail -n "+${first_line}" "${workdir}/error.log" |
      while IFS= read -r line; do event_record "${line}" || true; done |
      grep -Fqx -- "${expected}"; then
      return 0
    fi
    attempt=$((attempt + 1))
    sleep 0.1
  done
  echo "event log did not contain exact record ${expected} after line ${first_line}" >&2
  tail -n "+${first_line}" "${workdir}/error.log" >&2 || true
  exit 1
}

log_lines() {
  wc -l <"${workdir}/error.log" | tr -d ' '
}

log_payload() {
  line="$1"
  case "${line}" in
    *'cdnca_waf '*) payload="${line#*cdnca_waf }" ;;
    *) return 1 ;;
  esac
  case "${payload}" in
    *', client: '*) payload="${payload%%, client: *}" ;;
  esac
  printf '%s\n' "${payload}"
}

event_record() {
  payload="$(log_payload "$1")" || return 1
  first="${payload%% *}"
  rest="${payload#* }"
  [ "${rest}" != "${payload}" ] || return 1
  second="${rest%% *}"
  third="${rest#* }"
  [ "${third}" != "${rest}" ] || return 1
  case "${third}" in
    *' '*) return 1 ;;
  esac
  case "${first}" in
    reason=?*) reason="${first#reason=}" ;;
    *) return 1 ;;
  esac
  case "${second}" in
    rule_id=?*) rule_id="${second#rule_id=}" ;;
    *) return 1 ;;
  esac
  case "${third}" in
    policy_version=?*) version="${third#policy_version=}" ;;
    *) return 1 ;;
  esac
  case "${version}" in
    ''|*[!0-9]*) return 1 ;;
  esac
  printf '%s\t%s\t%s\n' "${reason}" "${rule_id}" "${version}"
}

rule_event_record() {
  record="$(event_record "$1")" || return 1
  record_reason="$(printf '%s\n' "${record}" | cut -f 1)"
  case "${record_reason}" in
    allowlist_continue|allowlist_stop|rule_expired|rule_log|rule_block)
      printf '%s\n' "${record}"
      ;;
    *) return 1 ;;
  esac
}

assert_event_since() {
  first_line="$1"
  expected="$(printf '%s\t%s\t%s' "$2" "$3" "$4")"
  if ! tail -n "+${first_line}" "${workdir}/error.log" |
    while IFS= read -r line; do event_record "${line}" || true; done |
    grep -Fqx -- "${expected}"; then
    echo "event log did not contain exact record ${expected} after line ${first_line}" >&2
    exit 1
  fi
}

assert_decision_since() {
  first_line="$1"
  expected_action="$2"
  expected_reason="$3"
  expected_rule_id="$4"
  expected_version="$5"
  line="$(tail -n "+${first_line}" "${workdir}/error.log" | grep -F 'cdnca_waf decision action=' | tail -n 1 || true)"
  decision="$(log_payload "${line}")" || decision=''
  expected="decision action=${expected_action} reason=${expected_reason} rule_id=${expected_rule_id} policy_version=${expected_version}"
  if [ "${decision}" != "${expected}" ]; then
    echo "decision log mismatch: got ${decision}, want ${expected}" >&2
    exit 1
  fi
}

assert_policy_unavailable_file() {
  log_file="$1"
  line="$(grep -F 'cdnca_waf decision action=' "${log_file}" | tail -n 1 || true)"
  decision="$(log_payload "${line}")" || decision=''
  expected='decision action=block reason=policy_unavailable rule_id=- policy_version=1'
  if [ "${decision}" != "${expected}" ]; then
    echo "undersized shared dict decision mismatch in ${log_file}: got ${decision}, want ${expected}" >&2
    exit 1
  fi
  event="$(printf 'policy_unavailable\t-\t1')"
  if ! while IFS= read -r line; do event_record "${line}" || true; done <"${log_file}" |
    grep -Fqx -- "${event}"; then
    echo "undersized shared dict log did not contain ${event}: ${log_file}" >&2
    exit 1
  fi
}

boundary_expected='decision action=allow reason=no_match rule_id=- policy_version=10'
test "$(log_payload "prefix cdnca_waf ${boundary_expected}, client: 127.0.0.1")" = "${boundary_expected}"
if [ "$(log_payload 'prefix cdnca_waf decision action=allow reason=no_match rule_id=- policy_version=100')" = "${boundary_expected}" ]; then
  echo 'decision version 100 matched version 10' >&2
  exit 1
fi
if [ "$(log_payload 'prefix cdnca_waf decision action=allow reason=no_match rule_id=- policy_version=10 garbage')" = "${boundary_expected}" ]; then
  echo 'decision with trailing garbage matched the exact record' >&2
  exit 1
fi
event_boundary_expected="$(printf 'rule_block\tcidr-v4-32\t10')"
test "$(event_record 'prefix cdnca_waf reason=rule_block rule_id=cidr-v4-32 policy_version=10, client: 127.0.0.1')" = "${event_boundary_expected}"
if [ "$(event_record 'prefix cdnca_waf reason=rule_block rule_id=cidr-v4-32 policy_version=100')" = "${event_boundary_expected}" ]; then
  echo 'event version 100 matched version 10' >&2
  exit 1
fi
if event_record 'prefix cdnca_waf reason=rule_block rule_id=cidr-v4-32 policy_version=10 garbage' >/dev/null; then
  echo 'event with trailing garbage was accepted' >&2
  exit 1
fi
if rule_event_record 'prefix cdnca_waf reason=request_limit rule_id=- policy_version=10' >/dev/null; then
  echo 'request diagnostic was included in rule-event parity' >&2
  exit 1
fi

docker exec --detach "${container}" /usr/local/openresty/bin/openresty \
  -g 'daemon off;' -p /work/undersized-clock/ -c nginx.conf
docker exec --detach "${container}" /usr/local/openresty/bin/openresty \
  -g 'daemon off;' -p /work/undersized-locks/ -c nginx.conf
wait_status_once 403 'http://127.0.0.1:18086/undersized-clock'
request 403 'http://127.0.0.1:18086/undersized-clock'
assert_policy_unavailable_file "${workdir}/undersized-clock/error.log"
wait_status_once 403 'http://127.0.0.1:18087/undersized-locks'
request 403 'http://127.0.0.1:18087/undersized-locks'
assert_policy_unavailable_file "${workdir}/undersized-locks/error.log"

before_allow="$(log_lines)"
request 200 -H 'Host: waf.example.test' -H 'X-Allow: yes' 'http://127.0.0.1:18081/allow?audit=1'
allow_first_line=$((before_allow + 1))
assert_decision_since "${allow_first_line}" allow allowlist_continue allow-office 1
request 200 -H 'Host: waf.example.test' 'http://127.0.0.1:18081/allow-stop'
request 200 -H 'Host: waf.example.test' 'http://127.0.0.1:18081/stop'
request 200 -H 'Host: waf.example.test' 'http://127.0.0.1:18081/continue'
request 403 -H 'Host: waf.example.test' -H 'X-Mode: strict' 'http://127.0.0.1:18081/fields?token=ok'
request 200 -H 'Host: waf.example.test' -H 'X-Mode: strict' 'http://127.0.0.1:18081/fields?token=ok&token=ok'
request 200 -H 'Host: waf.example.test' 'http://127.0.0.1:18081/fields?token=ok'
request 403 -H 'Host: waf.example.test' 'http://127.0.0.1:18081/port'
request 200 -H 'Host: waf.example.test' 'http://127.0.0.1:18082/port'
request 403 -H 'Host: waf.example.test' 'http://127.0.0.1:18081/ipv4'
request 403 -g -H 'Host: waf.example.test' 'http://[::1]:18081/ipv6'
request 403 'http://127.0.0.1:18083/startup-fail-closed'

cat >"${workdir}/policy-v2.json" <<'EOF'
{
  "schema_version":"cdnca.edge.waf/v1",
  "policy_version":2,
  "rules":[
    {"rule_id":"reload-block","priority":1,"action":"block","flow":"stop","match":{"path":{"kind":"exact","value":"/reload"}}},
    {"rule_id":"lkg-log","priority":2,"action":"log","flow":"stop","match":{"path":{"kind":"exact","value":"/lkg"}}}
  ]
}
EOF
request 200 'http://127.0.0.1:18081/reload'
publish_waf publish-v2 "${workdir}/policy-v2.json" "${workdir}/publish-v2.txt" "${workdir}/policy"
wait_status_on_two_workers 403 'http://127.0.0.1:18081/reload'
reload_v2_pid_one="${wait_pid_one}"
reload_v2_pid_two="${wait_pid_two}"
test "${reload_v2_pid_one}" != "${reload_v2_pid_two}"
request 403 'http://127.0.0.1:18081/reload'
request 200 'http://127.0.0.1:18081/lkg'

printf '%s\n' '{"schema_version":"cdnca.edge.waf/v1","policy_version":3,"rules":[' >"${workdir}/policy/.corrupt.json"
mv "${workdir}/policy/.corrupt.json" "${workdir}/policy/current.json"
sleep 0.3
request 200 'http://127.0.0.1:18081/lkg'
request 403 'http://127.0.0.1:18081/reload'

# New workers use only the sealed fallback while current is invalid.
docker kill --signal HUP "${container}" >/dev/null
wait_status_on_two_workers 200 'http://127.0.0.1:18081/reload'
# A full restart also recovers the fallback when current is missing.
rm -f "${workdir}/policy/current.json"
docker restart "${container}" >/dev/null
wait_status_on_two_workers 200 'http://127.0.0.1:18081/reload'

# An idempotent publish of the immutable latest version repairs current.
publish_waf repair-v2 "${workdir}/policy-v2.json" "${workdir}/repair-v2.txt" "${workdir}/policy"
wait_status_on_two_workers 403 'http://127.0.0.1:18081/reload'

cat >"${workdir}/policy/.duplicate.json" <<'EOF'
{"schema_version":"cdnca.edge.waf/v1","policy_version":3,"policy_version":4,"rules":[{"rule_id":"duplicate-key-block","priority":1,"action":"block","flow":"stop","match":{"path":{"kind":"exact","value":"/duplicate-key"}}}]}
EOF
mv "${workdir}/policy/.duplicate.json" "${workdir}/policy/current.json"
sleep 0.3
request 200 'http://127.0.0.1:18081/duplicate-key'
request 403 'http://127.0.0.1:18081/reload'

cat >"${workdir}/policy-v3.json" <<'EOF'
{
  "schema_version":"cdnca.edge.waf/v1",
  "policy_version":3,
  "rules":[
    {"rule_id":"v3-block","priority":1,"action":"block","flow":"stop","match":{"path":{"kind":"exact","value":"/v3"}}},
    {"rule_id":"parallel-block","priority":2,"action":"block","flow":"stop","match":{"path":{"kind":"exact","value":"/parallel-block"}}}
  ]
}
EOF
publish_waf publish-v3 "${workdir}/policy-v3.json" "${workdir}/publish-v3.txt" "${workdir}/policy"
wait_status_on_two_workers 200 'http://127.0.0.1:18081/reload'
reload_v3_pid_one="${wait_pid_one}"
reload_v3_pid_two="${wait_pid_two}"
test "${reload_v3_pid_one}" != "${reload_v3_pid_two}"
request 200 'http://127.0.0.1:18081/reload'
request 403 'http://127.0.0.1:18081/v3'

docker exec "${container}" /bin/sh -c '
  seq 1 80 | xargs -P 16 -I{} sh -c '\''
    code=$(curl --noproxy "*" --silent --output /dev/null --write-out "%{http_code}" http://127.0.0.1:18081/parallel-ok)
    test "$code" = 200
  '\''
  seq 1 80 | xargs -P 16 -I{} sh -c '\''
    code=$(curl --noproxy "*" --silent --output /dev/null --write-out "%{http_code}" http://127.0.0.1:18081/parallel-block)
    test "$code" = 403
  '\''
'

assert_event_since 1 allowlist_continue allow-office 1
assert_event_since 1 rule_block block-allow 1
assert_event_since 1 rule_log log-allow 1
assert_event_since 1 policy_rejected - 2
assert_event_since 1 rule_block parallel-block 3

fixture_policy="${repo_root}/edge/openresty/waf-fixtures/sec0405-policy.json"
fixture_requests="${repo_root}/edge/openresty/waf-fixtures/sec0405-requests.jsonl"
before_load="$(log_lines)"
publish_waf publish-parity "${fixture_policy}" "${workdir}/publish-parity.txt" "${workdir}/policy"
first_load_line=$((before_load + 1))
wait_event_since "${first_load_line}" policy_loaded - 10
wait_status_on_two_workers 403 -H 'Host: waf.example.test' 'http://127.0.0.1:18081/cidr-v4-32'
parity_pid_one="${wait_pid_one}"
parity_pid_two="${wait_pid_two}"
test "${parity_pid_one}" != "${parity_pid_two}"
"${workdir}/waf-evaluate" -input "${fixture_policy}" <"${fixture_requests}" >"${workdir}/go-decisions.jsonl"
test "$(wc -l <"${fixture_requests}" | tr -d ' ')" = "$(wc -l <"${workdir}/go-decisions.jsonl" | tr -d ' ')"

paste "${fixture_requests}" "${workdir}/go-decisions.jsonl" |
while IFS="$(printf '\t')" read -r request_json decision_json; do
  case_id="$(printf '%s' "${request_json}" | jq -er '.case_id')"
  test "$(printf '%s' "${decision_json}" | jq -er '.case_id')" = "${case_id}"
  host="$(printf '%s' "${request_json}" | jq -er '.host')"
  port="$(printf '%s' "${request_json}" | jq -er '.port')"
  method="$(printf '%s' "${request_json}" | jq -er '.method')"
  path="$(printf '%s' "${request_json}" | jq -er '.path')"
  source_addr="$(printf '%s' "${request_json}" | jq -er '.source_addr')"
  token="$(printf '%s' "${request_json}" | jq -r '.query.token[0] // empty')"
  mode="$(printf '%s' "${request_json}" | jq -r '.header["X-Mode"][0] // empty')"
  case "${source_addr}" in
    127.0.0.1) request_host='127.0.0.1' ;;
    ::1) request_host='[::1]' ;;
    ::ffff:127.0.0.1) request_host='[::ffff:127.0.0.1]' ;;
    *) echo "unsupported parity source_addr ${source_addr}" >&2; exit 1 ;;
  esac
  if [ -n "${token}" ]; then
    path="${path}?token=$(printf '%s' "${token}" | jq -sRr @uri)"
  fi
  set -- -X "${method}" -H "Host: ${host}"
  if [ -n "${mode}" ]; then
    set -- "$@" -H "X-Mode: ${mode}"
  fi
  expected_action="$(printf '%s' "${decision_json}" | jq -er '.action')"
  expected_reason="$(printf '%s' "${decision_json}" | jq -er '.reason')"
  expected_rule_id="$(printf '%s' "${decision_json}" | jq -r '.rule_id // "-"')"
  expected_version="$(printf '%s' "${decision_json}" | jq -er '.policy_version')"
  if [ "${expected_action}" = block ]; then
    expected_status=403
  else
    expected_status=200
  fi
  before="$(log_lines)"
  request "${expected_status}" "$@" "http://${request_host}:${port}${path}"
  first_line=$((before + 1))
  assert_decision_since "${first_line}" "${expected_action}" "${expected_reason}" "${expected_rule_id}" "${expected_version}"
  if [ "${expected_reason}" = request_limit ]; then
    assert_event_since "${first_line}" request_limit - "${expected_version}"
  fi
  expected_events="$(printf '%s' "${decision_json}" | jq -r --arg version "${expected_version}" \
    '.events[] | [.reason, .rule_id, $version] | @tsv')"
  actual_events="$(tail -n "+${first_line}" "${workdir}/error.log" |
    while IFS= read -r line; do
      rule_event_record "${line}" || true
    done)"
  if [ "${actual_events}" != "${expected_events}" ]; then
    printf 'parity events mismatch for %s:\ngot:\n%s\nwant:\n%s\n' \
      "${case_id}" "${actual_events}" "${expected_events}" >&2
    exit 1
  fi
done

reject_candidate() {
  candidate="$1"
  cp "${candidate}" "${workdir}/policy/current.json"
  sleep 0.3
  before="$(log_lines)"
  request 403 'http://127.0.0.1:18081/cidr-v4-32'
  first_line=$((before + 1))
  assert_decision_since "${first_line}" block rule_block cidr-v4-32 10
  assert_event_since "${first_line}" policy_rejected - 10
}

cat >"${workdir}/unknown.json" <<'EOF'
{"schema_version":"cdnca.edge.waf/v1","policy_version":11,"rules":[],"unknown":true}
EOF
cat >"${workdir}/rules-object.json" <<'EOF'
{"schema_version":"cdnca.edge.waf/v1","policy_version":11,"rules":{}}
EOF
cat >"${workdir}/mapped.json" <<'EOF'
{"schema_version":"cdnca.edge.waf/v1","policy_version":11,"rules":[{"rule_id":"mapped","priority":1,"action":"block","flow":"stop","match":{"source_cidr":{"family":6,"network":[0,0,0,0,0,0,0,0,0,0,255,255,192,0,2,0],"prefix_length":120}}}]}
EOF
cat >"${workdir}/unmasked.json" <<'EOF'
{"schema_version":"cdnca.edge.waf/v1","policy_version":11,"rules":[{"rule_id":"unmasked","priority":1,"action":"block","flow":"stop","match":{"source_cidr":{"family":4,"network":[127,0,0,1],"prefix_length":31}}}]}
EOF
cat >"${workdir}/bad-prefix.json" <<'EOF'
{"schema_version":"cdnca.edge.waf/v1","policy_version":11,"rules":[{"rule_id":"bad-prefix","priority":1,"action":"block","flow":"stop","match":{"source_cidr":{"family":6,"network":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"prefix_length":129}}}]}
EOF
cat >"${workdir}/unsorted.json" <<'EOF'
{"schema_version":"cdnca.edge.waf/v1","policy_version":11,"rules":[{"rule_id":"later","priority":2,"action":"block","flow":"stop","match":{"method":"GET"}},{"rule_id":"earlier","priority":1,"action":"block","flow":"stop","match":{"method":"GET"}}]}
EOF
cat >"${workdir}/duplicate-rule.json" <<'EOF'
{"schema_version":"cdnca.edge.waf/v1","policy_version":11,"rules":[{"rule_id":"same","priority":1,"action":"block","flow":"stop","match":{"method":"GET"}},{"rule_id":"same","priority":2,"action":"block","flow":"stop","match":{"method":"GET"}}]}
EOF
cat >"${workdir}/control-comment.json" <<'EOF'
{"schema_version":"cdnca.edge.waf/v1","policy_version":11,"rules":[{"rule_id":"control-comment","priority":1,"action":"block","flow":"stop","comment":"bad\u000acomment","match":{"source_cidr":{"family":4,"network":[127,0,0,1],"prefix_length":32}}}]}
EOF
cat >"${workdir}/unicode-control-comment.json" <<'EOF'
{"schema_version":"cdnca.edge.waf/v1","policy_version":11,"rules":[{"rule_id":"unicode-control-comment","priority":1,"action":"block","flow":"stop","comment":"bad\u0085comment","match":{"source_cidr":{"family":4,"network":[127,0,0,1],"prefix_length":32}}}]}
EOF
cat >"${workdir}/whitespace-controls-comment.json" <<'EOF'
{"schema_version":"cdnca.edge.waf/v1","policy_version":11,"rules":[{"rule_id":"whitespace-controls-comment","priority":1,"action":"block","flow":"stop","comment":"\u0009\u000a\u000b\u000c\u000d\u0085","match":{"source_cidr":{"family":4,"network":[127,0,0,1],"prefix_length":32}}}]}
EOF
cat >"${workdir}/nbsp-comment.json" <<'EOF'
{"schema_version":"cdnca.edge.waf/v1","policy_version":11,"rules":[{"rule_id":"nbsp-comment","priority":1,"action":"block","flow":"stop","comment":"\u00a0","match":{"source_cidr":{"family":4,"network":[127,0,0,1],"prefix_length":32}}}]}
EOF
cat >"${workdir}/ideographic-space-comment.json" <<'EOF'
{"schema_version":"cdnca.edge.waf/v1","policy_version":11,"rules":[{"rule_id":"ideographic-space-comment","priority":1,"action":"block","flow":"stop","comment":"\u3000","match":{"source_cidr":{"family":4,"network":[127,0,0,1],"prefix_length":32}}}]}
EOF
cat >"${workdir}/mixed-space-comment.json" <<'EOF'
{"schema_version":"cdnca.edge.waf/v1","policy_version":11,"rules":[{"rule_id":"mixed-space-comment","priority":1,"action":"block","flow":"stop","comment":" \u00a0\u3000 ","match":{"source_cidr":{"family":4,"network":[127,0,0,1],"prefix_length":32}}}]}
EOF
cat >"${workdir}/unicode-whitespace-all-comment.json" <<'EOF'
{"schema_version":"cdnca.edge.waf/v1","policy_version":11,"rules":[{"rule_id":"unicode-whitespace-all-comment","priority":1,"action":"block","flow":"stop","comment":"\u0020\u00a0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a\u2028\u2029\u202f\u205f\u3000","match":{"source_cidr":{"family":4,"network":[127,0,0,1],"prefix_length":32}}}]}
EOF
cat >"${workdir}/unicode-space-valid.json" <<'EOF'
{"schema_version":"cdnca.edge.waf/v1","policy_version":11,"rules":[{"rule_id":"unicode-space-valid","priority":1,"action":"block","flow":"stop","comment":"\u0020\u00a0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a\u2028\u2029\u202f\u205f\u3000valid","match":{"path":{"kind":"exact","value":"/unicode-space-valid"},"source_cidr":{"family":4,"network":[127,0,0,1],"prefix_length":32}}}]}
EOF
cat >"${workdir}/metadata-without-cidr.json" <<'EOF'
{"schema_version":"cdnca.edge.waf/v1","policy_version":11,"rules":[{"rule_id":"metadata-without-cidr","priority":1,"action":"block","flow":"stop","comment":"temporary","expires_at_unix":2000000000,"match":{"method":"GET"}}]}
EOF
cat >"${workdir}/downgrade.json" <<'EOF'
{"schema_version":"cdnca.edge.waf/v1","policy_version":9,"rules":[]}
EOF
cat >"${workdir}/same-version.json" <<'EOF'
{"schema_version":"cdnca.edge.waf/v1","policy_version":10,"rules":[]}
EOF
awk 'BEGIN {
  print "{\"schema_version\":\"cdnca.edge.waf/v1\",\"policy_version\":11,\"rules\":["
  for (i = 1; i <= 513; i++) {
    if (i > 1) printf ","
    printf "{\"rule_id\":\"rule-%03d\",\"priority\":%d,\"action\":\"block\",\"flow\":\"stop\",\"match\":{\"method\":\"GET\"}}", i, i
  }
  print "]}"
}' >"${workdir}/over-limit.json"

for candidate in unknown rules-object mapped unmasked bad-prefix unsorted duplicate-rule control-comment unicode-control-comment whitespace-controls-comment nbsp-comment ideographic-space-comment mixed-space-comment unicode-whitespace-all-comment metadata-without-cidr downgrade same-version over-limit; do
  reject_candidate "${workdir}/${candidate}.json"
done

cp "${workdir}/unicode-space-valid.json" "${workdir}/policy/current.json"
sleep 0.3
before="$(log_lines)"
request 403 'http://127.0.0.1:18081/unicode-space-valid'
first_line=$((before + 1))
assert_decision_since "${first_line}" block rule_block unicode-space-valid 11
assert_event_since "${first_line}" policy_loaded - 11

cat >"${workdir}/clock-v1.json" <<'EOF'
{"schema_version":"cdnca.edge.waf/v1","policy_version":1,"rules":[{"rule_id":"temporary-clock-block","priority":1,"action":"block","flow":"stop","comment":"expires at the exact boundary","expires_at":"2030-01-02T03:04:05Z","match":{"path":{"kind":"exact","value":"/clock"},"source_cidr":"127.0.0.1/32"}}]}
EOF
publish_waf publish-clock-v1 "${workdir}/clock-v1.json" "${workdir}/publish-clock-v1.txt" "${workdir}/clock"
expiry="$(jq -er '.rules[0].expires_at_unix' "${workdir}/clock/current.json")"
before_expiry=$((expiry - 1))
rollback_time=$((expiry - 3600))

before="$(log_lines)"
clock_before_pid="$(request_pid 403 -H "X-WAF-Test-Now: ${before_expiry}" 'http://127.0.0.1:18084/clock')"
assert_decision_since "$((before + 1))" block rule_block temporary-clock-block 1
before="$(log_lines)"
clock_expiry_pid="$(request_pid 200 -H "X-WAF-Test-Now: ${expiry}" 'http://127.0.0.1:18084/clock')"
first_line=$((before + 1))
assert_decision_since "${first_line}" allow no_match - 1
assert_event_since "${first_line}" rule_expired temporary-clock-block 1
before="$(log_lines)"
clock_rollback_pid="$(request_different_pid 200 "${clock_expiry_pid}" \
  -H "X-WAF-Test-Now: ${rollback_time}" 'http://127.0.0.1:18084/clock')"
first_line=$((before + 1))
assert_decision_since "${first_line}" allow no_match - 1
assert_event_since "${first_line}" rule_expired temporary-clock-block 1
test "${clock_expiry_pid}" != "${clock_rollback_pid}"
case "${clock_before_pid}:${clock_expiry_pid}:${clock_rollback_pid}" in
  *[!0-9:]*) echo 'clock worker PID evidence is malformed' >&2; exit 1 ;;
esac

sed 's/"policy_version":1/"policy_version":2/' "${workdir}/clock-v1.json" >"${workdir}/clock-v2.json"
publish_waf publish-clock-v2 "${workdir}/clock-v2.json" "${workdir}/publish-clock-v2.txt" "${workdir}/clock"
sleep 0.3
before="$(log_lines)"
request_pid 200 -H "X-WAF-Test-Now: ${rollback_time}" 'http://127.0.0.1:18084/clock' >/dev/null
first_line=$((before + 1))
assert_decision_since "${first_line}" allow no_match - 2
assert_event_since "${first_line}" rule_expired temporary-clock-block 2

printf 'openresty_version=%s\npolicy_v1_sha256=%s\nworker_processes=2\nreload_v2_worker_pids=%s,%s\nreload_v3_worker_pids=%s,%s\nparity_worker_pids=%s,%s\nclock_worker_pids=%s,%s,%s\nstrict_invalid_rejected=true\nduplicate_json_rejected=true\nrules_array_token=true\ncontinue_stop=true\nallowlist_priority=true\nhost_port=true\nheader_query=true\ncidr_ipv4_boundaries=true\ncidr_ipv6_boundaries=true\nmapped_ipv6_rejected=true\nmapped_request_parity=true\nlist_metadata=true\nunicode_trim_space=true\nexpiry_observable=true\nclock_rollback_no_revival=true\ncross_worker_clock_rollback=true\nundersized_shared_dicts_fail_closed=true\ngo_lua_parity_cases=14\nstartup_fail_closed=true\ncorrupt_candidate_kept_lkg=true\ndurable_fallback=true\nhup_bad_current_fallback=true\nrestart_missing_current_fallback=true\ninvalid_candidates_kept_lkg=18\nreload_v2_v3=true\nconcurrent_allowed=80\nconcurrent_blocked=80\nexact_log_records=true\nstable_final_decisions=true\n' \
  "${OPENRESTY_VERSION}" "${v1_digest}" \
  "${reload_v2_pid_one}" "${reload_v2_pid_two}" "${reload_v3_pid_one}" "${reload_v3_pid_two}" \
  "${parity_pid_one}" "${parity_pid_two}" \
  "${clock_before_pid}" "${clock_expiry_pid}" "${clock_rollback_pid}"
