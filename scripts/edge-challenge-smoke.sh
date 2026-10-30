#!/bin/sh
set -eu

serve=0
case "${1:-}" in
  "") ;;
  --serve) serve=1 ;;
  *) echo "usage: $0 [--serve]" >&2; exit 2 ;;
esac

repo_root="$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)"
# shellcheck source=edge/openresty/runtime.env
# shellcheck disable=SC1091
. "${repo_root}/edge/openresty/runtime.env"

# Physical path: key files are opened component by component without
# following symlinks (challenge readSecureKey), and macOS /tmp, /var are links.
tmp_base="$(CDPATH='' cd -- "${TMPDIR:-/tmp}" && pwd -P)"
workdir="$(mktemp -d "${tmp_base%/}/cdnca-edge-challenge.XXXXXX")"
suffix="$(basename "${workdir}" | sed 's/^cdnca-edge-challenge\.//')"
container="cdnca-edge-challenge-${suffix}"
bad_container="${container}-bad"

cleanup() {
  docker rm -f "${bad_container}" "${container}" >/dev/null 2>&1 || true
  case "${workdir}" in
    "${tmp_base%/}"/cdnca-edge-challenge.*)
      chmod -R u+w "${workdir}" 2>/dev/null || true
      rm -rf -- "${workdir}"
      ;;
    *) echo "refusing to remove unexpected path: ${workdir}" >&2 ;;
  esac
}
trap cleanup EXIT HUP INT TERM

fail() {
  echo "edge challenge smoke: $*" >&2
  if docker inspect "${container}" >/dev/null 2>&1; then
    docker logs "${container}" >&2 || true
  fi
  if [ -f "${workdir}/runtime/logs/error.log" ]; then
    tail -n 80 "${workdir}/runtime/logs/error.log" >&2 || true
  fi
  exit 1
}

mkdir -p "${workdir}/keys" "${workdir}/policy" "${workdir}/runtime/logs"
chmod 0700 "${workdir}/keys" "${workdir}/policy"
umask 077
openssl rand -hex 48 | tr -d '\n' >"${workdir}/keys/key-1"
openssl rand -hex 48 | tr -d '\n' >"${workdir}/keys/key-2"
chmod 0600 "${workdir}/keys/key-1" "${workdir}/keys/key-2"

(
  cd "${repo_root}/agents/edge-agent"
  GOWORK=off go build -trimpath -o "${workdir}/challenge-policy" ./internal/challenge/cmd/challenge-policy
)

publish_policy() {
  publish_version="$1"
  publish_current_id="$2"
  publish_current_file="$3"
  publish_previous_id="$4"
  publish_previous_file="$5"
  publish_trusted="$6"
  publish_b_mode="$7"
  publish_pass_ttl="$8"
  publish_failures="$9"

  if [ -n "${publish_previous_id}" ]; then
    publish_previous="$(jq -cn \
      --arg key_id "${publish_previous_id}" --arg key_file "${publish_previous_file}" \
      '{key_id:$key_id,key_file:$key_file}')"
  else
    publish_previous='null'
  fi
  if [ "${publish_b_mode}" = delay ]; then
    publish_b_delay=5
  else
    publish_b_delay=0
  fi

  jq -n \
    --argjson version "${publish_version}" \
    --arg current_id "${publish_current_id}" \
    --arg current_file "${publish_current_file}" \
    --argjson previous "${publish_previous}" \
    --argjson trusted "${publish_trusted}" \
    --arg b_mode "${publish_b_mode}" \
    --argjson b_delay "${publish_b_delay}" \
    --argjson pass_ttl "${publish_pass_ttl}" \
    --argjson failures "${publish_failures}" \
    '{
      schema_version:"cdnca.edge.challenge/v1",
      policy_version:$version,
      algorithm:"hmac-sha256",
      cookie_name:"__Host-cdnca_challenge",
      trusted_proxies:$trusted,
      bypass_routes:[
        {kind:"prefix",path:"/.well-known/acme-challenge/"},
        {kind:"prefix",path:"/agent/"},
        {kind:"prefix",path:"/api/"},
        {kind:"prefix",path:"/events/"},
        {kind:"exact",path:"/healthz"},
        {kind:"prefix",path:"/import/"},
        {kind:"prefix",path:"/ws/"}
      ],
      current_key:{key_id:$current_id,key_file:$current_file},
      previous_key:$previous,
      rules:[
        {
          rule_id:"delay-gate",priority:10,tenant_id:"tenant-a",site_id:"site-a",host:"edge-a.test",
          mode:"delay",min_delay_seconds:5,challenge_ttl_seconds:60,pass_ttl_seconds:$pass_ttl,
          clock_skew_seconds:1,attempts_per_nonce:1,failure_window_seconds:30,
          max_failures_per_window:$failures,ip_binding:"exact",bind_user_agent:true
        },
        {
          rule_id:"site-b-gate",priority:20,tenant_id:"tenant-a",site_id:"site-b",host:"edge-b.test",
          mode:$b_mode,min_delay_seconds:$b_delay,challenge_ttl_seconds:60,pass_ttl_seconds:$pass_ttl,
          clock_skew_seconds:1,attempts_per_nonce:1,failure_window_seconds:30,
          max_failures_per_window:$failures,ip_binding:"exact",bind_user_agent:true
        },
        {
          rule_id:"site-c-click",priority:30,tenant_id:"tenant-a",site_id:"site-c",host:"edge-c.test",
          mode:"click",min_delay_seconds:0,challenge_ttl_seconds:60,pass_ttl_seconds:$pass_ttl,
          clock_skew_seconds:1,attempts_per_nonce:1,failure_window_seconds:30,
          max_failures_per_window:$failures,ip_binding:"none",bind_user_agent:false
        },
        {
          rule_id:"site-d-slider",priority:40,tenant_id:"tenant-a",site_id:"site-d",host:"edge-d.test",
          mode:"slider",min_delay_seconds:0,challenge_ttl_seconds:60,pass_ttl_seconds:$pass_ttl,
          clock_skew_seconds:1,attempts_per_nonce:1,failure_window_seconds:30,
          max_failures_per_window:$failures,ip_binding:"exact",bind_user_agent:true
        },
        {
          rule_id:"site-e-captcha",priority:50,tenant_id:"tenant-a",site_id:"site-e",host:"edge-e.test",
          mode:"captcha",min_delay_seconds:0,challenge_ttl_seconds:60,pass_ttl_seconds:$pass_ttl,
          clock_skew_seconds:1,attempts_per_nonce:1,failure_window_seconds:30,
          max_failures_per_window:$failures,ip_binding:"exact",bind_user_agent:true
        }
      ]
    }' >"${workdir}/candidate.json"
  "${workdir}/challenge-policy" -root "${workdir}/policy" \
    <"${workdir}/candidate.json" >"${workdir}/publish-${publish_version}.log"
}

key_1="${workdir}/keys/key-1"
key_2="${workdir}/keys/key-2"
publish_policy 1 key-1 "${key_1}" "" "" '[]' click 30 20

openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
  -subj '/CN=edge-a.test' \
  -keyout "${workdir}/runtime/tls.key" \
  -out "${workdir}/runtime/tls.crt" >/dev/null 2>&1
chmod 0600 "${workdir}/runtime/tls.key"

cat >"${workdir}/runtime/nginx.conf" <<'EOF'
worker_processes 1;
pid /tmp/cdnca-challenge-nginx.pid;
error_log /runtime/logs/error.log notice;

events { worker_connections 1024; }

http {
    lua_package_path '/opt/cdnca-challenge/?.lua;;';
    lua_shared_dict cdnca_challenge_state 128k;
    lua_shared_dict smoke_metrics 64k;
    log_format challenge_smoke '$request_method $host $uri $status';
    access_log /runtime/logs/access.log challenge_smoke;

    map $host $challenge_site {
        default "";
        edge-a.test site-a;
        edge-b.test site-b;
        edge-c.test site-c;
        edge-d.test site-d;
        edge-e.test site-e;
    }

    init_worker_by_lua_block {
        require("engine").init({
            policy_path = "/policy/current.json",
            state_dict = "cdnca_challenge_state",
            reload_interval = 0.05,
        })
    }

    server {
        listen 8443 ssl;
        ssl_certificate /runtime/tls.crt;
        ssl_certificate_key /runtime/tls.key;
        ssl_protocols TLSv1.2 TLSv1.3;
        server_name _;

        location / {
            access_by_lua_block {
                ngx.shared.smoke_metrics:incr("machine_guard_hits", 1, 0)
                if ngx.var.uri == "/api/blocked" then
                    return ngx.exit(429)
                end
                local context = {
                    tenant_id = "tenant-a",
                    site_id = ngx.var.challenge_site,
                }
                if ngx.var.uri == "/decision-bad-context" then
                    context.site_id = ""
                elseif ngx.var.uri == "/decision-bad-rule" then
                    context.site_id = "missing-site"
                end
                return require("engine").access(context)
            }
            header_filter_by_lua_block {
                local decision = ngx.ctx.cdnca_challenge_decision
                if type(decision) == "table" then
                    ngx.header["X-CDNCA-Challenge-Test-Decision"] = require("cjson.safe").encode(decision)
                end
            }
            proxy_set_header Host $host;
            proxy_pass http://127.0.0.1:8081;
        }
    }

    server {
        listen 8081;
        server_name _;
        location / {
            content_by_lua_block {
                local hits = ngx.shared.smoke_metrics:incr("origin_hits", 1, 0)
                ngx.header["Content-Type"] = "text/plain"
                ngx.say("origin-ok:", hits)
            }
        }
    }

    server {
        listen 8082;
        server_name _;

        location = /status {
            content_by_lua_block { ngx.say(require("engine").policy_version()) }
        }
        location = /hits {
            content_by_lua_block { ngx.say(ngx.shared.smoke_metrics:get("origin_hits") or 0) }
        }
        location = /guards {
            content_by_lua_block { ngx.say(ngx.shared.smoke_metrics:get("machine_guard_hits") or 0) }
        }
        location = /client {
            content_by_lua_block { ngx.say(require("engine").resolve_client_ip() or "invalid") }
        }
        location = /clear {
            content_by_lua_block {
                local dict = ngx.shared.cdnca_challenge_state
                dict:flush_all()
                dict:flush_expired()
                ngx.say("cleared")
            }
        }
        location = /fill {
            content_by_lua_block {
                local dict = ngx.shared.cdnca_challenge_state
                local value = string.rep("x", 2048)
                for index = 1, 10000 do
                    local ok, err, forcible = dict:set("smoke-fill:" .. index, value, 30)
                    if not ok then
                        ngx.status = 500
                        ngx.say(err or "set failed")
                        return
                    end
                    if forcible then
                        ngx.say("forcible")
                        return
                    end
                end
                ngx.status = 500
                ngx.say("capacity not reached")
            }
        }
    }
}
EOF

cat >"${workdir}/runtime/bad-nginx.conf" <<'EOF'
worker_processes 1;
pid /tmp/cdnca-challenge-bad-nginx.pid;
error_log stderr notice;
events { worker_connections 128; }
http {
    lua_package_path '/opt/cdnca-challenge/?.lua;;';
    lua_shared_dict cdnca_challenge_state 64k;
    init_worker_by_lua_block {
        require("engine").init({
            policy_path = "/missing/current.json",
            state_dict = "cdnca_challenge_state",
            reload_interval = 0.1,
        })
    }
    server {
        listen 8090;
        location / {
            access_by_lua_block {
                return require("engine").access({
                    tenant_id = "tenant-a",
                    site_id = "site-a",
                })
            }
            content_by_lua_block { ngx.say("must-not-reach-origin") }
        }
    }
}
EOF

docker run --detach \
  --name "${bad_container}" \
  --volume "${repo_root}/edge/openresty/challenge:/opt/cdnca-challenge:ro" \
  --volume "${workdir}/runtime:/runtime" \
  --entrypoint /usr/local/openresty/bin/openresty \
  "${OPENRESTY_IMAGE}" \
  -p /runtime/ -c bad-nginx.conf -g 'daemon off;' >/dev/null
sleep 0.2
bad_body="$(docker exec "${bad_container}" curl --noproxy '*' --silent \
  --max-time 1 http://127.0.0.1:8090/ 2>/dev/null || true)"
[ "${bad_body}" != must-not-reach-origin ] || fail "invalid startup policy reached origin"
bad_attempt=0
while ! docker logs "${bad_container}" 2>&1 | grep -F 'no valid challenge policy code=policy_open_failed' >/dev/null; do
  bad_attempt=$((bad_attempt + 1))
  if [ "${bad_attempt}" -ge 30 ]; then
    docker logs "${bad_container}" >&2 || true
    fail "invalid startup policy did not fail closed"
  fi
  sleep 0.1
done
docker rm -f "${bad_container}" >/dev/null

docker run --detach \
  --name "${container}" \
  --publish 127.0.0.1::8443 \
  --publish 127.0.0.1::8082 \
  --volume "${repo_root}/edge/openresty/challenge:/opt/cdnca-challenge:ro" \
  --volume "${workdir}/policy:/policy:ro" \
  --volume "${workdir}/runtime:/runtime" \
  --volume "${workdir}:${workdir}:ro" \
  --entrypoint /usr/local/openresty/bin/openresty \
  "${OPENRESTY_IMAGE}" \
  -p /runtime/ -c nginx.conf -g 'daemon off;' >/dev/null

edge_published="$(docker port "${container}" 8443/tcp | tail -n 1)"
admin_published="$(docker port "${container}" 8082/tcp | tail -n 1)"
case "${edge_published}:${admin_published}" in
  127.0.0.1:*:127.0.0.1:*) ;;
  *) fail "ports are not loopback-only: ${edge_published} ${admin_published}" ;;
esac
edge_port="${edge_published##*:}"
admin_url="http://${admin_published}"
smoke_ua='cdnca-challenge-smoke/1.0'

wait_version() {
  expected="$1"
  attempt=0
  while [ "${attempt}" -lt 100 ]; do
    actual="$(curl --noproxy '*' --silent "${admin_url}/status" 2>/dev/null || true)"
    [ "${actual}" = "${expected}" ] && return 0
    docker inspect --format '{{.State.Running}}' "${container}" 2>/dev/null \
      | grep -Fx true >/dev/null || fail "OpenResty stopped while waiting for policy ${expected}"
    attempt=$((attempt + 1))
    sleep 0.1
  done
  fail "policy version did not become ${expected}; last=${actual}"
}

request_status() {
  request_host="$1"
  request_path="$2"
  shift 2
  request_accept='text/html'
  if [ "${1:-}" = --smoke-accept ]; then
    [ "$#" -ge 2 ] || fail "missing smoke Accept value"
    request_accept="$2"
    shift 2
  fi
  request_result="$(curl --noproxy '*' --silent --show-error --insecure \
    --resolve "${request_host}:${edge_port}:127.0.0.1" \
    --user-agent "${smoke_ua}" \
    --header "Accept: ${request_accept}" \
    --dump-header "${workdir}/last.headers" \
    --output "${workdir}/last.body" \
    --write-out '%{http_code}' \
    "$@" "https://${request_host}:${edge_port}${request_path}")"
  assert_decision_shape
  printf '%s' "${request_result}"
}

request_status_without_challenge() {
  request_host="$1"
  request_path="$2"
  shift 2
  curl --noproxy '*' --silent --show-error --insecure \
    --resolve "${request_host}:${edge_port}:127.0.0.1" \
    --user-agent "${smoke_ua}" \
    --header 'Accept: text/html' \
    --dump-header "${workdir}/last.headers" \
    --output "${workdir}/last.body" \
    --write-out '%{http_code}' \
    "$@" "https://${request_host}:${edge_port}${request_path}"
}

decision_json() {
  awk 'tolower($0) ~ /^x-cdnca-challenge-test-decision:/ {
    sub(/^[^:]*:[[:space:]]*/, "")
    sub(/\r$/, "")
    print
  }' "${workdir}/last.headers"
}

assert_decision_shape() {
  decision_count="$(grep -Eic '^X-CDNCA-Challenge-Test-Decision:' "${workdir}/last.headers" || true)"
  [ "${decision_count}" -eq 1 ] || fail "challenge request emitted ${decision_count} decision headers, want exactly one"
  decision_value="$(decision_json)"
  [ "${#decision_value}" -le 512 ] || fail "challenge decision header exceeded 512 bytes"
  printf '%s' "${decision_value}" | jq -e '
    type == "object"
    and keys == ["decision","fallback_reason","policy_state","policy_version","reason","rule_id","status"]
    and (.decision == "allow" or .decision == "challenge" or .decision == "block" or .decision == "error")
    and (.reason | type == "string" and length >= 1 and length <= 64 and test("^[a-z][a-z0-9_]*$"))
    and (.status == 0 or .status == 200 or .status == 303 or .status == 403 or .status == 405 or .status == 429 or .status == 503)
    and (.policy_version | type == "number" and floor == . and . >= 0)
    and (.rule_id | type == "string" and length >= 1 and length <= 128 and test("^-$|^[A-Za-z0-9][A-Za-z0-9._:-]*$"))
    and (.policy_state == "active" or .policy_state == "lkg" or .policy_state == "unavailable")
    and (.fallback_reason | type == "string" and length >= 1 and length <= 64 and test("^-$|^[a-z][a-z0-9_]*$"))
  ' >/dev/null || fail "challenge decision did not match the bounded seven-key contract"
}

assert_last_decision() {
  expected_decision="$1"
  expected_reason="$2"
  expected_status="$3"
  expected_version="$4"
  expected_rule="$5"
  expected_state="$6"
  expected_fallback="$7"
  decision_value="$(decision_json)"
  printf '%s' "${decision_value}" | jq -e \
    --arg decision "${expected_decision}" \
    --arg reason "${expected_reason}" \
    --argjson status "${expected_status}" \
    --argjson policy_version "${expected_version}" \
    --arg rule_id "${expected_rule}" \
    --arg policy_state "${expected_state}" \
    --arg fallback_reason "${expected_fallback}" \
    '. == {
      decision:$decision,
      reason:$reason,
      status:$status,
      policy_version:$policy_version,
      rule_id:$rule_id,
      policy_state:$policy_state,
      fallback_reason:$fallback_reason
    }' >/dev/null || fail "unexpected challenge decision: ${decision_value}"
}

expect_status() {
  expected="$1"
  request_host="$2"
  request_path="$3"
  shift 3
  actual="$(request_status "${request_host}" "${request_path}" "$@")"
  [ "${actual}" = "${expected}" ] || fail "${request_host}${request_path}: status ${actual}, want ${expected}"
}

origin_hits() {
  curl --noproxy '*' --fail --silent --show-error "${admin_url}/hits"
}

guard_hits() {
  curl --noproxy '*' --fail --silent --show-error "${admin_url}/guards"
}

assert_hits() {
  expected="$1"
  actual="$(origin_hits)"
  [ "${actual}" = "${expected}" ] || fail "origin hits ${actual}, want ${expected}"
}

nonce_from_last_body() {
  sed -n 's/.*name="nonce" value="\([^"]*\)".*/\1/p' "${workdir}/last.body"
}

response_from_last_body() {
  response_mode="$1"
  case "${response_mode}" in
    delay|click)
      sed -n 's/.*name="response" value="\([^"]*\)".*/\1/p' "${workdir}/last.body"
      ;;
    slider)
      sed -n 's/.*目标位置：\([0-9][0-9]*\)%.*/\1/p' "${workdir}/last.body"
      ;;
    captcha)
      sed -n 's/.*class="captcha"[^>]*>\([0-9A-F][0-9A-F]*\)<\/div>.*/\1/p' "${workdir}/last.body"
      ;;
    *) fail "unknown response mode ${response_mode}" ;;
  esac
}

cookie_from_last_headers() {
  sed -n 's/^[Ss]et-[Cc]ookie: \([^;]*\).*/\1/p' "${workdir}/last.headers" \
    | tr -d '\r' | tail -n 1
}

get_nonce() {
  nonce_host="$1"
  nonce_path="$2"
  shift 2
  expect_status 200 "${nonce_host}" "${nonce_path}" "$@"
  nonce_value="$(nonce_from_last_body)"
  [ "${#nonce_value}" -eq 32 ] || fail "challenge page did not contain a bounded nonce"
  printf '%s' "${nonce_value}"
}

submit_nonce() {
  submit_host="$1"
  submit_nonce_value="$2"
  submit_response="$3"
  shift 3
  request_status "${submit_host}" '/.cdnca/challenge/verify' \
    --request POST \
    --header 'Content-Type: application/x-www-form-urlencoded' \
    --data "nonce=${submit_nonce_value}&response=${submit_response}" "$@"
}

solve_click() {
  solve_host="$1"
  shift
  case "${solve_host}" in
    edge-b.test) solve_rule=site-b-gate ;;
    edge-c.test) solve_rule=site-c-click ;;
    *) fail "unsupported click host ${solve_host}" ;;
  esac
  solve_nonce="$(get_nonce "${solve_host}" '/click' "$@")"
  solve_version="$(curl --noproxy '*' --fail --silent --show-error "${admin_url}/status")"
  assert_last_decision challenge pass_cookie_missing 200 "${solve_version}" "${solve_rule}" active -
  solve_response="$(response_from_last_body click)"
  [ -n "${solve_response}" ] || fail "click page did not contain a server-bound response"
  sleep 0.25
  solve_status="$(submit_nonce "${solve_host}" "${solve_nonce}" "${solve_response}" "$@")"
  [ "${solve_status}" = 303 ] || fail "click proof returned ${solve_status}"
  assert_last_decision allow proof_valid 303 "${solve_version}" "${solve_rule}" active -
  solve_cookie="$(cookie_from_last_headers)"
  [ -n "${solve_cookie}" ] || fail "click proof did not issue a pass cookie"
  printf '%s' "${solve_cookie}"
}

decode_cookie_payload() {
  decode_value="${1#*=}"
  decode_encoded="${decode_value%%.*}"
  decode_remainder=$((${#decode_encoded} % 4))
  case "${decode_remainder}" in
    0) decode_padding='' ;;
    2) decode_padding='==' ;;
    3) decode_padding='=' ;;
    *) fail "invalid cookie encoding" ;;
  esac
  printf '%s%s' "${decode_encoded}" "${decode_padding}" | tr '_-' '/+' | openssl base64 -d -A
}

signed_time_cookie() {
  source_cookie="$1"
  issued="$2"
  expires="$3"
  signing_key="$4"
  source_value="${source_cookie#*=}"
  encoded="${source_value%%.*}"
  remainder=$((${#encoded} % 4))
  case "${remainder}" in
    0) padding='' ;;
    2) padding='==' ;;
    3) padding='=' ;;
    *) fail "invalid source cookie encoding" ;;
  esac
  payload="$(printf '%s%s' "${encoded}" "${padding}" | tr '_-' '/+' | openssl base64 -d -A)"
  old_ifs="${IFS}"
  IFS='|'
  # shellcheck disable=SC2086
  set -- ${payload}
  IFS="${old_ifs}"
  [ "$#" -eq 7 ] || fail "invalid source cookie payload"
  altered="$1|$2|${issued}|${expires}|$5|$6|$7"
  altered_encoded="$(printf '%s' "${altered}" | openssl base64 -A | tr '+/' '-_' | tr -d '=')"
  signature="$(printf '%s' "${altered}" | openssl dgst -sha256 -hmac "$(cat "${signing_key}")" | awk '{print $NF}')"
  printf '%s=%s.%s' "${source_cookie%%=*}" "${altered_encoded}" "${signature}"
}

clear_state() {
  [ "$(curl --noproxy '*' --fail --silent "${admin_url}/clear")" = cleared ] || fail "state clear failed"
}

wait_version 1
assert_hits 0

# The page is non-cacheable, nonce-bound by CSP, and does not expose policy internals.
delay_nonce="$(get_nonce edge-a.test '/protected?return=one%20two')"
assert_last_decision challenge pass_cookie_missing 200 1 delay-gate active -
grep -Fi 'Cache-Control: no-store' "${workdir}/last.headers" >/dev/null || fail "missing no-store"
grep -F "Content-Security-Policy: default-src 'none'" "${workdir}/last.headers" >/dev/null || fail "missing strict CSP"
grep -F "script-src 'nonce-" "${workdir}/last.headers" >/dev/null || fail "delay CSP lacks script nonce"
grep -F '<style nonce="' "${workdir}/last.body" >/dev/null || fail "style nonce is malformed"
delay_manual_count="$(grep -Fo '<noscript><button id="manual-continue" type="submit" form="challenge-form">' \
  "${workdir}/last.body" | wc -l | tr -d '[:space:]')"
[ "${delay_manual_count}" = 1 ] || fail "delay page exposed ${delay_manual_count} no-JS manual submits, want exactly one"
grep -F '<form id="challenge-form" method="post" action="/.cdnca/challenge/verify">' \
  "${workdir}/last.body" >/dev/null || fail "delay manual submit is not bound to the challenge form"
grep -F '<button id="continue" type="submit" disabled>' "${workdir}/last.body" >/dev/null \
  || fail "delay enhanced submit is not initially disabled"
if grep -Ei 'https?://|<script[^>]+src=|<(link|img|iframe|object|embed)[^>]+(href|src|data)=' \
  "${workdir}/last.body" >/dev/null; then
  fail "delay page depends on an external resource"
fi
if grep -E 'delay-gate|policy_version|key-[12]|key_sha256' "${workdir}/last.body" >/dev/null; then
  fail "challenge response leaked internal rule data"
fi
assert_hits 0

# Request-level audit distinguishes invalid context, unavailable rules, bad clients, methods, and targets.
expect_status 503 edge-b.test /decision-bad-context
assert_last_decision error context_invalid 503 1 - active -
expect_status 503 edge-b.test /decision-bad-rule
assert_last_decision error rule_unavailable 503 1 - active -
bad_user_agent="$(printf '%1025s' x | tr ' ' x)"
expect_status 403 edge-a.test /decision-bad-client --user-agent "${bad_user_agent}"
assert_last_decision block client_context_invalid 403 1 delay-gate active -
expect_status 405 edge-a.test '/.cdnca/challenge/verify'
assert_last_decision block verify_method_invalid 405 1 delay-gate active -
expect_status 403 edge-a.test '/decision-bad-target?value=%00' --path-as-is
assert_last_decision block target_invalid 403 1 delay-gate active -
assert_hits 0

# The five-second proof is server-timed; an early proof consumes its nonce.
early_status="$(submit_nonce edge-a.test "${delay_nonce}" delay)"
[ "${early_status}" = 403 ] || fail "early delay proof returned ${early_status}"
assert_last_decision block proof_invalid_or_too_early 403 1 delay-gate active -
replay_status="$(submit_nonce edge-a.test "${delay_nonce}" delay)"
[ "${replay_status}" = 403 ] || fail "early nonce replay returned ${replay_status}"
assert_last_decision block nonce_missing_or_replayed 403 1 delay-gate active -
assert_hits 0

delay_nonce="$(get_nonce edge-a.test '/protected?return=one%20two')"
sleep 5.2
delay_status="$(submit_nonce edge-a.test "${delay_nonce}" delay)"
[ "${delay_status}" = 303 ] || fail "valid delay proof returned ${delay_status}"
assert_last_decision allow proof_valid 303 1 delay-gate active -
grep -F 'Location: /protected?return=one%20two' "${workdir}/last.headers" >/dev/null \
  || fail "safe request target was not restored"
grep -Fi 'Secure; HttpOnly; SameSite=Lax' "${workdir}/last.headers" >/dev/null \
  || fail "pass cookie security attributes are missing"
delay_cookie="$(cookie_from_last_headers)"
expect_status 200 edge-a.test '/protected?return=one%20two' --header "Cookie: ${delay_cookie}"
assert_last_decision allow pass_cookie_valid 0 1 delay-gate active -
grep -F 'origin-ok:' "${workdir}/last.body" >/dev/null || fail "valid delay cookie did not reach origin"
assert_hits 1

# UA binding is enforced, while the origin stays untouched on rejection.
expect_status 200 edge-a.test /protected \
  --user-agent 'changed-user-agent/1.0' --header "Cookie: ${delay_cookie}"
assert_last_decision challenge pass_cookie_invalid 200 1 delay-gate active -
grep -F '正在进行五秒安全检查' "${workdir}/last.body" >/dev/null || fail "UA change did not restart challenge"
assert_hits 1

# Click confirmation is a real one-time POST, including atomic concurrent consumption.
click_cookie="$(solve_click edge-b.test)"
click_payload="$(decode_cookie_payload "${click_cookie}")"
case "${click_payload}" in
  *tenant-a*|*site-b*|*edge-b.test*|*'|click|'*) fail "pass cookie exposed internal scope" ;;
esac
click_nonce="$(get_nonce edge-b.test /concurrent)"
click_response="$(response_from_last_body click)"
sleep 0.25
concurrent_index=1
concurrent_pids=''
while [ "${concurrent_index}" -le 2 ]; do
  curl --noproxy '*' --silent --show-error --insecure \
    --resolve "edge-b.test:${edge_port}:127.0.0.1" \
    --user-agent "${smoke_ua}" \
    --output "${workdir}/concurrent-${concurrent_index}.body" \
    --write-out '%{http_code}' \
    --request POST \
    --header 'Content-Type: application/x-www-form-urlencoded' \
    --data "nonce=${click_nonce}&response=${click_response}" \
    "https://edge-b.test:${edge_port}/.cdnca/challenge/verify" \
    >"${workdir}/concurrent-${concurrent_index}.status" &
  concurrent_pids="${concurrent_pids} $!"
  concurrent_index=$((concurrent_index + 1))
done
for concurrent_pid in ${concurrent_pids}; do
  wait "${concurrent_pid}"
done
[ "$(awk '$0 == "303" {n++} END {print n+0}' "${workdir}"/concurrent-*.status)" -eq 1 ] \
  || fail "concurrent nonce had more or fewer than one success"
[ "$(awk '$0 == "403" {n++} END {print n+0}' "${workdir}"/concurrent-*.status)" -eq 1 ] \
  || fail "concurrent nonce did not reject exactly one replay"
assert_hits 1

# Replay, signature tamper, cross-site use, and validly signed clock changes are rejected.
click_replay_nonce="$(get_nonce edge-b.test /replay)"
click_replay_response="$(response_from_last_body click)"
sleep 0.25
[ "$(submit_nonce edge-b.test "${click_replay_nonce}" "${click_replay_response}")" = 303 ] || fail "click setup failed"
[ "$(submit_nonce edge-b.test "${click_replay_nonce}" "${click_replay_response}")" = 403 ] || fail "successful nonce replay was accepted"

click_value="${click_cookie#*=}"
click_prefix="${click_value%?}"
click_last="${click_value#"${click_prefix}"}"
if [ "${click_last}" = 0 ]; then tamper_last=1; else tamper_last=0; fi
tampered_cookie="${click_cookie%%=*}=${click_prefix}${tamper_last}"
expect_status 200 edge-b.test /tamper --header "Cookie: ${tampered_cookie}"
assert_last_decision challenge pass_cookie_invalid 200 1 site-b-gate active -
assert_hits 1

expect_status 200 edge-c.test /cross-site --header "Cookie: ${click_cookie}"
grep -F '请确认您正在访问此网站' "${workdir}/last.body" >/dev/null || fail "cross-site cookie was accepted"
assert_hits 1

now="$(date +%s)"
future_cookie="$(signed_time_cookie "${click_cookie}" "$((now + 300))" "$((now + 330))" "${key_1}")"
expired_cookie="$(signed_time_cookie "${click_cookie}" "$((now - 31))" "$((now - 1))" "${key_1}")"
expect_status 200 edge-b.test /future --header "Cookie: ${future_cookie}"
expect_status 200 edge-b.test /expired --header "Cookie: ${expired_cookie}"
assert_hits 1

# Current and previous HMAC keys overlap only during explicit rotation.
publish_policy 2 key-2 "${key_2}" key-1 "${key_1}" '[]' click 30 20
wait_version 2
expect_status 200 edge-b.test /rotation --header "Cookie: ${click_cookie}"
assert_hits 2

publish_policy 3 key-2 "${key_2}" key-1 "${key_1}" '[]' delay 30 20
wait_version 3
expect_status 200 edge-b.test /cross-mode --header "Cookie: ${click_cookie}"
grep -F '正在进行五秒安全检查' "${workdir}/last.body" >/dev/null || fail "cross-mode cookie was accepted"
assert_hits 2

publish_policy 4 key-2 "${key_2}" key-1 "${key_1}" '[]' click 30 20
wait_version 4
expect_status 200 edge-b.test /rotation-restored --header "Cookie: ${click_cookie}"
assert_hits 3

publish_policy 5 key-2 "${key_2}" "" "" '[]' click 30 20
wait_version 5
expect_status 200 edge-b.test /retired-key --header "Cookie: ${click_cookie}"
assert_hits 3

# X-Forwarded-For is ignored until a proxy CIDR is explicit.
default_proxy_cookie="$(solve_click edge-b.test --header 'X-Forwarded-For: 198.51.100.10')"
expect_status 200 edge-b.test /proxy-default \
  --header 'X-Forwarded-For: 198.51.100.11' --header "Cookie: ${default_proxy_cookie}"
assert_hits 4

# Malformed, older, and same-version-changed candidates retain the in-worker LKG.
cp "${workdir}/policy/current.json" "${workdir}/v5-good.json"
printf '%s\n' '{"schema_version":"cdnca.edge.challenge/v1","policy_version":6,"rules":[' \
  >"${workdir}/policy/.corrupt.json"
chmod 0600 "${workdir}/policy/.corrupt.json"
mv "${workdir}/policy/.corrupt.json" "${workdir}/policy/current.json"
sleep 0.2
[ "$(curl --noproxy '*' --silent "${admin_url}/status")" = 5 ] || fail "malformed policy displaced LKG"
expect_status 200 edge-b.test /lkg-malformed
assert_last_decision challenge pass_cookie_missing 200 5 site-b-gate lkg policy_decode_invalid

cp "${workdir}/policy/versions/00000000000000000004.json" "${workdir}/policy/.older.json"
chmod 0600 "${workdir}/policy/.older.json"
mv "${workdir}/policy/.older.json" "${workdir}/policy/current.json"
sleep 0.2
[ "$(curl --noproxy '*' --silent "${admin_url}/status")" = 5 ] || fail "older policy displaced LKG"
expect_status 200 edge-b.test /lkg-older
assert_last_decision challenge pass_cookie_missing 200 5 site-b-gate lkg policy_version_older

sed 's/"cookie_name":"__Host-cdnca_challenge"/"cookie_name":"__Host-cdnca_changed"/' \
  "${workdir}/v5-good.json" >"${workdir}/policy/.same-version.json"
chmod 0600 "${workdir}/policy/.same-version.json"
mv "${workdir}/policy/.same-version.json" "${workdir}/policy/current.json"
sleep 0.2
[ "$(curl --noproxy '*' --silent "${admin_url}/status")" = 5 ] || fail "same-version mutation displaced LKG"
expect_status 200 edge-b.test /lkg-same-version
assert_last_decision challenge pass_cookie_missing 200 5 site-b-gate lkg policy_same_version_changed

# Restore the sealed v5 as current: the publisher refuses to publish over a
# current.json that conflicts with the latest sealed version.
cp "${workdir}/v5-good.json" "${workdir}/policy/.restore.json"
chmod 0600 "${workdir}/policy/.restore.json"
mv "${workdir}/policy/.restore.json" "${workdir}/policy/current.json"

# Short pass TTL expires in real OpenResty time.
publish_policy 6 key-2 "${key_2}" "" "" '[]' click 2 20
wait_version 6
short_cookie="$(solve_click edge-b.test --header 'X-Forwarded-For: 198.51.100.20')"
sleep 2.2
expect_status 200 edge-b.test /expired-real --header "Cookie: ${short_cookie}"
assert_hits 4

# Explicit trusted proxies select the first untrusted hop and support IPv4 and IPv6.
publish_policy 7 key-2 "${key_2}" "" "" '["0.0.0.0/0"]' click 30 20
wait_version 7
[ "$(curl --noproxy '*' --silent --header 'X-Forwarded-For: 198.51.100.30' "${admin_url}/client")" = 198.51.100.30 ] \
  || fail "trusted IPv4 proxy chain was not honored"
ipv4_cookie="$(solve_click edge-b.test --header 'X-Forwarded-For: 198.51.100.30')"
expect_status 200 edge-b.test /ipv4 \
  --header 'X-Forwarded-For: 198.51.100.30' --header "Cookie: ${ipv4_cookie}"
assert_hits 5
expect_status 200 edge-b.test /ipv4-change \
  --header 'X-Forwarded-For: 198.51.100.31' --header "Cookie: ${ipv4_cookie}"
assert_hits 5

[ "$(curl --noproxy '*' --silent --header 'X-Forwarded-For: 2001:db8::30' "${admin_url}/client")" = 2001:db8::30 ] \
  || fail "trusted IPv6 proxy chain was not honored"
ipv6_cookie="$(solve_click edge-b.test --header 'X-Forwarded-For: 2001:db8::30')"
expect_status 200 edge-b.test /ipv6 \
  --header 'X-Forwarded-For: 2001:db8::30' --header "Cookie: ${ipv6_cookie}"
assert_hits 6
expect_status 200 edge-b.test /ipv6-change \
  --header 'X-Forwarded-For: 2001:db8::31' --header "Cookie: ${ipv6_cookie}"
assert_hits 6

# A rule can explicitly opt out of IP and UA binding.
unbound_cookie="$(solve_click edge-c.test \
  --header 'X-Forwarded-For: 198.51.100.40' --user-agent 'first-agent/1.0')"
expect_status 200 edge-c.test /unbound \
  --header 'X-Forwarded-For: 2001:db8::40' \
  --user-agent 'second-agent/1.0' \
  --header "Cookie: ${unbound_cookie}"
assert_hits 7

# Failure counters are bounded per tenant, site, host, mode, and rule.
publish_policy 8 key-2 "${key_2}" "" "" '["0.0.0.0/0"]' click 30 2
wait_version 8
clear_state
invalid_nonce='AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
first_failure="$(submit_nonce edge-b.test "${invalid_nonce}" click \
  --header 'X-Forwarded-For: 203.0.113.80')"
assert_last_decision block nonce_missing_or_replayed 403 8 site-b-gate active -
second_failure="$(submit_nonce edge-b.test "${invalid_nonce}" click \
  --header 'X-Forwarded-For: 203.0.113.80')"
assert_last_decision block failure_threshold 429 8 site-b-gate active -
[ "${first_failure}" = 403 ] || fail "first invalid proof returned ${first_failure}"
[ "${second_failure}" = 429 ] || fail "failure limit returned ${second_failure}"
expect_status 429 edge-b.test /failure-limit --header 'X-Forwarded-For: 203.0.113.80'
assert_hits 7

# Request bodies are not logged, and shared-dict eviction fails closed.
body_marker='REQUEST_BODY_MUST_NOT_BE_LOGGED_7a85'
request_status edge-c.test '/.cdnca/challenge/verify' \
  --request POST --header 'Content-Type: application/x-www-form-urlencoded' \
  --data "nonce=${invalid_nonce}&response=invalid&marker=${body_marker}" >/dev/null
assert_last_decision block form_invalid 403 8 site-c-click active -
if grep -F "${body_marker}" "${workdir}/runtime/logs/error.log" "${workdir}/runtime/logs/access.log" >/dev/null; then
  fail "request body appeared in logs"
fi
clear_state
[ "$(curl --noproxy '*' --fail --silent "${admin_url}/fill")" = forcible ] || fail "state dict was not filled"
expect_status 503 edge-b.test /capacity
assert_last_decision error state_capacity_unavailable 503 8 site-b-gate active -
assert_hits 7
clear_state

# Restore a browser-ready LKG after pressure and prove recovery.
publish_policy 9 key-2 "${key_2}" "" "" '[]' click 60 20
wait_version 9
expect_status 200 edge-b.test /recovered
assert_last_decision challenge pass_cookie_missing 200 9 site-b-gate active -
grep -F '请确认您正在访问此网站' "${workdir}/last.body" >/dev/null || fail "challenge did not recover"
assert_hits 7

# A real OpenResty HUP keeps shared nonce state and activates a valid worker LKG.
reload_nonce="$(get_nonce edge-b.test /reload-state)"
reload_response="$(response_from_last_body click)"
docker kill --signal HUP "${container}" >/dev/null
wait_version 9
sleep 0.25
[ "$(submit_nonce edge-b.test "${reload_nonce}" "${reload_response}")" = 303 ] || fail "nonce did not survive OpenResty HUP"
reload_cookie="$(cookie_from_last_headers)"
expect_status 200 edge-b.test /reload-state --header "Cookie: ${reload_cookie}"
assert_hits 8

# Browser challenge bypasses machine traffic only after the independent guard has run.
bypass_origin_before="$(origin_hits)"
bypass_guard_before="$(guard_hits)"
expect_status 200 edge-b.test /api/data
assert_last_decision allow bypass_route 0 9 site-b-gate active -
expect_status 200 edge-b.test /agent/heartbeat
assert_last_decision allow bypass_route 0 9 site-b-gate active -
expect_status 200 edge-b.test /ws/connect --header 'Connection: Upgrade' --header 'Upgrade: websocket'
assert_last_decision allow bypass_route 0 9 site-b-gate active -
expect_status 200 edge-b.test /events/jobs --smoke-accept text/event-stream
assert_last_decision allow bypass_route 0 9 site-b-gate active -
expect_status 200 edge-b.test /import/jobs --request POST --data 'job=one'
assert_last_decision allow bypass_route 0 9 site-b-gate active -
expect_status 200 edge-b.test '/.well-known/acme-challenge/token'
assert_last_decision allow bypass_route 0 9 site-b-gate active -
expect_status 200 edge-b.test /healthz
assert_last_decision allow bypass_route 0 9 site-b-gate active -
expect_status 200 edge-b.test /machine-upgrade --header 'Connection: Upgrade' --header 'Upgrade: websocket'
assert_last_decision allow bypass_upgrade 0 9 site-b-gate active -
expect_status 200 edge-b.test /machine-event-stream --smoke-accept text/event-stream
assert_last_decision allow bypass_event_stream 0 9 site-b-gate active -
expect_status 200 edge-b.test /machine-method --request POST --data 'job=one'
assert_last_decision allow bypass_method 0 9 site-b-gate active -
expect_status 200 edge-b.test /machine-content-type --header 'Content-Type: application/json'
assert_last_decision allow bypass_content_type 0 9 site-b-gate active -
expect_status 200 edge-b.test /machine-fetch-destination --header 'Sec-Fetch-Dest: image'
assert_last_decision allow bypass_fetch_destination 0 9 site-b-gate active -
expect_status 200 edge-b.test /machine-non-document --smoke-accept text/plain
assert_last_decision allow bypass_non_document_accept 0 9 site-b-gate active -
expect_status 200 edge-b.test /machine-json --smoke-accept application/json
assert_last_decision allow bypass_machine_accept 0 9 site-b-gate active -
expect_status 200 edge-b.test /machine-auth --header 'Authorization: Bearer smoke-machine-token'
assert_last_decision allow bypass_authorization 0 9 site-b-gate active -
[ "$(request_status_without_challenge edge-b.test /api/blocked)" = 429 ] \
  || fail "independent machine guard did not return 429"
[ "$(( $(origin_hits) - bypass_origin_before ))" -eq 15 ] || fail "machine bypass origin count is incorrect"
[ "$(( $(guard_hits) - bypass_guard_before ))" -eq 16 ] || fail "browser bypass skipped the machine guard"
assert_hits 23

# Slider and text CAPTCHA are server-state challenges with accessible controls and one-time answers.
slider_nonce="$(get_nonce edge-d.test '/slider?x=%3Cscript%3Ealert(1)%3C/script%3E')"
slider_target="$(response_from_last_body slider)"
grep -F 'type="range"' "${workdir}/last.body" >/dev/null || fail "slider control is missing"
grep -F 'aria-describedby="slider-value"' "${workdir}/last.body" >/dev/null || fail "slider accessibility binding is missing"
grep -F "script-src 'nonce-" "${workdir}/last.headers" >/dev/null || fail "slider CSP lacks script nonce"
slider_manual_count="$(grep -Fo '<noscript><button id="manual-continue" type="submit" form="challenge-form">' \
  "${workdir}/last.body" | wc -l | tr -d '[:space:]')"
[ "${slider_manual_count}" = 1 ] || fail "slider page exposed ${slider_manual_count} no-JS manual submits, want exactly one"
grep -F '<form id="challenge-form" method="post" action="/.cdnca/challenge/verify">' \
  "${workdir}/last.body" >/dev/null || fail "slider manual submit is not bound to the challenge form"
grep -F '<button id="continue" type="submit" disabled>' "${workdir}/last.body" >/dev/null \
  || fail "slider enhanced submit is not initially disabled"
if grep -Ei 'https?://|<script[^>]+src=|<(link|img|iframe|object|embed)[^>]+(href|src|data)=' \
  "${workdir}/last.body" >/dev/null; then
  fail "slider page depends on an external resource"
fi
if grep -F '<script>alert(1)</script>' "${workdir}/last.body" >/dev/null; then
  fail "request query was reflected into challenge HTML"
fi
sleep 0.25
[ "$(submit_nonce edge-d.test "${slider_nonce}" "$((slider_target - 1))")" = 403 ] || fail "wrong slider answer was accepted"
assert_last_decision block proof_invalid_or_too_early 403 9 site-d-slider active -
assert_hits 23
slider_nonce="$(get_nonce edge-d.test /slider-valid)"
slider_target="$(response_from_last_body slider)"
sleep 0.25
[ "$(submit_nonce edge-d.test "${slider_nonce}" "${slider_target}")" = 303 ] || fail "valid slider answer was rejected"
assert_last_decision allow proof_valid 303 9 site-d-slider active -
assert_hits 23
slider_cookie="$(cookie_from_last_headers)"
expect_status 200 edge-d.test /slider-valid --header "Cookie: ${slider_cookie}"
assert_hits 24

captcha_nonce="$(get_nonce edge-e.test /captcha-wrong)"
captcha_answer="$(response_from_last_body captcha)"
grep -F 'role="img" aria-label="验证码 ' "${workdir}/last.body" >/dev/null || fail "captcha accessible text is missing"
grep -F 'for="captcha-response"' "${workdir}/last.body" >/dev/null || fail "captcha label is missing"
grep -F "script-src 'none'" "${workdir}/last.headers" >/dev/null || fail "captcha unexpectedly enabled script"
if grep -E 'https?://|<script[^>]+src=' "${workdir}/last.body" >/dev/null; then
  fail "challenge page loaded a third-party resource"
fi
captcha_first="$(printf '%s' "${captcha_answer}" | cut -c 1)"
if [ "${captcha_first}" = 0 ]; then captcha_replacement=1; else captcha_replacement=0; fi
captcha_wrong="${captcha_replacement}$(printf '%s' "${captcha_answer}" | cut -c 2-)"
sleep 0.25
[ "$(submit_nonce edge-e.test "${captcha_nonce}" "${captcha_wrong}")" = 403 ] || fail "wrong captcha answer was accepted"
captcha_nonce="$(get_nonce edge-e.test /captcha-valid)"
captcha_answer="$(response_from_last_body captcha)"
captcha_lower="$(printf '%s' "${captcha_answer}" | tr 'A-F' 'a-f')"
sleep 0.25
[ "$(submit_nonce edge-e.test "${captcha_nonce}" "${captcha_lower}")" = 303 ] || fail "valid captcha answer was rejected"
captcha_cookie="$(cookie_from_last_headers)"
expect_status 200 edge-e.test /captcha-valid --header "Cookie: ${captcha_cookie}"
assert_hits 25

# Runtime key metadata drift is rejected without displacing the loaded secret or policy.
chmod 0644 "${key_2}"
sleep 0.2
[ "$(curl --noproxy '*' --silent "${admin_url}/status")" = 9 ] || fail "public key permissions displaced LKG"
expect_status 200 edge-b.test /lkg-key-metadata
assert_last_decision challenge pass_cookie_missing 200 9 site-b-gate lkg key_metadata_invalid
grep -F 'key_metadata_invalid' "${workdir}/runtime/logs/error.log" >/dev/null \
  || fail "public key permissions were not rejected"
chmod 0600 "${key_2}"

chmod 0755 "${workdir}/keys"
sleep 0.2
[ "$(curl --noproxy '*' --silent "${admin_url}/status")" = 9 ] || fail "public key directory displaced LKG"
expect_status 200 edge-b.test /lkg-key-parent-metadata
assert_last_decision challenge pass_cookie_missing 200 9 site-b-gate lkg key_parent_metadata_invalid
grep -F 'key_parent_metadata_invalid' "${workdir}/runtime/logs/error.log" >/dev/null \
  || fail "public key directory was not rejected"
chmod 0700 "${workdir}/keys"
sleep 0.2
expect_status 200 edge-b.test /key-metadata-recovered
assert_last_decision challenge pass_cookie_missing 200 9 site-b-gate active -

grep -F 'challenge policy reload rejected; retaining' "${workdir}/runtime/logs/error.log" >/dev/null \
  || fail "LKG rejection was not logged"
if grep -F -- "${delay_nonce}" "${workdir}/runtime/logs/error.log" "${workdir}/runtime/logs/access.log" >/dev/null; then
  fail "nonce appeared in logs"
fi
for secret_file in "${key_1}" "${key_2}"; do
  secret="$(cat "${secret_file}")"
  if grep -F -- "${secret}" "${workdir}/runtime/logs/error.log" "${workdir}/runtime/logs/access.log" \
    "${workdir}/last.body" >/dev/null; then
    fail "HMAC secret appeared in public output"
  fi
done

printf '%s\n' \
  "openresty_version=${OPENRESTY_VERSION}" \
  "policy_version=9" \
  "startup_fail_closed=true" \
  "delay_early_status=403" \
  "delay_valid_status=303" \
  "click_valid_status=303" \
  "slider_valid_status=303" \
  "captcha_valid_status=303" \
  "concurrent_nonce_success=1" \
  "concurrent_nonce_rejected=1" \
  "cookie_tamper_rejected=true" \
  "cookie_clock_rejected=true" \
  "cookie_cross_site_mode_rejected=true" \
  "key_rotation_overlap=true" \
  "trusted_proxy_ipv4_ipv6=true" \
  "browser_machine_bypass=true" \
  "machine_guard_preserved=true" \
  "nojs_manual_delay_slider=true" \
  "shared_dict_capacity_fail_closed=true" \
  "lkg_retained=true" \
  "origin_hits=25"

if [ "${serve}" -eq 1 ]; then
  printf '%s\n' \
    "CHALLENGE_SMOKE_URL=https://edge-a.test:${edge_port}/browser" \
    "CHALLENGE_CLICK_URL=https://edge-b.test:${edge_port}/browser" \
    "CHALLENGE_SLIDER_URL=https://edge-d.test:${edge_port}/browser" \
    "CHALLENGE_CAPTCHA_URL=https://edge-e.test:${edge_port}/browser" \
    "CHALLENGE_WORKDIR=${workdir}" \
    "CHALLENGE_CONTAINER=${container}"
  while docker inspect --format '{{.State.Running}}' "${container}" 2>/dev/null | grep -Fx true >/dev/null; do
    sleep 1
  done
fi
