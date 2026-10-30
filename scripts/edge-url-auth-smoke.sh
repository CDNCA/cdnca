#!/bin/sh
set -eu

repo_root="$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)"
# shellcheck source=edge/openresty/runtime.env
. "${repo_root}/edge/openresty/runtime.env"

tmp_base="${TMPDIR:-/tmp}"
case "${tmp_base}" in
  /*) ;;
  *) echo "TMPDIR must be absolute" >&2; exit 64 ;;
esac
tmp_base="$(CDPATH='' cd -- "${tmp_base}" && pwd -P)"
workdir="$(mktemp -d "${tmp_base%/}/cdnca-edge-url-auth.XXXXXX")"
suffix="$(basename "${workdir}" | sed 's/^cdnca-edge-url-auth\.//')"
container="cdnca-edge-url-auth-${suffix}"

cleanup() {
  docker rm -f "${container}" >/dev/null 2>&1 || true
  case "${workdir}" in
    "${tmp_base%/}"/cdnca-edge-url-auth.*)
      chmod -R u+w "${workdir}" 2>/dev/null || true
      rm -rf -- "${workdir}"
      ;;
    *) echo "refusing to remove unexpected path: ${workdir}" >&2 ;;
  esac
}
trap cleanup EXIT HUP INT TERM

install -d -m 0700 "${workdir}/keys" "${workdir}/policy" "${workdir}/runtime" "${workdir}/runtime/logs"
printf '%s' 'url-auth-smoke-key-one-32-bytes!!' >"${workdir}/keys/k1.key"
printf '%s' 'url-auth-smoke-key-two-32-bytes!!' >"${workdir}/keys/k2.key"
printf '%s' 'url-auth-smoke-bad-key-32-bytes!!!' >"${workdir}/keys/bad.key"
chmod 0600 "${workdir}/keys/"*.key

(
  cd "${repo_root}/agents/edge-agent"
  GOWORK=off go build -trimpath -o "${workdir}/url-auth-tool" ./internal/urlauth/cmd/url-auth-tool
)

publish_policy() {
  publish_version="$1"
  publish_bind="$2"
  publish_trusted="$3"
  publish_current_id="$4"
  publish_current_file="$5"
  publish_previous_id="$6"
  publish_previous_file="$7"
  publish_max_uses="$8"
  publish_previous=""
  if [ -n "${publish_previous_id}" ]; then
    publish_previous=",\"previous_key\":{\"key_id\":\"${publish_previous_id}\",\"key_file\":\"${publish_previous_file}\"}"
  fi
  "${workdir}/url-auth-tool" publish -root "${workdir}/policy" <<EOF
{
  "schema_version": "cdnca.edge.urlauth/v1",
  "policy_version": ${publish_version},
  "tenant_id": "tenant-a",
  "site_id": "site-a",
  "algorithm": "hmac-sha256",
  "signature_parameter": "sig",
  "expiration_parameter": "exp",
  "key_id_parameter": "kid",
  "bind_client_ip": ${publish_bind},
  "max_clock_skew_seconds": 2,
  "max_validity_seconds": 300,
  "max_signature_uses": ${publish_max_uses},
  "excluded_query_parameters": ["utm_source"],
  "trusted_proxies": ${publish_trusted},
  "current_key": {"key_id":"${publish_current_id}","key_file":"${publish_current_file}"}${publish_previous}
}
EOF
}

publish_policy 1 false '[]' k1 "${workdir}/keys/k1.key" '' '' 0 >"${workdir}/publish-v1.log"

cat >"${workdir}/runtime/nginx.conf" <<EOF
worker_processes 4;
pid ${workdir}/runtime/nginx.pid;
error_log ${workdir}/runtime/error.log notice;

events { worker_connections 1024; }

http {
    access_log off;
    lua_package_path '${repo_root}/edge/openresty/urlauth/?.lua;;';
    lua_shared_dict cdnca_url_auth_state 4m;
    lua_shared_dict smoke_metrics 1m;

    init_worker_by_lua_block {
        require("engine").init({
            policy_path = "${workdir}/policy/current.json",
            state_dict = "cdnca_url_auth_state",
            reload_interval = 0.05,
        })
    }

    server {
        listen 18091;
        location / {
            access_by_lua_block {
                return require("engine").access({tenant_id = "tenant-a", site_id = "site-a"})
            }
            proxy_pass http://127.0.0.1:18092;
        }
    }

    server {
        listen 18092;
        location / {
            content_by_lua_block {
                ngx.shared.smoke_metrics:incr("origin_hits", 1, 0)
                ngx.say("origin")
            }
        }
    }

    server {
        listen 18093;
        location = /version {
            content_by_lua_block { ngx.say(ngx.worker.pid(), ":", require("engine").policy_version()) }
        }
        location = /client {
            content_by_lua_block { ngx.say(require("engine").resolve_client_ip() or "unavailable") }
        }
        location = /hits {
            content_by_lua_block { ngx.say(ngx.shared.smoke_metrics:get("origin_hits") or 0) }
        }
        location = /url-auth-metrics {
            content_by_lua_block {
                local values = require("engine").metrics()
                for _, key in ipairs({"allow", "block", "error", "reload_rejected"}) do
                    ngx.say(key, "=", values[key] or 0)
                end
            }
        }
    }
}
EOF

docker run --detach --init \
  --name "${container}" \
  --publish 127.0.0.1::18091 \
  --publish 127.0.0.1::18093 \
  --volume "${repo_root}/edge/openresty/urlauth:${repo_root}/edge/openresty/urlauth:ro" \
  --volume "${workdir}/keys:${workdir}/keys:ro" \
  --volume "${workdir}/policy:${workdir}/policy:ro" \
  --volume "${workdir}/runtime:${workdir}/runtime" \
  --entrypoint /usr/local/openresty/bin/openresty \
  "${OPENRESTY_IMAGE}" \
  -p "${workdir}/runtime/" -c nginx.conf -g 'daemon off;' >/dev/null

edge_published="$(docker port "${container}" 18091/tcp | tail -n 1)"
admin_published="$(docker port "${container}" 18093/tcp | tail -n 1)"
case "${edge_published}:${admin_published}" in
  127.0.0.1:*:127.0.0.1:*) ;;
  *) echo "URL auth smoke ports were not bound to loopback: ${edge_published} ${admin_published}" >&2; exit 1 ;;
esac
edge_url="http://${edge_published}"
admin_url="http://${admin_published}"

wait_version() {
  wait_expected="$1"
  wait_attempt=0
  : >"${workdir}/wait-version-pids"
  while [ "${wait_attempt}" -lt 200 ]; do
    wait_value="$(curl --silent --show-error "${admin_url}/version" 2>/dev/null || true)"
    case "${wait_value}" in
      *:"${wait_expected}")
        wait_pid="${wait_value%%:*}"
        if ! grep -Fx "${wait_pid}" "${workdir}/wait-version-pids" >/dev/null; then
          printf '%s\n' "${wait_pid}" >>"${workdir}/wait-version-pids"
        fi
        if [ "$(wc -l <"${workdir}/wait-version-pids" | tr -d ' ')" -ge 4 ]; then
          return 0
        fi
        ;;
    esac
    if ! docker inspect --format '{{.State.Running}}' "${container}" 2>/dev/null | grep -Fx true >/dev/null; then
      docker logs "${container}" >&2 || true
      return 1
    fi
    wait_attempt=$((wait_attempt + 1))
    sleep 0.1
  done
  echo "URL auth policy version did not become ${wait_expected}" >&2
  cat "${workdir}/runtime/error.log" >&2 2>/dev/null || true
  docker logs "${container}" >&2 || true
  return 1
}

current_version() {
  current_value="$(curl --fail --silent --show-error "${admin_url}/version")"
  printf '%s\n' "${current_value#*:}"
}

sign_target() {
  sign_target_value="$1"
  sign_expiration="$2"
  sign_key_id="$3"
  sign_client_ip="$4"
  sign_now="$5"
  set -- sign -policy "${workdir}/policy/current.json" -method GET -target "${sign_target_value}" -expires-at "${sign_expiration}"
  if [ -n "${sign_key_id}" ]; then
    set -- "$@" -key-id "${sign_key_id}"
  fi
  if [ -n "${sign_client_ip}" ]; then
    set -- "$@" -client-ip "${sign_client_ip}"
  fi
  if [ -n "${sign_now}" ]; then
    set -- "$@" -now "${sign_now}"
  fi
  "${workdir}/url-auth-tool" "$@"
}

request_code() {
  request_target="$1"
  shift
  curl --globoff --silent --show-error --output "${workdir}/last.body" --dump-header "${workdir}/last.headers" \
    --write-out '%{http_code}' "$@" "${edge_url}${request_target}"
}

expect_code() {
  expect_status="$1"
  expect_target="$2"
  shift 2
  actual_status="$(request_code "${expect_target}" "$@")"
  if [ "${actual_status}" != "${expect_status}" ]; then
    echo "${expect_target}: status ${actual_status}, want ${expect_status}" >&2
    cat "${workdir}/last.body" >&2 || true
    docker logs "${container}" >&2 || true
    exit 1
  fi
}

query_value() {
  query_target="$1"
  query_name="$2"
  printf '%s\n' "${query_target#*\?}" | tr '&' '\n' | sed -n "s/^${query_name}=//p"
}

origin_hits() {
  curl --fail --silent --show-error "${admin_url}/hits"
}

wait_version 1
now="$(date +%s)"
expires=$((now + 120))
valid="$(sign_target '/asset?b=two&a=one&utm_source=alpha' "${expires}" '' '' '')"
expect_code 200 "${valid}" -H 'X-Forwarded-For: 198.51.100.8'
sig="$(query_value "${valid}" sig)"
reordered="/asset?utm_source=beta&sig=${sig}&b=two&kid=k1&a=one&exp=${expires}"
expect_code 200 "${reordered}" -H 'X-Forwarded-For: 203.0.113.9'

untrusted_client="$(curl --fail --silent --show-error -H 'X-Forwarded-For: 198.51.100.8' "${admin_url}/client")"
test "${untrusted_client}" != '198.51.100.8'

before="$(origin_hits)"
expect_code 403 "${reordered%a=one*}a=changed&exp=${expires}" -H 'X-Forwarded-For: 203.0.113.9'
test "$(origin_hits)" = "${before}"
expect_code 403 "/other?utm_source=beta&sig=${sig}&b=two&kid=k1&a=one&exp=${expires}"
expect_code 403 "${valid}" -X POST
expect_code 403 "${valid}&sig=duplicate"
expect_code 403 "${valid}&%73ig=duplicate"
expect_code 403 "${valid}&bad=%0A"
expect_code 403 "$(printf '%s' "${valid}" | sed 's/exp=[0-9][0-9]*/exp=invalid/')"
expect_code 403 "$(printf '%s' "${valid}" | sed 's/kid=k1/kid=unknown/')"
if grep -Eiq 'tenant|site|policy|signature|hmac|k1|secret' "${workdir}/last.body" "${workdir}/last.headers"; then
  echo "URL auth rejection leaked internal policy details" >&2
  exit 1
fi

long_target="/asset?x=$(awk 'BEGIN { for (i = 0; i < 5000; i++) printf "a" }')"
long_status="$(request_code "${long_target}")"
case "${long_status}" in
  400|403|414) ;;
  *) echo "overlong URI status ${long_status}, want rejection" >&2; exit 1 ;;
esac

trusted='["10.0.0.0/8","127.0.0.0/8","172.16.0.0/12","192.168.0.0/16","::1/128"]'
publish_policy 2 true "${trusted}" k1 "${workdir}/keys/k1.key" '' '' 0 >"${workdir}/publish-v2.log"
wait_version 2
now="$(date +%s)"
expires=$((now + 120))
ipv4_url="$(sign_target '/bound?v=4' "${expires}" k1 198.51.100.8 '')"
expect_code 200 "${ipv4_url}" -H 'X-Forwarded-For: 198.51.100.8'
expect_code 403 "${ipv4_url}" -H 'X-Forwarded-For: 198.51.100.9'
expect_code 403 "${ipv4_url}" -H 'X-Forwarded-For: invalid'
test "$(curl --fail --silent --show-error -H 'X-Forwarded-For: 198.51.100.8' "${admin_url}/client")" = '198.51.100.8'

ipv6_url="$(sign_target '/bound?v=6' "${expires}" k1 2001:db8::8 '')"
expect_code 200 "${ipv6_url}" -H 'X-Forwarded-For: 2001:db8::8'

docker kill --signal HUP "${container}" >/dev/null
sleep 1
wait_version 2
reload_url="$(sign_target '/reload?nonce=one' "$(( $(date +%s) + 120 ))" k1 198.51.100.8 '')"
expect_code 200 "${reload_url}" -H 'X-Forwarded-For: 198.51.100.8'

publish_policy 3 true "${trusted}" k2 "${workdir}/keys/k2.key" k1 "${workdir}/keys/k1.key" 0 >"${workdir}/publish-v3.log"
wait_version 3
expires=$(( $(date +%s) + 120 ))
previous_url="$(sign_target '/rotation?key=previous' "${expires}" k1 198.51.100.8 '')"
current_url="$(sign_target '/rotation?key=current' "${expires}" k2 198.51.100.8 '')"
expect_code 200 "${previous_url}" -H 'X-Forwarded-For: 198.51.100.8'
expect_code 200 "${current_url}" -H 'X-Forwarded-For: 198.51.100.8'

cp "${workdir}/policy/current.json" "${workdir}/policy/current.good"
sed 's/"algorithm":"hmac-sha256"/"algorithm":"md5"/' "${workdir}/policy/current.good" >"${workdir}/policy/current.bad"
chmod 0600 "${workdir}/policy/current.bad"
mv "${workdir}/policy/current.bad" "${workdir}/policy/current.json"
sleep 0.2
wait_version 3
expect_code 200 "${current_url}" -H 'X-Forwarded-For: 198.51.100.8'
publish_policy 3 true "${trusted}" k2 "${workdir}/keys/k2.key" k1 "${workdir}/keys/k1.key" 0 >"${workdir}/restore-v3.log"
wait_version 3

chmod 0644 "${workdir}/keys/bad.key"
if publish_policy 4 true "${trusted}" bad "${workdir}/keys/bad.key" '' '' 0 >"${workdir}/bad-permission.out" 2>"${workdir}/bad-permission.err"; then
  echo "publisher accepted a permissive key file" >&2
  exit 1
fi
chmod 0600 "${workdir}/keys/bad.key"
test "$(current_version)" = 3

publish_policy 4 true "${trusted}" k2 "${workdir}/keys/k2.key" '' '' 3 >"${workdir}/publish-v4.log"
wait_version 4
expect_code 403 "${previous_url}" -H 'X-Forwarded-For: 198.51.100.8'
expires=$(( $(date +%s) + 120 ))
replay_url="$(sign_target '/replay?nonce=concurrent' "${expires}" k2 198.51.100.8 '')"
replay_index=1
replay_pids=""
while [ "${replay_index}" -le 12 ]; do
  curl --globoff --silent --show-error --output "${workdir}/replay-${replay_index}.body" --write-out '%{http_code}' \
    -H 'X-Forwarded-For: 198.51.100.8' "${edge_url}${replay_url}" >"${workdir}/replay-${replay_index}.status" &
  replay_pids="${replay_pids} $!"
  replay_index=$((replay_index + 1))
done
for replay_pid in ${replay_pids}; do
  wait "${replay_pid}"
done
allowed_count="$(awk '$0 == 200 { count++ } END { print count + 0 }' "${workdir}"/replay-*.status)"
rejected_count="$(awk '$0 == 403 { count++ } END { print count + 0 }' "${workdir}"/replay-*.status)"
test "${allowed_count}" -eq 3
test "${rejected_count}" -eq 9

publish_policy 5 true "${trusted}" k2 "${workdir}/keys/k2.key" '' '' 3 >"${workdir}/publish-v5.log"
wait_version 5
expect_code 403 "${replay_url}" -H 'X-Forwarded-For: 198.51.100.8'

now="$(date +%s)"
expired_url="$(sign_target '/time?case=expired' "$((now - 10))" k2 198.51.100.8 "$((now - 20))")"
expect_code 403 "${expired_url}" -H 'X-Forwarded-For: 198.51.100.8'
future_url="$(sign_target '/time?case=future' "$((now + 310))" k2 198.51.100.8 "$((now + 10))")"
expect_code 403 "${future_url}" -H 'X-Forwarded-For: 198.51.100.8'

metrics="$(curl --fail --silent --show-error "${admin_url}/url-auth-metrics")"
for metric in allow block reload_rejected; do
  value="$(printf '%s\n' "${metrics}" | sed -n "s/^${metric}=//p")"
  case "${value}" in
    ''|*[!0-9]*) echo "invalid URL auth metric ${metric}=${value}" >&2; exit 1 ;;
  esac
  test "${value}" -gt 0
done
if printf '%s\n' "${metrics}" | grep -Eiq 'uri|query|signature|kid|secret|client|ip'; then
  echo "URL auth metrics leaked high-cardinality or sensitive labels" >&2
  exit 1
fi

if grep -F 'url-auth-smoke-key-' "${workdir}/runtime/error.log" "${workdir}/last.body" "${workdir}/last.headers" >/dev/null 2>&1; then
  echo "URL auth logs or responses leaked a key" >&2
  exit 1
fi
for sensitive_signature in "${sig}" "$(query_value "${current_url}" sig)" "$(query_value "${replay_url}" sig)"; do
  if grep -F "${sensitive_signature}" "${workdir}/runtime/error.log" "${workdir}/last.body" "${workdir}/last.headers" >/dev/null 2>&1; then
    echo "URL auth logs or responses leaked a signature" >&2
    exit 1
  fi
done

printf '{\n'
printf '  "valid_and_canonical_query": true,\n'
printf '  "path_query_ip_tamper_rejected": true,\n'
printf '  "ipv4_ipv6_and_trusted_proxy": true,\n'
printf '  "current_previous_rotation": true,\n'
printf '  "concurrent_replay_allowed": %s,\n' "${allowed_count}"
printf '  "concurrent_replay_rejected": %s,\n' "${rejected_count}"
printf '  "reload_and_bad_policy_lkg": true,\n'
printf '  "bounded_rejection_metrics": true,\n'
printf '  "strict_key_permissions": true,\n'
printf '  "final_policy_version": 5\n'
printf '}\n'
printf 'openresty_version=%s\nimage=%s\ncontainer=%s\nisolation=task-owned-container-and-state\n' \
  "${OPENRESTY_VERSION}" "${OPENRESTY_IMAGE}" "${container}"
