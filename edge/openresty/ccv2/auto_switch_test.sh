#!/bin/sh
# CC v5 auto switch (自动切换) on a real OpenResty:
#   - a policy without auto_switch still loads and runs (pre-v5 shape);
#   - once a second carried qps_total requests the site runs the switch
#     rules (a 1-request limit), for every client; the status endpoint
#     reports it engaged with the trigger rate and a new sequence;
#   - origin 5xx responses per second (qps_5xx) engage it as well, while the
#     engine's own 503 challenge pages do not count;
#   - after recover_seconds below both thresholds the site's own rules run
#     again and the status reports the recovery (sequence advanced again);
#   - an auto switch on a disabled policy, without a threshold or sharing a
#     rule ID with the policy is refused (the site answers 503).
#
# Usage: edge/openresty/ccv2/auto_switch_test.sh
#        CC_ENGINE=<path to engine.lua> ...
set -eu

repo_root="$(CDPATH='' cd -- "$(dirname -- "$0")/../../.." && pwd)"
# shellcheck disable=SC1091
. "${repo_root}/edge/openresty/runtime.env"
engine="${CC_ENGINE:-${repo_root}/edge/openresty/ccv2/engine.lua}"

workdir="$(mktemp -d "${TMPDIR:-/tmp}/cdnca-g1-autoswitch-lua.XXXXXX")"
container="cdnca-g1-autoswitch-$(basename "${workdir}" | tr -cd 'A-Za-z0-9')"
cleanup() {
  docker rm -f "${container}" >/dev/null 2>&1 || true
  rm -rf -- "${workdir}"
}
trap cleanup EXIT HUP INT TERM
fail() { echo "FAIL: $*" >&2; exit 1; }

tenant="018f1000-0000-7000-8000-000000000001"
uuid() { printf '018f1000-0000-7000-8000-%012d' "$1"; }
entry_id() { printf '%s\0%s\0%s\0%s\0%s' "${tenant}" "$1" localhost "$2" http | sha256sum | awk '{print substr($1,1,32)}'; }

# site <n> <port> <rules json> <extra policy fields> <location body> [enabled]
registry=""
servers=""
site() {
  site_id="$(uuid "$1")"
  policy_id="$(uuid "$(( $1 + 100 ))")"
  binding_id="$(uuid "$(( $1 + 200 ))")"
  publication_id="$(uuid "$(( $1 + 300 ))")"
  mkdir -p "${workdir}/security/${site_id}"
  printf '{"schema_version":"cdnca.edge.cc/v2","tenant_scope_id":"%s","site_id":"%s","policy_id":"%s","policy_version":1,"binding_id":"%s","binding_revision":1,"publication_id":"%s","enabled":%s,"trusted_proxies":[],"allowlist":[],"rules":%s%s}' \
    "${tenant}" "${site_id}" "${policy_id}" "${binding_id}" "${publication_id}" "${6:-true}" "$3" "$4" >"${workdir}/security/${site_id}/cc.compiled.json"
  sha="$(sha256sum "${workdir}/security/${site_id}/cc.compiled.json" | awk '{print $1}')"
  entry="$(entry_id "${site_id}" "$2")"
  item="{\"entry_id\":\"${entry}\",\"tenant_scope_id\":\"${tenant}\",\"site_id\":\"${site_id}\",\"hostname\":\"localhost\",\"listen_port\":$2,\"protocol\":\"http\",\"policy_id\":\"${policy_id}\",\"policy_version\":1,\"binding_id\":\"${binding_id}\",\"binding_revision\":1,\"publication_id\":\"${publication_id}\",\"source_sha256\":\"$(printf 'a%.0s' $(seq 64))\",\"compiled_path\":\"security/${site_id}/cc.compiled.json\",\"compiled_sha256\":\"${sha}\"}"
  registry="${registry:+${registry},}${item}"
  servers="${servers}
  server {
    listen $2;
    server_rewrite_by_lua_block { return require(\"cc\").access(\"${entry}\") }
    log_by_lua_block { require(\"cc\").log() }
    location / { $5 }
  }"
}
rule() { # n priority limit action
  printf '{"rule_id":"%s","priority":%s,"flow":"stop","match":{"path":{"kind":"prefix","value":"/"}},"dimension":"client_ip","limit":%s,"action":%s}' \
    "$(uuid "$1")" "$2" "$3" "$4"
}
fixed() { printf '{"algorithm":"fixed_window","requests":%s,"window_seconds":60}' "$1"; }
reject='{"kind":"reject_429"}'
ok_body="return 200 ok;"
origin_body="proxy_pass http://127.0.0.1:18190;"
switch() { # qps_total qps_5xx rule
  printf ',"auto_switch":{"qps_total":%s,"qps_5xx":%s,"recover_seconds":60,"rules":[%s]}' "$1" "$2" "$3"
}
challenge='{"kind":"challenge","ban_seconds":600,"challenge":{"mode":"js","failure_window_seconds":60,"max_failures":1000,"pass_seconds":3600,"pow_bits":8,"challenge_seconds":120,"bind_ipv4_prefix":24,"bind_ipv6_prefix":64,"key_rotate_seconds":86400}}'

# Registry entries must be ordered by port.
# 1: no auto switch (pre-v5 policy).
site 1 18201 "[$(rule 11 1 "$(fixed 1000)" "${reject}")]" "" "${ok_body}"
# 2: total 20/s -> 1 request per client per minute.
site 2 18202 "[$(rule 21 1 "$(fixed 1000)" "${reject}")]" "$(switch 20 0 "$(rule 22 1 "$(fixed 1)" "${reject}")")" "${ok_body}"
# 3: 5xx 5/s from the origin -> 1 request per client per minute.
site 3 18203 "[$(rule 31 1 "$(fixed 1000)" "${reject}")]" "$(switch 0 5 "$(rule 32 1 "$(fixed 1)" "${reject}")")" "${origin_body}"
# 4: the policy itself challenges every client (503 pages): never 5xx.
site 4 18204 "[$(rule 41 1 '{"algorithm":"always"}' "${challenge}")]" "$(switch 0 3 "$(rule 42 1 "$(fixed 1)" "${reject}")")" "${ok_body}"

valid_registry="${registry}"
valid_servers="${servers}"

nginx_conf() { # <registry file> <servers>
  cat <<EOF
worker_processes 2;
error_log logs/error.log info;
pid nginx.pid;
events { worker_connections 64; }
http {
  lua_package_path '/usr/local/share/cdnca/security/?.lua;;';
  lua_shared_dict cdnca_cc_v2_state 4m;
  set_real_ip_from 127.0.0.1;
  real_ip_header X-Real-IP;
  init_by_lua_block {
    local file = assert(io.open("/runtime/$1", "rb"))
    local registry = file:read("*a")
    file:close()
    require("cc").init({state_dict="cdnca_cc_v2_state", release_root="/runtime", registry_json=registry})
  }
  server {
    listen 18199;
    location = /status {
      default_type application/json;
      content_by_lua_block { ngx.print(require("cjson.safe").encode(require("cc").auto_switch_status())) }
    }
  }
  server {
    listen 18190;
    location = /fail { return 502; }
    location / { return 200 'origin\n'; }
  }
  $2
}
EOF
}
printf '{"schema_version":"cdnca.edge.cc-registry/v1","config_version_id":"auto-switch","entries":[%s]}' "${valid_registry}" >"${workdir}/registry.json"
nginx_conf registry.json "${valid_servers}" >"${workdir}/nginx.conf"
mkdir -p "${workdir}/logs"

docker run -d --rm --name "${container}" --network none --cpus 1 --memory 128m --pids-limit 64 \
  --volume "${engine}:/usr/local/share/cdnca/security/cc.lua:ro" \
  --volume "${workdir}:/runtime" --workdir /runtime \
  "${OPENRESTY_IMAGE}" openresty -g 'daemon off;' -p /runtime/ -c nginx.conf >/dev/null

ready=""
for _ in $(seq 1 100); do
  if docker exec "${container}" curl -fsS -o /dev/null http://127.0.0.1:18199/status 2>/dev/null; then ready=1; break; fi
  sleep 0.1
done
if [ -z "${ready}" ]; then
  cat "${workdir}/logs/error.log" >&2 2>/dev/null || true
  fail "cc.lua did not start with auto switch policies"
fi

if ! docker exec -i -e SITE2="$(uuid 2)" -e SITE3="$(uuid 3)" -e SITE4="$(uuid 4)" "${container}" sh -eu <<'INNER'
fail() { echo "FAIL: $*" >&2; exit 1; }
req() { curl -sS -o /dev/null -w '%{http_code}' -H "X-Real-IP: $2" "http://127.0.0.1:$1$3"; }
expect() { test "$3" = "$2" || fail "$1: want $2, got $3"; }
# status_field <site> <field> -> value from the status endpoint
status_field() {
  curl -fsS http://127.0.0.1:18199/status | tr '{' '\n' | grep "\"site_id\":\"$1\"" | tr ',' '\n' |
    sed -n "s/^\"$2\":\\(.*\\)$/\\1/p" | tr -d '}]'
}
# burst <port> <path> <count>: <count> requests from distinct clients, back
# to back (well under a second each; three times the threshold makes one
# second reach it even when the burst straddles seconds).
burst() {
  n=0
  while [ "${n}" -lt "$3" ]; do
    req "$1" "10.9.$(( n / 250 )).$(( n % 250 + 1 ))" "$2" >/dev/null
    n=$(( n + 1 ))
  done
}

# Pre-v5 policy: unaffected.
for n in 1 2 3; do expect "plain ${n}" 200 "$(req 18201 192.0.2.1 /)"; done
echo "ok   policy without auto_switch runs unchanged"

# Below the thresholds the site's own rules (1000/min) run.
expect "site 2 below 1" 200 "$(req 18202 192.0.2.10 /)"
expect "site 2 below 2" 200 "$(req 18202 192.0.2.10 /)"
test "$(status_field "${SITE2}" active)" = "false" || fail "site 2 engaged before the burst"
seq_before="$(status_field "${SITE2}" sequence)"

burst 18202 / 60
sleep 1.2
# The next request evaluates the burst second and runs the switch rules:
# a fresh client gets its single request, the second is over the limit.
expect "site 2 switched first" 200 "$(req 18202 192.0.2.20 /)"
expect "site 2 switched limit" 429 "$(req 18202 192.0.2.20 /)"
test "$(status_field "${SITE2}" active)" = "true" || fail "site 2 status not engaged"
seq_after="$(status_field "${SITE2}" sequence)"
test "${seq_after}" -gt "${seq_before}" || fail "site 2 sequence did not advance (${seq_before} -> ${seq_after})"
trigger="$(status_field "${SITE2}" trigger_qps)"
test "${trigger}" -ge 20 || fail "site 2 trigger_qps=${trigger}"
echo "ok   ${trigger} requests/s engaged the switch rules (sequence ${seq_before} -> ${seq_after})"

# Origin 5xx: 15 failing requests back to back reach qps_5xx 5.
for n in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do req 18203 "10.8.0.${n}" /fail >/dev/null; done
sleep 1.2
expect "site 3 switched first" 200 "$(req 18203 192.0.2.30 /)"
expect "site 3 switched limit" 429 "$(req 18203 192.0.2.30 /)"
test "$(status_field "${SITE3}" active)" = "true" || fail "site 3 status not engaged by 5xx"
test "$(status_field "${SITE3}" trigger_5xx)" -ge 5 || fail "site 3 trigger_5xx=$(status_field "${SITE3}" trigger_5xx)"
echo "ok   origin 5xx/s engaged the switch rules"

# The engine's own challenge pages (503) are not origin errors.
for n in 1 2 3 4 5 6 7 8 9 10; do
  code="$(req 18204 "10.7.0.${n}" /)"
  test "${code}" = 503 || fail "site 4 challenge page status ${code}"
done
sleep 1.2
req 18204 10.7.1.1 / >/dev/null
test "$(status_field "${SITE4}" active)" = "false" || fail "challenge 503 pages engaged the 5xx switch"
echo "ok   challenge pages do not count as 5xx"

# Recovery: quiet for recover_seconds (60) -> the site's own rules again.
sleep 65
status="$(curl -fsS http://127.0.0.1:18199/status)"
test "$(status_field "${SITE2}" active)" = "false" || fail "site 2 did not recover: ${status}"
test "$(status_field "${SITE3}" active)" = "false" || fail "site 3 did not recover: ${status}"
test "$(status_field "${SITE2}" sequence)" -gt "${seq_after}" || fail "site 2 recovery did not advance the sequence"
for n in 1 2 3; do expect "site 2 recovered ${n}" 200 "$(req 18202 192.0.2.20 /)"; done
for n in 1 2 3; do expect "site 3 recovered ${n}" 200 "$(req 18203 192.0.2.30 /)"; done
echo "ok   recovered to the site's rules after recover_seconds"
INNER
then
  tail -n 40 "${workdir}/logs/error.log" >&2 2>/dev/null || true
  fail "auto switch behaviour"
fi
grep -q "cc auto switch engaged" "${workdir}/logs/error.log" || fail "engage not logged"
grep -q "cc auto switch recovered" "${workdir}/logs/error.log" || fail "recovery not logged"

# Invalid auto switch shapes are refused at load: init_by_lua fails with the
# validation error and nginx exits (timeout only stops a started one).
docker rm -f "${container}" >/dev/null 2>&1 || true
for case in disabled nothreshold sharedid; do
  registry=""
  servers=""
  case "${case}" in
    disabled) site 5 18205 "[]" "$(switch 20 0 "$(rule 52 1 "$(fixed 1)" "${reject}")")" "${ok_body}" false ;;
    nothreshold) site 5 18205 "[$(rule 51 1 "$(fixed 1000)" "${reject}")]" "$(switch 0 0 "$(rule 52 1 "$(fixed 1)" "${reject}")")" "${ok_body}" ;;
    sharedid) site 5 18205 "[$(rule 51 1 "$(fixed 1000)" "${reject}")]" "$(switch 20 0 "$(rule 51 1 "$(fixed 1)" "${reject}")")" "${ok_body}" ;;
  esac
  printf '{"schema_version":"cdnca.edge.cc-registry/v1","config_version_id":"auto-switch-%s","entries":[%s]}' "${case}" "${registry}" >"${workdir}/registry-${case}.json"
  nginx_conf "registry-${case}.json" "${servers}" >"${workdir}/nginx-${case}.conf"
  if docker run --rm --network none --cpus 1 --memory 128m --pids-limit 64 \
    --volume "${engine}:/usr/local/share/cdnca/security/cc.lua:ro" \
    --volume "${workdir}:/runtime" --workdir /runtime \
    "${OPENRESTY_IMAGE}" timeout 5 openresty -g 'daemon off;' -p /runtime/ -c "nginx-${case}.conf" >"${workdir}/t-${case}.log" 2>&1 ||
    ! grep -q "invalid auto switch\|invalid or duplicate policy rule\|invalid policy rules" "${workdir}/t-${case}.log"; then
    cat "${workdir}/t-${case}.log" >&2
    fail "invalid auto switch (${case}) loaded"
  fi
done
echo "ok   disabled policy, missing threshold and shared rule ID are refused"
echo "PASS auto switch"
