#!/bin/sh
# CC v8 auto switch region / node overrides (fix-fwregion) on a real
# OpenResty. The engine is told its node ID (init node_id); each site's
# policy carries the global switch plus overrides:
#   - site 1: global 20/s, this node overridden off -> never switches, the
#     status lists no auto switch for it;
#   - site 2: global off, this node overridden to 20/s with rule set "g2"
#     (a 1-request limit) -> switches, status source "override";
#   - site 3: global 20/s, an override naming another node only -> this
#     node runs global (status source "global");
#   - a node listed in two overrides, an unused rule set or an override on
#     the global rules while global is off is refused.
#
# Usage: edge/openresty/ccv2/auto_switch_overrides_test.sh
#        CC_ENGINE=<path to engine.lua> ...
set -eu

repo_root="$(CDPATH='' cd -- "$(dirname -- "$0")/../../.." && pwd)"
# shellcheck disable=SC1091
. "${repo_root}/edge/openresty/runtime.env"
engine="${CC_ENGINE:-${repo_root}/edge/openresty/ccv2/engine.lua}"

workdir="$(mktemp -d "${TMPDIR:-/tmp}/fix-fwregion-lua.XXXXXX")"
container="fix-fwregion-$(basename "${workdir}" | tr -cd 'A-Za-z0-9')"
cleanup() {
  docker rm -f "${container}" >/dev/null 2>&1 || true
  rm -rf -- "${workdir}"
}
trap cleanup EXIT HUP INT TERM
fail() { echo "FAIL: $*" >&2; exit 1; }

tenant="018f1000-0000-7000-8000-000000000001"
this_node="018f1000-0000-7000-8000-0000000000aa"
other_node="018f1000-0000-7000-8000-0000000000bb"
uuid() { printf '018f1000-0000-7000-8000-%012d' "$1"; }
entry_id() { printf '%s\0%s\0%s\0%s\0%s' "${tenant}" "$1" localhost "$2" http | sha256sum | awk '{print substr($1,1,32)}'; }

registry=""
servers=""
site() { # <n> <port> <rules json> <extra policy fields>
  site_id="$(uuid "$1")"
  policy_id="$(uuid "$(( $1 + 100 ))")"
  binding_id="$(uuid "$(( $1 + 200 ))")"
  publication_id="$(uuid "$(( $1 + 300 ))")"
  mkdir -p "${workdir}/security/${site_id}"
  printf '{"schema_version":"cdnca.edge.cc/v2","tenant_scope_id":"%s","site_id":"%s","policy_id":"%s","policy_version":1,"binding_id":"%s","binding_revision":1,"publication_id":"%s","enabled":true,"trusted_proxies":[],"allowlist":[],"rules":%s%s}' \
    "${tenant}" "${site_id}" "${policy_id}" "${binding_id}" "${publication_id}" "$3" "$4" >"${workdir}/security/${site_id}/cc.compiled.json"
  sha="$(sha256sum "${workdir}/security/${site_id}/cc.compiled.json" | awk '{print $1}')"
  entry="$(entry_id "${site_id}" "$2")"
  item="{\"entry_id\":\"${entry}\",\"tenant_scope_id\":\"${tenant}\",\"site_id\":\"${site_id}\",\"hostname\":\"localhost\",\"listen_port\":$2,\"protocol\":\"http\",\"policy_id\":\"${policy_id}\",\"policy_version\":1,\"binding_id\":\"${binding_id}\",\"binding_revision\":1,\"publication_id\":\"${publication_id}\",\"source_sha256\":\"$(printf 'a%.0s' $(seq 64))\",\"compiled_path\":\"security/${site_id}/cc.compiled.json\",\"compiled_sha256\":\"${sha}\"}"
  registry="${registry:+${registry},}${item}"
  servers="${servers}
  server {
    listen $2;
    server_rewrite_by_lua_block { return require(\"cc\").access(\"${entry}\") }
    log_by_lua_block { require(\"cc\").log() }
    location / { return 200 ok; }
  }"
}
rule() { # n priority limit action
  printf '{"rule_id":"%s","priority":%s,"flow":"stop","match":{"path":{"kind":"prefix","value":"/"}},"dimension":"client_ip","limit":%s,"action":%s}' \
    "$(uuid "$1")" "$2" "$3" "$4"
}
fixed() { printf '{"algorithm":"fixed_window","requests":%s,"window_seconds":60}' "$1"; }
reject='{"kind":"reject_429"}'

# 1: global 20/s, this node off.
site 1 18301 "[$(rule 11 1 "$(fixed 1000)" "${reject}")]" \
  ",\"auto_switch\":{\"qps_total\":20,\"qps_5xx\":0,\"recover_seconds\":60,\"rules\":[$(rule 12 1 "$(fixed 1)" "${reject}")],\"overrides\":[{\"nodes\":[\"${this_node}\"],\"qps_total\":0,\"qps_5xx\":0,\"recover_seconds\":0}]}"
# 2: global off, this node 20/s on rule set g2.
site 2 18302 "[$(rule 21 1 "$(fixed 1000)" "${reject}")]" \
  ",\"auto_switch\":{\"qps_total\":0,\"qps_5xx\":0,\"recover_seconds\":0,\"rules\":[],\"overrides\":[{\"nodes\":[\"${this_node}\"],\"qps_total\":20,\"qps_5xx\":0,\"recover_seconds\":60,\"rule_set\":\"g2\"}],\"rule_sets\":[{\"name\":\"g2\",\"rules\":[$(rule 22 1 "$(fixed 1)" "${reject}")]}]}"
# 3: global 20/s, only another node overridden.
site 3 18303 "[$(rule 31 1 "$(fixed 1000)" "${reject}")]" \
  ",\"auto_switch\":{\"qps_total\":20,\"qps_5xx\":0,\"recover_seconds\":60,\"rules\":[$(rule 32 1 "$(fixed 1)" "${reject}")],\"overrides\":[{\"nodes\":[\"${other_node}\"],\"qps_total\":0,\"qps_5xx\":0,\"recover_seconds\":0}]}"
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
    require("cc").init({state_dict="cdnca_cc_v2_state", release_root="/runtime", registry_json=registry, node_id="${this_node}"})
  }
  server {
    listen 18299;
    location = /status {
      default_type application/json;
      content_by_lua_block { ngx.print(require("cjson.safe").encode(require("cc").auto_switch_status())) }
    }
  }
  $2
}
EOF
}
printf '{"schema_version":"cdnca.edge.cc-registry/v1","config_version_id":"auto-switch-overrides","entries":[%s]}' "${valid_registry}" >"${workdir}/registry.json"
nginx_conf registry.json "${valid_servers}" >"${workdir}/nginx.conf"
mkdir -p "${workdir}/logs"

docker run -d --rm --name "${container}" --network none --cpus 1 --memory 128m --pids-limit 64 \
  --volume "${engine}:/usr/local/share/cdnca/security/cc.lua:ro" \
  --volume "${workdir}:/runtime" --workdir /runtime \
  "${OPENRESTY_IMAGE}" openresty -g 'daemon off;' -p /runtime/ -c nginx.conf >/dev/null

ready=""
for _ in $(seq 1 100); do
  if docker exec "${container}" curl -fsS -o /dev/null http://127.0.0.1:18299/status 2>/dev/null; then ready=1; break; fi
  sleep 0.1
done
if [ -z "${ready}" ]; then
  cat "${workdir}/logs/error.log" >&2 2>/dev/null || true
  fail "cc.lua did not start with auto switch overrides"
fi

if ! docker exec -i -e SITE1="$(uuid 1)" -e SITE2="$(uuid 2)" -e SITE3="$(uuid 3)" "${container}" sh -eu <<'INNER'
fail() { echo "FAIL: $*" >&2; exit 1; }
req() { curl -sS -o /dev/null -w '%{http_code}' -H "X-Real-IP: $2" "http://127.0.0.1:$1/"; }
expect() { test "$3" = "$2" || fail "$1: want $2, got $3"; }
status_field() {
  curl -fsS http://127.0.0.1:18299/status | tr '{' '\n' | grep "\"site_id\":\"$1\"" | tr ',' '\n' |
    sed -n "s/^\"$2\":\\(.*\\)$/\\1/p" | tr -d '}]"'
}
burst() {
  n=0
  while [ "${n}" -lt "$2" ]; do
    req "$1" "10.9.$(( n / 250 )).$(( n % 250 + 1 ))" >/dev/null
    n=$(( n + 1 ))
  done
}

for port in 18301 18302 18303; do burst "${port}" 60; done
sleep 1.2

expect "site 1 first" 200 "$(req 18301 192.0.2.10)"
expect "site 1 second" 200 "$(req 18301 192.0.2.10)"
test -z "$(status_field "${SITE1}" active)" || fail "site 1 (overridden off) is in the status"
echo "ok   node override off: global switch does not run here"

expect "site 2 switched first" 200 "$(req 18302 192.0.2.20)"
expect "site 2 switched limit" 429 "$(req 18302 192.0.2.20)"
test "$(status_field "${SITE2}" active)" = "true" || fail "site 2 not engaged"
test "$(status_field "${SITE2}" source)" = "override" || fail "site 2 source $(status_field "${SITE2}" source)"
echo "ok   node override with its own rule set runs while global is off"

expect "site 3 switched first" 200 "$(req 18303 192.0.2.30)"
expect "site 3 switched limit" 429 "$(req 18303 192.0.2.30)"
test "$(status_field "${SITE3}" source)" = "global" || fail "site 3 source $(status_field "${SITE3}" source)"
echo "ok   another node's override leaves this node on global"
INNER
then
  cat "${workdir}/logs/error.log" >&2 2>/dev/null || true
  fail "auto switch overrides"
fi

for case in twice unused globaloff; do
  registry=""
  servers=""
  case "${case}" in
    twice) site 5 18305 "[$(rule 51 1 "$(fixed 1000)" "${reject}")]" \
      ",\"auto_switch\":{\"qps_total\":20,\"qps_5xx\":0,\"recover_seconds\":60,\"rules\":[$(rule 52 1 "$(fixed 1)" "${reject}")],\"overrides\":[{\"nodes\":[\"${this_node}\"],\"qps_total\":0,\"qps_5xx\":0,\"recover_seconds\":0},{\"nodes\":[\"${this_node}\"],\"qps_total\":30,\"qps_5xx\":0,\"recover_seconds\":60}]}" ;;
    unused) site 5 18305 "[$(rule 51 1 "$(fixed 1000)" "${reject}")]" \
      ",\"auto_switch\":{\"qps_total\":20,\"qps_5xx\":0,\"recover_seconds\":60,\"rules\":[$(rule 52 1 "$(fixed 1)" "${reject}")],\"overrides\":[{\"nodes\":[\"${this_node}\"],\"qps_total\":0,\"qps_5xx\":0,\"recover_seconds\":0}],\"rule_sets\":[{\"name\":\"g\",\"rules\":[$(rule 53 1 "$(fixed 1)" "${reject}")]}]}" ;;
    globaloff) site 5 18305 "[$(rule 51 1 "$(fixed 1000)" "${reject}")]" \
      ",\"auto_switch\":{\"qps_total\":0,\"qps_5xx\":0,\"recover_seconds\":0,\"rules\":[],\"overrides\":[{\"nodes\":[\"${this_node}\"],\"qps_total\":30,\"qps_5xx\":0,\"recover_seconds\":60}]}" ;;
  esac
  printf '{"schema_version":"cdnca.edge.cc-registry/v1","config_version_id":"overrides-%s","entries":[%s]}' "${case}" "${registry}" >"${workdir}/registry-${case}.json"
  nginx_conf "registry-${case}.json" "${servers}" >"${workdir}/nginx-${case}.conf"
  if docker run --rm --network none --cpus 1 --memory 128m --pids-limit 64 \
    --volume "${engine}:/usr/local/share/cdnca/security/cc.lua:ro" \
    --volume "${workdir}:/runtime" --workdir /runtime \
    "${OPENRESTY_IMAGE}" timeout 5 openresty -g 'daemon off;' -p /runtime/ -c "nginx-${case}.conf" >"${workdir}/t-${case}.log" 2>&1 ||
    ! grep -q "auto switch" "${workdir}/t-${case}.log"; then
    cat "${workdir}/t-${case}.log" >&2
    fail "invalid auto switch override (${case}) loaded"
  fi
done
echo "ok   duplicate node, unused rule set and global-rules override while global off are refused"
echo "PASS auto switch overrides"
