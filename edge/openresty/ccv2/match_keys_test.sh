#!/bin/sh
# CC API v7 (CAPABILITY_NAME_CC_MATCH_KEYS) on a real
# OpenResty: counting by User-Agent, Referer, a named header, cookie and
# query argument (a request without the value is not counted), ja4 + uri,
# and rules matching on JA4 (match.ja4: listed fingerprints only, never a
# request without one).
#
# Usage: edge/openresty/ccv2/match_keys_test.sh
#        CC_ENGINE=<path to engine.lua> ...   (e.g. the pre-v4 engine)
set -eu

repo_root="$(CDPATH='' cd -- "$(dirname -- "$0")/../../.." && pwd)"
# shellcheck disable=SC1091
. "${repo_root}/edge/openresty/runtime.env"
engine="${CC_ENGINE:-${repo_root}/edge/openresty/ccv2/engine.lua}"

workdir="$(mktemp -d "${TMPDIR:-/tmp}/cdnca-fix-ja4rule-cc.XXXXXX")"
container="cdnca-ja4rule-cc-$(basename "${workdir}" | tr -cd 'A-Za-z0-9')"
cleanup() {
  docker rm -f "${container}" >/dev/null 2>&1 || true
  rm -rf -- "${workdir}"
}
trap cleanup EXIT HUP INT TERM
fail() { echo "FAIL: $*" >&2; exit 1; }

tenant="018f1000-0000-7000-8000-000000000001"
uuid() { printf '018f1000-0000-7000-8000-%012d' "$1"; }
entry_id() { printf '%s\0%s\0%s\0%s\0%s' "${tenant}" "$1" localhost "$2" http | sha256sum | awk '{print substr($1,1,32)}'; }

# site <n> <port> <rules json>: one CC v2 policy, its registry entry and server.
registry=""
servers=""
site() {
  site_id="$(uuid "$1")"
  policy_id="$(uuid "$(( $1 + 100 ))")"
  binding_id="$(uuid "$(( $1 + 200 ))")"
  publication_id="$(uuid "$(( $1 + 300 ))")"
  mkdir -p "${workdir}/security/${site_id}"
  printf '{"schema_version":"cdnca.edge.cc/v2","tenant_scope_id":"%s","site_id":"%s","policy_id":"%s","policy_version":1,"binding_id":"%s","binding_revision":1,"publication_id":"%s","enabled":true,"trusted_proxies":[],"allowlist":[],"rules":%s}' \
    "${tenant}" "${site_id}" "${policy_id}" "${binding_id}" "${publication_id}" "$3" >"${workdir}/security/${site_id}/cc.compiled.json"
  sha="$(sha256sum "${workdir}/security/${site_id}/cc.compiled.json" | awk '{print $1}')"
  entry="$(entry_id "${site_id}" "$2")"
  item="{\"entry_id\":\"${entry}\",\"tenant_scope_id\":\"${tenant}\",\"site_id\":\"${site_id}\",\"hostname\":\"localhost\",\"listen_port\":$2,\"protocol\":\"http\",\"policy_id\":\"${policy_id}\",\"policy_version\":1,\"binding_id\":\"${binding_id}\",\"binding_revision\":1,\"publication_id\":\"${publication_id}\",\"source_sha256\":\"$(printf 'a%.0s' $(seq 64))\",\"compiled_path\":\"security/${site_id}/cc.compiled.json\",\"compiled_sha256\":\"${sha}\"}"
  registry="${registry:+${registry},}${item}"
  servers="${servers}
  server {
    listen $2;
    server_rewrite_by_lua_block { return require(\"cc\").access(\"${entry}\") }
    log_by_lua_block { require(\"cc\").log() }
    location / { return 200 'ok\n'; }
  }"
}
rule() { # n priority match count_by limit action
  printf '{"rule_id":"%s","priority":%s,"flow":"stop","match":%s,"dimension":"client_ip"%s,"limit":%s,"action":%s}' \
    "$(uuid "$1")" "$2" "$3" "$4" "$5" "$6"
}
any='{"path":{"kind":"prefix","value":"/"}}'
fixed3='{"algorithm":"fixed_window","requests":3,"window_seconds":60}'
reject='{"kind":"reject_429"}'

any='{"path":{"kind":"prefix","value":"/"}}'
fixed3='{"algorithm":"fixed_window","requests":3,"window_seconds":60}'
reject='{"kind":"reject_429"}'
fp_a=t13d1516h2_8daaf6152771_02713d6af862
fp_b=t13d1516h2_8daaf6152771_b186095e22b6

# Registry entries must be ordered by port.
site 1 18301 "[$(rule 11 1 "${any}" ',"count_by":[{"key":"user_agent"}]' "${fixed3}" "${reject}")]"
site 2 18302 "[$(rule 21 1 "${any}" ',"count_by":[{"key":"referer"}]' "${fixed3}" "${reject}")]"
site 3 18303 "[$(rule 31 1 "${any}" ',"count_by":[{"key":"header","name":"x-api-key"}]' "${fixed3}" "${reject}")]"
site 4 18304 "[$(rule 41 1 "${any}" ',"count_by":[{"key":"cookie","name":"sid"}]' "${fixed3}" "${reject}")]"
site 5 18305 "[$(rule 51 1 "${any}" ',"count_by":[{"key":"query","name":"token"}]' "${fixed3}" "${reject}")]"
site 6 18306 "[$(rule 61 1 "${any}" ',"count_by":[{"key":"uri_path"},{"key":"ja4"}]' "${fixed3}" "${reject}")]"
ja4_match='{"path":{"kind":"prefix","value":"/"},"ja4":["'"${fp_a}"'","'"${fp_b}"'"]}'
site 7 18307 "[$(rule 71 1 "${ja4_match}" '' "${fixed3}" "${reject}")]"

cat >"${workdir}/nginx.conf" <<EOF
worker_processes 1;
error_log logs/error.log info;
pid nginx.pid;
events { worker_connections 64; }
http {
  lua_package_path '/usr/local/share/cdnca/security/?.lua;;';
  lua_shared_dict cdnca_cc_v2_state 4m;
  # Stands in for the native JA4 module's \$cdnca_ja4 (G2).
  map \$http_x_test_ja4 \$cdnca_ja4 { default \$http_x_test_ja4; }
  set_real_ip_from 127.0.0.1;
  real_ip_header X-Real-IP;
  # The registry is long for one inline Lua block; read it from a file.
  init_by_lua_block {
    local file = assert(io.open("/runtime/registry.json", "rb"))
    local registry = file:read("*a")
    file:close()
    require("cc").init({state_dict="cdnca_cc_v2_state", release_root="/runtime", registry_json=registry})
  }
  server {
    listen 18199;
    location = /metric {
      content_by_lua_block {
        local value = ngx.shared.cdnca_cc_v2_state:get(ngx.var.arg_key)
        ngx.print(tostring(value or 0))
      }
    }
    location = /snapshot {
      set \$cdnca_node_id 018f1000-0000-7000-8000-000000000999;
      content_by_lua_block {
        local snapshot, err = require("cc").metrics(ngx.var.arg_entry)
        if not snapshot then return ngx.exit(500) end
        ngx.print(require("cjson.safe").encode(snapshot))
      }
    }
  }
  ${servers}
}
EOF
printf '{"schema_version":"cdnca.edge.cc-registry/v1","config_version_id":"match-keys","entries":[%s]}' "${registry}" >"${workdir}/registry.json"
mkdir -p "${workdir}/logs"

docker run -d --rm --name "${container}" --network none --cpus 1 --memory 128m --pids-limit 64 \
  --volume "${engine}:/usr/local/share/cdnca/security/cc.lua:ro" \
  --volume "${workdir}:/runtime" --workdir /runtime \
  "${OPENRESTY_IMAGE}" openresty -g 'daemon off;' -p /runtime/ -c nginx.conf >/dev/null

ready=""
for _ in $(seq 1 100); do
  if docker exec "${container}" curl -fsS -o /dev/null http://127.0.0.1:18199/metric?key=x 2>/dev/null; then ready=1; break; fi
  sleep 0.1
done
if [ -z "${ready}" ]; then
  cat "${workdir}/logs/error.log" >&2 2>/dev/null || true
  fail "cc.lua did not start with CC v7 policies"
fi

if ! docker exec -i -e FP_A="${fp_a}" -e FP_B="${fp_b}" "${container}" sh -eu <<'INNER'
fail() { echo "FAIL: $*" >&2; exit 1; }
# req <port> <ip> <path> [header line] -> status
req() {
  # -A '': no User-Agent unless the case sends one (curl adds its own).
  curl -sS -o /dev/null -w '%{http_code}' -A '' -H "X-Real-IP: $2" ${4:+-H "$4"} "http://127.0.0.1:$1$3"
}
expect() { test "$3" = "$2" || fail "$1: want $2, got $3"; }
# shared <port> <header for the bucket> <header for another bucket> <label>:
# three clients sharing the value fill the bucket, a fourth is over the
# limit, another value and requests without one pass.
shared() {
  expect "$4 1" 200 "$(req "$1" 192.0.2.1 /a "$2")"
  expect "$4 2" 200 "$(req "$1" 192.0.2.2 /b "$2")"
  expect "$4 3" 200 "$(req "$1" 192.0.2.3 /c "$2")"
  expect "$4 over limit" 429 "$(req "$1" 192.0.2.4 /d "$2")"
  expect "$4 other value" 200 "$(req "$1" 192.0.2.4 /d "$3")"
  for n in 1 2 3 4 5; do expect "$4 absent ${n}" 200 "$(req "$1" 192.0.2.5 /e)"; done
  echo "ok   $4"
}
shared 18301 "User-Agent: bot/1" "User-Agent: bot/2" user_agent
shared 18302 "Referer: https://a.test/" "Referer: https://b.test/" referer
shared 18303 "X-Api-Key: k1" "X-Api-Key: k2" "header x-api-key"
shared 18304 "Cookie: a=1; sid=s1" "Cookie: sid=s2" "cookie sid"

# query token: the value of ?token=, other arguments do not matter.
expect "query 1" 200 "$(req 18305 192.0.2.1 '/a?token=t1&x=1')"
expect "query 2" 200 "$(req 18305 192.0.2.2 '/b?x=2&token=t1')"
expect "query 3" 200 "$(req 18305 192.0.2.3 '/c?token=t1')"
expect "query over limit" 429 "$(req 18305 192.0.2.4 '/d?token=t1')"
expect "query other value" 200 "$(req 18305 192.0.2.4 '/d?token=t2')"
for n in 1 2 3 4 5; do expect "query absent ${n}" 200 "$(req 18305 192.0.2.5 '/e?x=1')"; done
echo "ok   query token"

# uri_path + ja4: same path and fingerprint add up; another path or
# fingerprint is another bucket; no fingerprint is not counted.
expect "path+ja4 1" 200 "$(req 18306 192.0.2.1 /p "X-Test-JA4: ${FP_A}")"
expect "path+ja4 2" 200 "$(req 18306 192.0.2.2 /p "X-Test-JA4: ${FP_A}")"
expect "path+ja4 3" 200 "$(req 18306 192.0.2.3 /p "X-Test-JA4: ${FP_A}")"
expect "path+ja4 over limit" 429 "$(req 18306 192.0.2.4 /p "X-Test-JA4: ${FP_A}")"
expect "path+ja4 other path" 200 "$(req 18306 192.0.2.4 /q "X-Test-JA4: ${FP_A}")"
expect "path+ja4 other ja4" 200 "$(req 18306 192.0.2.4 /p "X-Test-JA4: ${FP_B}")"
for n in 1 2 3 4 5; do expect "path+ja4 no ja4 ${n}" 200 "$(req 18306 192.0.2.5 /p)"; done
echo "ok   uri_path + ja4"

# match.ja4: only listed fingerprints are limited (per client IP).
for n in 1 2 3; do expect "ja4 match ${n}" 200 "$(req 18307 192.0.2.9 / "X-Test-JA4: ${FP_A}")"; done
expect "ja4 match over limit" 429 "$(req 18307 192.0.2.9 / "X-Test-JA4: ${FP_A}")"
for n in 1 2 3 4 5; do expect "ja4 unlisted ${n}" 200 "$(req 18307 192.0.2.10 / "X-Test-JA4: t13d3112h2_e8f1e7e78f70_6bebaf5329ac")"; done
for n in 1 2 3 4 5; do expect "ja4 none ${n}" 200 "$(req 18307 192.0.2.11 /)"; done
echo "ok   match.ja4"
INNER
then
  tail -n 40 "${workdir}/logs/error.log" >&2 2>/dev/null || true
  exit 1
fi
if grep -E '\[(error|crit|alert|emerg)\]' "${workdir}/logs/error.log" >&2; then
  fail "engine logged errors"
fi
echo "PASS ccv2 match_keys (CC v7)"
