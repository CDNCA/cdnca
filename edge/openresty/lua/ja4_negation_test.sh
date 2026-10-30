#!/bin/sh
# WAF rules "JA4 not in list" (WAFMatch.not_ja4, rule plan
# op ja4_not_in, CAPABILITY_NAME_WAF_JA4_NEGATION v1) on a real OpenResty
# (the pinned OpenResty of edge/openresty/runtime.env, one --rm --network none
# container; $cdnca_ja4 stands in for the native JA4 module as in
# ccv2/count_by_test.sh), both executors:
#   - 18601: the rendered location (security-location, as the site runtime
#     renders a bound policy);
#   - 18602: the rule plan interpreter (cdnca_rule_interp, dynamic routing).
# One rule blocks /na unless the JA4 is one of two allowed fingerprints, and
# one blocks /in when the JA4 is one of them (ja4_in, unchanged). A request
# without a fingerprint (plain HTTP / HTTP/3: empty $cdnca_ja4) never matches
# either rule. The fingerprint comes from X-Test-JA4.
# Usage: edge/openresty/lua/ja4_negation_test.sh
set -eu
repo_root="$(CDPATH='' cd -- "$(dirname -- "$0")/../../.." && pwd)"
. "${repo_root}/edge/openresty/runtime.env"
image="${JA4_NEGATION_IMAGE:-${OPENRESTY_IMAGE}}"
docker image inspect "${image}" >/dev/null 2>&1 || { echo "BLOCKED: ${image} missing" >&2; exit 69; }
work="$(mktemp -d "${TMPDIR:-/tmp}/cdnca-ja4-negation.XXXXXX")"
container="cdnca-ja4-negation-$(basename "${work}" | tr -cd 'a-z0-9')"
cleanup() { docker rm -f "${container}" >/dev/null 2>&1 || true; rm -rf -- "${work}"; }
trap cleanup EXIT HUP INT TERM
fail() { echo "FAIL: $*" >&2; exit 1; }

allowed_a=t13d1516h2_8daaf6152771_e5627efa2ab1
allowed_b=t13d1516h2_8daaf6152771_b186095e22b6
site=5ee00000-0000-4000-8000-0000000000d1
policy=6ee00000-0000-4000-8000-0000000000d2
zero="$(printf '%064d' 0)"
mkdir -p "${work}/lua" "${work}/logs"
for file in cdnca_waf.lua cdnca_banlist.lua cdnca_rule_interp.lua; do cp "${repo_root}/edge/openresty/lua/${file}" "${work}/lua/${file}"; done

rules='[{"rule_id":"7ee00000-0000-4000-8000-0000000000e1","match":{"path":{"kind":"prefix","value":"/na"},"not_ja4":["'"${allowed_b}"'","'"${allowed_a}"'"]},"action":"block","flow":"stop"},{"rule_id":"7ee00000-0000-4000-8000-0000000000e2","match":{"path":{"kind":"prefix","value":"/in"},"ja4":["'"${allowed_b}"'","'"${allowed_a}"'"]},"action":"block","flow":"stop"}]'
printf '[{"kind":"waf","policy_id":"%s","policy_version":1,"binding_revision":1,"runtime_sha256":"%s","enabled":true,"default_action":"allow","rules":%s}]' \
  "${policy}" "${zero}" "${rules}" |
  GOWORK="${repo_root}/go.work" go -C "${repo_root}/libs/edgeconfig" run ./cmd/security-location "${site}" |
  awk 'BEGIN{n=0} /^=====$/{n++; next} n==1' >"${work}/rendered.lua"
grep -q 'cdnca_ja4 or "") ~= ""' "${work}/rendered.lua" || fail "not_ja4 not rendered"
# The plan CompileSecurityRulePlan builds for the same policy (values sorted).
cat >"${work}/plan.json" <<EOF
{"schema":"cdnca.edge.rule-plan/v1","header_overflow":"none","telemetry":false,"segments":[{"kind":"waf","policy_id":"${policy}","policy_version":1,"binding_revision":1,"runtime_sha256":"${zero}","enabled":true,"default_action":"allow","default_rule_id":"${policy}:default","rules":[
{"rule_id":"7ee00000-0000-4000-8000-0000000000e1","action":"block","flow":"stop","conditions":[{"op":"path_prefix","value":"/na"},{"op":"ja4_not_in","values":["${allowed_b}","${allowed_a}"]}]},
{"rule_id":"7ee00000-0000-4000-8000-0000000000e2","action":"block","flow":"stop","conditions":[{"op":"path_prefix","value":"/in"},{"op":"ja4_in","values":["${allowed_b}","${allowed_a}"]}]}]}]}
EOF

telemetry='set $cdnca_security_emit ""; set $cdnca_security_type ""; set $cdnca_security_action ""; set $cdnca_security_severity ""; set $cdnca_security_rule_id ""; set $cdnca_security_block_page ""; set $cdnca_security_policy_id ""; set $cdnca_security_detector ""; set $cdnca_security_matched ""; set $cdnca_security_body "";'
cat >"${work}/nginx.conf" <<EOF
worker_processes 1;
error_log logs/error.log info;
pid logs/nginx.pid;
events { worker_connections 64; }
http {
  access_log off;
  # Stands in for the native JA4 module's \$cdnca_ja4.
  map \$http_x_test_ja4 \$cdnca_ja4 { default \$http_x_test_ja4; }
  lua_package_path "/w/lua/?.lua;;";
  lua_shared_dict cdnca_waf_state 4m;
  lua_shared_dict cdnca_security_bans 4m;
  init_by_lua_block {
    local file = assert(io.open("/w/plan.json"))
    local program, err = require("cdnca_rule_interp").compile_json(file:read("*a"))
    file:close()
    if not program then error("rule plan: " .. tostring(err)) end
    ja4_negation_program = program
  }
  server { listen 127.0.0.1:18601; ${telemetry}
    location / {
$(cat "${work}/rendered.lua")
      content_by_lua_block { ngx.say("ok") }
    } }
  server { listen 127.0.0.1:18602; ${telemetry}
    location / {
      rewrite_by_lua_block { require("cdnca_rule_interp").enforce(ja4_negation_program) }
      content_by_lua_block { ngx.say("ok") }
    } }
}
EOF
chmod -R a+rwX "${work}"
docker run -d --rm --name "${container}" --network none --cpus 1 --memory 128m --pids-limit 32 -v "${work}:/w" \
  "${image}" openresty -g 'daemon off;' -p /w/ -c nginx.conf >/dev/null
ready=""
for _ in $(seq 1 100); do
  if docker exec "${container}" sh -c 'printf "GET / HTTP/1.0\r\n\r\n" | nc -w 2 127.0.0.1 18602' 2>/dev/null | grep -q '^HTTP/1.1 200'; then ready=1; break; fi
  sleep 0.1
done
[ -n "${ready}" ] || { cat "${work}/logs/error.log" >&2 2>/dev/null || true; fail "OpenResty did not start"; }

if ! docker exec -i -e A="${allowed_a}" -e B="${allowed_b}" "${container}" sh -eu <<'INNER'
fail() { echo "FAIL: $*" >&2; exit 1; }
# code <port> <path> [ja4]
code() {
  header=""; [ -n "${3:-}" ] && header="X-Test-JA4: $3\r\n"
  printf "GET $2 HTTP/1.0\r\nHost: action.test\r\n${header}\r\n" | nc -w 5 127.0.0.1 "$1" | head -1 | awk '{print $2}'
}
other=t13d3112h2_e8f1e7e78f70_6bebaf5329ac
for port in 18601 18602; do
  [ "$(code "$port" /na "$other")" = 403 ] || fail "$port: other JA4 on not_ja4 rule must be 403"
  [ "$(code "$port" /na "$A")" = 200 ] || fail "$port: allowed JA4 A on not_ja4 rule must pass"
  [ "$(code "$port" /na "$B")" = 200 ] || fail "$port: allowed JA4 B on not_ja4 rule must pass"
  [ "$(code "$port" /na)" = 200 ] || fail "$port: no fingerprint must never match not_ja4"
  [ "$(code "$port" /in "$A")" = 403 ] || fail "$port: ja4_in must still block a listed JA4"
  [ "$(code "$port" /in "$other")" = 200 ] || fail "$port: ja4_in must pass an unlisted JA4"
  [ "$(code "$port" /in)" = 200 ] || fail "$port: no fingerprint must never match ja4_in"
  echo "PASS port $port (7 cases)"
done
INNER
then
  cat "${work}/logs/error.log" >&2 2>/dev/null || true
  fail "cases failed"
fi
if grep -E '\[(error|crit|alert|emerg)\]' "${work}/logs/error.log" >/dev/null; then
  grep -E '\[(error|crit|alert|emerg)\]' "${work}/logs/error.log" | head -5 >&2
  fail "error log has errors"
fi
echo "PASS ja4_negation_test"
