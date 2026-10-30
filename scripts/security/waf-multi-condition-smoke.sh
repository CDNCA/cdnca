#!/bin/sh
# Real-OpenResty evidence that the node enforces a WAF rule of several inspect
# clauses on one target and of more than four conditions (S1 raised the rule
# to edgeconfig.MaxWAFInspectPerRule = 8 clauses, content conditions
# repeatable), as WAF subscription feeds compile them
# (services/control-api/internal/wafsubscription): the rule is rendered by
# libs/edgeconfig (cmd/security-location, the v7 node renderer) and every
# clause must hold (AND), so a request matching all clauses is blocked and a
# request missing any one clause passes.
#   WAF_MULTI_IMAGE  node runtime image (default cdnca-native-runtime:edge-golden)
# Prints PASS|FAIL <case>; exits non-zero on any failure.
set -eu
repo_root="$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)"
image="${WAF_MULTI_IMAGE:-cdnca-native-runtime:edge-golden}"
work="$(mktemp -d "${TMPDIR:-/tmp}/cdnca-waf-multi.XXXXXX")"
container="cdnca-waf-multi-$(basename "${work}" | tr -cd 'a-z0-9')"
cleanup() { docker rm -f "${container}" >/dev/null 2>&1 || true; rm -rf -- "${work}"; }
trap cleanup EXIT HUP INT TERM
fail() { echo "FAIL: $*" >&2; exit 1; }

site=5ee00000-0000-4000-8000-0000000000f0
mkdir -p "${work}/lua" "${work}/logs"
cp "${repo_root}/edge/openresty/lua/cdnca_waf.lua" "${work}/lua/cdnca_waf.lua"
# Rule 1: two clauses on args (contains "x" AND regex "y"), /dup only.
# Rule 2: five conditions on five targets, /five only.
cat >"${work}/policy.json" <<'JSON'
[{"kind":"waf","policy_id":"6ee00000-0000-4000-8000-0000000000f1","policy_version":1,"binding_revision":1,
  "runtime_sha256":"0000000000000000000000000000000000000000000000000000000000000000","enabled":true,"default_action":"allow",
  "rules":[
   {"rule_id":"7ee00000-0000-4000-8000-0000000000f1","match":{"path":{"kind":"prefix","value":"/dup"},
     "inspect":[{"target":"args","operator":"contains","values":["xx"]},{"target":"args","operator":"regex","values":["y[0-9]"]}]},
    "action":"block","flow":"stop"},
   {"rule_id":"7ee00000-0000-4000-8000-0000000000f2","match":{"path":{"kind":"prefix","value":"/five"},
     "inspect":[{"target":"args","operator":"contains","values":["a1"]},{"target":"query","operator":"contains","values":["a1"]},
       {"target":"body","operator":"contains","values":["b2"]},{"target":"cookie","operator":"contains","values":["c3"]},
       {"target":"referer","operator":"contains","values":["d4"]}]},
    "action":"block","flow":"stop"}]}]
JSON
GOWORK="${repo_root}/go.work" go -C "${repo_root}/libs/edgeconfig" run ./cmd/security-location "${site}" <"${work}/policy.json" |
  awk 'BEGIN{n=0} /^=====$/{n++; next} n==1' >"${work}/waf.lua"
grep -q 'cdnca_waf").inspect' "${work}/waf.lua" || fail "inspect clauses not rendered"
telemetry='set $cdnca_security_emit 0; set $cdnca_security_type ""; set $cdnca_security_action ""; set $cdnca_security_severity ""; set $cdnca_security_rule_id ""; set $cdnca_security_block_page 0; set $cdnca_security_policy_id ""; set $cdnca_security_detector ""; set $cdnca_security_matched ""; set $cdnca_security_body "";'
cat >"${work}/nginx.conf" <<EOF
worker_processes 1;
error_log logs/error.log warn;
pid logs/nginx.pid;
events { worker_connections 64; }
http {
  access_log off;
  lua_package_path "/w/lua/?.lua;;";
  lua_shared_dict cdnca_waf_state 4m;
  client_body_buffer_size 16k;
  client_body_temp_path /tmp/waf-multi-body;
  server { listen 127.0.0.1:18421; ${telemetry}
    location / {
$(cat "${work}/waf.lua")
      content_by_lua_block { ngx.say("ok") }
    } }
}
EOF
chmod -R a+rwX "${work}"
docker run -d --rm --name "${container}" --network none --cpus 1 --memory 128m --pids-limit 64 -v "${work}:/w" \
  --entrypoint /usr/local/openresty/bin/openresty "${image}" -g 'daemon off;' -p /w/ -c nginx.conf >/dev/null
ready=""
for _ in $(seq 1 100); do
  if docker exec "${container}" sh -c 'printf "GET / HTTP/1.0\r\n\r\n" | nc -w 2 127.0.0.1 18421' 2>/dev/null | grep -q '^HTTP/1.1 200'; then ready=1; break; fi
  sleep 0.1
done
[ -n "${ready}" ] || { cat "${work}/logs/error.log" >&2 2>/dev/null || true; fail "OpenResty did not start"; }

if ! docker exec -i "${container}" sh -eu <<'INNER'
failures=0
code() { # target [headers] [body]
  body="${3:-}"
  printf "POST %s HTTP/1.0\r\nHost: t\r\n%bContent-Type: text/plain\r\nContent-Length: %d\r\n\r\n%s" "$1" "${2:-}" "${#body}" "${body}" |
    nc -w 5 127.0.0.1 18421 | tr -d '\r' | awk 'NR==1 {print $2}'
}
expect() {
  if [ "$3" = "$2" ]; then echo "PASS $1"; else echo "FAIL $1: want $2, got $3"; failures=$((failures + 1)); fi
}
expect "same target: both clauses -> block" 403 "$(code '/dup?q=xx-y7')"
expect "same target: only contains -> pass" 200 "$(code '/dup?q=xx-yz')"
expect "same target: only regex -> pass" 200 "$(code '/dup?q=x-y7')"
full='Cookie: s=c3\r\nReferer: https://r.test/d4\r\n'
expect "five conditions: all hold -> block" 403 "$(code '/five?k=a1' "${full}" 'body-b2')"
expect "five conditions: no body -> pass" 200 "$(code '/five?k=a1' "${full}" 'body')"
expect "five conditions: no cookie -> pass" 200 "$(code '/five?k=a1' 'Referer: https://r.test/d4\r\n' 'body-b2')"
expect "five conditions: no referer (5th) -> pass" 200 "$(code '/five?k=a1' 'Cookie: s=c3\r\n' 'body-b2')"
expect "five conditions: no query -> pass" 200 "$(code '/five' "${full}" 'body-b2')"
[ "${failures}" -eq 0 ]
INNER
then
  tail -20 "${work}/logs/error.log" >&2 2>/dev/null || true
  fail "multi-condition WAF rules"
fi
if grep -E '\[(error|crit|alert|emerg)\]' "${work}/logs/error.log"; then fail "error log"; fi
echo "RESULT ok"
