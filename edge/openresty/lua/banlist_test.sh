#!/bin/sh
# The node side of the ban list library (cdnca_banlist.lua) on
# a real OpenResty, no network:
#   - a snapshot (POST <health>/security-bans) bans a client on a site for
#     WAF v2 and CC v2 alike (403 X-Cdnca-Ban: listed), only that site;
#   - a newer snapshot without the ban lifts it; an older revision is refused;
#   - a release lifts the node's own automatic bans of the client on the site
#     that started before it: WAF ban (cdnca_waf), CC rate limit ban and CC
#     challenge failure ban (logic 3: a CC automatic ban could not be lifted);
#     a later ban of the same client applies again;
#   - a WAF automatic ban is queued for the kernel firewall (GET drains it);
#   - network bans (IPv4 /24, IPv6 /48) refuse every client in
#     them, only on their site; the same re-post keeps the matcher; a newer
#     snapshot without them lifts them; a network release is accepted.
# Usage: edge/openresty/lua/banlist_test.sh
set -eu
repo_root="$(CDPATH='' cd -- "$(dirname -- "$0")/../../.." && pwd)"
# shellcheck disable=SC1091
. "${repo_root}/edge/openresty/runtime.env"
image="${BANLIST_IMAGE:-cdnca-native-runtime:edge-golden}"
work="$(mktemp -d "${TMPDIR:-/tmp}/cdnca-banlist.XXXXXX")"
container="cdnca-banlist-$(basename "${work}" | tr -cd 'a-z0-9')"
cleanup() { docker rm -f "${container}" >/dev/null 2>&1 || true; rm -rf -- "${work}"; }
trap cleanup EXIT HUP INT TERM
fail() { echo "FAIL: $*" >&2; exit 1; }

tenant=018f1000-0000-7000-8000-000000000001
waf_site=5ee00000-0000-4000-8000-0000000000a1
cc_site=018f1000-0000-7000-8000-000000000011
mkdir -p "${work}/lua" "${work}/logs" "${work}/security/${cc_site}"
for file in cdnca_waf.lua cdnca_banlist.lua; do cp "${repo_root}/edge/openresty/lua/${file}" "${work}/lua/${file}"; done
cp "${repo_root}/edge/openresty/ccv2/engine.lua" "${work}/lua/cc.lua"

# WAF v2: /ban bans 300 s (rendered by edgeconfig like the node renderer).
cat >"${work}/policy.json" <<JSON
[{"kind":"waf","policy_id":"6ee00000-0000-4000-8000-0000000000b1","policy_version":1,"binding_revision":1,
  "runtime_sha256":"$(printf '%064d' 0)","enabled":true,"default_action":"allow",
  "rules":[{"rule_id":"7ee00000-0000-4000-8000-0000000000c2","match":{"path":{"kind":"prefix","value":"/ban"}},
    "action":"ban","flow":"stop","action_config":{"ban_seconds":300}}]}]
JSON
GOWORK="${repo_root}/go.work" go -C "${repo_root}/libs/edgeconfig" run ./cmd/security-location "${waf_site}" <"${work}/policy.json" |
  awk 'BEGIN{n=0} /^=====$/{n++; next} n==1' >"${work}/waf.lua"
grep -q 'cdnca_waf").act' "${work}/waf.lua" || fail "WAF location not rendered"

# CC v2: 3 requests a minute, then a 120 s temporary ban of the client.
uuid() { printf '018f1000-0000-7000-8000-%012d' "$1"; }
printf '{"schema_version":"cdnca.edge.cc/v2","tenant_scope_id":"%s","site_id":"%s","policy_id":"%s","policy_version":1,"binding_id":"%s","binding_revision":1,"publication_id":"%s","enabled":true,"trusted_proxies":[],"allowlist":[],"rules":[{"rule_id":"%s","priority":1,"flow":"stop","match":{"path":{"kind":"prefix","value":"/"}},"dimension":"client_ip","limit":{"algorithm":"fixed_window","requests":3,"window_seconds":60},"action":{"kind":"temporary_ban","ban_seconds":120}}]}' \
  "${tenant}" "${cc_site}" "$(uuid 101)" "$(uuid 201)" "$(uuid 301)" "$(uuid 401)" >"${work}/security/${cc_site}/cc.compiled.json"
sha="$(shasum -a 256 "${work}/security/${cc_site}/cc.compiled.json" | awk '{print $1}')"
entry="$(printf '%s\0%s\0%s\0%s\0%s' "${tenant}" "${cc_site}" localhost 18402 http | shasum -a 256 | awk '{print substr($1,1,32)}')"
printf '{"schema_version":"cdnca.edge.cc-registry/v1","config_version_id":"banlist","entries":[{"entry_id":"%s","tenant_scope_id":"%s","site_id":"%s","hostname":"localhost","listen_port":18402,"protocol":"http","policy_id":"%s","policy_version":1,"binding_id":"%s","binding_revision":1,"publication_id":"%s","source_sha256":"%s","compiled_path":"security/%s/cc.compiled.json","compiled_sha256":"%s"}]}' \
  "${entry}" "${tenant}" "${cc_site}" "$(uuid 101)" "$(uuid 201)" "$(uuid 301)" "$(printf 'a%.0s' $(seq 64))" "${cc_site}" "${sha}" >"${work}/registry.json"

telemetry='set $cdnca_security_emit 0; set $cdnca_security_type ""; set $cdnca_security_action ""; set $cdnca_security_severity ""; set $cdnca_security_rule_id ""; set $cdnca_security_block_page 0; set $cdnca_security_policy_id ""; set $cdnca_security_detector ""; set $cdnca_security_matched ""; set $cdnca_security_body "";'
cat >"${work}/nginx.conf" <<EOF
worker_processes 2;
error_log logs/error.log info;
pid logs/nginx.pid;
events { worker_connections 128; }
http {
  access_log off;
  lua_package_path "/w/lua/?.lua;;";
  lua_shared_dict cdnca_waf_state 4m;
  lua_shared_dict cdnca_security_bans 4m;
  lua_shared_dict cdnca_cc_v2_state 4m;
  client_body_temp_path /tmp/banlist-body;
  set_real_ip_from 127.0.0.1;
  real_ip_header X-Real-IP;
  init_by_lua_block {
    local file = assert(io.open("/w/registry.json", "rb"))
    local registry = file:read("*a")
    file:close()
    require("cc").init({ state_dict = "cdnca_cc_v2_state", release_root = "/w", registry_json = registry })
  }
  server { listen 127.0.0.1:18401; ${telemetry}
    location / {
$(cat "${work}/waf.lua")
      content_by_lua_block { ngx.say("waf ok") }
    } }
  server { listen 127.0.0.1:18402; ${telemetry}
    server_rewrite_by_lua_block { return require("cc").access("${entry}") }
    location / { content_by_lua_block { ngx.say("cc ok") } } }
  server { listen 127.0.0.1:18499;
    location = /healthz/security-bans {
      client_max_body_size 4m;
      client_body_buffer_size 4m;
      content_by_lua_block { require("cdnca_banlist").handle() }
    } }
}
EOF
chmod -R a+rwX "${work}"
docker run -d --rm --name "${container}" --network none --cpus 1 --memory 192m --pids-limit 64 -v "${work}:/w" \
  --entrypoint /usr/local/openresty/bin/openresty "${image}" -g 'daemon off;' -p /w/ -c nginx.conf >/dev/null
ready=""
for _ in $(seq 1 100); do
  if docker exec "${container}" sh -c 'printf "GET /healthz/security-bans HTTP/1.0\r\n\r\n" | nc -w 2 127.0.0.1 18499' 2>/dev/null | grep -q '^HTTP/1.1 200'; then ready=1; break; fi
  sleep 0.1
done
[ -n "${ready}" ] || { cat "${work}/logs/error.log" >&2 2>/dev/null || true; fail "OpenResty did not start"; }

if ! docker exec -i -e WAF_SITE="${waf_site}" -e CC_SITE="${cc_site}" "${container}" sh -eu <<'INNER'
fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "PASS $*"; }
# raw HTTP/1.0 over nc (the node image has no curl)
http() { printf '%b' "$2" | nc -w 5 127.0.0.1 "$1" | tr -d '\r'; }
get() { http "$1" "GET $3 HTTP/1.0\r\nHost: t\r\nX-Real-IP: $2\r\n\r\n"; }
code() { get "$1" "$2" "$3" | awk 'NR==1 {print $2}'; }
header() { get "$1" "$2" "$3" | awk -v name="$4" 'NR>1 && $0=="" {exit} tolower($1)==tolower(name)":" {print $2}'; }
post() {
  response="$(http 18499 "$(printf 'POST /healthz/security-bans HTTP/1.0\r\nHost: t\r\nContent-Length: %d\r\n\r\n%s' "${#1}" "$1")")"
  printf '%s\n' "${response}" | awk 'f {print} $0=="" {f=1}' >/tmp/apply.json
  printf '%s\n' "${response}" | awk 'NR==1 {print $2}'
}
drain() { get 18499 127.0.0.1 /healthz/security-bans | awk 'f && $0!="" {print} $0=="" {f=1}'; }
expect() { [ "$3" = "$2" ] || fail "$1: want $2, got $3"; }
now=$(date +%s)
later=$((now + 600))

# 1. listed bans
expect "apply r1" 200 "$(post "{\"revision\":1,\"bans\":[{\"site_id\":\"${WAF_SITE}\",\"client\":\"198.51.100.9\",\"until\":${later}},{\"site_id\":\"${CC_SITE}\",\"client\":\"198.51.100.9\",\"until\":${later}},{\"site_id\":\"${CC_SITE}\",\"client\":\"2001:db8::9\",\"until\":${later}}],\"releases\":[]}")"
grep -q '"bans":3' /tmp/apply.json || fail "apply result $(cat /tmp/apply.json)"
expect "WAF listed ban" 403 "$(code 18401 198.51.100.9 /)"
expect "WAF listed header" listed "$(header 18401 198.51.100.9 / X-Cdnca-Ban)"
expect "CC listed ban" 403 "$(code 18402 198.51.100.9 /)"
expect "CC listed IPv6 ban" 403 "$(code 18402 2001:db8::9 /)"
expect "other client" 200 "$(code 18401 198.51.100.10 /)"
pass "listed bans refuse the client on WAF and CC sites (IPv4, IPv6), other clients pass"

# 2. replacement and stale refusal
expect "apply r2" 200 "$(post "{\"revision\":2,\"bans\":[{\"site_id\":\"${CC_SITE}\",\"client\":\"198.51.100.9\",\"until\":${later}}],\"releases\":[]}")"
expect "WAF ban lifted by r2" 200 "$(code 18401 198.51.100.9 /)"
expect "CC IPv6 lifted by r2" 200 "$(code 18402 2001:db8::9 /)"
expect "CC kept by r2" 403 "$(code 18402 198.51.100.9 /)"
expect "stale r1" 409 "$(post '{"revision":1,"bans":[],"releases":[]}')"
expect "bad body" 400 "$(post '{"revision":3,"bans":[{"site_id":"x","client":"1.2.3.4","until":1}],"releases":[]}')"
expect "CC still kept" 403 "$(code 18402 198.51.100.9 /)"
pass "a snapshot replaces the previous list; stale and invalid snapshots refused"

# 3. WAF automatic ban -> kernel queue -> release lifts it
drain >/dev/null
expect "WAF ban rule" 403 "$(code 18401 203.0.113.5 /ban)"
expect "WAF banned" 403 "$(code 18401 203.0.113.5 /)"
expect "WAF ban header" banned "$(header 18401 203.0.113.5 / X-Cdnca-WAF)"
line="$(drain)"
case "${line}" in "${WAF_SITE}|203.0.113.5|"*) ;; *) fail "WAF kernel ban line = ${line}" ;; esac
until="${line##*|}"; [ $((until - now)) -ge 295 ] && [ $((until - now)) -le 305 ] || fail "kernel ban end ${until}"
[ -z "$(drain)" ] || fail "kernel queue drained twice"
pass "WAF automatic ban queued for the kernel firewall once"

# 4. CC automatic ban
for n in 1 2 3; do expect "CC ${n}" 200 "$(code 18402 203.0.113.5 /)"; done
expect "CC over limit" 429 "$(code 18402 203.0.113.5 /)"
expect "CC banned" 429 "$(code 18402 203.0.113.5 /)"
sleep 1
released=$(date +%s)
expect "apply r3 release" 200 "$(post "{\"revision\":3,\"bans\":[],\"releases\":[{\"site_id\":\"${WAF_SITE}\",\"client\":\"203.0.113.5\",\"released_at\":${released}},{\"site_id\":\"${CC_SITE}\",\"client\":\"203.0.113.5\",\"released_at\":${released}}]}")"
grep -q '"releases":2' /tmp/apply.json || fail "release result $(cat /tmp/apply.json)"
expect "WAF released" 200 "$(code 18401 203.0.113.5 /)"
expect "CC released" 200 "$(code 18402 203.0.113.5 /)"
expect "CC listed r2 ban lifted by r3" 200 "$(code 18402 198.51.100.9 /)"
pass "a release lifts the node's own WAF and CC automatic bans (logic 3)"

# 5. a ban after the release applies again
sleep 1
expect "WAF ban again" 403 "$(code 18401 203.0.113.5 /ban)"
expect "WAF banned again" 403 "$(code 18401 203.0.113.5 /)"
for n in 1 2; do expect "CC again ${n}" 200 "$(code 18402 203.0.113.5 /)"; done
expect "CC over limit again" 429 "$(code 18402 203.0.113.5 /)"
expect "CC banned again" 429 "$(code 18402 203.0.113.5 /)"
pass "a ban that starts after the release applies"

# 6. network bans (BAN_CIDR)
expect "apply r4 networks" 200 "$(post "{\"revision\":4,\"bans\":[{\"site_id\":\"${WAF_SITE}\",\"client\":\"192.0.2.0/24\",\"until\":${later}},{\"site_id\":\"${CC_SITE}\",\"client\":\"192.0.2.0/24\",\"until\":${later}},{\"site_id\":\"${CC_SITE}\",\"client\":\"2001:db8:5::/48\",\"until\":${later}},{\"site_id\":\"${CC_SITE}\",\"client\":\"198.18.0.1\",\"until\":${later}}],\"releases\":[]}")"
grep -q '"bans":4' /tmp/apply.json || fail "network apply result $(cat /tmp/apply.json)"
for ip in 192.0.2.1 192.0.2.200 192.0.2.255; do
  expect "WAF network ${ip}" 403 "$(code 18401 "${ip}" /)"
  expect "CC network ${ip}" 403 "$(code 18402 "${ip}" /)"
done
expect "WAF network header" listed "$(header 18401 192.0.2.77 / X-Cdnca-Ban)"
expect "outside the /24" 200 "$(code 18401 192.0.3.1 /)"
expect "CC IPv6 network" 403 "$(code 18402 2001:db8:5:ffff::1 /)"
expect "CC IPv6 outside" 200 "$(code 18402 2001:db8:6::1 /)"
expect "WAF has no IPv6 network" 200 "$(code 18401 2001:db8:5::1 /)"
expect "CC exact address with networks" 403 "$(code 18402 198.18.0.1 /)"
# the Agent re-posts the same snapshot: still banned on both workers
expect "re-post r4" 200 "$(post "{\"revision\":4,\"bans\":[{\"site_id\":\"${WAF_SITE}\",\"client\":\"192.0.2.0/24\",\"until\":${later}},{\"site_id\":\"${CC_SITE}\",\"client\":\"192.0.2.0/24\",\"until\":${later}},{\"site_id\":\"${CC_SITE}\",\"client\":\"2001:db8:5::/48\",\"until\":${later}},{\"site_id\":\"${CC_SITE}\",\"client\":\"198.18.0.1\",\"until\":${later}}],\"releases\":[]}")"
for n in 1 2 3 4; do expect "WAF network after re-post ${n}" 403 "$(code 18401 192.0.2.$n /)"; done
expect "bad network" 400 "$(post "{\"revision\":5,\"bans\":[{\"site_id\":\"${WAF_SITE}\",\"client\":\"192.0.2.0/99\",\"until\":${later}}],\"releases\":[]}")"
expect "kept after bad network" 403 "$(code 18401 192.0.2.9 /)"
released=$(date +%s)
expect "apply r5 network lifted" 200 "$(post "{\"revision\":5,\"bans\":[{\"site_id\":\"${CC_SITE}\",\"client\":\"2001:db8:5::/48\",\"until\":${later}}],\"releases\":[{\"site_id\":\"${WAF_SITE}\",\"client\":\"192.0.2.0/24\",\"released_at\":${released}}]}")"
grep -q '"releases":1' /tmp/apply.json || fail "network release result $(cat /tmp/apply.json)"
for n in 1 2 3 4; do
  expect "WAF network lifted ${n}" 200 "$(code 18401 192.0.2.$n /)"
  expect "CC network lifted ${n}" 200 "$(code 18402 192.0.2.$n /)"
done
expect "CC IPv6 network kept" 403 "$(code 18402 2001:db8:5::abcd /)"
expect "CC exact lifted" 200 "$(code 18402 198.18.0.1 /)"
expect "apply r6 empty" 200 "$(post '{"revision":6,"bans":[],"releases":[]}')"
expect "CC IPv6 network lifted" 200 "$(code 18402 2001:db8:5::abcd /)"
pass "network bans refuse every client in them on their site only, and are lifted by a newer snapshot"
INNER
then
  cat "${work}/logs/error.log" >&2 2>/dev/null | tail -20 || true
  fail "ban list"
fi
if grep -E '\[(error|crit|alert|emerg)\]' "${work}/logs/error.log"; then fail "error log"; fi
echo "RESULT ok"
