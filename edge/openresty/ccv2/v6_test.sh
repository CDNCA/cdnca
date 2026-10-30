#!/bin/sh
# CC v6 on a real OpenResty:
#   - client_ip lists: every entry holds, a negated entry excludes (NF27);
#   - header / User-Agent (regex) / Referer matches, every entry holds, any of
#     a repeated header's values matches (NF32);
#   - trusted crawlers (FX47): a crawler token from its network is trusted, a
#     token from elsewhere or a network without the token is not; an address
#     whose PTR forward-confirms under an rDNS suffix is trusted once the
#     background lookup cached it (IPv4 and IPv6), while a PTR that does not
#     confirm, a wrong suffix or NXDOMAIN keep it an ordinary client; cached
#     results are not looked up again;
#   - the pass cookie carries Domain=challenge_cookie_domain only for hosts
#     under it (NF28);
#   - malformed v6 shapes are refused at load.
# DNS is a Lua UDP stub on 127.0.0.1:53 inside the same OpenResty.
#
# Usage: edge/openresty/ccv2/v6_test.sh
#        CC_ENGINE=<path to engine.lua> ...
set -eu

repo_root="$(CDPATH='' cd -- "$(dirname -- "$0")/../../.." && pwd)"
# shellcheck disable=SC1091
. "${repo_root}/edge/openresty/runtime.env"
engine="${CC_ENGINE:-${repo_root}/edge/openresty/ccv2/engine.lua}"

workdir="$(mktemp -d "${TMPDIR:-/tmp}/cdnca-g1f-v6-lua.XXXXXX")"
container="cdnca-g1f-v6-$(basename "${workdir}" | tr -cd 'A-Za-z0-9')"
cleanup() {
  docker rm -f "${container}" >/dev/null 2>&1 || true
  rm -rf -- "${workdir}"
}
trap cleanup EXIT HUP INT TERM
fail() { echo "FAIL: $*" >&2; exit 1; }

tenant="018f1000-0000-7000-8000-000000000001"
uuid() { printf '018f1000-0000-7000-8000-%012d' "$1"; }
entry_id() { printf '%s\0%s\0%s\0%s\0%s' "${tenant}" "$1" localhost "$2" http | sha256sum | awk '{print substr($1,1,32)}'; }

# site <n> <port> <rules json> <extra policy fields> [enabled]
registry=""
servers=""
site() {
  site_id="$(uuid "$1")"
  policy_id="$(uuid "$(( $1 + 100 ))")"
  binding_id="$(uuid "$(( $1 + 200 ))")"
  publication_id="$(uuid "$(( $1 + 300 ))")"
  mkdir -p "${workdir}/security/${site_id}"
  printf '{"schema_version":"cdnca.edge.cc/v2","tenant_scope_id":"%s","site_id":"%s","policy_id":"%s","policy_version":1,"binding_id":"%s","binding_revision":1,"publication_id":"%s","enabled":%s,"trusted_proxies":[],"allowlist":[],"rules":%s%s}' \
    "${tenant}" "${site_id}" "${policy_id}" "${binding_id}" "${publication_id}" "${5:-true}" "$3" "$4" >"${workdir}/security/${site_id}/cc.compiled.json"
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
rule() { # n priority match limit action
  printf '{"rule_id":"%s","priority":%s,"flow":"stop","match":%s,"dimension":"client_ip","limit":%s,"action":%s}' \
    "$(uuid "$1")" "$2" "$3" "$4" "$5"
}
one='{"algorithm":"fixed_window","requests":1,"window_seconds":60}'
reject='{"kind":"reject_429"}'
ban='{"kind":"temporary_ban","ban_seconds":60}'

# Registry entries must be ordered by port.
site 1 18301 "[$(rule 11 1 '{"client_ip":[{"cidrs":["10.0.0.0/24"]},{"negate":true,"cidrs":["10.0.0.7/32"]}]}' "${one}" "${reject}")]" ""
site 2 18302 "[$(rule 21 1 '{"headers":[{"name":"user-agent","kind":"regex","values":["(?i)python"]},{"name":"x-api","kind":"exact","values":["a","b"]}]}' "${one}" "${reject}"),$(rule 22 2 '{"headers":[{"name":"referer","kind":"prefix","values":["https://spam."]}]}' "${one}" "${reject}")]" ""
site 3 18303 "[$(rule 31 1 '{"path":{"kind":"prefix","value":"/"}}' "${one}" "${ban}")]" \
  ',"trusted_crawlers":[{"name":"google","user_agent_tokens":["Googlebot"],"rdns_suffixes":["googlebot.com"]},{"name":"netbot","user_agent_tokens":["NetBot"],"networks":["198.51.100.0/24"]}]'
site 4 18304 "[$(rule 41 1 '{"path":{"kind":"prefix","value":"/"}}' '{"algorithm":"always"}' '{"kind":"challenge","ban_seconds":600,"challenge":{"mode":"redirect","failure_window_seconds":60,"max_failures":1000,"pass_seconds":3600,"pow_bits":0,"challenge_seconds":120,"bind_ipv4_prefix":24,"bind_ipv6_prefix":64,"key_rotate_seconds":86400}}')]" \
  ',"challenge_cookie_domain":"example.test"'
valid_registry="${registry}"
valid_servers="${servers}"

# The DNS stub: PTR / A / AAAA answers from a fixed zone, NXDOMAIN for
# unknown PTR names, NOERROR without answers for unknown forward names.
cat >"${workdir}/dnsstub.lua" <<'LUA'
local zone = {
  ["5.64.249.66.in-addr.arpa|12"] = { ptr = "crawl-66-249-64-5.googlebot.com" },
  ["crawl-66-249-64-5.googlebot.com|1"] = { a = { 66, 249, 64, 5 } },
  ["6.64.249.66.in-addr.arpa|12"] = { ptr = "fake.googlebot.com" },
  ["fake.googlebot.com|1"] = { a = { 192, 0, 2, 99 } },
  ["7.64.249.66.in-addr.arpa|12"] = { ptr = "crawl.evil.example" },
  ["crawl.evil.example|1"] = { a = { 66, 249, 64, 7 } },
  ["5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa|12"] = { ptr = "crawl6.googlebot.com" },
  ["crawl6.googlebot.com|28"] = { aaaa = { 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5 } },
}
local function u16(value) return string.char(math.floor(value / 256), value % 256) end
local function name_bytes(name)
  local parts = {}
  for label in name:gmatch("[^.]+") do parts[#parts + 1] = string.char(#label) .. label end
  return table.concat(parts) .. "\0"
end
local sock = assert(ngx.req.socket())
local data = assert(sock:receive())
local pos, labels = 13, {}
while true do
  local length = data:byte(pos)
  if length == 0 then pos = pos + 1 break end
  labels[#labels + 1] = data:sub(pos + 1, pos + length)
  pos = pos + length + 1
end
local qtype = data:byte(pos) * 256 + data:byte(pos + 1)
local name = table.concat(labels, "."):lower()
ngx.log(ngx.NOTICE, "DNSSTUB query ", name, " type ", qtype)
local record = zone[name .. "|" .. qtype]
local rdata
if record and record.ptr then rdata = name_bytes(record.ptr)
elseif record and record.a then rdata = string.char(unpack(record.a))
elseif record and record.aaaa then rdata = string.char(unpack(record.aaaa)) end
local flags = 0x8180
if not record and qtype == 12 then flags = 0x8183 end
local answer = ""
if rdata then answer = "\192\012" .. u16(qtype) .. u16(1) .. "\0\0\0\60" .. u16(#rdata) .. rdata end
sock:send(data:sub(1, 2) .. u16(flags) .. u16(1) .. u16(rdata and 1 or 0) .. u16(0) .. u16(0) .. data:sub(13, pos + 3) .. answer)
LUA
printf 'nameserver 127.0.0.1\n' >"${workdir}/resolv.conf"

nginx_conf() { # <registry file> <servers>
  cat <<EOF
worker_processes 2;
error_log logs/error.log info;
pid nginx.pid;
events { worker_connections 64; }
stream {
  server {
    listen 127.0.0.1:53 udp;
    content_by_lua_file /runtime/dnsstub.lua;
  }
}
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
    listen 18399;
    location = /ready { return 200; }
  }
  $2
}
EOF
}
printf '{"schema_version":"cdnca.edge.cc-registry/v1","config_version_id":"v6","entries":[%s]}' "${valid_registry}" >"${workdir}/registry.json"
nginx_conf registry.json "${valid_servers}" >"${workdir}/nginx.conf"
mkdir -p "${workdir}/logs"

docker run -d --rm --name "${container}" --network none --cpus 1 --memory 128m --pids-limit 64 \
  --volume "${engine}:/usr/local/share/cdnca/security/cc.lua:ro" \
  --volume "${workdir}/resolv.conf:/etc/resolv.conf:ro" \
  --volume "${workdir}:/runtime" --workdir /runtime \
  "${OPENRESTY_IMAGE}" openresty -g 'daemon off;' -p /runtime/ -c nginx.conf >/dev/null

ready=""
for _ in $(seq 1 100); do
  if docker exec "${container}" curl -fsS -o /dev/null http://127.0.0.1:18399/ready 2>/dev/null; then ready=1; break; fi
  sleep 0.1
done
if [ -z "${ready}" ]; then
  cat "${workdir}/logs/error.log" >&2 2>/dev/null || true
  fail "cc.lua did not start with CC v6 policies"
fi

if ! docker exec -i "${container}" sh -eu <<'INNER'
fail() { echo "FAIL: $*" >&2; exit 1; }
# req <port> <client ip> [curl args...] -> status
req() {
  port="$1"; ip="$2"; shift 2
  curl -sS -o /dev/null -w '%{http_code}' -H "X-Real-IP: ${ip}" "$@" "http://127.0.0.1:${port}/"
}
expect() { test "$3" = "$2" || fail "$1: want $2, got $3"; }
google='Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)'

# client_ip list: in 10.0.0.0/24 and not 10.0.0.7.
expect "listed 1" 200 "$(req 18301 10.0.0.9)"
expect "listed 2" 429 "$(req 18301 10.0.0.9)"
for n in 1 2 3; do expect "excluded ${n}" 200 "$(req 18301 10.0.0.7)"; done
for n in 1 2 3; do expect "outside ${n}" 200 "$(req 18301 10.0.1.9)"; done
echo "ok   client_ip list with an exclusion"

# headers: UA regex AND x-api exact; Referer prefix.
expect "headers 1" 200 "$(req 18302 192.0.2.1 -A 'Python-urllib/3.11' -H 'x-api: a')"
expect "headers 2" 429 "$(req 18302 192.0.2.1 -A 'Python-urllib/3.11' -H 'x-api: a')"
for n in 1 2 3; do expect "ua only ${n}" 200 "$(req 18302 192.0.2.2 -A 'python-requests' )"; done
for n in 1 2 3; do expect "header only ${n}" 200 "$(req 18302 192.0.2.3 -A curl/8 -H 'x-api: a')"; done
expect "repeated header 1" 200 "$(req 18302 192.0.2.4 -A PYTHON -H 'x-api: c' -H 'x-api: b')"
expect "repeated header 2" 429 "$(req 18302 192.0.2.4 -A PYTHON -H 'x-api: c' -H 'x-api: b')"
expect "referer 1" 200 "$(req 18302 192.0.2.5 -A curl/8 -H 'Referer: https://spam.example/x')"
expect "referer 2" 429 "$(req 18302 192.0.2.5 -A curl/8 -H 'Referer: https://spam.example/x')"
for n in 1 2 3; do expect "other referer ${n}" 200 "$(req 18302 192.0.2.6 -A curl/8 -H 'Referer: https://www.example/')"; done
echo "ok   header, User-Agent regex and Referer matches (all entries hold)"

# Trusted crawlers by network.
for n in 1 2 3 4 5; do expect "netbot ${n}" 200 "$(req 18303 198.51.100.5 -A 'NetBot/1.0')"; done
expect "spoofed netbot 1" 200 "$(req 18303 192.0.2.10 -A 'NetBot/1.0')"
expect "spoofed netbot 2" 429 "$(req 18303 192.0.2.10 -A 'NetBot/1.0')"
expect "network without token 1" 200 "$(req 18303 198.51.100.6 -A 'curl/8')"
expect "network without token 2" 429 "$(req 18303 198.51.100.6 -A 'curl/8')"
echo "ok   crawler network needs its User-Agent token and vice versa"

# Trusted crawlers by forward-confirmed rDNS (background lookup, then cache).
for ip in 66.249.64.5 66.249.64.6 66.249.64.7 66.249.64.8 2001:db8::5; do
  expect "first ${ip}" 200 "$(req 18303 "${ip}" -A "${google}")"
done
sleep 1
for n in 1 2 3 4 5; do expect "googlebot ${n}" 200 "$(req 18303 66.249.64.5 -A "${google}")"; done
for n in 1 2 3; do expect "googlebot v6 ${n}" 200 "$(req 18303 2001:db8::5 -A "${google}")"; done
expect "unconfirmed ptr" 429 "$(req 18303 66.249.64.6 -A "${google}")"
expect "wrong suffix" 429 "$(req 18303 66.249.64.7 -A "${google}")"
expect "nxdomain" 429 "$(req 18303 66.249.64.8 -A "${google}")"
echo "ok   forward-confirmed rDNS trusts real crawlers only (IPv4 and IPv6)"

# Cookie domain: hosts under example.test get Domain=example.test.
pass_cookie() { # <host> -> the pass Set-Cookie line
  probe="$(curl -sS -o /dev/null -D - -H "Host: $1" -H 'X-Real-IP: 203.0.113.5' http://127.0.0.1:18304/ |
    tr -d '\r' | sed -n 's/^[Ss]et-[Cc]ookie: \(__cdnca_cc_probe=[0-9a-f]*\).*/\1/p')"
  test -n "${probe}" || fail "no probe cookie for $1"
  curl -sS -o /dev/null -D - -H "Host: $1" -H 'X-Real-IP: 203.0.113.5' -H "Cookie: ${probe}" http://127.0.0.1:18304/ |
    tr -d '\r' | grep -i '^set-cookie: __cdnca_cc_pass=' || true
}
line="$(pass_cookie www.example.test)"
echo "${line}" | grep -q '; Domain=example.test;' || fail "pass cookie for www.example.test: ${line}"
line="$(pass_cookie example.test)"
echo "${line}" | grep -q '; Domain=example.test;' || fail "pass cookie for example.test: ${line}"
line="$(pass_cookie other.test)"
test -n "${line}" || fail "no pass cookie for other.test"
if echo "${line}" | grep -qi 'domain='; then fail "pass cookie for other.test has a Domain: ${line}"; fi
echo "ok   pass cookie Domain only for hosts under challenge_cookie_domain"

# ge-waf (logic 4): a POST under the redirect challenge is answered 307 to the
# same URL (method and body kept), never 302 to "/".
head="$(curl -sS -o /dev/null -D - -X POST --data 'a=1&b=2' -H 'Host: www.example.test' -H 'X-Real-IP: 203.0.113.9' \
  'http://127.0.0.1:18304/form/submit?x=1' | tr -d '\r')"
echo "${head}" | grep -q '^HTTP/1.1 307' || fail "POST challenge status: ${head}"
echo "${head}" | grep -qi '^location: /form/submit?x=1$' || fail "POST challenge location: ${head}"
probe="$(echo "${head}" | sed -n 's/^[Ss]et-[Cc]ookie: \(__cdnca_cc_probe=[0-9a-f]*\).*/\1/p')"
test -n "${probe}" || fail "POST challenge without probe cookie"
head="$(curl -sS -o /dev/null -D - -X POST --data 'a=1&b=2' -H 'Host: www.example.test' -H 'X-Real-IP: 203.0.113.9' \
  -H "Cookie: ${probe}" 'http://127.0.0.1:18304/form/submit?x=1' | tr -d '\r')"
echo "${head}" | grep -q '^HTTP/1.1 307' || fail "POST probe pass status: ${head}"
echo "${head}" | grep -qi '^location: /form/submit?x=1$' || fail "POST probe pass location: ${head}"
echo "${head}" | grep -qi '^set-cookie: __cdnca_cc_pass=' || fail "POST probe pass without pass cookie: ${head}"
head="$(curl -sS -o /dev/null -D - -H 'Host: www.example.test' -H 'X-Real-IP: 203.0.113.10' 'http://127.0.0.1:18304/page' | tr -d '\r')"
echo "${head}" | grep -q '^HTTP/1.1 302' || fail "GET challenge status: ${head}"
echo "ok   POST redirect challenge keeps method, body and URL (307)"
INNER
then
  tail -n 40 "${workdir}/logs/error.log" >&2 2>/dev/null || true
  fail "CC v6 behaviour"
fi
grep -q "cc v2 trusted crawler=netbot" "${workdir}/logs/error.log" || fail "trusted crawler not logged"
# Each address was looked up once: the cache answers later requests.
ptr_queries="$(grep -c 'DNSSTUB query 5.64.249.66.in-addr.arpa type 12' "${workdir}/logs/error.log" || true)"
test "${ptr_queries}" = 1 || fail "66.249.64.5 PTR looked up ${ptr_queries} times"
echo "ok   rDNS results are cached (one PTR lookup per address)"

# Malformed v6 shapes are refused at load.
docker rm -f "${container}" >/dev/null 2>&1 || true
for case in plaincidr badregex unsortedcrawlers disableddomain; do
  registry=""
  servers=""
  case "${case}" in
    plaincidr) site 5 18305 "[$(rule 51 1 '{"client_ip":[{"cidrs":["10.0.0.0/24"]}]}' "${one}" "${reject}")]" "" ;;
    badregex) site 5 18305 "[$(rule 51 1 '{"headers":[{"name":"user-agent","kind":"regex","values":["(python"]}]}' "${one}" "${reject}")]" "" ;;
    unsortedcrawlers) site 5 18305 "[]" ',"trusted_crawlers":[{"name":"z","user_agent_tokens":["Zbot"],"networks":["10.0.0.0/8"]},{"name":"a","user_agent_tokens":["Abot"],"networks":["10.0.0.0/8"]}]' ;;
    disableddomain) site 5 18305 "[]" ',"challenge_cookie_domain":"example.test"' false ;;
  esac
  printf '{"schema_version":"cdnca.edge.cc-registry/v1","config_version_id":"v6-%s","entries":[%s]}' "${case}" "${registry}" >"${workdir}/registry-${case}.json"
  nginx_conf "registry-${case}.json" "${servers}" >"${workdir}/nginx-${case}.conf"
  if docker run --rm --network none --cpus 1 --memory 128m --pids-limit 64 \
    --volume "${engine}:/usr/local/share/cdnca/security/cc.lua:ro" \
    --volume "${workdir}:/runtime" --workdir /runtime \
    "${OPENRESTY_IMAGE}" timeout 5 openresty -g 'daemon off;' -p /runtime/ -c "nginx-${case}.conf" >"${workdir}/t-${case}.log" 2>&1 ||
    ! grep -q "invalid or duplicate policy rule\|invalid trusted crawlers or challenge cookie domain" "${workdir}/t-${case}.log"; then
    cat "${workdir}/t-${case}.log" >&2
    fail "malformed v6 policy (${case}) loaded"
  fi
done
echo "ok   single plain CIDR list, bad regex, unsorted crawlers and a disabled policy's cookie domain are refused"
echo "PASS CC v6"
