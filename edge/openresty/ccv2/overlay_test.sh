#!/bin/sh
# CC v2 auto defense overlay (ADR 0010 §7A.2, contract §4) on a real
# OpenResty: access_object(digest, read, overlay) runs the site object's
# policy tightened by the overlay values in force.
#   - no overlay: the policy's own fixed window (5 requests per client);
#   - cc.per_ip_requests 2: the third request of a client is 429; a larger
#     value (100) never relaxes the policy (still 5);
#   - cc.ban_seconds lengthens a temporary ban, never shortens it (the ban
#     key's TTL in the state dictionary);
#   - cc.auto_switch_qps lowers the auto switch threshold (20 -> 5 requests
#     per second engages the switch rules);
#   - invalid overlay values are ignored (the policy runs unchanged).
#   - bot.fake_crawler_block 1 (ad-16): a Googlebot User-Agent outside the
#     crawler's networks is 403; inside them it passes; without the value
#     the fake crawler is an ordinary client.
#   - cc.limit_permille (ad-bot-cc): a count_by fixed window (client_cidr,
#     10 per window) and a leaky bucket (burst 10) run at the share of their
#     limits (500: 5); 1000, values above 1000 and invalid values change
#     nothing; a smaller share tightens further (200: 2).
#
# Usage: edge/openresty/ccv2/overlay_test.sh
#        CC_ENGINE=<path to engine.lua> ...
set -eu

repo_root="$(CDPATH='' cd -- "$(dirname -- "$0")/../../.." && pwd)"
# shellcheck disable=SC1091
. "${repo_root}/edge/openresty/runtime.env"
engine="${CC_ENGINE:-${repo_root}/edge/openresty/ccv2/engine.lua}"

workdir="$(mktemp -d "${TMPDIR:-/tmp}/cdnca-ad-overlay-lua.XXXXXX")"
container="cdnca-ad-overlay-$(basename "${workdir}" | tr -cd 'A-Za-z0-9')"
cleanup() {
  docker rm -f "${container}" >/dev/null 2>&1 || true
  rm -rf -- "${workdir}"
}
trap cleanup EXIT HUP INT TERM
fail() { echo "FAIL: $*" >&2; exit 1; }

tenant="018f1000-0000-7000-8000-000000000001"
uuid() { printf '018f1000-0000-7000-8000-%012d' "$1"; }
rule() { # n limit action
  printf '{"rule_id":"%s","priority":1,"flow":"stop","match":{"path":{"kind":"prefix","value":"/"}},"dimension":"client_ip","limit":%s,"action":%s}' \
    "$(uuid "$1")" "$2" "$3"
}
fixed() { printf '{"algorithm":"fixed_window","requests":%s,"window_seconds":60}' "$1"; }
reject='{"kind":"reject_429"}'
ban='{"kind":"temporary_ban","ban_seconds":60}'
# policy <n> <rules> <extra>: writes objects/<n>.json, prints nothing
policy() {
  printf '{"schema_version":"cdnca.edge.cc/v2","tenant_scope_id":"%s","site_id":"%s","policy_id":"%s","policy_version":1,"binding_id":"%s","binding_revision":1,"publication_id":"%s","enabled":true,"trusted_proxies":[],"allowlist":[],"rules":%s%s}' \
    "${tenant}" "$(uuid "$1")" "$(uuid "$(( $1 + 100 ))")" "$(uuid "$(( $1 + 200 ))")" "$(uuid "$(( $1 + 300 ))")" "$2" "$3" >"${workdir}/objects/$1.json"
}
mkdir -p "${workdir}/objects" "${workdir}/logs"
policy 1 "[$(rule 11 "$(fixed 5)" "${reject}")]" ""
policy 3 "[$(rule 31 "$(fixed 1000)" "${reject}")]" ",\"auto_switch\":{\"qps_total\":20,\"qps_5xx\":0,\"recover_seconds\":60,\"rules\":[$(rule 32 "$(fixed 1)" "${reject}")]}"
policy 4 "[$(rule 41 "$(fixed 1)" "${ban}")]" ""
# 6: count_by client_cidr /24 fixed window 10; 7: leaky bucket 1/s burst 10
policy 6 "[$(printf '{"rule_id":"%s","priority":1,"flow":"stop","match":{"path":{"kind":"prefix","value":"/"}},"dimension":"client_ip","count_by":[{"key":"client_cidr","ipv4_prefix":24,"ipv6_prefix":64}],"limit":%s,"action":%s}' "$(uuid 61)" "$(fixed 10)" "${reject}")]" ""
policy 7 "[$(rule 71 '{"algorithm":"leaky_bucket","rate_per_second":1,"burst":10}' "${reject}")]" ""
# 5: a trusted crawler known by its network only (no rDNS: the check is definite)
policy 5 "[$(rule 51 "$(fixed 1000)" "${reject}")]" ',"trusted_crawlers":[{"name":"googlebot","user_agent_tokens":["Googlebot"],"networks":["203.0.113.0/24"]}]'

cat >"${workdir}/nginx.conf" <<'EOF'
worker_processes 1;
error_log logs/error.log info;
pid nginx.pid;
events { worker_connections 64; }
http {
  lua_package_path '/usr/local/share/cdnca/security/?.lua;;';
  lua_shared_dict cdnca_cc_v2_state 4m;
  set_real_ip_from 127.0.0.1;
  real_ip_header X-Real-IP;
  init_by_lua_block {
    require("cc").configure({ state_dict = "cdnca_cc_v2_state" })
    local digests = {}
    for _, n in ipairs({ 1, 3, 4, 5, 6, 7 }) do
      local file = assert(io.open("/runtime/objects/" .. n .. ".json", "rb"))
      local raw = file:read("*a")
      file:close()
      local digest = require("resty.sha256"):new()
      digest:update(raw)
      local hex = require("resty.string").to_hex(digest:final())
      digests[n] = { digest = hex, raw = raw }
    end
    CC_OBJECTS = digests
  }
  server {
    listen 18300;
    # /p<n>?o=<json overlay>: site object n with the overlay values
    location / {
      access_by_lua_block {
        local object = CC_OBJECTS[tonumber(ngx.var.uri:match("^/p(%d)"))]
        local overlay = ngx.var.arg_o and require("cjson.safe").decode(ngx.unescape_uri(ngx.var.arg_o)) or nil
        return require("cc").access_object(object.digest, function() return object.raw end, overlay)
      }
      content_by_lua_block { ngx.say("ok") }
    }
    location = /ttl {
      content_by_lua_block {
        local dict = ngx.shared.cdnca_cc_v2_state
        local best = 0
        for _, key in ipairs(dict:get_keys(0)) do
          if key:find("ban:", 1, true) then
            local ttl = dict:ttl(key)
            if ttl and ttl > best then best = ttl end
          end
        end
        ngx.say(math.floor(best))
      }
    }
    location = /flush { content_by_lua_block { ngx.shared.cdnca_cc_v2_state:flush_all() ngx.say("ok") } }
  }
}
EOF

docker run -d --rm --name "${container}" --network none --cpus 1 --memory 128m --pids-limit 64 \
  --volume "${engine}:/usr/local/share/cdnca/security/cc.lua:ro" \
  --volume "${workdir}:/runtime" --workdir /runtime \
  "${OPENRESTY_IMAGE}" openresty -g 'daemon off;' -p /runtime/ -c nginx.conf >/dev/null

ready=""
for _ in $(seq 1 100); do
  if docker exec "${container}" curl -fsS -o /dev/null http://127.0.0.1:18300/flush 2>/dev/null; then ready=1; break; fi
  sleep 0.1
done
if [ -z "${ready}" ]; then
  cat "${workdir}/logs/error.log" >&2 2>/dev/null || true
  fail "cc.lua did not start"
fi

if ! docker exec -i "${container}" sh -eu <<'INNER'
fail() { echo "FAIL: $*" >&2; exit 1; }
# req <path> <client> [overlay json]
req() {
  if [ -n "${3:-}" ]; then
    curl -sS -o /dev/null -w '%{http_code}' -G -H "X-Real-IP: $2" --data-urlencode "o=$3" "http://127.0.0.1:18300$1"
  else
    curl -sS -o /dev/null -w '%{http_code}' -H "X-Real-IP: $2" "http://127.0.0.1:18300$1"
  fi
}
expect() { test "$3" = "$2" || fail "$1: want $2, got $3"; }
# nth <path> <client> <n> [overlay]: status of the n-th request in a row
nth() {
  i=1; code=""
  while [ "${i}" -le "$3" ]; do code="$(req "$1" "$2" "${4:-}")"; i=$(( i + 1 )); done
  echo "${code}"
}

expect "no overlay 5th" 200 "$(nth /p1 192.0.2.1 5)"
expect "no overlay 6th" 429 "$(req /p1 192.0.2.1)"
echo "ok   no overlay: the policy's 5 requests per window"

expect "per_ip 2nd" 200 "$(nth /p1 192.0.2.2 2 '{"cc.per_ip_requests":2}')"
expect "per_ip 3rd" 429 "$(req /p1 192.0.2.2 '{"cc.per_ip_requests":2}')"
expect "per_ip larger 5th" 200 "$(nth /p1 192.0.2.3 5 '{"cc.per_ip_requests":100}')"
expect "per_ip larger 6th" 429 "$(req /p1 192.0.2.3 '{"cc.per_ip_requests":100}')"
expect "per_ip invalid 5th" 200 "$(nth /p1 192.0.2.4 5 '{"cc.per_ip_requests":0}')"
echo "ok   cc.per_ip_requests tightens (2), never relaxes (100), invalid ignored"

curl -fsS http://127.0.0.1:18300/flush >/dev/null
expect "ban short 2nd" 429 "$(nth /p4 192.0.2.5 2 '{"cc.ban_seconds":30}')"
ttl="$(curl -fsS http://127.0.0.1:18300/ttl)"
test "${ttl}" -gt 30 && test "${ttl}" -le 60 || fail "cc.ban_seconds 30 shortened the 60 s ban: ttl ${ttl}"
curl -fsS http://127.0.0.1:18300/flush >/dev/null
expect "ban long 2nd" 429 "$(nth /p4 192.0.2.6 2 '{"cc.ban_seconds":3600}')"
ttl="$(curl -fsS http://127.0.0.1:18300/ttl)"
test "${ttl}" -gt 3000 || fail "cc.ban_seconds 3600 did not lengthen the ban: ttl ${ttl}"
echo "ok   cc.ban_seconds lengthens a temporary ban (ttl ${ttl}), never shortens it"

# auto switch: 15 requests back to back stay below qps_total 20 but reach the
# overlay's 5 within a second; the next second runs the switch rules (1 per
# client)
n=1; while [ "${n}" -le 15 ]; do req /p3 "10.9.0.${n}" '{"cc.auto_switch_qps":5}' >/dev/null; n=$(( n + 1 )); done
sleep 1.2
expect "switch first" 200 "$(req /p3 192.0.2.7 '{"cc.auto_switch_qps":5}')"
expect "switch limit" 429 "$(req /p3 192.0.2.7 '{"cc.auto_switch_qps":5}')"
echo "ok   cc.auto_switch_qps lowers the switch threshold"

# bot.fake_crawler_block (ad-16): a User-Agent claiming the trusted crawler
ua_req() { curl -sS -o /dev/null -w '%{http_code}' -G -A 'Mozilla/5.0 (compatible; Googlebot/2.1)' -H "X-Real-IP: $1" --data-urlencode "o=$2" "http://127.0.0.1:18300/p5"; }
expect "fake crawler blocked" 403 "$(ua_req 192.0.2.8 '{"bot.fake_crawler_block":1}')"
expect "real crawler passes" 200 "$(ua_req 203.0.113.9 '{"bot.fake_crawler_block":1}')"
expect "fake crawler without overlay" 200 "$(ua_req 192.0.2.8 '{}')"
expect "fake crawler overlay off" 200 "$(ua_req 192.0.2.8 '{"bot.fake_crawler_block":0}')"
expect "browser not a crawler" 200 "$(req /p5 192.0.2.8 '{"bot.fake_crawler_block":1}')"
echo "ok   bot.fake_crawler_block refuses a fake crawler only"

# cc.limit_permille (ad-bot-cc): count_by and leaky bucket rules tighten
curl -fsS http://127.0.0.1:18300/flush >/dev/null
expect "count_by no overlay 10th" 200 "$(nth /p6 198.18.1.1 10)"
expect "count_by no overlay 11th (same /24)" 429 "$(req /p6 198.18.1.2)"
expect "count_by permille 500: 5th" 200 "$(nth /p6 198.18.2.1 5 '{"cc.limit_permille":500}')"
expect "count_by permille 500: 6th (same /24)" 429 "$(req /p6 198.18.2.9 '{"cc.limit_permille":500}')"
expect "count_by permille 200: 3rd" 429 "$(nth /p6 198.18.3.1 3 '{"cc.limit_permille":200}')"
expect "count_by permille 1000: 10th" 200 "$(nth /p6 198.18.4.1 10 '{"cc.limit_permille":1000}')"
expect "count_by permille 5000 never relaxes: 11th" 429 "$(nth /p6 198.18.5.1 11 '{"cc.limit_permille":5000}')"
expect "count_by permille invalid: 10th" 200 "$(nth /p6 198.18.6.1 10 '{"cc.limit_permille":"x"}')"
echo "ok   cc.limit_permille tightens a count_by fixed window, never relaxes"
expect "bucket no overlay 10th" 200 "$(nth /p7 192.0.2.20 10)"
expect "bucket no overlay 11th" 429 "$(req /p7 192.0.2.20)"
expect "bucket permille 500: 5th" 200 "$(nth /p7 192.0.2.21 5 '{"cc.limit_permille":500}')"
expect "bucket permille 500: 6th" 429 "$(req /p7 192.0.2.21 '{"cc.limit_permille":500}')"
echo "ok   cc.limit_permille tightens a leaky bucket's burst"
# relaxing: the overlay gone, the rule's own burst applies again
expect "bucket relaxed 10th" 200 "$(nth /p7 192.0.2.22 10)"
echo "ok   without cc.limit_permille the rules run at their own limits again"
INNER
then
  tail -n 40 "${workdir}/logs/error.log" >&2 2>/dev/null || true
  fail "overlay behaviour"
fi
if grep -E '\[(alert|crit|emerg|error)\]' "${workdir}/logs/error.log" | head -5 | grep .; then fail "error.log"; fi
echo "PASS cc overlay"
