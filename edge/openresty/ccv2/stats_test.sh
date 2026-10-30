#!/bin/sh
# CC v2 rule statistics. Every worker counts per site,
# policy, rule and minute (matched / triggered / challenged / blocked /
# passed / ja4_unavailable, triggered top clients and paths) and pushes one
# frame per second; stats() drains the frames once. Real OpenResty, two
# workers, no network.
#
# Usage: edge/openresty/ccv2/stats_test.sh
set -eu

repo_root="$(CDPATH='' cd -- "$(dirname -- "$0")/../../.." && pwd)"
# shellcheck disable=SC1091
. "${repo_root}/edge/openresty/runtime.env"
engine="${CC_ENGINE:-${repo_root}/edge/openresty/ccv2/engine.lua}"

workdir="$(mktemp -d "${TMPDIR:-/tmp}/cdnca-cc-stats.XXXXXX")"
container="cdnca-cc-stats-$(basename "${workdir}" | tr -cd 'A-Za-z0-9')"
cleanup() {
  docker rm -f "${container}" >/dev/null 2>&1 || true
  rm -rf -- "${workdir}"
}
trap cleanup EXIT HUP INT TERM
fail() { echo "FAIL: $*" >&2; exit 1; }

tenant="018f1000-0000-7000-8000-000000000001"
uuid() { printf '018f1000-0000-7000-8000-%012d' "$1"; }
entry_id() { printf '%s\0%s\0%s\0%s\0%s' "${tenant}" "$1" localhost "$2" http | sha256sum | awk '{print substr($1,1,32)}'; }

registry=""
servers=""
site() {
  site_id="$(uuid "$1")"
  policy_id="$(uuid "$(( $1 + 100 ))")"
  binding_id="$(uuid "$(( $1 + 200 ))")"
  publication_id="$(uuid "$(( $1 + 300 ))")"
  mkdir -p "${workdir}/security/${site_id}"
  printf '{"schema_version":"cdnca.edge.cc/v2","tenant_scope_id":"%s","site_id":"%s","policy_id":"%s","policy_version":7,"binding_id":"%s","binding_revision":1,"publication_id":"%s","enabled":true,"trusted_proxies":[],"allowlist":[],"rules":%s}' \
    "${tenant}" "${site_id}" "${policy_id}" "${binding_id}" "${publication_id}" "$3" >"${workdir}/security/${site_id}/cc.compiled.json"
  sha="$(sha256sum "${workdir}/security/${site_id}/cc.compiled.json" | awk '{print $1}')"
  entry="$(entry_id "${site_id}" "$2")"
  item="{\"entry_id\":\"${entry}\",\"tenant_scope_id\":\"${tenant}\",\"site_id\":\"${site_id}\",\"hostname\":\"localhost\",\"listen_port\":$2,\"protocol\":\"http\",\"policy_id\":\"${policy_id}\",\"policy_version\":7,\"binding_id\":\"${binding_id}\",\"binding_revision\":1,\"publication_id\":\"${publication_id}\",\"source_sha256\":\"$(printf 'a%.0s' $(seq 64))\",\"compiled_path\":\"security/${site_id}/cc.compiled.json\",\"compiled_sha256\":\"${sha}\"}"
  registry="${registry:+${registry},}${item}"
  servers="${servers}
  server {
    listen $2;
    server_rewrite_by_lua_block { return require(\"cc\").access(\"${entry}\") }
    log_by_lua_block { require(\"cc\").log() }
    location / { return 200 'ok\n'; }
  }"
}
rule() { # n priority match count_by limit action [flow]
  printf '{"rule_id":"%s","priority":%s,"flow":"%s","match":%s,"dimension":"client_ip"%s,"limit":%s,"action":%s}' \
    "$(uuid "$1")" "$2" "${7:-stop}" "$3" "$4" "$5" "$6"
}
any='{"path":{"kind":"prefix","value":"/"}}'
fixed3='{"algorithm":"fixed_window","requests":3,"window_seconds":60}'
redirect='{"kind":"challenge","ban_seconds":600,"challenge":{"mode":"redirect","failure_window_seconds":60,"max_failures":2,"pass_seconds":3600,"pow_bits":0,"challenge_seconds":120,"bind_ipv4_prefix":24,"bind_ipv6_prefix":64,"key_rotate_seconds":86400}}'

# Registry entries must be ordered by port.
site 1 18401 "[$(rule 11 1 "${any}" '' "${fixed3}" '{"kind":"temporary_ban","ban_seconds":120}')]"
site 2 18402 "[$(rule 21 1 "${any}" '' "${fixed3}" '{"kind":"log"}' continue)]"
site 3 18403 "[$(rule 31 1 "${any}" '' '{"algorithm":"always"}' "${redirect}")]"
site 4 18404 "[$(rule 41 1 "${any}" ',"count_by":[{"key":"ja4"}]' "${fixed3}" '{"kind":"temporary_ban","ban_seconds":120}')]"

cat >"${workdir}/nginx.conf" <<EOF
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
    local file = assert(io.open("/runtime/registry.json", "rb"))
    local registry = file:read("*a")
    file:close()
    require("cc").init({state_dict="cdnca_cc_v2_state", release_root="/runtime", registry_json=registry})
  }
  server {
    listen 18499;
    location = /cc-stats {
      default_type text/plain;
      content_by_lua_block { for _, line in ipairs(require("cc").stats()) do ngx.say(line) end }
    }
  }
  ${servers}
}
EOF
printf '{"schema_version":"cdnca.edge.cc-registry/v1","config_version_id":"cc-stats","entries":[%s]}' "${registry}" >"${workdir}/registry.json"
mkdir -p "${workdir}/logs"

docker run -d --rm --name "${container}" --network none --cpus 1 --memory 128m --pids-limit 64 \
  --volume "${engine}:/usr/local/share/cdnca/security/cc.lua:ro" \
  --volume "${workdir}:/runtime" --workdir /runtime \
  "${OPENRESTY_IMAGE}" openresty -g 'daemon off;' -p /runtime/ -c nginx.conf >/dev/null

ready=""
for _ in $(seq 1 100); do
  if docker exec "${container}" curl -fsS -o /dev/null http://127.0.0.1:18499/cc-stats 2>/dev/null; then ready=1; break; fi
  sleep 0.1
done
if [ -z "${ready}" ]; then
  cat "${workdir}/logs/error.log" >&2 2>/dev/null || true
  fail "cc.lua did not start"
fi

# The checks run inside the container: resty's cjson sums the drained frames
# (both workers) per site / rule.
if ! docker exec -i -e TENANT="${tenant}" "${container}" sh -eu <<'INNER'
fail() { echo "FAIL: $*" >&2; exit 1; }
req() { curl -sS -o /dev/null -w '%{http_code}' -H "X-Real-IP: $2" ${4:+-H "Cookie: $4"} "http://127.0.0.1:$1$3"; }
expect() { test "$3" = "$2" || fail "$1: want $2, got $3"; }
uuid() { printf '018f1000-0000-7000-8000-%012d' "$1"; }

test -z "$(curl -fsS http://127.0.0.1:18499/cc-stats)" || fail "frames before any request"

# Site 1: 3 allowed, 4th over the limit (ban), 5th hits the ban.
for n in 1 2 3; do expect "ban ${n}" 200 "$(req 18401 198.51.100.7 /a)"; done
expect "ban over" 429 "$(req 18401 198.51.100.7 /a)"
expect "ban hit" 429 "$(req 18401 198.51.100.7 /b)"
# Site 2: log action, 5 requests, 2 over the limit, all served.
for n in 1 2 3 4 5; do expect "log ${n}" 200 "$(req 18402 203.0.113.9 /log)"; done
# Site 3: redirect challenge: page (challenged), probe cookie (passed), pass (passed).
headers="$(curl -sS -D - -o /dev/null -H 'X-Real-IP: 192.0.2.5' http://127.0.0.1:18403/c)"
printf '%s' "${headers}" | grep -q '^HTTP/1.1 302' || fail "no redirect challenge"
probe="$(printf '%s' "${headers}" | tr -d '\r' | sed -n 's/^Set-Cookie: \(__cdnca_cc_probe=[0-9a-f]*\).*/\1/p')"
test -n "${probe}" || fail "no probe cookie"
headers="$(curl -sS -D - -o /dev/null -H 'X-Real-IP: 192.0.2.5' -H "Cookie: ${probe}" http://127.0.0.1:18403/c)"
pass="$(printf '%s' "${headers}" | tr -d '\r' | sed -n 's/^Set-Cookie: \(__cdnca_cc_pass=[^;]*\).*/\1/p')"
test -n "${pass}" || fail "probe did not issue a pass"
expect "pass" 200 "$(req 18403 192.0.2.5 /c "${pass}")"
# Site 3, another client: two pages then the third breaches max_failures 2 -> ban.
for n in 1 2; do expect "unpassed ${n}" 302 "$(req 18403 192.0.2.6 /d)"; done
expect "challenge ban" 403 "$(req 18403 192.0.2.6 /d)"
expect "challenge banned" 403 "$(req 18403 192.0.2.6 /d)"
# Site 4: ja4 count_by on plaintext: no fingerprint, never counted.
for n in 1 2; do expect "ja4 ${n}" 200 "$(req 18404 198.51.100.8 /j)"; done

sleep 2
curl -fsS http://127.0.0.1:18499/cc-stats >/tmp/frames
test -s /tmp/frames || fail "no frames"
test -z "$(curl -fsS http://127.0.0.1:18499/cc-stats)" || fail "frames drained twice"
grep -q dropped /tmp/frames && fail "unexpected drops: $(cat /tmp/frames)"

cat >/tmp/sum.lua <<'LUA'
local cjson = require("cjson.safe")
local totals, tops, versions = {}, {}, {}
for line in io.lines("/tmp/frames") do
  local frame = assert(cjson.decode(line))
  assert(frame.schema == "cdnca.edge.cc-stats-frame/v1", "schema")
  for _, row in ipairs(frame.rows) do
    assert(row.minute % 60 == 0 and row.tenant_scope_id == os.getenv("TENANT"), "row identity")
    versions[row.policy_version] = true
    local key = row.site_id:sub(-2) .. "/" .. (row.rule_id == "" and "-" or row.rule_id:sub(-2))
    local total = totals[key] or { 0, 0, 0, 0, 0, 0 }
    for index, field in ipairs({ "matched", "triggered", "challenged", "blocked", "passed", "ja4_unavailable" }) do
      total[index] = total[index] + row[field]
    end
    totals[key] = total
    for value, count in pairs(row.top_clients) do tops[key .. " client " .. value] = (tops[key .. " client " .. value] or 0) + count end
    for value, count in pairs(row.top_paths) do tops[key .. " path " .. value] = (tops[key .. " path " .. value] or 0) + count end
  end
end
local version_count = 0
for _ in pairs(versions) do version_count = version_count + 1 end
assert(versions["7"] and version_count == 1, "policy_version is decimal text")
local keys = {}
for key in pairs(totals) do keys[#keys + 1] = key end
table.sort(keys)
for _, key in ipairs(keys) do print(key .. " " .. table.concat(totals[key], ",")) end
local names = {}
for key in pairs(tops) do names[#names + 1] = key end
table.sort(names)
for _, key in ipairs(names) do print("top " .. key .. " " .. tops[key]) end
LUA
TENANT="${TENANT}" resty /tmp/sum.lua >/tmp/sum || fail "sum: $(cat /tmp/sum)"
want='01/11 5,2,0,2,0,0
02/21 5,2,0,0,0,0
03/- 0,1,0,1,0,0
03/31 6,4,3,1,2,0
04/41 0,0,0,0,0,2'
got="$(grep -v '^top ' /tmp/sum)"
test "${got}" = "${want}" || fail "totals:
${got}
want:
${want}"
echo "ok   matched/triggered/challenged/blocked/passed/ja4_unavailable per rule"
grep -qx 'top 01/11 client 198.51.100.7 2' /tmp/sum || fail "top client: $(grep '^top 01' /tmp/sum)"
grep -qx 'top 01/11 path /a 1' /tmp/sum && grep -qx 'top 01/11 path /b 1' /tmp/sum || fail "top paths: $(grep '^top 01' /tmp/sum)"
grep -qx 'top 02/21 client 203.0.113.9 2' /tmp/sum || fail "log top"
grep -qx 'top 03/31 client 192.0.2.6 3' /tmp/sum && grep -qx 'top 03/31 client 192.0.2.5 1' /tmp/sum && grep -qx 'top 03/- client 192.0.2.6 1' /tmp/sum || fail "challenge top: $(grep '^top 03' /tmp/sum)"
echo "ok   triggered top clients and paths"
INNER
then
  cat "${workdir}/logs/error.log" >&2 2>/dev/null || true
  fail "cc stats"
fi
grep -E '\[(error|crit|alert|emerg)\]' "${workdir}/logs/error.log" && fail "error log has errors"
echo "PASS cc rule statistics"
