#!/bin/sh
# FX45 firewall action escalation on a real OpenResty (the dynamic routing
# object entries handle_object / status_objects):
#   - a block_networks client gets the normal action (429 page), any other
#     client passes; a burst of passing clients is no load;
#   - once a second carried engage_threshold blocked requests the site is
#     escalated (status active, sequence advanced): block_networks clients are
#     disconnected (444) while other clients still pass;
#   - with no blocked requests for recovery_windows seconds the site recovers
#     on its own status polls (no traffic needed) and blocks with the page again.
#
# Usage: edge/openresty/firewallaction/escalation_test.sh
set -eu

repo_root="$(CDPATH='' cd -- "$(dirname -- "$0")/../../.." && pwd)"
# shellcheck disable=SC1091
. "${repo_root}/edge/openresty/runtime.env"
engine="${FIREWALL_ACTION_ENGINE:-${repo_root}/edge/openresty/firewallaction/engine.lua}"
ipmatcher="${repo_root}/tests/edge-site/lua/resty/ipmatcher.lua"

workdir="$(mktemp -d "${TMPDIR:-/tmp}/cdnca-g1-autoswitch-fw.XXXXXX")"
container="cdnca-g1-autoswitch-fw-$(basename "${workdir}" | tr -cd 'A-Za-z0-9')"
cleanup() {
  docker rm -f "${container}" >/dev/null 2>&1 || true
  rm -rf -- "${workdir}"
}
trap cleanup EXIT HUP INT TERM

site="018f1000-0000-7000-8000-000000000002"
cat >"${workdir}/policy.json" <<EOF
{"schema_version":"cdnca.edge.firewall-action/v1","policy_version":1,
 "tenant_id":"018f1000-0000-7000-8000-000000000001","site_id":"${site}",
 "policy_id":"018f1000-0000-7000-8000-000000000003","expected_active_policy_version":0,
 "normal_action":"return_page","escalated_action":"nftables",
 "engage_threshold":5,"recover_threshold":0,"recovery_windows":2,
 "block_networks":["198.51.100.0/24"],"trusted_proxies":["127.0.0.1/32"],"trusted_crawlers":[],
 "return_page":{"status":429,"content_type":"text/plain; charset=utf-8","body":"limited"}}
EOF
digest="$( (sha256sum "${workdir}/policy.json" 2>/dev/null || shasum -a 256 "${workdir}/policy.json") | awk '{print $1}')"
cp "${workdir}/policy.json" "${workdir}/${digest}"
cat >"${workdir}/nginx.conf" <<EOF
error_log /runtime/error.log notice;
pid /runtime/nginx.pid;
events { worker_connections 64; }
http {
  access_log off;
  lua_package_path '/usr/local/share/cdnca/?.lua;/opt/lua/?.lua;;';
  lua_shared_dict cdnca_firewall_action 1m;
  init_by_lua_block {
    read_object = function(digest)
      local file = io.open("/runtime/" .. digest, "rb")
      if not file then return nil end
      local raw = file:read("*a") file:close() return raw
    end
  }
  server {
    listen 18080;
    location = /healthz/firewall-action {
      default_type application/json;
      content_by_lua_block {
        ngx.print(require("cjson.safe").encode(require("firewallaction.engine").status_objects({
          { site_id = "${site}", sha256 = "${digest}" },
        }, read_object)))
      }
    }
    location / {
      access_by_lua_block {
        require("firewallaction.engine").handle_object("${digest}", read_object, "${site}")
      }
      content_by_lua_block { ngx.print("ok") }
    }
  }
}
EOF

docker run -d --rm --name "${container}" --network none --cpus 1 --memory 128m --pids-limit 64 \
  --volume "${engine}:/usr/local/share/cdnca/firewallaction/engine.lua:ro" \
  --volume "${ipmatcher}:/opt/lua/resty/ipmatcher.lua:ro" \
  --volume "${workdir}:/runtime" "${OPENRESTY_IMAGE}" \
  openresty -g 'daemon off;' -p /runtime/ -c /runtime/nginx.conf >/dev/null

if ! docker exec -i -e SITE="${site}" "${container}" sh -eu <<'INNER'
fail() { echo "FAIL: $*" >&2; exit 1; }
req() { curl -sS -o /dev/null -w '%{http_code}' -H "X-Forwarded-For: $1" http://127.0.0.1:18080/ 2>/dev/null || true; }
status() { curl -fsS http://127.0.0.1:18080/healthz/firewall-action; }
field() { status | sed -n "s/.*\"$1\":\([^,}]*\).*/\1/p"; }
wait_active() {
  for _ in $(seq 1 40); do test "$(field active)" = "$1" && return 0; sleep 0.2; done
  fail "status never became active=$1: $(status)"
}
ready=""
for _ in $(seq 1 50); do status >/dev/null 2>&1 && { ready=1; break; }; sleep 0.1; done
test -n "${ready}" || fail "OpenResty did not start"

test "$(req 203.0.113.9)" = 200 || fail "clean client was blocked"
test "$(req 198.51.100.7)" = 429 || fail "block_networks client did not get the page"
for _ in $(seq 1 30); do req 203.0.113.9 >/dev/null; done
sleep 1.2
test "$(field active)" = false || fail "passing clients engaged the site: $(status)"
status | grep -q "\"site_id\":\"${SITE}\"" || fail "status misses the site: $(status)"

for _ in $(seq 1 20); do req 198.51.100.7 >/dev/null; done
wait_active true
test "$(field sequence)" = 1 || fail "engage did not advance the sequence: $(status)"
test "$(req 203.0.113.9)" = 200 || fail "escalated site disconnected a clean client"
test "$(req 198.51.100.8)" = 000 || fail "escalated site did not disconnect a block_networks client"

# No traffic: the status polls alone recover the site.
wait_active false
test "$(field sequence)" = 2 || fail "recovery did not advance the sequence: $(status)"
test "$(req 198.51.100.7)" = 429 || fail "recovered site does not block with the page"
echo "firewall action escalation: ok"
INNER
then
  tail -20 "${workdir}/error.log" >&2 2>/dev/null || true
  exit 1
fi
