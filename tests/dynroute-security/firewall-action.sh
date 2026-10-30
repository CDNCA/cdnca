#!/bin/sh
# Dynamic routing D7: the firewall action engine run from a policy object
# (handle_object, what cdnca_security calls with the site object's
# firewall_action reference) decides exactly as the v7 path (handle with the
# release file). One real OpenResty (the node runtime image, --rm --network
# none), the same policy bytes on both paths:
#   - a block_networks client gets the return page, any other client passes
#     (IPv4 and IPv6, client address through a trusted proxy);
#   - the object path refuses (503) an object whose bytes do not match the
#     digest and a policy of another site.
#
#   tests/dynroute-security/firewall-action.sh
#   CDNCA_D7_IMAGE  node runtime image (default cdnca-native-runtime:edge-golden)
#   IPMATCHER=none  run without supplying resty.ipmatcher (the image's own):
#                   an image built before the native fix fails (every 503)
set -eu
here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH='' cd -- "${here}/../.." && pwd)
image=${CDNCA_D7_IMAGE:-cdnca-native-runtime:edge-golden}
work=$(mktemp -d /tmp/cdnca-d7-fw.XXXXXX)
trap 'rm -rf "${work}"' EXIT
mkdir -p "${work}/lua/firewallaction" "${work}/lua/resty" "${work}/objects" "${work}/logs"
cp "${repo_root}/edge/openresty/firewallaction/engine.lua" "${work}/lua/firewallaction/engine.lua"
cp "${here}/firewall-action-check.lua" "${work}/lua/check.lua"
if [ "${IPMATCHER:-repo}" != none ]; then
	cp "${repo_root}/edge/openresty/vendor/lua-resty-ipmatcher/ipmatcher.lua" "${work}/lua/resty/ipmatcher.lua"
fi
site=018f1000-0000-7000-8000-000000000002
printf '%s' '{"schema_version":"cdnca.edge.firewall-action/v1","policy_version":1,"tenant_id":"018f1000-0000-7000-8000-000000000001","site_id":"'"${site}"'","policy_id":"018f1000-0000-7000-8000-000000000003","expected_active_policy_version":0,"normal_action":"return_page","escalated_action":"nftables","engage_threshold":1000,"recover_threshold":0,"recovery_windows":2,"block_networks":["198.51.100.0/24","2001:db8:dead::/48"],"trusted_proxies":["127.0.0.1/32"],"trusted_crawlers":[],"return_page":{"status":429,"content_type":"text/plain; charset=utf-8","body":"limited"}}' > "${work}/policy.json"
digest=$( (sha256sum "${work}/policy.json" 2>/dev/null || shasum -a 256 "${work}/policy.json") | awk '{print $1}')
cp "${work}/policy.json" "${work}/objects/${digest}"
tampered=0000000000000000000000000000000000000000000000000000000000000000
printf 'tampered' > "${work}/objects/${tampered}"
cat > "${work}/nginx.conf" <<EOF
error_log /w/logs/error.log notice;
pid /w/logs/nginx.pid;
events { worker_connections 64; }
http {
  access_log off;
  lua_package_path '/w/lua/?.lua;;';
  lua_shared_dict cdnca_firewall_action 1m;
  init_by_lua_block {
    read_object = function(digest)
      local file = io.open("/w/objects/" .. digest, "rb")
      if not file then return nil end
      local raw = file:read("*a") file:close() return raw
    end
  }
  server {
    listen 127.0.0.1:18970;
    location /v7 { access_by_lua_block { require("firewallaction.engine").handle("/w/policy.json") } content_by_lua_block { ngx.print("pass") } }
    location /object { access_by_lua_block { require("firewallaction.engine").handle_object("${digest}", read_object, "${site}") } content_by_lua_block { ngx.print("pass") } }
    location /tampered { access_by_lua_block { require("firewallaction.engine").handle_object("${tampered}", read_object, "${site}") } content_by_lua_block { ngx.print("pass") } }
    location /other-site { access_by_lua_block { require("firewallaction.engine").handle_object("${digest}", read_object, "018f1000-0000-7000-8000-0000000000ff") } content_by_lua_block { ngx.print("pass") } }
    location = /__check { content_by_lua_block { require("check").run() } }
  }
}
EOF
cat > "${work}/run.sh" <<'EOF'
set -eu
openresty -p /w/ -c nginx.conf
sleep 0.3
# the check runs inside nginx (the image has no HTTP client): a worker
# timer writes the report, this script waits for it.
i=0; while [ ! -s /w/logs/report ] && [ "${i}" -lt 50 ]; do sleep 0.1; i=$((i + 1)); done
openresty -p /w/ -c nginx.conf -s stop
cat /w/logs/report
if grep -E '\[(alert|crit|emerg)\]' /w/logs/error.log; then exit 1; fi
grep -qx 'RESULT ok' /w/logs/report
EOF
sed -i.bak 's|^  init_by_lua_block {|  init_worker_by_lua_block { ngx.timer.at(0.2, function() require("check").run() end) }\n  init_by_lua_block {|' "${work}/nginx.conf"
chmod -R a+rwX "${work}"
docker run --rm --network none -v "${work}:/w" --entrypoint sh "${image}" /w/run.sh
