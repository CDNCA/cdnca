#!/bin/sh
# Real-OpenResty test of WAF v2 actions (libs/edgeconfig waf_action.go,
# edge/openresty/lua/cdnca_waf.lua act / gate): challenge with proof of work
# and pass cookie, POST challenge answered 307 keeping method and body, ban,
# auto block, observe mode and unban. The location Lua is rendered by
# edgeconfig (cmd/security-location) for two policies (defend / observe).
#   WAF_ACTION_IMAGE  OpenResty image (default the pinned node release, runtime.env)
set -eu
repo_root="$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)"
. "${repo_root}/edge/openresty/runtime.env"
image="${WAF_ACTION_IMAGE:-${OPENRESTY_IMAGE}}"
work="$(mktemp -d "${TMPDIR:-/tmp}/cdnca-waf-action.XXXXXX")"
container="cdnca-ge-waf-action-$(basename "${work}" | tr 'A-Z.' 'a-z-')"
cleanup() { docker rm -f "${container}" >/dev/null 2>&1 || true; rm -rf -- "${work}"; }
trap cleanup EXIT INT TERM
mkdir -p "${work}/lua" "${work}/logs"
cp "${repo_root}/edge/openresty/lua/cdnca_waf.lua" "${work}/lua/cdnca_waf.lua"
cp "${repo_root}/scripts/security/waf-action-cases.lua" "${work}/cases.lua"
site=5ee00000-0000-4000-8000-0000000000a1
policy() { # mode
  cat <<JSON
[{"kind":"waf","policy_id":"6ee00000-0000-4000-8000-0000000000b1","policy_version":1,"binding_revision":1,
  "runtime_sha256":"$(printf '%064d' 0)","enabled":true,"default_action":"allow","mode":"$1",
  "auto_block":{"window_seconds":60,"hit_threshold":3,"block_seconds":120},
  "rules":[
   {"rule_id":"7ee00000-0000-4000-8000-0000000000c1","match":{"path":{"kind":"prefix","value":"/challenge"}},
    "action":"challenge","flow":"stop","action_config":{"pass_seconds":600,"pow_bits":8}},
   {"rule_id":"7ee00000-0000-4000-8000-0000000000c2","match":{"path":{"kind":"prefix","value":"/ban"}},
    "action":"ban","flow":"stop","action_config":{"ban_seconds":300}},
   {"rule_id":"7ee00000-0000-4000-8000-0000000000c3","match":{"path":{"kind":"prefix","value":"/blocked"}},
    "action":"block","flow":"stop"}]}]
JSON
}
render() { policy "$1" | GOWORK="${repo_root}/go.work" go -C "${repo_root}/libs/edgeconfig" run ./cmd/security-location "$2"; }
# Output parts (=====-separated): http, location, telemetry http, telemetry server.
render "" "${site}" | awk 'BEGIN{n=0} /^=====$/{n++; next} n==1' >"${work}/defend.lua"
render observe 5ee00000-0000-4000-8000-0000000000a2 | awk 'BEGIN{n=0} /^=====$/{n++; next} n==1' >"${work}/observe.lua"
grep -q 'cdnca_waf").act' "${work}/defend.lua"
# fix-cfl-b: an ACL policy with a ban rule runs its gate
# before the WAF policy whose challenge issued the nonce; the verification
# POST must reach the WAF segment's gate (not be refused 403 by the ACL's).
cat <<JSON | GOWORK="${repo_root}/go.work" go -C "${repo_root}/libs/edgeconfig" run ./cmd/security-location 5ee00000-0000-4000-8000-0000000000a3 |
  awk 'BEGIN{n=0} /^=====$/{n++; next} n==1' >"${work}/dual.lua"
[{"kind":"acl","policy_id":"6ee00000-0000-4000-8000-0000000000b3","policy_version":1,"binding_revision":1,
  "runtime_sha256":"$(printf '%064d' 0)","enabled":true,"default_action":"allow",
  "rules":[{"rule_id":"7ee00000-0000-4000-8000-0000000000d1","match":{"path":{"kind":"prefix","value":"/acl-ban"}},
    "action":"ban","flow":"stop","action_config":{"ban_seconds":300}}]},
 {"kind":"waf","policy_id":"6ee00000-0000-4000-8000-0000000000b4","policy_version":1,"binding_revision":1,
  "runtime_sha256":"$(printf '%064d' 0)","enabled":true,"default_action":"allow",
  "rules":[{"rule_id":"7ee00000-0000-4000-8000-0000000000d2","match":{"path":{"kind":"prefix","value":"/challenge"}},
    "action":"challenge","flow":"stop","action_config":{"pass_seconds":600,"pow_bits":8}}]}]
JSON
[ "$(grep -c 'cdnca_waf").gate' "${work}/dual.lua")" -eq 2 ]
telemetry='set $cdnca_security_emit 0; set $cdnca_security_type ""; set $cdnca_security_action ""; set $cdnca_security_severity ""; set $cdnca_security_rule_id ""; set $cdnca_security_block_page 0; set $cdnca_security_policy_id ""; set $cdnca_security_detector ""; set $cdnca_security_matched ""; set $cdnca_security_body "";'
origin='content_by_lua_block { ngx.req.read_body(); ngx.print("origin ", ngx.req.get_method(), " ", ngx.req.get_body_data() or "") }'
cat >"${work}/nginx.conf" <<EOF2
worker_processes 1;
error_log logs/error.log warn;
pid logs/nginx.pid;
events { worker_connections 256; }
http {
  access_log off;
  lua_package_path "\$prefix/lua/?.lua;;";
  lua_shared_dict cdnca_waf_state 4m;
  set_real_ip_from 127.0.0.1;
  real_ip_header X-Real-IP;
  client_body_temp_path /tmp/action-body;
  server { listen 127.0.0.1:18091; ${telemetry}
    location / {
$(cat "${work}/defend.lua")
      ${origin}
    } }
  server { listen 127.0.0.1:18092; ${telemetry}
    location / {
$(cat "${work}/observe.lua")
      ${origin}
    } }
  server { listen 127.0.0.1:18094; ${telemetry}
    location / {
$(cat "${work}/dual.lua")
      ${origin}
    } }
  server { listen 127.0.0.1:18093;
    location = /unban { content_by_lua_block { ngx.req.read_body(); ngx.say(tostring(require("cdnca_waf").unban("site:${site}", ngx.req.get_body_data()))) } } }
}
EOF2
chmod -R a+rwX "${work}"
docker run -d --rm --name "${container}" --network none -v "${work}:/w" --entrypoint sh "${image}" -c 'sleep 600' >/dev/null
docker exec "${container}" openresty -p /w/ -c nginx.conf
docker exec "${container}" sh -c 'cd /w && resty cases.lua'
if grep -E '\[(error|crit|alert|emerg)\]' "${work}/logs/error.log"; then
  echo "FAIL error log"
  exit 1
fi
