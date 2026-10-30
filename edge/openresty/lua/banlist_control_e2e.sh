#!/bin/sh
# Control plane to real OpenResty for the ban list library.
# Starts the node runtime (cdnca_banlist + a WAF v2 site, like banlist_test.sh)
# with the site and the loopback health endpoint published on 127.0.0.1, then
# runs the control-api integration test TestSecurityBanControlToOpenResty:
# a manual ban made through internal/securityban is signed, opened as the
# Agent does and applied to the node (403 X-Cdnca-Ban: listed), the release
# lets the client through again; receipts land in security_ban_node_state.
# Usage: TEST_DATABASE_URL=... [TEST_DATABASE_TEMPLATE=...] edge/openresty/lua/banlist_control_e2e.sh [control-api dir]
set -eu
repo_root="$(CDPATH='' cd -- "$(dirname -- "$0")/../../.." && pwd)"
control="${1:-${repo_root}/services/control-api}"
image="${BANLIST_IMAGE:-cdnca-native-runtime:edge-golden}"
work="$(mktemp -d "${TMPDIR:-/tmp}/cdnca-banlist-e2e.XXXXXX")"
container="cdnca-banlist-e2e-$(basename "${work}" | tr -cd 'a-z0-9')"
cleanup() { docker rm -f "${container}" >/dev/null 2>&1 || true; rm -rf -- "${work}"; }
trap cleanup EXIT HUP INT TERM
fail() { echo "FAIL: $*" >&2; exit 1; }
: "${TEST_DATABASE_URL:?TEST_DATABASE_URL is required}"

site=5ee00000-0000-4000-8000-0000000000e1
mkdir -p "${work}/lua" "${work}/logs"
for file in cdnca_waf.lua cdnca_banlist.lua; do cp "${repo_root}/edge/openresty/lua/${file}" "${work}/lua/${file}"; done
cat >"${work}/policy.json" <<JSON
[{"kind":"waf","policy_id":"6ee00000-0000-4000-8000-0000000000e2","policy_version":1,"binding_revision":1,
  "runtime_sha256":"$(printf '%064d' 0)","enabled":true,"default_action":"allow",
  "rules":[{"rule_id":"7ee00000-0000-4000-8000-0000000000e3","match":{"path":{"kind":"prefix","value":"/never"}},
    "action":"ban","flow":"stop","action_config":{"ban_seconds":300}}]}]
JSON
GOWORK="${repo_root}/go.work" go -C "${repo_root}/libs/edgeconfig" run ./cmd/security-location "${site}" <"${work}/policy.json" |
  awk 'BEGIN{n=0} /^=====$/{n++; next} n==1' >"${work}/waf.lua"
grep -q 'cdnca_waf").act' "${work}/waf.lua" || fail "WAF location not rendered"
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
  client_body_temp_path /tmp/banlist-body;
  set_real_ip_from 0.0.0.0/0;
  set_real_ip_from ::/0;
  real_ip_header X-Real-IP;
  server { listen 18411; ${telemetry}
    location / {
$(cat "${work}/waf.lua")
      content_by_lua_block { ngx.say("site ok") }
    } }
  # Published to the host for the test (the node binds it to 127.0.0.1).
  server { listen 18499;
    location = /healthz/security-bans {
      client_max_body_size 4m;
      client_body_buffer_size 4m;
      content_by_lua_block { require("cdnca_banlist").handle() }
    } }
}
EOF
chmod -R a+rwX "${work}"
docker run -d --rm --name "${container}" --cpus 1 --memory 192m --pids-limit 64 -v "${work}:/w" \
  -p 127.0.0.1::18411 -p 127.0.0.1::18499 \
  --entrypoint /usr/local/openresty/bin/openresty "${image}" -g 'daemon off;' -p /w/ -c nginx.conf >/dev/null
site_port="$(docker port "${container}" 18411/tcp | head -1 | awk -F: '{print $NF}')"
health_port="$(docker port "${container}" 18499/tcp | head -1 | awk -F: '{print $NF}')"
ready=""
for _ in $(seq 1 100); do
  if curl -fsS -o /dev/null "http://127.0.0.1:${health_port}/healthz/security-bans" 2>/dev/null; then ready=1; break; fi
  sleep 0.1
done
[ -n "${ready}" ] || { cat "${work}/logs/error.log" >&2 2>/dev/null || true; fail "OpenResty did not start"; }

SECURITY_BAN_E2E_HEALTH="http://127.0.0.1:${health_port}/healthz" SECURITY_BAN_E2E_SITE_URL="http://127.0.0.1:${site_port}/" \
SECURITY_BAN_E2E_SITE_ID="${site}" go -C "${control}" test -tags integration -count=1 -p 1 -timeout 10m \
  -run '^TestSecurityBanControlToOpenResty$' -v ./internal/securityban/ || {
  tail -20 "${work}/logs/error.log" >&2 2>/dev/null || true
  fail "control plane to OpenResty"
}
if grep -E '\[(error|crit|alert|emerg)\]' "${work}/logs/error.log"; then fail "error log"; fi
echo "RESULT ok"
