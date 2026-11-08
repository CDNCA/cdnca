#!/bin/sh
# dynamic routing security on a real OpenResty run locally (no
# Docker): the node's cdnca_security, CC engine (cc = ccv2/engine.lua) and
# ban list (cdnca_banlist) with cdnca_site / cdnca_filters stubbed. One site
# object per X-Site header, every site on one port.
#   D5  a site without a CC binding or WAF action segment still enforces the
#       ban list (403, X-Cdnca-Ban: listed); a site with CC answers the same
#       as before; other sites / clients are untouched; a release lifts it.
#       A site with no listed ban (with or without CC) does not look the
#       client up (banned() not called); a network ban counts as a listed
#       ban of its site; a site added to a non-empty list applies within the
#       per-worker refresh (1 s). A site with a WAF action segment (its
#       gate checks the list too) looks the client up only when the site has
#       a listed ban, and a ban added to it applies at once.
#   D4  a temporary ban of a rule counting by something other than the
#       client (count_by uri, or target count_key) is marked on its security
#       line (detector "count_key") and never queued for the kernel; a ban of
#       the client itself (no count_by, client_ip + uri) is unmarked and queued.
#   D1  /healthz/cc-auto-switch reports an engaged dynamic routing site (CC
#       object policy) and, without traffic, its recovery after recover_seconds.
# Usage: edge/openresty/dynroute/security_objects_local_test.sh
#   OPENRESTY=<nginx binary> (default: openresty on PATH)
#   OPENRESTY_LUALIB=<lualib dir> (default: <binary>/../../lualib)
#   SKIP_RECOVER=1 skips D1's 60-second recovery wait.
set -eu
repo_root="$(CDPATH='' cd -- "$(dirname -- "$0")/../../.." && pwd)"
openresty="${OPENRESTY:-$(command -v openresty || true)}"
[ -x "${openresty}" ] || { echo "BLOCKED: no OpenResty binary (set OPENRESTY)" >&2; exit 69; }
lualib="${OPENRESTY_LUALIB:-$(CDPATH='' cd -- "$(dirname -- "${openresty}")/../.." && pwd)/lualib}"
work="$(mktemp -d "${TMPDIR:-/tmp}/cdnca-secobj.XXXXXX")"
cleanup() {
  [ -f "${work}/logs/nginx.pid" ] && "${openresty}" -p "${work}/" -c nginx.conf -s stop 2>/dev/null || true
  rm -rf -- "${work}"
}
trap cleanup EXIT HUP INT TERM
sha() { if command -v sha256sum >/dev/null; then sha256sum | awk '{print $1}'; else shasum -a 256 | awk '{print $1}'; fi; }
edge="${repo_root}/edge/openresty"
mkdir -p "${work}/lua" "${work}/logs" "${work}/objects" "${work}/sites"
for file in dynroute/cdnca_security.lua dynroute/cdnca_rule_plan.lua lua/cdnca_waf.lua lua/cdnca_rule_interp.lua lua/cdnca_banlist.lua; do
  ln -s "${edge}/${file}" "${work}/lua/$(basename "${file}")"
done
ln -s "${edge}/ccv2/engine.lua" "${work}/lua/cc.lua"
ln -s "${edge}/firewallaction" "${work}/lua/firewallaction"
ln -s "${edge}/httppolicy" "${work}/lua/httppolicy"
ln -s "${edge}/vendor/lua-resty-ipmatcher/ipmatcher.lua" "${work}/lua/ipmatcher.lua"
mkdir -p "${work}/lua/resty" && ln -s "${edge}/vendor/lua-resty-ipmatcher/ipmatcher.lua" "${work}/lua/resty/ipmatcher.lua"
# cdnca_site stub: sites/<X-Site>.json is the request's site object,
# objects/<sha256> the node object directory.
cat >"${work}/lua/cdnca_site.lua" <<EOF
local cjson = require "cjson.safe"
local _M = {}
local function read(path)
  local file = io.open(path, "rb")
  if not file then return nil end
  local data = file:read("*a")
  file:close()
  return data
end
function _M.object(digest) return read("${work}/objects/" .. digest) end
function _M.current()
  local name = ngx.var.http_x_site
  if not name or not name:match("^%w+$") then return nil end
  local raw = read("${work}/sites/" .. name .. ".json")
  if not raw then return nil end
  ngx.var.cdnca_site_digest = ngx.md5(raw)
  return cjson.decode(raw)
end
function _M.slot_page() return nil end
return _M
EOF
# cdnca_filters stub: the default blacklist page (status only).
cat >"${work}/lua/cdnca_filters.lua" <<'EOF'
local _M = {}
function _M.send_default(kind, status)
  ngx.status = status
  ngx.header["Content-Type"] = "text/plain"
  ngx.print(kind, "\n")
  return ngx.exit(status)
end
return _M
EOF

port=18921
admin=18929
cat >"${work}/nginx.conf" <<EOF
worker_processes 2;
error_log logs/error.log info;
pid logs/nginx.pid;
events { worker_connections 256; }
http {
  lua_package_path "${work}/lua/?.lua;${lualib}/?.lua;;";
  lua_package_cpath "${lualib}/?.so;;";
  lua_shared_dict cdnca_cc_state 8m;
  lua_shared_dict cdnca_security_bans 4m;
  lua_shared_dict cdnca_waf_state 4m;
  lua_shared_dict cdnca_firewall_action 1m;
  lua_shared_dict cdnca_challenge_state 1m;
  lua_shared_dict cdnca_test_counts 1m;
  set_real_ip_from 127.0.0.1;
  real_ip_header X-Real-IP;
  log_format sec escape=json '{"site":"\$http_x_site","client":"\$remote_addr","action":"\$cdnca_security_action","rule_id":"\$cdnca_security_rule_id","detector":"\$cdnca_security_detector"}';
  map \$cdnca_security_emit \$sec_emit { "1" 1; default 0; }
  init_by_lua_block {
    require("cdnca_security").configure({ node_id = "" })
    -- counts the ban list lookups (D5: a site without listed bans skips them)
    local banlist = require("cdnca_banlist")
    local banned = banlist.banned
    banlist.banned = function(...) ngx.shared.cdnca_test_counts:incr("banned", 1, 0); return banned(...) end
  }
  server {
    listen 127.0.0.1:${port};
    access_log logs/security.jsonl sec if=\$sec_emit;
    # declares the variables the modules write (as the skeleton does)
    location = /__never { internal;
      set \$cdnca_site_digest ""; set \$cdnca_security_emit ""; set \$cdnca_security_type "";
      set \$cdnca_security_action ""; set \$cdnca_security_severity ""; set \$cdnca_security_rule_id "";
      set \$cdnca_security_block_page ""; set \$cdnca_security_detector ""; set \$cdnca_security_policy_id "";
      set \$cdnca_security_aggregate ""; set \$cdnca_security_matched ""; set \$cdnca_security_user_agent "";
      set \$cdnca_security_body ""; }
    server_rewrite_by_lua_block {
      local site = require("cdnca_site").current()
      if not site then return ngx.exit(421) end
      ngx.ctx.site = site
      return require("cdnca_security").server_rewrite(site)
    }
    rewrite_by_lua_block { return require("cdnca_security").rewrite(ngx.ctx.site) }
    location / { content_by_lua_block { ngx.say("ok") } }
    log_by_lua_block { if ngx.ctx.site then require("cdnca_security").log(ngx.ctx.site) end }
  }
  server {
    listen 127.0.0.1:${admin};
    access_log off;
    location = /healthz/cc-auto-switch {
      default_type application/json;
      content_by_lua_block { ngx.print(require("cjson.safe").encode(require("cc").auto_switch_status())) }
    }
    location = /healthz/cc-kernel-bans {
      default_type text/plain;
      content_by_lua_block { for _, line in ipairs(require("cc").kernel_bans()) do ngx.say(line) end }
    }
    location = /healthz/security-bans {
      client_max_body_size 4m; client_body_buffer_size 4m;
      content_by_lua_block { require("cdnca_banlist").handle() }
    }
    location = /test/banned-count {
      content_by_lua_block {
        local counts = ngx.shared.cdnca_test_counts
        ngx.print(counts:get("banned") or 0)
        if ngx.var.arg_reset then counts:set("banned", 0) end
      }
    }
  }
}
EOF
tenant="018f1000-0000-7000-8000-0000000000aa"
uuid() { printf '5ee0e000-0000-4000-8000-%012d' "$1"; }
# policy <n> <rules json> [auto_switch json]: a CC policy object of site n
# (its sha256 printed).
policy() {
  body="$(printf '{"schema_version":"cdnca.edge.cc/v2","tenant_scope_id":"%s","site_id":"%s","policy_id":"%s","policy_version":1,"binding_id":"%s","binding_revision":1,"publication_id":"%s","enabled":true,"trusted_proxies":[],"allowlist":[],"rules":%s%s}' \
    "${tenant}" "$(uuid "$1")" "$(uuid "$(( $1 + 100 ))")" "$(uuid "$(( $1 + 200 ))")" "$(uuid "$(( $1 + 300 ))")" "$2" "${3:-}")"
  digest="$(printf '%s' "${body}" | sha)"
  printf '%s' "${body}" >"${work}/objects/${digest}"
  printf '%s' "${digest}"
}
# site <name> <n> [policy sha256]: the site object (with a CC binding of the
# port when a policy is given).
site() {
  security='{}'
  [ -n "${3:-}" ] && security="{\"cc\":[{\"ports\":[${port}],\"policy\":{\"sha256\":\"$3\"}}]}"
  printf '{"site_id":"%s","tenant_id":"%s","security":%s}' "$(uuid "$2")" "${tenant}" "${security}" >"${work}/sites/$1.json"
}
rule() { # id path count_by limit action
  printf '{"rule_id":"%s","priority":1,"flow":"stop","match":{"path":{"kind":"prefix","value":"%s"}},"dimension":"client_ip"%s,"limit":%s,"action":%s}' \
    "$(uuid "$1")" "$2" "$3" "$4" "$5"
}
fixed3='{"algorithm":"fixed_window","requests":3,"window_seconds":60}'
roomy='{"algorithm":"fixed_window","requests":100000,"window_seconds":60}'
ban='{"kind":"temporary_ban","ban_seconds":120}'
keyban='{"kind":"temporary_ban","ban_seconds":120,"target":"count_key"}'

site plain 1
site ccsite 2 "$(policy 2 "[$(rule 21 /never '' "${fixed3}" '{"kind":"reject_429"}')]")"
site byuri 3 "$(policy 3 "[$(rule 31 /hot ',"count_by":[{"key":"uri"}]' "${fixed3}" "${ban}")]")"
site bykey 4 "$(policy 4 "[$(rule 41 /hot ',"count_by":[{"key":"uri"}]' "${fixed3}" "${keyban}")]")"
site byclient 5 "$(policy 5 "[$(rule 51 /hot '' "${fixed3}" "${ban}")]")"
site byclienturi 6 "$(policy 6 "[$(rule 61 /hot ',"count_by":[{"key":"client_ip"},{"key":"uri"}]' "${fixed3}" "${ban}")]")"
# (built in steps: /bin/sh 3.2 misparses nested quoted substitutions)
switch_rule="$(rule 72 / '' "${roomy}" '{"kind":"reject_429"}')"
switch_json=",\"auto_switch\":{\"qps_total\":20,\"qps_5xx\":0,\"recover_seconds\":60,\"rules\":[${switch_rule}]}"
switch_rules="[$(rule 71 / '' "${roomy}" '{"kind":"reject_429"}')]"
site switch 7 "$(policy 7 "${switch_rules}" "${switch_json}")"
site plain2 8
site plainnet 9
# waf <name> <n>: a site whose WAF policy has a ban rule (a segment action, so
# its rule plan runs cdnca_waf.gate) that never matches.
waf() {
  printf '{"site_id":"%s","tenant_id":"%s","security":{"rules":{"header_overflow":"none","policies":[{"kind":"waf","policy_id":"%s","policy_version":1,"binding_revision":1,"runtime_sha256":"%064d","enabled":true,"default_action":"allow","rules":[{"rule_id":"%s","action":"ban","flow":"stop","action_config":{"ban_seconds":60},"match":{"path":{"kind":"prefix","value":"/never"}}}]}]}}}' \
    "$(uuid "$2")" "${tenant}" "$(uuid "$(( $2 + 100 ))")" 0 "$(uuid "$(( $2 + 200 ))")" >"${work}/sites/$1.json"
}
waf wafsite 10
waf waf2 11

export DYLD_LIBRARY_PATH="$(dirname "${lualib}")/luajit/lib${DYLD_LIBRARY_PATH:+:${DYLD_LIBRARY_PATH}}"
"${openresty}" -p "${work}/" -c nginx.conf || { cat "${work}/logs/error.log" >&2; exit 1; }
ready=""
for _ in $(seq 1 50); do
  curl -fsS -o /dev/null "http://127.0.0.1:${admin}/healthz/cc-auto-switch" 2>/dev/null && { ready=1; break; }
  sleep 0.1
done
[ -n "${ready}" ] || { cat "${work}/logs/error.log" >&2; echo "FAIL: OpenResty did not start" >&2; exit 1; }

failed=0
check() { # label want got
  if [ "$2" = "$3" ]; then echo "PASS $1"; else echo "FAIL $1: want $2, got $3"; failed=$((failed + 1)); fi
}
code() { curl -sS -o /dev/null -w '%{http_code}' -H "X-Site: $1" -H "X-Real-IP: $2" "http://127.0.0.1:${port}$3"; }
header() { curl -sS -D - -o /dev/null -H "X-Site: $1" -H "X-Real-IP: $2" "http://127.0.0.1:${port}$3" | tr -d '\r' | awk -v name="$4" 'tolower($1) == tolower(name) ":" {print $2}'; }
post_bans() {
  curl -sS -o "${work}/bans.out" -w '%{http_code}' -X POST --data-binary "$1" "http://127.0.0.1:${admin}/healthz/security-bans"
}
lookups() { curl -sS "http://127.0.0.1:${admin}/test/banned-count?reset=1"; }
json() { python3 -I -c "import json,sys; d=json.load(sys.stdin); print($1)"; }

# --- D5: the ban list without a CC binding / WAF action segment ----------
now="$(date +%s)"
check "D5 plain site serves before the ban" 200 "$(code plain 198.51.100.7 /)"
s1="$(uuid 1)" s2="$(uuid 2)" s8="$(uuid 8)" s9="$(uuid 9)" s10="$(uuid 10)" s11="$(uuid 11)"
snapshot="{\"revision\":1,\"bans\":[{\"site_id\":\"${s10}\",\"client\":\"198.51.100.7\",\"until\":$((now + 300))},{\"site_id\":\"${s1}\",\"client\":\"198.51.100.7\",\"until\":$((now + 300))},{\"site_id\":\"${s2}\",\"client\":\"198.51.100.7\",\"until\":$((now + 300))},{\"site_id\":\"${s9}\",\"client\":\"192.0.2.0/24\",\"until\":$((now + 300))}],\"releases\":[]}"
check "D5 snapshot applied" 200 "$(post_bans "${snapshot}")"
sleep 1.2 # the per-worker set of sites with bans refreshes once a second
check "D5 plain site refuses the listed client" 403 "$(code plain 198.51.100.7 /)"
check "D5 plain site X-Cdnca-Ban" listed "$(header plain 198.51.100.7 / X-Cdnca-Ban)"
check "D5 plain site other client" 200 "$(code plain 198.51.100.8 /)"
check "D5 CC site refuses the listed client (unchanged)" 403 "$(code ccsite 198.51.100.7 /)"
check "D5 CC site X-Cdnca-Ban (unchanged)" listed "$(header ccsite 198.51.100.7 / X-Cdnca-Ban)"
check "D5 another site is untouched" 200 "$(code byclient 198.51.100.7 /)"
check "D5 plain site network ban" 403 "$(code plainnet 192.0.2.77 /)"
check "D5 plain site outside the network" 200 "$(code plainnet 192.0.3.1 /)"
lookups >/dev/null
for _ in 1 2 3 4; do code plain2 198.51.100.7 / >/dev/null; code byclient 198.51.100.7 / >/dev/null; done
check "D5 sites without listed bans skip the lookup" 0 "$(lookups)"
check "D5 WAF site serves before its rules" 200 "$(code waf2 198.51.100.7 /)"
for _ in 1 2 3; do code waf2 198.51.100.7 / >/dev/null; done
check "D5 WAF site without listed bans skips the lookup" 0 "$(lookups)"
check "D5 WAF site refuses the listed client" 403 "$(code wafsite 198.51.100.7 /)"
check "D5 WAF site X-Cdnca-Ban" listed "$(header wafsite 198.51.100.7 / X-Cdnca-Ban)"
check "D5 WAF site other client" 200 "$(code wafsite 198.51.100.8 /)"
# The checkpoint's lookup is the request's one; the WAF gate
# does not repeat it (it did before: 2 per request)
lookups >/dev/null
check "D5 listed WAF site looks up once per request" 200 "$(code wafsite 198.51.100.8 /)"
check "D5 listed WAF site lookups counted" 1 "$(lookups)"
lookups >/dev/null
check "D5 listed site still looks up" 403 "$(code plain 198.51.100.7 /)"
check "D5 listed site lookups counted" 1 "$(lookups)"
snapshot="{\"revision\":2,\"bans\":[{\"site_id\":\"${s1}\",\"client\":\"198.51.100.7\",\"until\":$((now + 300))},{\"site_id\":\"${s8}\",\"client\":\"198.51.100.7\",\"until\":$((now + 300))},{\"site_id\":\"${s11}\",\"client\":\"198.51.100.7\",\"until\":$((now + 300))}],\"releases\":[]}"
check "D5 site added to a non-empty list" 200 "$(post_bans "${snapshot}")"
# a WAF site's gate reads the list's generation on every request: no refresh wait
for n in 1 2 3 4 5 6; do check "D5 added WAF site refuses the listed client at once ${n}" 403 "$(code waf2 198.51.100.7 /)"; done
sleep 1.2 # the per-worker set of sites with bans refreshes once a second
for n in 1 2 3 4; do check "D5 added site refuses the listed client ${n}" 403 "$(code plain2 198.51.100.7 /)"; done
for n in 1 2; do check "D5 site dropped from the list serves ${n}" 200 "$(code plainnet 192.0.2.77 /)"; done
snapshot="{\"revision\":3,\"bans\":[],\"releases\":[{\"site_id\":\"${s1}\",\"client\":\"198.51.100.7\",\"released_at\":$((now + 1))}]}"
check "D5 release applied" 200 "$(post_bans "${snapshot}")"
check "D5 plain site serves after the release" 200 "$(code plain 198.51.100.7 /)"
check "D5 WAF site dropped from the list serves" 200 "$(code waf2 198.51.100.7 /)"

# --- D4: what a CC temporary ban applies to ------------------------------
# ban_line <site>: "<client>|<detector>" of the site's last temporary_ban line
ban_line() {
  grep "\"site\":\"$1\"" "${work}/logs/security.jsonl" 2>/dev/null | grep '"action":"temporary_ban"' | tail -1 |
    json "d['client'] + '|' + d['detector']" 2>/dev/null || echo none
}
a=198.51.100.11 b=198.51.100.12
for s in byuri bykey; do code "$s" "$a" /hot >/dev/null; code "$s" "$a" /hot >/dev/null; code "$s" "$b" /hot >/dev/null; done
check "D4 count_by uri: the 4th request of the URI is refused" 429 "$(code byuri "$b" /hot)"
check "D4 count_by uri: the ban is the rule's, not the site's" 200 "$(code byuri "$b" /other)"
check "D4 count_by uri: line marks the count key" "${b}|count_key" "$(ban_line byuri)"
check "D4 target count_key: the 4th request of the URI is refused" 429 "$(code bykey "$b" /hot)"
check "D4 target count_key: every client of the key is refused" 429 "$(code bykey "$a" /hot)"
check "D4 target count_key: line marks the count key" "${b}|count_key" "$(ban_line bykey)"
for _ in 1 2 3; do code byclient "$a" /hot >/dev/null; code byclienturi "$a" /hot >/dev/null; done
check "D4 client ban: refused" 429 "$(code byclient "$a" /hot)"
check "D4 client ban: line unmarked" "${a}|" "$(ban_line byclient)"
check "D4 client_ip+uri ban: refused" 429 "$(code byclienturi "$a" /hot)"
check "D4 client_ip+uri ban: line unmarked" "${a}|" "$(ban_line byclienturi)"
kernel="$(curl -sS "http://127.0.0.1:${admin}/healthz/cc-kernel-bans")"
queued() { printf '%s\n' "${kernel}" | grep -c "|$(uuid "$1")|$2|" || true; }
check "D4 kernel queue: client ban queued" 1 "$(queued 5 "$a")"
check "D4 kernel queue: client_ip+uri ban queued" 1 "$(queued 6 "$a")"
check "D4 kernel queue: count_by uri ban not queued" 0 "$(queued 3 "$b")"
check "D4 kernel queue: count_key ban not queued" 0 "$(queued 4 "$b")"

# --- D1: auto switch status of dynamic routing sites ----------------------
switch_state() {
  curl -sS "http://127.0.0.1:${admin}/healthz/cc-auto-switch" | json "next(('%s|%s|%s|%s' % (str(s['active']).lower(), s['policy_id'], s['qps_total'], 'since' if s['since'] > 0 else 'nosince') for s in (d['sites'] if isinstance(d['sites'], list) else []) if s['site_id'] == '$(uuid 7)'), 'absent')"
}
check "D1 idle site is not reported" absent "$(switch_state)"
stop=$(( $(date +%s) + 3 ))
while [ "$(date +%s)" -lt "${stop}" ]; do code switch 198.51.100.21 / >/dev/null; done
check "D1 engaged site reported" "true|$(uuid 107)|20|since" "$(switch_state)"
grep -q "cc auto switch engaged site=$(uuid 7)" "${work}/logs/error.log" && echo "PASS D1 engage logged" || { echo "FAIL D1 engage not logged"; failed=$((failed + 1)); }
if [ "${SKIP_RECOVER:-}" != 1 ]; then
  sleep 63
  check "D1 idle engaged site recovers through the status read" "false|$(uuid 107)|20|since" "$(switch_state)"
  check "D1 recovered site no longer reported" absent "$(switch_state)"
fi

if [ "${failed}" -ne 0 ]; then
  echo "${failed} failed"
  grep -E '\[(error|crit|alert)\]' "${work}/logs/error.log" | tail -20 >&2 || true
  exit 1
fi
echo "all passed"
