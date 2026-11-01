#!/bin/sh
# Real OpenResty functional acceptance of the node IP intelligence lookup
# (r136 G3-c, edge/openresty/iplib/cdnca_iplib.lua, Lua FFI over mmap):
#   1. Lua parity with the Go reference (*Table).Lookup on the runtime LuaJIT;
#   2. library missing / malformed: conditions never match (negated ones
#      included), requests are answered normally, the problem is logged;
#   3. WAF carrier / IDC / ASN / country conditions hit matching client
#      addresses and miss the others (IPv4 and IPv6);
#   4. a malformed replacement keeps the loaded revision (last known good);
#   5. hot replacement by rename: new lookups answer from the new revision.
# Client addresses come from X-Forwarded-For through the realip module
# (set_real_ip_from 127.0.0.1), the same $binary_remote_addr production
# lookups read after realip / PROXY protocol. No address is spoofed, no load
# is generated; the container runs with --network none.
# Conditions use the exact spec syntax rendered by libs/edgeconfig
# RenderWAFIPIntelCondition (tag bits: carrier:cn-telecom 0, carrier:cn-unicom 1,
# idc:cn 16), wrapped the way bound WAF rules deny (ngx.exit(403)).
#   IPLIB_IMAGE  native runtime image (default cdnca-native-runtime:edge-golden)
#   IPLIB_NAME   container name prefix
# Prints PASS|FAIL <id> expected=<..> actual=<..> <note>; exits non-zero on failures.
set -eu
repo_root="$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)"
image="${IPLIB_IMAGE:-cdnca-native-runtime:edge-golden}"
work="$(mktemp -d "${TMPDIR:-/tmp}/cdnca-iplib.XXXXXX")"
container="${IPLIB_NAME:-cdnca-iplib-smoke}-$(basename "${work}" | tr 'A-Z.' 'a-z-')"
cleanup() { docker rm -f "${container}" >/dev/null 2>&1 || true; rm -rf -- "${work}"; }
trap cleanup EXIT INT TERM
failures=0
check() {
  if [ "$2" = "$3" ]; then echo "PASS $1 expected=$2 actual=$3 $4"
  else echo "FAIL $1 expected=$2 actual=$3 $4"; failures=$((failures + 1)); fi
}

mkdir -p "${work}/fixtures" "${work}/scratch" "${work}/state" "${work}/run/logs"
IPINTEL_LUA_FIXTURE_DIR="${work}/fixtures" go -C "${repo_root}/libs/entitlement" test ./ipintel/ \
  -run '^TestWriteLuaParityFixtures$' -count=1 >"${work}/fixtures.log" 2>&1 || { cat "${work}/fixtures.log" >&2; exit 1; }
for f in boundary.ipi boundary.cases boundary-next.ipi large.ipi large.cases; do
  [ -s "${work}/fixtures/${f}" ] || { echo "fixture ${f} missing" >&2; exit 1; }
done
# Deliberately malformed libraries: wrong magic, and a valid header cut short.
printf 'NOTANIPI%056d' 0 >"${work}/fixtures/bad-magic.ipi"
head -c 100 "${work}/fixtures/boundary-next.ipi" >"${work}/fixtures/truncated.ipi"

cat >"${work}/run/nginx.conf" <<'EOF'
worker_processes 2; pid /run/iplib/nginx.pid; error_log /run/iplib/logs/error.log notice;
events { worker_connections 256; }
http {
  access_log off;
  client_body_temp_path /run/iplib/body; proxy_temp_path /run/iplib/proxy;
  fastcgi_temp_path /run/iplib/fastcgi; uwsgi_temp_path /run/iplib/uwsgi; scgi_temp_path /run/iplib/scgi;
  lua_package_path '/usr/local/share/cdnca/security/?.lua;;';
  set_real_ip_from 127.0.0.1;
  set_real_ip_from ::1;
  real_ip_header X-Forwarded-For;
  server {
    listen 127.0.0.1:8080;
    default_type text/plain;
    location = /status {
      content_by_lua_block {
        local iplib = require("cdnca_iplib")
        iplib.lookup_client() -- triggers the once-per-second header check
        local s = iplib.status()
        ngx.say(s.ready and ("ready revision=" .. s.revision) or "not_ready", " problem=", tostring(s.problem))
      }
    }
    location /telecom { access_by_lua_block { if require("cdnca_iplib").match("tag=0000000000000001") then return ngx.exit(403) end } content_by_lua_block { ngx.say("ok") } }
    location /unicom  { access_by_lua_block { if require("cdnca_iplib").match("tag=0000000000000002") then return ngx.exit(403) end } content_by_lua_block { ngx.say("ok") } }
    location /idc-cn  { access_by_lua_block { if require("cdnca_iplib").match("tag=0000000000010000") then return ngx.exit(403) end } content_by_lua_block { ngx.say("ok") } }
    location /asn     { access_by_lua_block { if require("cdnca_iplib").match("asn=15169") then return ngx.exit(403) end } content_by_lua_block { ngx.say("ok") } }
    location /us      { access_by_lua_block { if require("cdnca_iplib").match("country=US") then return ngx.exit(403) end } content_by_lua_block { ngx.say("ok") } }
    location /not-cn  { access_by_lua_block { if require("cdnca_iplib").match("country!=CN") then return ngx.exit(403) end } content_by_lua_block { ngx.say("ok") } }
  }
}
EOF
chmod -R a+rwX "${work}"

docker rm -f "${container}" >/dev/null 2>&1 || true
docker run -d --rm --name "${container}" --network none \
  -v "${work}/fixtures:/fixtures:ro" -v "${work}/scratch:/scratch" -v "${work}/run:/run/iplib" \
  -v "${work}/state:/var/lib/cdnca-edge/ip-intel" \
  -v "${repo_root}/edge/openresty/iplib:/iplib:ro" \
  -v "${repo_root}/edge/openresty/iplib/cdnca_iplib.lua:/usr/local/share/cdnca/security/cdnca_iplib.lua:ro" \
  --entrypoint sh "${image}" -c 'sleep 1800' >/dev/null
run() { docker exec "${container}" sh -c "$1"; }
run 'openresty -v 2>&1' | sed 's/^/runtime: /'

# code <client address> <path>: HTTP status (000 when no response).
code() {
  run "wget -q -S -O /dev/null --header 'X-Forwarded-For: $1' 'http://127.0.0.1:8080$2' 2>&1 | sed -n 's/^ *HTTP\/[0-9.]* \([0-9]*\).*/\1/p' | tail -n 1" | grep . || echo 000
}
status() { run "wget -q -O - http://127.0.0.1:8080/status" 2>/dev/null || echo unreachable; }
install() { # fixture: atomic replace by rename, as the agent does
  run "cp /fixtures/$1 /var/lib/cdnca-edge/ip-intel/.incoming && mv /var/lib/cdnca-edge/ip-intel/.incoming /var/lib/cdnca-edge/ip-intel/current.ipi"
}
# Each worker re-reads the header at most once per second; wait past it and
# ask several times so both workers have answered at least once.
settle() { sleep 1.3; for _ in 1 2 3 4 5 6; do status >/dev/null; done; }
errlog() { run "grep -c -- '$1' /run/iplib/logs/error.log || true"; }
crashes() { run "grep -c -E 'signal [0-9]+|exited on signal|\[alert\]|\[crit\]' /run/iplib/logs/error.log || true"; }

echo "== 1. Lua parity / reload against the Go reference (runtime LuaJIT)"
run '/usr/local/openresty/luajit/bin/luajit /iplib/parity_test.lua /fixtures /scratch' >"${work}/parity.log" 2>&1 || true
grep -E '^(FAIL|ALL)' "${work}/parity.log" | head -20
check PARITY "ALL PASS" "$(grep -o '^ALL PASS' "${work}/parity.log" || echo missing)" "$(grep -c '^PASS' "${work}/parity.log") 项 PASS"

echo "== 2. library missing / malformed"
check NGINX-T ok "$(run 'openresty -t -p /run/iplib/ -c nginx.conf >/dev/null 2>&1 && echo ok || echo fail')" "nginx -t"
run 'openresty -p /run/iplib/ -c nginx.conf'
for _ in $(seq 1 50); do [ "$(status)" != unreachable ] && break; sleep 0.2; done
check MISSING-status "not_ready problem=library missing" "$(status)" "库文件不存在：未就绪"
check MISSING-telecom 200 "$(code 1.0.0.1 /telecom)" "未就绪：电信规则不误拦"
check MISSING-negated 200 "$(code 1.0.2.9 /not-cn)" "未就绪：country!=CN 也不命中"
check MISSING-log-once 1 "$(run "grep -c 'cdnca_iplib: library missing' /run/iplib/logs/error.log | awk '{print (\$1 >= 1 && \$1 <= 2) ? 1 : \$1}'")" "每个 worker 只记一次（2 个 worker 共 1~2 行）"
install bad-magic.ipi; settle
check BADMAGIC-status "not_ready problem=invalid header" "$(status)" "魔数错误：拒绝加载"
check BADMAGIC-telecom 200 "$(code 1.0.0.1 /telecom)" "格式错：规则不命中"
check BADMAGIC-negated 200 "$(code 1.0.2.9 /not-cn)" "格式错：取反条件也不命中"
install truncated.ipi; settle
check TRUNCATED-status "not_ready problem=invalid layout" "$(status)" "截断文件：布局校验拒绝"
check TRUNCATED-telecom 200 "$(code 1.0.0.1 /telecom)" "截断文件：规则不命中"
check NOCRASH-1 0 "$(crashes)" "无 worker 崩溃 / alert / crit"

echo "== 3. WAF conditions on client addresses (revision 7)"
install boundary.ipi; settle
check LOAD-status "ready revision=7 problem=nil" "$(status)" "加载 boundary.ipi"
check LOAD-log yes "$(run "grep -q 'cdnca_iplib: loaded revision 7' /run/iplib/logs/error.log && echo yes || echo no")" "加载日志"
check HIT-telecom 403 "$(code 1.0.0.1 /telecom)" "carrier:cn-telecom 1.0.0.1 命中"
check MISS-telecom-unicom 200 "$(code 1.0.1.9 /telecom)" "联通地址不命中电信规则"
check HIT-unicom 403 "$(code 1.0.1.9 /unicom)" "carrier:cn-unicom 1.0.1.9 命中"
check MISS-unicom-telecom 200 "$(code 1.0.0.1 /unicom)" "电信地址不命中联通规则"
check HIT-telecom-v6 403 "$(code 240e::1 /telecom)" "IPv6 电信 240e::/20 命中"
check HIT-idc-cn-v6 403 "$(code 2400:3200::8 /idc-cn)" "idc:cn（IPv6 2400:3200::/32）命中"
check MISS-idc-cn 200 "$(code 8.8.8.8 /idc-cn)" "idc:global 地址不命中 idc:cn"
check HIT-asn 403 "$(code 8.8.8.8 /asn)" "asn=15169 命中"
check MISS-asn 200 "$(code 1.0.0.200 /asn)" "asn=4134 不命中 asn=15169"
check HIT-country 403 "$(code 8.8.8.8 /us)" "country=US 命中"
check MISS-country 200 "$(code 1.0.0.1 /us)" "CN 地址不命中 country=US"
check HIT-negated-unknown 403 "$(code 1.0.2.9 /not-cn)" "库外地址：country!=CN 命中（按设计）"
check MISS-negated-cn 200 "$(code 1.0.1.9 /not-cn)" "CN 地址：country!=CN 不命中"
check MISS-unknown 200 "$(code 1.0.2.9 /telecom)" "库外地址不命中等值条件"
check MISS-unknown-v6 200 "$(code 2001:db8::9 /idc-cn)" "IPv6 库外地址不命中"

echo "== 4. malformed replacement keeps the loaded revision"
install bad-magic.ipi; settle
check LKG-status "ready revision=7 problem=invalid header, keeping revision 7" "$(status)" "坏文件替换：继续用 revision 7"
check LKG-telecom 403 "$(code 1.0.0.1 /telecom)" "坏文件替换后规则照常命中"
check LKG-log yes "$(run "grep -q 'invalid header, keeping revision 7' /run/iplib/logs/error.log && echo yes || echo no")" "保留旧库写日志"

echo "== 5. hot replacement by rename (1.0.0.0/24: telecom -> unicom in revision 8)"
install boundary.ipi; settle
check SWAP-before 403 "$(code 1.0.0.1 /telecom)" "替换前 revision 7"
install boundary-next.ipi; settle
check SWAP-status "ready revision=8 problem=nil" "$(status)" "切到 revision 8"
check SWAP-old-rule 200 "$(code 1.0.0.1 /telecom)" "新查询按新库：不再是电信"
check SWAP-new-rule 403 "$(code 1.0.0.1 /unicom)" "新查询按新库：联通规则命中"
check SWAP-workers 0 "$(for _ in 1 2 3 4 5 6 7 8 9 10; do code 1.0.0.1 /unicom; done | grep -vc '^403$' || true)" "10 次请求（2 个 worker）全部按新库"
check SWAP-log yes "$(run "grep -q 'cdnca_iplib: loaded revision 8' /run/iplib/logs/error.log && echo yes || echo no")" "切换日志"
check NOCRASH-2 0 "$(crashes)" "全程无 worker 崩溃 / alert / crit"

run 'openresty -p /run/iplib/ -c nginx.conf -s stop' >/dev/null 2>&1 || true
if [ "${failures}" -ne 0 ]; then
  echo "iplib smoke: ${failures} failure(s)"; sed -n '1,40p' "${work}/run/logs/error.log" >&2 || true; exit 1
fi
echo "iplib smoke: all checks passed"
