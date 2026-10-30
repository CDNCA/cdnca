#!/bin/sh
# Real-NGINX smoke of native patch 24 (proxy_cache_valid with variables,
# docs/adr/0009 §4, dynamic routing D8). The cache time comes from a variable
# (a map on the URI, or Lua in server_rewrite as the dynamic routing entry
# writes it), so one server{} carries many sites with their own rule TTLs.
# Every protocol (h1/h2/h3) and the status paths 200, 404, an origin 503 and a
# proxy-generated 502 (upstream down) must cache for the per-request time; an
# empty value is "do not cache", a malformed value is logged and not cached;
# origin Cache-Control/X-Accel-Expires keep their precedence; values without
# variables keep the stock semantics.
#   CACHE_VALID_IMAGE  OpenResty runtime image built with the locked patch chain
#                      (edge/openresty/native/Dockerfile --target runtime); one
#                      --network none container.
# Prints PASS|FAIL <id> expected=<..> actual=<..> <note>; exits non-zero on failures.
set -eu
repo_root="$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)"
work="$(mktemp -d "${TMPDIR:-/tmp}/cdnca-cache-valid.XXXXXX")"
container="cdnca-cache-valid-$(basename "${work}" | tr 'A-Z.' 'a-z-')"
image="${CACHE_VALID_IMAGE:-cdnca-native-runtime:edge-golden}"
cleanup() { docker rm -f "${container}" >/dev/null 2>&1 || true; rm -rf -- "${work}"; }
trap cleanup EXIT INT TERM

run=/run/cv
mkdir -p "${work}/probe" "${work}/run/logs"
cp "${repo_root}/edge/openresty/http3/client/client.mod" "${work}/probe/go.mod"
cp "${repo_root}/edge/openresty/http3/client/client.sum" "${work}/probe/go.sum"
cp "${repo_root}/scripts/security/wafbodyprobe/main.go" "${work}/probe/main.go"
arch="$(docker image inspect "${image}" --format '{{.Architecture}}')"
GOWORK=off GOFLAGS=-mod=readonly CGO_ENABLED=0 GOOS=linux GOARCH="${arch}" \
  go -C "${work}/probe" build -trimpath -o "${work}/run/probe" .

cat >"${work}/run/nginx.conf" <<EOF
worker_processes 1; pid ${run}/nginx.pid; error_log ${run}/error.log notice;
events { worker_connections 256; }
http {
  access_log off;
  client_body_temp_path ${run}/body; proxy_temp_path ${run}/proxy;
  fastcgi_temp_path ${run}/fastcgi; uwsgi_temp_path ${run}/uwsgi; scgi_temp_path ${run}/scgi;
  proxy_cache_path ${run}/cache levels=1:2 keys_zone=cv:4m inactive=1h use_temp_path=off;
  # per-site rule TTL (what the dynamic routing cache module writes)
  map \$uri \$site_ttl {
    ~^/[a-z0-9]+/[a-z0-9]+/2s/    2s;
    ~^/[a-z0-9]+/[a-z0-9]+/1m/    1m;
    ~^/[a-z0-9]+/[a-z0-9]+/1s/    1s;
    ~^/[a-z0-9]+/[a-z0-9]+/empty/ "";
    ~^/[a-z0-9]+/[a-z0-9]+/bad/   10x;
    ~^/[a-z0-9]+/[a-z0-9]+/zero/  0;
    default             "";
  }
  # the dynamic routing form: Lua writes a per-site status table, the map
  # picks the entry of the (last) upstream status, else "any", else not cached
  map \$uri \$site_ttls {
    ~^/tab[0-9]*/[a-z0-9]+/a/ " 200=60 404=0 any=60 ";
    ~^/tab[0-9]*/[a-z0-9]+/b/ " 404=60 ";
    default "";
  }
  map "\$upstream_status|\$site_ttls" \$table_ttl {
    volatile;
    "~^(?:[^|]*, )?(?<s>[0-9]{3})\\|.* \\k<s>=(?<t>[0-9]+) " \$t;
    "~^[^|]*\\|.* any=(?<t>[0-9]+) " \$t;
    default "";
  }
  server { listen 127.0.0.1:9000;
    location /o404/ { return 404 "nf"; }
    location /o503/ { return 503 "down"; }
    location /o301/ { return 301 /elsewhere; }
    location /o410/ { return 410 "gone"; }
    location /occ/  { add_header Cache-Control "max-age=60"; return 200 "cc"; }
    location /oxa/  { add_header X-Accel-Expires 0; return 200 "xa"; }
    location / { return 200 "ok"; } }
  server {
    listen 127.0.0.1:8443 ssl;
    listen 127.0.0.1:8443 quic;
    http2 on; http3 on;
    server_name _;
    ssl_certificate ${run}/tls.crt; ssl_certificate_key ${run}/tls.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    # \$lua_ttl is declared by set (never reached) and written by Lua.
    if (\$host = never.invalid) { set \$lua_ttl ""; }
    server_rewrite_by_lua_block {
      local m = ngx.var.uri:match("^/lua/[a-z0-9]+/(%w+)/")
      if m == "1m" then ngx.var.lua_ttl = "1m" elseif m == "bad" then ngx.var.lua_ttl = "x" end
    }
    add_header X-Seen "\$upstream_cache_status" always;
    proxy_cache cv;
    proxy_cache_key "\$uri";
    location /v200/   { proxy_cache_valid 200 \$site_ttl; proxy_pass http://127.0.0.1:9000/; }
    location /v404/   { proxy_cache_valid 404 \$site_ttl; proxy_pass http://127.0.0.1:9000/o404/; }
    location /v503/   { proxy_cache_valid 503 \$site_ttl; proxy_pass http://127.0.0.1:9000/o503/; }
    location /v502/   { proxy_cache_valid 502 \$site_ttl; proxy_connect_timeout 1s; proxy_pass http://127.0.0.1:9/; }
    location /vany/   { proxy_cache_valid any \$site_ttl; proxy_pass http://127.0.0.1:9000/o410/; }
    location /vdef/   { proxy_cache_valid \$site_ttl; proxy_pass http://127.0.0.1:9000/; }
    location /vlist/  { proxy_cache_valid 200 404 \$site_ttl; proxy_pass http://127.0.0.1:9000/o404/; }
    location /vother/ { proxy_cache_valid 200 \$site_ttl; proxy_pass http://127.0.0.1:9000/o404/; }
    location /vcc/    { proxy_cache_valid 200 \$site_ttl; proxy_pass http://127.0.0.1:9000/occ/; }
    location /vxa/    { proxy_cache_valid 200 \$site_ttl; proxy_pass http://127.0.0.1:9000/oxa/; }
    location /vstat/  { proxy_cache_valid 200 1m; proxy_pass http://127.0.0.1:9000/; }
    location /vmix/   { proxy_cache_valid 404 1m; proxy_cache_valid 200 \$site_ttl; proxy_pass http://127.0.0.1:9000/; }
    location /vskip/  { proxy_cache_valid 200 \$site_ttl; proxy_cache_valid any 1m; proxy_pass http://127.0.0.1:9000/; }
    location /vzero/  { proxy_cache_valid 200 \$site_ttl; proxy_cache_valid any 1m; proxy_pass http://127.0.0.1:9000/; }
    location /tab/    { proxy_cache_valid any \$table_ttl; proxy_pass http://127.0.0.1:9000/; }
    location /tab404/ { proxy_cache_valid any \$table_ttl; proxy_pass http://127.0.0.1:9000/o404/; }
    location /tab503/ { proxy_cache_valid any \$table_ttl; proxy_pass http://127.0.0.1:9000/o503/; }
    location /lua/    { proxy_cache_valid 200 \$lua_ttl; proxy_pass http://127.0.0.1:9000/; }
  }
}
EOF
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=cache.valid.test \
  -keyout "${work}/run/tls.key" -out "${work}/run/tls.crt" >/dev/null 2>&1
chmod -R a+rwX "${work}"
docker run -d --rm --name "${container}" --network none -v "${work}/run:${run}" \
  --entrypoint sh "${image}" -c 'sleep 900' >/dev/null
ngx() { docker exec "${container}" openresty -p "${run}/" "$@"; }
ngx -c "${run}/nginx.conf" || { echo "openresty failed to start" >&2; cat "${work}/run/error.log" >&2 2>/dev/null; exit 1; }

failures=0
check() { if [ "$2" = "$3" ]; then echo "PASS $1 expected=$2 actual=$3 $4"; else echo "FAIL $1 expected=$2 actual=$3 $4"; failures=$((failures + 1)); fi; }
# "<status> <cache status>"
get() { docker exec "${container}" "${run}/probe" -url "https://127.0.0.1:8443$1" -proto "$2" -method GET 2>/dev/null | cut -d' ' -f1,2 || echo error; }
pair() { a=$(get "$1" "$2"); b=$(get "$1" "$2"); echo "${a}/${b}"; }

for proto in h1 h2 h3; do
  p=${proto}
  check "${p}-200-VAR" "200 MISS/200 HIT" "$(pair /v200/${p}/2s/a "${p}")" "200 按变量 2s 缓存"
  sleep 3
  check "${p}-200-VAR-EXPIRED" "200 EXPIRED" "$(get /v200/${p}/2s/a "${p}")" "变量 2s 到期后 EXPIRED"
  check "${p}-404-VAR" "404 MISS/404 HIT" "$(pair /v404/${p}/1m/a "${p}")" "404 按变量缓存"
  check "${p}-503-VAR" "503 MISS/503 HIT" "$(pair /v503/${p}/1m/a "${p}")" "源站 503 按变量缓存"
  check "${p}-502-VAR" "502 MISS/502 HIT" "$(pair /v502/${p}/1m/a "${p}")" "源站不可达 502（错误路径）按变量缓存"
  check "${p}-ANY-VAR" "410 MISS/410 HIT" "$(pair /vany/${p}/1m/a "${p}")" "any 状态按变量缓存"
  check "${p}-DEFAULT-STATUSES" "200 MISS/200 HIT" "$(pair /vdef/${p}/1m/a "${p}")" "省略状态 = 200 301 302"
  check "${p}-LIST-VAR" "404 MISS/404 HIT" "$(pair /vlist/${p}/1m/a "${p}")" "状态列表共享一个变量"
  check "${p}-OTHER-STATUS" "404 MISS/404 MISS" "$(pair /vother/${p}/1m/a "${p}")" "未列出的状态不缓存"
  check "${p}-EMPTY" "200 MISS/200 MISS" "$(pair /v200/${p}/empty/a "${p}")" "变量为空且无后续条目 = 不缓存"
  check "${p}-EMPTY-SKIPS" "200 MISS/200 HIT" "$(pair /vskip/${p}/empty/a "${p}")" "变量为空跳过该条目，后面的 any 生效"
  check "${p}-ZERO" "200 MISS/200 MISS" "$(pair /vzero/${p}/zero/a "${p}")" "变量为 0 = 不缓存（与 nginx 静态 0 同义，按条目顺序先匹配 200）"
  check "${p}-BAD" "200 MISS/200 MISS" "$(pair /v200/${p}/bad/a "${p}")" "变量非法 = 记日志且不缓存"
  check "${p}-404-EMPTY" "404 MISS/404 MISS" "$(pair /v404/${p}/empty/a "${p}")" "404 变量为空不缓存"
  check "${p}-503-EMPTY" "503 MISS/503 MISS" "$(pair /v503/${p}/empty/a "${p}")" "503 变量为空不缓存"
  check "${p}-ORIGIN-CC" "200 MISS/200 HIT" "$(pair /vcc/${p}/1s/a "${p}")" "源站 max-age=60 优先于变量 1s"
  sleep 2
  check "${p}-ORIGIN-CC-HOLDS" "200 HIT" "$(get /vcc/${p}/1s/a "${p}")" "变量 1s 过后仍按源站 60s 命中"
  check "${p}-ORIGIN-XA0" "200 MISS/200 MISS" "$(pair /vxa/${p}/1m/a "${p}")" "源站 X-Accel-Expires: 0 仍不缓存"
  check "${p}-STATIC" "200 MISS/200 HIT" "$(pair /vstat/${p}/a "${p}")" "静态值语义不变"
  check "${p}-MIXED" "200 MISS/200 HIT" "$(pair /vmix/${p}/1m/a "${p}")" "静态与变量混用"
  check "${p}-TABLE-200" "200 MISS/200 HIT" "$(pair /tab/${p}/a/x "${p}")" "状态表 200=60 命中"
  check "${p}-TABLE-NONE" "200 MISS/200 MISS" "$(pair /tab/${p}/b/y "${p}")" "状态表无 200 也无 any：不缓存"
  check "${p}-TABLE-404-ZERO" "404 MISS/404 MISS" "$(pair /tab404/${p}/a/x "${p}")" "状态表 404=0 不缓存（不落到 any）"
  check "${p}-TABLE-503-ANY" "503 MISS/503 HIT" "$(pair /tab503/${p}/a/x "${p}")" "状态表 503 无条目走 any=60"
  check "${p}-TABLE-404" "404 MISS/404 HIT" "$(pair /tab404/${p}/b/x "${p}")" "状态表 404=60"
  check "${p}-LUA" "200 MISS/200 HIT" "$(pair /lua/${p}/1m/a "${p}")" "server_rewrite_by_lua 写入的 TTL 生效"
  check "${p}-LUA-UNSET" "200 MISS/200 MISS" "$(pair /lua/${p}/none/a "${p}")" "Lua 未写入（未命中站点）不缓存"
  check "${p}-LUA-BAD" "200 MISS/200 MISS" "$(pair /lua/${p}/bad/a "${p}")" "Lua 写入非法值不缓存"
done

conf_fails() {
  printf 'pid %s/t.pid; events {} http { proxy_cache_path %s/c2 keys_zone=c2:1m; server { location / { proxy_cache c2; %s proxy_pass http://127.0.0.1:9; } } }\n' "${run}" "${run}" "$2" >"${work}/run/t-$1.conf"
  if ngx -t -c "${run}/t-$1.conf" >"${work}/run/t-$1.log" 2>&1; then echo accepted
  else grep -q "$3" "${work}/run/t-$1.log" && echo rejected || echo other; fi
}
check CONF-STATIC-INVALID rejected "$(conf_fails inv 'proxy_cache_valid 200 1x;' 'invalid time value')" "静态非法值仍在配置期拒绝"
check CONF-UNKNOWN-VAR rejected "$(conf_fails unk 'proxy_cache_valid 200 $no_such_var;' 'unknown')" "未知变量配置期拒绝"
check CONF-BAD-STATUS rejected "$(conf_fails sts 'proxy_cache_valid 99 $uri;' 'invalid status')" "非法状态码仍拒绝"
check CONF-VAR-OK accepted "$(conf_fails ok 'proxy_cache_valid 200 302 $uri;' x)" "变量值配置通过"
bad=$(grep -c 'invalid proxy_cache_valid time' "${work}/run/error.log" || true)
check LOG-BAD-VALUE yes "$([ "${bad}" -ge 6 ] && echo yes || echo "no(${bad})")" "非法值记 error 日志"

grep -E "\[(crit|alert|emerg)\]" "${work}/run/error.log" | tail -5 || true
echo "runtime=${image} failures=${failures}"
[ "${failures}" -eq 0 ]
