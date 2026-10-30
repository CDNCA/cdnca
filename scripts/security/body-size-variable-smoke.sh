#!/bin/sh
# Real-NGINX smoke of native patch 23 (client_max_body_size with variables,
# docs/adr/0009 §4). The limit comes from a map on the URI, so one server{}
# carries many "sites"; every protocol path must enforce the per-request value:
# HTTP/1.1 Content-Length and chunked, HTTP/2 and HTTP/3 with and without
# Content-Length. Empty, malformed, zero or overflowing values must answer 500,
# never lift the limit. Values without variables keep the stock semantics.
#   BODY_SIZE_IMAGE  OpenResty runtime image built with the locked patch chain
#                    (edge/openresty/native/Dockerfile --target runtime); runs in
#                    a --network none container, also covers server_rewrite_by_lua.
#   BODY_SIZE_NGINX  instead of the image: a host nginx binary built from the
#                    verified source tree (--with-http_ssl_module --with-http_v2_module
#                    --with-http_v3_module); Lua cases are skipped.
#   BODY_SIZE_NAME   container name prefix
# Prints PASS|FAIL <id> expected=<..> actual=<..> <note>; exits non-zero on failures.
set -eu
repo_root="$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)"
work="$(mktemp -d "${TMPDIR:-/tmp}/cdnca-body-size.XXXXXX")"
container="${BODY_SIZE_NAME:-cdnca-body-size}-$(basename "${work}" | tr 'A-Z.' 'a-z-')"
nginx_bin="${BODY_SIZE_NGINX:-}"
image="${BODY_SIZE_IMAGE:-cdnca-native-runtime:body-size}"
cleanup() {
  if [ -n "${nginx_bin}" ]; then
    [ -f "${work}/run/nginx.pid" ] && kill "$(cat "${work}/run/nginx.pid")" 2>/dev/null || true
  else
    docker rm -f "${container}" >/dev/null 2>&1 || true
  fi
  rm -rf -- "${work}"
}
trap cleanup EXIT INT TERM

mkdir -p "${work}/probe" "${work}/run/logs"
cp "${repo_root}/edge/openresty/http3/client/client.mod" "${work}/probe/go.mod"
cp "${repo_root}/edge/openresty/http3/client/client.sum" "${work}/probe/go.sum"
cp "${repo_root}/scripts/security/wafbodyprobe/main.go" "${work}/probe/main.go"
if [ -n "${nginx_bin}" ]; then
  run=${work}/run lua=0
  GOWORK=off GOFLAGS=-mod=readonly CGO_ENABLED=0 go -C "${work}/probe" build -trimpath -o "${run}/wafbodyprobe" .
else
  run=/run/body lua=1
  arch="$(docker image inspect "${image}" --format '{{.Architecture}}')"
  GOWORK=off GOFLAGS=-mod=readonly CGO_ENABLED=0 GOOS=linux GOARCH="${arch}" \
    go -C "${work}/probe" build -trimpath -o "${work}/run/wafbodyprobe" .
fi
lua_server='' lua_location=''
if [ "${lua}" = 1 ]; then
  # ADR 0009 §3.2: the site is chosen in server_rewrite_by_lua, before find_config.
  # $lua_limit is declared by set (never reached: the if is false) and written by Lua.
  lua_server='if ($host = never.invalid) { set $lua_limit ""; }
    server_rewrite_by_lua_block { local m = ngx.var.uri:match("^/lua/(%w+)/") if m == "1k" then ngx.var.lua_limit = "1k" elseif m == "bad" then ngx.var.lua_limit = "x" end }'
  lua_location='location /lua/ { client_max_body_size $lua_limit; proxy_pass http://127.0.0.1:9000; }'
fi
cat >"${work}/run/nginx.conf" <<EOF
worker_processes 1; pid ${run}/nginx.pid; error_log ${run}/error.log notice;
events { worker_connections 256; }
http {
  access_log off;
  client_body_temp_path ${run}/body; proxy_temp_path ${run}/proxy;
  fastcgi_temp_path ${run}/fastcgi; uwsgi_temp_path ${run}/uwsgi; scgi_temp_path ${run}/scgi;
  map \$uri \$site_limit {
    ~^/[a-z]+/1k/    1k;
    ~^/[a-z]+/64k/   64k;
    ~^/[a-z]+/empty/ "";
    ~^/[a-z]+/zero/  0;
    ~^/[a-z]+/neg/   -1;
    ~^/[a-z]+/bad/   10x;
    ~^/[a-z]+/huge/  99999999999999999999;
    default          "";
  }
  server { listen 127.0.0.1:9000; client_max_body_size 0;
    location / { return 200 "origin/\$content_length\n"; } }
  server {
    listen 127.0.0.1:8443 ssl;
    listen 127.0.0.1:8443 quic;
    http2 on; http3 on;
    server_name waf.body.test;
    ${lua_server}
    ssl_certificate ${run}/tls.crt; ssl_certificate_key ${run}/tls.key;
    ssl_protocols TLSv1.2 TLSv1.3; ssl_session_tickets off;
    client_max_body_size \$site_limit;
    add_header X-Seen "\$server_protocol" always;
    proxy_http_version 1.1;
    location /proxy/ { proxy_pass http://127.0.0.1:9000; }
    location /stream/ { proxy_request_buffering off; proxy_pass http://127.0.0.1:9000; }
    location /return/ { return 200 "unread\n"; }
    location /static/ { client_max_body_size 1k; proxy_pass http://127.0.0.1:9000; }
    location /unlimited/ { client_max_body_size 0; proxy_pass http://127.0.0.1:9000; }
    location /locset/ { set \$loc_limit 1k; client_max_body_size \$loc_limit; proxy_pass http://127.0.0.1:9000; }
    ${lua_location}
  }
}
EOF
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=waf.body.test \
  -keyout "${work}/run/tls.key" -out "${work}/run/tls.crt" >/dev/null 2>&1

if [ -n "${nginx_bin}" ]; then
  ngx() { "${nginx_bin}" -p "${run}/" "$@"; }
  "${nginx_bin}" -p "${run}/" -c "${run}/nginx.conf" ||
    { echo "nginx failed to start" >&2; cat "${run}/error.log" >&2 2>/dev/null; exit 1; }
  probe() { "${run}/wafbodyprobe" -url "https://127.0.0.1:8443$1" -proto "$2" ${3:+"$3"} -body x -repeat "$4" 2>/dev/null || echo error; }
  probe_get() { "${run}/wafbodyprobe" -url "https://127.0.0.1:8443$1" -proto "$2" -method GET 2>/dev/null || echo error; }
else
  chmod -R a+rwX "${work}"
  docker run -d --rm --name "${container}" --network none -v "${work}/run:${run}" \
    --entrypoint sh "${image}" -c 'sleep 900' >/dev/null
  ngx() { docker exec "${container}" openresty -p "${run}/" "$@"; }
  docker exec "${container}" openresty -p "${run}/" -c "${run}/nginx.conf" ||
    { echo "openresty failed to start" >&2; cat "${work}/run/error.log" >&2 2>/dev/null; exit 1; }
  probe() { docker exec "${container}" "${run}/wafbodyprobe" -url "https://127.0.0.1:8443$1" -proto "$2" ${3:+"$3"} -body x -repeat "$4" 2>/dev/null || echo error; }
  probe_get() { docker exec "${container}" "${run}/wafbodyprobe" -url "https://127.0.0.1:8443$1" -proto "$2" -method GET 2>/dev/null || echo error; }
fi

failures=0
check() { if [ "$2" = "$3" ]; then echo "PASS $1 expected=$2 actual=$3 $4"; else echo "FAIL $1 expected=$2 actual=$3 $4"; failures=$((failures + 1)); fi; }
code() { probe "$@" | cut -d' ' -f1; }
seen() { echo "200 HTTP/$1 origin/$2"; }
version() { case "$1" in h1) echo 1.1 ;; h2) echo 2.0 ;; h3) echo 3.0 ;; esac; }

for proto in h1 h2 h3; do
  v=$(version "${proto}")
  # Content-Length path: 413 from the limit of the URI's site, before any byte is proxied.
  check "${proto}-LEN-AT-LIMIT" "$(seen "${v}" 1024)" "$(probe /proxy/1k/ "${proto}" '' 1024)" "Content-Length 等于变量上限放行"
  check "${proto}-LEN-OVER" 413 "$(code /proxy/1k/ "${proto}" '' 1025)" "Content-Length 超变量上限 1 字节拒绝"
  # No Content-Length: h1 chunked, h2/h3 DATA frames until END_STREAM.
  check "${proto}-STREAM-AT-LIMIT" "$(seen "${v}" 1024)" "$(probe /proxy/1k/ "${proto}" -stream 1024)" "无长度体等于变量上限放行"
  check "${proto}-STREAM-OVER" 413 "$(code /proxy/1k/ "${proto}" -stream 1025)" "无长度体超变量上限 1 字节拒绝"
  check "${proto}-STREAM-64K-OK" "$(seen "${v}" 65536)" "$(probe /proxy/64k/ "${proto}" -stream 65536)" "另一站 64k 上限放行 64 KiB 流式体"
  check "${proto}-STREAM-64K-OVER" 413 "$(code /proxy/64k/ "${proto}" -stream 204800)" "200 KiB 流式体超 64k 拒绝（多次读）"
  check "${proto}-UNBUFFERED-OVER" 413 "$(code /stream/1k/ "${proto}" -stream 4096)" "proxy_request_buffering off 时同样拒绝"
  # Fail closed: a value the request cannot be limited by is a 500, never "unlimited".
  for bad in empty zero neg bad huge; do
    check "${proto}-LEN-${bad}" 500 "$(code "/proxy/${bad}/" "${proto}" '' 10)" "变量值 ${bad}：带长度体拒绝 500"
    check "${proto}-STREAM-${bad}" 500 "$(code "/proxy/${bad}/" "${proto}" -stream 10)" "变量值 ${bad}：无长度体拒绝 500"
  done
  check "${proto}-GET-empty" "200 HTTP/${v} origin/" "$(probe_get /proxy/empty/ "${proto}")" "无请求体时不求值（GET 不受影响）"
  # Static values keep the stock semantics.
  check "${proto}-STATIC-OVER" 413 "$(code /static/x/ "${proto}" -stream 1025)" "静态 1k 不变"
  check "${proto}-STATIC-AT-LIMIT" "$(seen "${v}" 1024)" "$(probe /static/x/ "${proto}" '' 1024)" "静态 1k 边界不变"
  check "${proto}-UNLIMITED" "$(seen "${v}" 2097152)" "$(probe /unlimited/x/ "${proto}" -stream 2097152)" "静态 0 仍为不限"
  # Location without body read: same find_config Content-Length check as stock nginx.
  check "${proto}-UNREAD-LEN-OVER" 413 "$(code /return/1k/ "${proto}" '' 1025)" "不读体的 location 按 Content-Length 早拒"
  check "${proto}-UNREAD-LEN-empty" 500 "$(code /return/empty/ "${proto}" '' 10)" "不读体的 location 变量为空拒绝"
  # A variable set in the location's rewrite phase is not set yet at find_config.
  check "${proto}-LOCSET-LEN" 500 "$(code /locset/x/ "${proto}" '' 10)" "location 内 set 的变量在 find_config 时未赋值：带长度体 500"
  check "${proto}-LOCSET-STREAM-OVER" 413 "$(code /locset/x/ "${proto}" -stream 1025)" "读体时已赋值：无长度体超限拒绝"
  if [ "${lua}" = 1 ]; then
    check "${proto}-LUA-LEN-OVER" 413 "$(code /lua/1k/ "${proto}" '' 1025)" "server_rewrite_by_lua 写入的上限对 Content-Length 生效"
    check "${proto}-LUA-STREAM-OVER" 413 "$(code /lua/1k/ "${proto}" -stream 1025)" "server_rewrite_by_lua 写入的上限对无长度体生效"
    check "${proto}-LUA-STREAM-OK" "$(seen "${v}" 1024)" "$(probe /lua/1k/ "${proto}" -stream 1024)" "server_rewrite_by_lua 上限边界放行"
    check "${proto}-LUA-UNSET" 500 "$(code /lua/none/ "${proto}" -stream 10)" "Lua 未写入（未命中站点）拒绝"
    check "${proto}-LUA-BAD" 500 "$(code /lua/bad/ "${proto}" '' 10)" "Lua 写入非法值拒绝"
  fi
done

# Configuration-time checks.
conf_fails() {
  printf 'events {} http { %s }\n' "$2" >"${work}/run/t-$1.conf"
  if ngx -t -c "${run}/t-$1.conf" >"${work}/run/t-$1.log" 2>&1; then echo accepted
  else grep -q "$3" "${work}/run/t-$1.log" && echo rejected || echo other; fi
}
check CONF-DUPLICATE rejected "$(conf_fails dup 'server { client_max_body_size $uri; client_max_body_size 1m; }' 'is duplicate')" "重复指令拒绝"
check CONF-STATIC-INVALID rejected "$(conf_fails inv 'server { client_max_body_size 1x; }' 'invalid value')" "静态非法值仍在配置期拒绝"
check CONF-UNKNOWN-VAR rejected "$(conf_fails unk 'server { client_max_body_size $no_such_var; }' 'unknown')" "未知变量配置期拒绝"

grep -E "\[(error|crit|alert|emerg)\]" "${work}/run/error.log" \
  | grep -v "too large\|invalid client_max_body_size value\|using uninitialized" | tail -5 || true
echo "runtime=${nginx_bin:-${image}} failures=${failures}"
[ "${failures}" -eq 0 ]
