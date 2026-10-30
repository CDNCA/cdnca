#!/bin/sh
# Real-OpenResty smoke of WAF request-body inspection without Content-Length.
# HTTP/2 and HTTP/3 may stream a body without Content-Length (END_STREAM ends
# it) and HTTP/1.1 may send it chunked; cdnca_waf.lua inspect() must read and
# inspect those bodies exactly like length-delimited ones (r135-secfix).
# The rewrite condition is the one libs/edgeconfig RenderWAFInspectCondition
# renders for {"target":"body","operator":"detect","values":["sqli"]}.
#   WAF_BODY_IMAGE  OpenResty runtime image with http_v2/http_v3 (default: native
#                   runtime built from edge/openresty/native/Dockerfile --target runtime)
#   WAF_BODY_LUA    cdnca_waf.lua under test (default: the repository copy)
#   WAF_BODY_NAME   container name prefix
# Prints PASS|FAIL <id> expected=<..> actual=<..> <note>; exits non-zero on failures.
set -eu
repo_root="$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)"
image="${WAF_BODY_IMAGE:-cdnca-native-runtime:wafdual}"
lua="${WAF_BODY_LUA:-${repo_root}/edge/openresty/lua/cdnca_waf.lua}"
work="$(mktemp -d "${TMPDIR:-/tmp}/cdnca-waf-body.XXXXXX")"
container="${WAF_BODY_NAME:-cdnca-waf-body}-$(basename "${work}" | tr 'A-Z.' 'a-z-')"
cleanup() { docker rm -f "${container}" >/dev/null 2>&1 || true; rm -rf -- "${work}"; }
trap cleanup EXIT INT TERM

arch="$(docker image inspect "${image}" --format '{{.Architecture}}')"
mkdir -p "${work}/probe" "${work}/run/logs" "${work}/lua"
cp "${repo_root}/edge/openresty/http3/client/client.mod" "${work}/probe/go.mod"
cp "${repo_root}/edge/openresty/http3/client/client.sum" "${work}/probe/go.sum"
cp "${repo_root}/scripts/security/wafbodyprobe/main.go" "${work}/probe/main.go"
GOWORK=off GOFLAGS=-mod=readonly CGO_ENABLED=0 GOOS=linux GOARCH="${arch}" \
  go -C "${work}/probe" build -trimpath -o "${work}/run/wafbodyprobe" .
cp "${lua}" "${work}/lua/cdnca_waf.lua"
sqli='require("cdnca_waf").inspect([[{"target":"body","operator":"detect","values":["sqli"]}]])'
xss='require("cdnca_waf").inspect([[{"target":"body","operator":"detect","values":["xss"]}]])'
cat >"${work}/run/nginx.conf" <<EOF
worker_processes 1; pid /run/waf/nginx.pid; error_log /run/waf/error.log notice;
events { worker_connections 256; }
http {
  access_log off;
  lua_package_path "/usr/local/share/cdnca/security/?.lua;;";
  client_max_body_size 1m;
  server { listen 127.0.0.1:9000;
    location /echo { content_by_lua_block { ngx.req.read_body(); ngx.say("echo=", ngx.req.get_body_data() or "") } }
    location / { return 200 "origin-ok \$content_length\n"; } }
  server {
    listen 127.0.0.1:8443 ssl;
    listen 127.0.0.1:8443 quic reuseport;
    http2 on; http3 on;
    server_name waf.body.test;
    ssl_certificate /run/waf/tls.crt; ssl_certificate_key /run/waf/tls.key;
    ssl_protocols TLSv1.2 TLSv1.3; ssl_session_tickets off;
    # CVE-2026-15176: URI-to-path mapping after rewrite in an alias location.
    location /cve15176/longer-prefix/ { alias /tmp/; rewrite ^ /x; return 200 "\$request_filename\n"; }
    location / {
      rewrite_by_lua_block {
        if ${sqli} or ${xss} then return ngx.exit(403) end
      }
      add_header X-Seen "\$server_protocol|cl=\$http_content_length|te=\$http_transfer_encoding" always;
      proxy_http_version 1.1;
      proxy_pass http://127.0.0.1:9000;
    }
  }
}
EOF
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=waf.body.test \
  -keyout "${work}/run/tls.key" -out "${work}/run/tls.crt" >/dev/null 2>&1
chmod -R a+rwX "${work}"
docker run -d --rm --name "${container}" --network none -v "${work}/run:/run/waf" \
  -v "${work}/lua:/usr/local/share/cdnca/security:ro" --entrypoint sh "${image}" -c 'sleep 600' >/dev/null
docker exec "${container}" openresty -p /run/waf/ -c nginx.conf ||
  { echo "openresty failed to start" >&2; cat "${work}/run/error.log" >&2 2>/dev/null; exit 1; }

failures=0
check() { if [ "$2" = "$3" ]; then echo "PASS $1 expected=$2 actual=$3 $4"; else echo "FAIL $1 expected=$2 actual=$3 $4"; failures=$((failures + 1)); fi; }
# quic-go logs a UDP buffer warning on stderr; the verdict is stdout only.
probe() { docker exec "${container}" /run/waf/wafbodyprobe -url https://127.0.0.1:8443/submit "$@" 2>/dev/null || echo error; }
status() { probe "$@" | cut -d' ' -f1; }
attack='user=admin%27%20OR%201%3D1--&pass=x'
benign='user=alice&bio=Tom+%26+Jerry+fan'
pad='note=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa&'

for proto in h1 h2 h3; do
  check "${proto}-LEN-SQLI" 403 "$(status -proto "${proto}" -body "${attack}")" "带 Content-Length 的 SQLi 表单体"
  check "${proto}-STREAM-SQLI" 403 "$(status -proto "${proto}" -stream -body "${attack}")" "无 Content-Length（h1=chunked）的 SQLi 表单体"
  check "${proto}-STREAM-XSS" 403 "$(status -proto "${proto}" -stream -content-type text/plain -body '<script>alert(1)</script>')" "无 Content-Length 的 XSS 原始体"
done
check h2-STREAM-JSON 403 "$(status -proto h2 -stream -content-type application/json -body '{"id":"1 UNION SELECT password FROM users"}')" "HTTP/2 流式 JSON 体"
check h3-STREAM-JSON 403 "$(status -proto h3 -stream -content-type application/json -body '{"id":"1 UNION SELECT password FROM users"}')" "HTTP/3 流式 JSON 体"
check h2-STREAM-GET 403 "$(status -proto h2 -stream -method GET -body "${attack}")" "HTTP/2 GET 携带流式 SQLi 体"
check h3-STREAM-GET 403 "$(status -proto h3 -stream -method GET -body "${attack}")" "HTTP/3 GET 携带流式 SQLi 体"
# 20 KiB padding: past client_body_buffer_size (body in a temp file), within the 64 KiB inspection limit.
for proto in h1 h2 h3; do
  check "${proto}-STREAM-FILE-SQLI" 403 "$(status -proto "${proto}" -stream -pad 20480 -body "${attack}")" "无长度体落临时文件后仍检测"
done

check h1-STREAM-OK "200 HTTP/1.1|cl=|te=chunked origin-ok ${#benign}" "$(probe -proto h1 -stream -body "${benign}")" "正常 chunked 表单放行，源站收到完整体"
check h2-STREAM-OK "200 HTTP/2.0|cl=|te= origin-ok ${#benign}" "$(probe -proto h2 -stream -body "${benign}")" "正常 HTTP/2 无长度表单放行"
check h3-STREAM-OK "200 HTTP/3.0|cl=|te= origin-ok ${#benign}" "$(probe -proto h3 -stream -body "${benign}")" "正常 HTTP/3 无长度表单放行"
check h2-LEN-OK "200 HTTP/2.0|cl=${#benign}|te= origin-ok ${#benign}" "$(probe -proto h2 -body "${benign}")" "正常 HTTP/2 带长度表单放行"
# 无体 GET 时源站可能收到 Content-Length: 0，取决于 QUIC 包到达时序（fix-r11 已抓包证实）：
# 请求头里没有 CL 时，ngx_http_v3_request.c 会试读一次请求流。如果 FIN 已经和 HEADERS 一起到达，
# 读到 eof，源站请求不带 CL。如果 FIN 在后面单独成包（quic-go 先写 HEADERS 再 Close），
# 就当作未知长度体来读，读完 content_length_n=0，proxy 转发时发 Content-Length: 0。
# 两种情况帧界都一样（零长度体），RFC 9110 §8.6 允许，WAF 判定也相同，所以两种都接受。
h3_get="$(probe -proto h3 -method GET)"
[ "${h3_get}" = "200 HTTP/3.0|cl=|te= origin-ok 0" ] && h3_get="200 HTTP/3.0|cl=|te= origin-ok"
check h3-GET-OK "200 HTTP/3.0|cl=|te= origin-ok" "${h3_get}" "无体 GET 放行（源站无 CL 或 CL: 0 均可）"
check h2-STREAM-LARGE-OK "200 HTTP/2.0|cl=|te= origin-ok $((${#pad} * 1600))" "$(probe -proto h2 -stream -body "${pad}" -repeat 1600)" "约 200 KiB 正常流式体（超检测上限）放行"
check h3-STREAM-LARGE-OK "200 HTTP/3.0|cl=|te= origin-ok $((${#pad} * 1600))" "$(probe -proto h3 -stream -body "${pad}" -repeat 1600)" "约 200 KiB 正常 HTTP/3 流式体放行"
check h2-STREAM-OVERSIZE 413 "$(status -proto h2 -stream -body "${pad}" -repeat 16384)" "2 MiB 流式体超 client_max_body_size 拒绝"
check h3-STREAM-OVERSIZE 413 "$(status -proto h3 -stream -body "${pad}" -repeat 16384)" "2 MiB HTTP/3 流式体超 client_max_body_size 拒绝"
check h1-STREAM-OVERSIZE 413 "$(status -proto h1 -stream -body "${pad}" -repeat 16384)" "2 MiB chunked 体超 client_max_body_size 拒绝"

# CVE-2026-95101 (nginx core, not the WAF): an unknown HTTP/3 frame split across
# packets must be skipped whole; affected nginx (< 1.31.7 without patch 18)
# proxies its tail as request body. Echo is "A=1" + "&B=2" only when fixed.
check H3-CVE-2026-95101 "200 echo=A=1&B=2" "$(probe -proto h3split -url https://127.0.0.1:8443/echo -body 'INJECTED')" "HTTP/3 未知帧跨包拆分不得注入请求体"

# Fixed nginx refuses the mapping with an alert; affected nginx maps the 2-byte
# URI through the 26-byte alias prefix (negative length, out-of-bounds copy).
probe -proto h3 -method GET -url https://127.0.0.1:8443/cve15176/longer-prefix/a >/dev/null
mapped=1; grep -q 'malloc(.*/cve15176/' "${work}/run/error.log" || mapped=0
check CVE-2026-15176-MAP 0 "${mapped}" "无越界长度分配（受影响版本 malloc 负长度）"
alias_alert=0; grep -q '"alias" cannot be used in location "/cve15176/longer-prefix/" where URI was rewritten' "${work}/run/error.log" && alias_alert=1
check CVE-2026-15176-ALERT 1 "${alias_alert}" "错误日志记录拒绝映射"

docker exec "${container}" sh -c 'grep -E "\[(error|crit|alert|emerg)\]" /run/waf/error.log | grep -v "client intended to send too large\|cannot be used in location" | tail -5' || true
echo "image=${image} lua_sha256=$(shasum -a 256 "${lua}" | cut -c1-64) failures=${failures}"
[ "${failures}" -eq 0 ]
