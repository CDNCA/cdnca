#!/usr/bin/env bash
# install-site.sh 容器验收（宿主机运行，需要 docker）。Ubuntu 24.04 容器里装 nginx，用测试证书跑
# install-site.sh install，市场卖家接口用 python TLS 替身（证书 my.example.test，回显 Host/Origin/XFF）。核对：
#   - www 托管官网、裸域 301 到 www、卖家站静态回退 index.html、安全头与缓存头；
#   - /seller/v1 经 TLS 反代到市场：校验市场证书名，Host/Origin 原样，X-Forwarded-For 覆盖为单个客户端地址；
#   - 官网 /public/v1 经 TLS 反代到市场公开监听（8443 替身）：只放行 GET/HEAD，Host 改为市场名，
#     丢弃 Cookie/Authorization，XFF 覆盖为单个访客地址；
#   - 官网 /public/v1/site-content 经 TLS 反代到授权端（8444 替身，证书 auth.example.test）：只放行 GET/HEAD，
#     Host 改为授权端名，丢弃 Cookie/Authorization/Origin、上游 Set-Cookie；授权端证书来自别的 CA 时 502；
#   - 市场证书名不对（--market-host 改成别的）或 CA 不对时 502，不会把请求发给假冒的市场；
#   - check 子命令通过；重复运行幂等；参数校验拒绝错误组合。
# 域名用测试值，不写死生产域名；不连任何真实服务器。KEEP=1 保留容器。
set -Eeuo pipefail
REPO=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
C=cdnca-site-$$
FAILED=0
cleanup() { [ "${KEEP:-0}" = 1 ] || docker rm -f "$C" >/dev/null 2>&1 || true; }
trap cleanup EXIT
expect() {
  local want=$1; shift
  printf '\n$ %s\n' "$*"
  set +e; docker exec "$C" bash -c "$*" 2>&1; local got=$?; set -e
  printf '（退出码 %s，期望 %s）\n' "$got" "$want"
  [ "$got" = "$want" ] || { printf '!!!! 不符合预期\n'; FAILED=1; }
}
command -v docker >/dev/null || { echo 'SKIP: docker is not available'; exit 0; }
docker run -d --name "$C" ubuntu:24.04 sleep infinity >/dev/null
docker exec "$C" bash -c 'apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends nginx openssl curl python3 ca-certificates iproute2 >/dev/null'
docker cp "$REPO/scripts/install-site.sh" "$C:/root/install-site.sh"
docker exec -i "$C" bash -s <<'SETUP'
set -e
mkdir -p /root/pki /root/www/assets /root/seller/assets
cd /root/pki
ca() { openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 30 -subj "/CN=$1" -keyout "$1.key" -out "$1.pem" 2>/dev/null; }
leaf() { # name san [ca]
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj "/CN=$1" -keyout "$1.key" -out "$1.csr" 2>/dev/null
  printf 'subjectAltName=%s\nextendedKeyUsage=serverAuth\n' "$2" >"$1.ext"
  openssl x509 -req -in "$1.csr" -CA "${3:-ca}.pem" -CAkey "${3:-ca}.key" -CAcreateserial -days 30 -extfile "$1.ext" -out "$1.pem" 2>/dev/null
}
ca ca; ca rogue
leaf site DNS:example.test,DNS:www.example.test
leaf seller DNS:developer.example.test
leaf market DNS:my.example.test
leaf fake DNS:my.example.test rogue
leaf auth DNS:auth.example.test
leaf fakeauth DNS:auth.example.test rogue
printf '<!doctype html><title>www</title>\n' >/root/www/index.html
printf '<!doctype html><title>docs</title>\n' >/root/www/docs.html
printf '<!doctype html><title>seller</title>\n' >/root/seller/index.html
printf 'console.log(1)\n' >/root/seller/assets/index-ab.js
mkdir -p /root/seller/downloads/cdnca-plugin /root/seller/downloads/dev-kit
printf 'bin\n' >/root/seller/downloads/cdnca-plugin/cdnca-plugin-linux-amd64
(cd /root/seller/downloads/cdnca-plugin && sha256sum cdnca-plugin-linux-amd64 >SHA256SUMS)
printf 'kit\n' >/root/seller/downloads/dev-kit/cdnca-dev-kit.tar.gz; printf '{}\n' >/root/seller/downloads/dev-kit/dev-kit.manifest.json
(cd /root/seller/downloads/dev-kit && sha256sum cdnca-dev-kit.tar.gz dev-kit.manifest.json >SHA256SUMS)
# 市场卖家接口替身：TLS（证书由参数指定），回显 Host/Origin/XFF/Proto 与路径。
cat >/root/market.py <<'PY'
import http.server, ssl, sys
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self): self.reply()
    def do_POST(self): self.reply()
    def reply(self):
        h = self.headers
        body = ('{"path":"%s","host":"%s","origin":"%s","xff":"%s","proto":"%s","cookie":"%s","auth":"%s"}' % (self.path, h.get('Host'),
            h.get('Origin'), ','.join(h.get_all('X-Forwarded-For') or []), h.get('X-Forwarded-Proto'), h.get('Cookie'),
            h.get('Authorization'))).encode()
        self.send_response(200); self.send_header('Content-Type', 'application/json')
        self.send_header('Set-Cookie', 'upstream=1'); self.send_header('X-Origin-Seen', h.get('Origin') or 'None')
        self.send_header('X-Rid-Seen', h.get('X-Request-ID') or 'None'); self.send_header('X-Request-ID', h.get('X-Request-ID') or 'upstream')
        self.send_header('Content-Length', str(len(body))); self.end_headers(); self.wfile.write(body)
    def log_message(self, *a): pass
s = http.server.ThreadingHTTPServer(('127.0.0.1', int(sys.argv[1])), H)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain('/root/pki/%s.pem' % sys.argv[2], '/root/pki/%s.key' % sys.argv[2])
s.socket = ctx.wrap_socket(s.socket, server_side=True)
s.serve_forever()
PY
(setsid python3 /root/market.py 9445 market </dev/null >/dev/null 2>&1 &)
(setsid python3 /root/market.py 9446 fake </dev/null >/dev/null 2>&1 &)
(setsid python3 /root/market.py 8443 market </dev/null >/dev/null 2>&1 &)
(setsid python3 /root/market.py 8444 auth </dev/null >/dev/null 2>&1 &)
(setsid python3 /root/market.py 8445 fakeauth </dev/null >/dev/null 2>&1 &)
cat >/usr/local/bin/systemctl <<'STUB'
#!/bin/sh
case "$*" in
  *is-active*nginx*) pgrep -x nginx >/dev/null ;;
  *reload*nginx*) nginx -s reload ;;
  *enable*nginx*|*start*nginx*) nginx ;;
  *) exit 0 ;;
esac
STUB
chmod +x /usr/local/bin/systemctl
sleep 1
SETUP
args='--www-dir /root/www --seller-dir /root/seller --site-domain example.test --seller-domain developer.example.test --market-host my.example.test --market-ip 127.0.0.1 --market-ca /root/pki/ca.pem --auth-host auth.example.test --auth-ip 127.0.0.1 --auth-port 8444 --auth-ca /root/pki/ca.pem --site-cert /root/pki/site.pem --site-key /root/pki/site.key --seller-cert /root/pki/seller.pem --seller-key /root/pki/seller.key --yes'
c='curl -sS --max-time 5 --cacert /root/pki/ca.pem --resolve example.test:443:127.0.0.1 --resolve www.example.test:443:127.0.0.1 --resolve developer.example.test:443:127.0.0.1 --resolve developer.example.test:80:127.0.0.1'
printf '\n==== 安装（提供证书），check 通过\n'
expect 0 "bash /root/install-site.sh install $args && nginx -t && cat /etc/cdnca/site/site.env"
printf '\n==== 官网：www 托管，裸域 301 到 www，页面路由回退 index.html\n'
expect 0 "$c https://www.example.test/ | grep -q '<title>www</title>'"
expect 0 "$c https://www.example.test/docs | grep -q '<title>docs</title>'"
expect 0 "$c -o /dev/null -w '%{http_code} %{redirect_url}' https://example.test/a?b=1 | grep -q '^301 https://www.example.test/a?b=1'"
expect 0 "$c -I https://www.example.test/ | grep -qi '^content-security-policy:'"
printf '\n==== 卖家站：静态与回退、缓存头；80 跳 443\n'
expect 0 "$c https://developer.example.test/plugins/abc | grep -q '<title>seller</title>'"
expect 0 "$c https://developer.example.test/downloads/dev-kit/SHA256SUMS | grep -q ' dev-kit.manifest.json\$'"
expect 0 "$c -o /dev/null -w '%{http_code}' https://developer.example.test/downloads/dev-kit/missing.tar.gz | grep -q '^404'"
expect 1 "rm -rf /tmp/s2 && cp -R /root/seller /tmp/s2 && rm /tmp/s2/downloads/dev-kit/cdnca-dev-kit.tar.gz && bash /root/install-site.sh install ${args/--seller-dir \/root\/seller /--seller-dir /tmp/s2 }"
expect 0 "$c -I https://developer.example.test/assets/index-ab.js | grep -qi '^cache-control: public, max-age=31536000, immutable'"
expect 0 "$c -I https://developer.example.test/ | grep -qi '^cache-control: no-store'"
expect 0 "$c https://developer.example.test/downloads/cdnca-plugin/SHA256SUMS | grep -q 'cdnca-plugin-linux-amd64'"
expect 0 "$c -o /dev/null -w '%{http_code}' https://developer.example.test/downloads/cdnca-plugin/missing | grep -q '^404'"
expect 0 "$c -o /dev/null -w '%{http_code} %{redirect_url}' http://developer.example.test/x | grep -q '^301 https://developer.example.test/x'"
printf '\n==== /seller/v1 反代：Host/Origin 原样，XFF 覆盖为单个客户端地址（客户端自带的链被丢弃），无缓存头覆盖\n'
expect 0 "$c -X POST -H 'Origin: https://developer.example.test' -H 'X-Forwarded-For: 203.0.113.9, 10.0.0.1' https://developer.example.test/seller/v1/session | tee /dev/stderr | grep -qF '\"path\":\"/seller/v1/session\",\"host\":\"developer.example.test\",\"origin\":\"https://developer.example.test\",\"xff\":\"127.0.0.1\",\"proto\":\"https\"'"
expect 0 "ip=\$(hostname -I | awk '{print \$1}'); curl -sS --max-time 5 --interface \$ip --cacert /root/pki/ca.pem --resolve developer.example.test:443:\$ip https://developer.example.test/seller/v1/site | tee /dev/stderr | grep -qF \"\\\"xff\\\":\\\"\$ip\\\"\""
expect 0 "h=\$($c -D - -o /dev/null https://developer.example.test/seller/v1/site) && ! printf '%s' \"\$h\" | grep -qi '^cache-control:'"
printf '\n==== /seller/v1 关联号：客户端伪造的 X-Request-ID 被本机 $request_id 覆盖，响应只有一个且与上游收到的相同，并写入访问日志\n'
expect 0 "h=\$($c -D - -o /dev/null -H 'X-Request-ID: forged-by-client' https://developer.example.test/seller/v1/site) && [ \$(printf '%s' \"\$h\" | grep -ci '^x-request-id:') = 1 ] && rid=\$(printf '%s' \"\$h\" | awk -F': ' 'tolower(\$1)==\"x-request-id\"{print \$2}' | tr -d '\\r') && printf '%s' \"\$h\" | grep -qi \"^x-rid-seen: \$rid\" && printf '%s' \"\$rid\" | grep -Eq '^[0-9a-f]{32}\$' && grep -q \"request_id=\$rid\" /var/log/nginx/cdnca-seller-api.log"
printf '\n==== 官网 /public/v1 反代到市场公开监听：Host 为市场名，Cookie/Authorization 丢弃，XFF 单值；写方法拒绝\n'
expect 0 "$c -H 'Cookie: s=1' -H 'Authorization: Bearer x' -H 'X-Forwarded-For: 203.0.113.9' 'https://www.example.test/public/v1/node-offers?limit=1' | tee /dev/stderr | grep -qF '\"path\":\"/public/v1/node-offers?limit=1\",\"host\":\"my.example.test\",\"origin\":\"None\",\"xff\":\"127.0.0.1\",\"proto\":\"https\",\"cookie\":\"None\",\"auth\":\"None\"'"
expect 0 "$c -o /dev/null -w '%{http_code}' -X POST https://www.example.test/public/v1/node-offers | grep -q '^403'"
expect 0 "$c https://developer.example.test/public/v1/node-offers | grep -q '<title>seller</title>'"
printf '\n==== 官网插件签名目录（公钥文档、快照、清单）只读反代到市场公开监听：Host 为市场名，Cookie 丢弃，不追加 no-store；写方法拒绝\n'
expect 0 "$c -H 'Cookie: s=1' https://www.example.test/.well-known/cdnca/plugin-catalog-key-v1.json | grep -qF '\"path\":\"/.well-known/cdnca/plugin-catalog-key-v1.json\",\"host\":\"my.example.test\"'"
expect 0 "$c https://www.example.test/.well-known/cdnca/plugin-catalog-v1.json | grep -qF '\"host\":\"my.example.test\",\"origin\":\"None\",\"xff\":\"127.0.0.1\",\"proto\":\"https\",\"cookie\":\"None\"'"
expect 0 "$c https://www.example.test/catalog/v1/manifests/acme.dev.forwarder/1.0.0/manifest.json | grep -qF '\"host\":\"my.example.test\"'"
expect 0 "h=\$($c -D - -o /dev/null https://www.example.test/.well-known/cdnca/plugin-catalog-v1.json) && ! printf '%s' \"\$h\" | grep -qi '^cache-control: no-store'"
expect 0 "$c -o /dev/null -w '%{http_code}' -X POST https://www.example.test/.well-known/cdnca/plugin-catalog-v1.json | grep -q '^403'"
printf '\n==== 官网 /public/v1/site-content 反代到授权端：Host 为授权端名，Cookie/Authorization/Origin 与上游 Set-Cookie 丢弃；写方法拒绝\n'
expect 0 "$c -H 'Cookie: s=1' -H 'Authorization: Bearer x' -H 'Origin: https://evil.example' 'https://www.example.test/public/v1/site-content' | tee /dev/stderr | grep -qF '\"path\":\"/public/v1/site-content\",\"host\":\"auth.example.test\",\"origin\":\"None\",\"xff\":\"127.0.0.1\",\"proto\":\"https\",\"cookie\":\"None\",\"auth\":\"None\"'"
expect 0 "$c 'https://www.example.test/public/v1/site-content/assets/$(printf 'a%.0s' $(seq 64))' | grep -qF '\"host\":\"auth.example.test\"'"
expect 0 "h=\$($c -D - -o /dev/null https://www.example.test/public/v1/site-content) && ! printf '%s' \"\$h\" | grep -qi '^set-cookie:'"
expect 0 "$c -o /dev/null -w '%{http_code}' -X POST https://www.example.test/public/v1/site-content | grep -q '^403'"
expect 0 "$c 'https://www.example.test/public/v1/node-offers?limit=1' | grep -qF '\"host\":\"my.example.test\"'"
expect 0 "bash /root/install-site.sh check"
printf '\n==== 假冒授权端（证书来自别的 CA）：官网内容 502，check 不通过\n'
expect 0 "bash /root/install-site.sh install $args --auth-port 8445 >/dev/null 2>&1; $c -o /dev/null -w '%{http_code}' https://www.example.test/public/v1/site-content | grep -q '^502'"
expect 3 "bash /root/install-site.sh check"
expect 0 "bash /root/install-site.sh install $args >/dev/null 2>&1"
printf '\n==== 假冒市场（证书来自别的 CA）：502，不转发\n'
expect 0 "bash /root/install-site.sh install $args --market-port 9446 >/dev/null 2>&1; $c -o /dev/null -w '%{http_code}' https://developer.example.test/seller/v1/site | grep -q '^502'"
expect 0 "h=\$($c -D - -o /dev/null https://developer.example.test/seller/v1/site) && printf '%s' \"\$h\" | grep -Eqi '^x-request-id: [0-9a-f]{32}'"
expect 3 "bash /root/install-site.sh check"
printf '\n==== 市场证书名不对（--market-host 与证书不符）：502\n'
expect 0 "bash /root/install-site.sh install $args --market-host other.example.test >/dev/null 2>&1; $c -o /dev/null -w '%{http_code}' https://developer.example.test/seller/v1/site | grep -q '^502'"
printf '\n==== 改回正确参数，幂等重跑\n'
expect 0 "bash /root/install-site.sh install $args >/dev/null && bash /root/install-site.sh install $args >/dev/null && [ \$(ls /etc/nginx/conf.d | wc -l) = 1 ] && $c https://developer.example.test/seller/v1/site | grep -q '\"xff\":\"127.0.0.1\"'"
printf '\n==== 参数校验\n'
expect 1 "bash /root/install-site.sh install $args --seller-domain www.example.test"
expect 1 "bash /root/install-site.sh install $args --market-port 70000"
expect 1 "bash /root/install-site.sh install $args --market-public-port 9445"
expect 1 "bash /root/install-site.sh install $args --auth-port 0"
expect 1 "bash /root/install-site.sh install $args --auth-host 'bad host'"
expect 1 "bash /root/install-site.sh install $args --auth-ca /root/nope.pem"
expect 1 "bash /root/install-site.sh install --www-dir /root/nope --seller-dir /root/seller --yes"
expect 1 "bash /root/install-site.sh install $args --site-cert /root/pki/site.pem --site-key ''"
printf '\n结果：%s\n' "$([ "$FAILED" = 0 ] && echo 全部符合预期 || echo 有不符合预期的步骤)"
exit "$FAILED"
