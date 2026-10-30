#!/bin/sh
# G8-b PoC：同一 443 端口的多个 HTTPS 站点 server 不写证书，能否由 default server 的 SSL_CTX 按 SNI 发证书。
# 3 个站点（a.example、b.example、*.c.example，自签 P-256），逐个形态起真实 OpenResty，宿主机
# openssl s_client -servername 握手（校验证书链与主机名、ALPN、按 SNI 进到哪个 server），并摘出 error.log。
# 形态：
#   luanocert      站点 server 不写证书，default server 挂 ssl_certificate_by_lua（G8-a 的 nocert）
#   luahello       同上，default server 再挂 ssl_client_hello_by_lua
#   luahttp        ssl_certificate_by_lua 写在 http 级（另有一个 listen 80 的站点）
#   luapersite     每个站点 server 挂 ssl_certificate_by_lua，不写证书
#   luaplaceholder 每个站点 server 写同一张占位证书 + ssl_certificate_by_lua（每站仍一个 SSL_CTX）
#   nativemap      站点 server 不写证书；default server 用 nginx 原生变量证书
#                  ssl_certificate $lazy_cert.crt + map $ssl_server_name（hostnames），
#                  ssl_reject_handshake on 拒绝未知/无 SNI；不用 Lua。另测证书文件原子替换后新握手拿新证书。
#   nativemapquic  同 nativemap 再加 listen 443 quic（只看 -t、启动与 TCP 握手；本机无 HTTP/3 客户端）
# 用法：tests/scale/cert-lazy-poc.sh ["形态 ..."]；LAZY_ECHO 追加站点回显内容（如 CDNCA_SCALE_IMAGE=cdnca-native-runtime:g2-ja4
#       LAZY_ECHO=' ja4=$cdnca_ja4' 核对 JA4 在无 SSL_CTX 的站点 server 上仍取得到）。1 个容器（--rm），用完即删。
set -eu
echo_extra=${LAZY_ECHO:-}
variants=${1:-luanocert luahello luahttp luapersite luaplaceholder nativemap nativemapquic}
image=${CDNCA_SCALE_IMAGE:-cdnca-native-runtime:wafdual}
container="cdnca-g8b-certlazy-poc-$$"
work=$(mktemp -d /tmp/cdnca-g8b-certlazy.XXXXXX)
cleanup() {
	docker rm -f "$container" >/dev/null 2>&1 || true
	case "$work" in /tmp/cdnca-g8b-certlazy.*) rm -rf -- "$work" ;; esac
}
trap cleanup EXIT HUP INT TERM
root=/var/tmp/lazy
bin=/usr/local/openresty/bin/openresty
mkdir -p "$work/certs" "$work/conf" "$work/rot"
selfsign() { # 目录 id CN
	openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 30 -subj "/CN=$3" \
		-addext "subjectAltName=DNS:$3" -keyout "$1/$2.key" -out "$1/$2.crt" 2>/dev/null
}
selfsign "$work/certs" a a.example; selfsign "$work/certs" b b.example
selfsign "$work/certs" c '*.c.example'; selfsign "$work/certs" placeholder placeholder.invalid
selfsign "$work/rot" a a.example
cat "$work/certs/a.crt" "$work/certs/b.crt" "$work/certs/c.crt" "$work/rot/a.crt" >"$work/ca.pem"
cat >"$work/conf/cert.lua" <<'EOF'
local ssl = require "ngx.ssl"
local name = ssl.server_name()
local id = name and (({ ["a.example"] = "a", ["b.example"] = "b" })[name] or (name:match("^[^.]+%.c%.example$") and "c"))
ngx.log(ngx.WARN, "CERTCB sni=", tostring(name), " id=", tostring(id))
if not id then return ngx.exit(ngx.ERROR) end
local function slurp(p) local f = assert(io.open(p)); local s = f:read("*a"); f:close(); return s end
assert(ssl.clear_certs())
assert(ssl.set_cert(assert(ssl.parse_pem_cert(slurp("/var/tmp/lazy/certs/" .. id .. ".crt")))))
assert(ssl.set_priv_key(assert(ssl.parse_pem_priv_key(slurp("/var/tmp/lazy/certs/" .. id .. ".key")))))
EOF
gen() {
	v=$1; ph="ssl_certificate $root/certs/placeholder.crt; ssl_certificate_key $root/certs/placeholder.key;"
	lua="ssl_certificate_by_lua_file $root/conf/cert.lua;"
	http=""; def="$ph $lua"; site=""; dq=""; sq=""; extra=""
	case $v in
	luanocert) ;;
	luahello) def="$def ssl_client_hello_by_lua_block { ngx.log(ngx.WARN, \"HELLO\") }" ;;
	luahttp) http=$lua; def=$ph; extra="server { listen 80; server_name plain.example; location / { return 200 plain; } }" ;;
	luapersite) site=$lua ;;
	luaplaceholder) site="$ph $lua" ;;
	nativemap | nativemapquic)
		http="map \$ssl_server_name \$lazy_cert { hostnames; default \"\"; a.example $root/certs/a; b.example $root/certs/b; *.c.example $root/certs/c; }"
		def="ssl_reject_handshake on; ssl_certificate \$lazy_cert.crt; ssl_certificate_key \$lazy_cert.key; ssl_certificate_cache max=1000 valid=2s;"
		if [ "$v" = nativemapquic ]; then dq=" listen 443 quic reuseport;"; sq=" listen 443 quic;"; fi ;;
	*) echo "未知形态 $v" >&2; exit 64 ;;
	esac
	{
		echo "worker_processes 1; error_log logs/error.log info; pid nginx.pid; events { worker_connections 1024; }"
		echo "http { access_log off; $http"
		echo "server { listen 443 ssl default_server;$dq server_name _; $def location / { return 421; } }"
		for s in a b c; do
			n=$s.example; [ $s = c ] && n='*.c.example'
			echo "server { listen 443 ssl;$sq http2 on; server_name $n; $site location / { return 200 \"site=$s sni=\$ssl_server_name$echo_extra\\n\"; } }"
		done
		echo "$extra }"
	} >"$work/conf/$v.conf"
}
for v in $variants; do gen "$v"; done

docker run --detach --rm --name "$container" -p 127.0.0.1::443 --entrypoint sh "$image" -c 'trap "exit 0" TERM; while :; do sleep 3600; done' >/dev/null
docker exec "$container" mkdir -p $root
docker cp "$work/certs" "$container:$root/certs"
docker cp "$work/conf" "$container:$root/conf"
docker cp "$work/rot" "$container:$root/rot"
docker exec "$container" sh -c "chmod -R a+rX $root && cp -a $root/certs $root/orig"
port=$(docker port "$container" 443/tcp | head -1 | sed 's/.*://')
echo "image=$image $(docker exec "$container" $bin -v 2>&1 | head -1)"

probe() { # 主机名（nosni = 不发 SNI）
	h=$1; set -- -servername "$h"; [ "$h" = nosni ] && set -- -noservername
	out=$(printf 'GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n' "$h" | openssl s_client -connect "127.0.0.1:$port" "$@" \
		-CAfile "$work/ca.pem" -verify_hostname "$h" -verify_return_error -alpn http/1.1 -ign_eof 2>&1 || true)
	alpn=$(openssl s_client -connect "127.0.0.1:$port" "$@" -alpn h2,http/1.1 </dev/null 2>&1 | sed -n 's/^ALPN protocol: //p' | head -1)
	body=$(printf '%s\n' "$out" | grep -o 'site=[a-z] sni=.*' | head -1)
	if [ -n "$body" ]; then
		echo "  $h: OK $(printf '%s\n' "$out" | grep -m1 '^subject=') | $(printf '%s\n' "$out" | grep -m1 'Verify return code') | alpn=$alpn | $body"
	else
		echo "  $h: FAIL $(printf '%s\n' "$out" | grep -m1 -i -E 'alert|error|errno|Verify return code: [1-9]' | sed 's/^[0-9A-F]*:error://')"
	fi
}
fingerprint() { openssl s_client -connect "127.0.0.1:$port" -servername a.example </dev/null 2>/dev/null | openssl x509 -noout -fingerprint -sha256 2>/dev/null | sed 's/.*=//' | cut -c1-23; }

for v in $variants; do
	echo "== $v"
	d=$root/run/$v
	docker exec "$container" sh -c "mkdir -p $d/logs && cp $root/orig/* $root/certs/"
	if ! docker exec "$container" $bin -p "$d/" -c "$root/conf/$v.conf" -t >"$work/t.out" 2>&1; then
		echo "  nginx -t 失败：$(grep -E 'emerg|alert' "$work/t.out" | head -2 | sed 's/^.*\[/[/')"; continue
	fi
	docker exec "$container" $bin -p "$d/" -c "$root/conf/$v.conf"
	sleep 1
	for h in a.example b.example x.c.example nosuch.example nosni; do probe $h; done
	if [ "${v#nativemap}" != "$v" ]; then
		before=$(fingerprint)
		docker exec "$container" sh -c "cp $root/rot/a.key $root/certs/a.key.new && cp $root/rot/a.crt $root/certs/a.crt.new && mv $root/certs/a.key.new $root/certs/a.key && mv $root/certs/a.crt.new $root/certs/a.crt"
		sleep 3
		echo "  轮换 a.example：替换前 $before… 替换后 $(fingerprint)…（新证书 $(openssl x509 -in "$work/rot/a.crt" -noout -fingerprint -sha256 | sed 's/.*=//' | cut -c1-23)…）"
	fi
	echo "  error.log："
	docker exec "$container" sh -c "grep -E '\[(alert|emerg|crit|error)\]|CERTCB|HELLO|SSL_do_handshake' $d/logs/error.log | sed -E 's/^[0-9\/ :]+//; s/, client: .*//; s/^\[[a-z]+\] [0-9#]+: \*[0-9]+ //' | sort | uniq -c | head -8"
	docker exec "$container" $bin -p "$d/" -c "$root/conf/$v.conf" -s stop
	sleep 1
done
