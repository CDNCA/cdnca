#!/bin/sh
# 拆分 server{} 与证书的内存成本，并验证 G8-b 形态（按 SNI 动态证书）可用。
# 在真实 OpenResty 里起 N 个最小 server，各模式分别测 master/worker 的 VmRSS 与 Pss：
#   empty   1 个 server（基线）
#   plain   N 个 listen 80 + server_name + return
#   tls     N 个 listen 443 ssl，每站独立证书（每个 server 一个 SSL_CTX，现状）
#   tlsone  N 个 listen 443 ssl，共用同一张证书文件（SSL_CTX 仍每站一个）
#   dynamic N 个 listen 80 server + 1 个 443 server，ssl_certificate_by_lua_block 按 SNI
#           从证书目录读取，并对首、中、末站点发真实 TLS 请求核对证书 CN。
#   nocert  N 个 listen 443 ssl 站点 server（不写 ssl_certificate）+ 1 个 default_server 用
#           ssl_certificate_by_lua 发证书（G8-b 形态：每站 server 保留，SSL_CTX 只有一个）；
#           TLS 请求核对是否按 SNI 进到了各站自己的 server。
#   nocertquic  同 nocert，再加 listen 443 quic（只测 -t 与内存）。
# 第二个参数可只跑部分模式，如 "nocert nocertquic"。
# 用法：tests/scale/server-cost.sh [N] [模式...]（默认 N=2000）。1 个容器，用完即删；证书由 certgen 在宿主机生成后拷入。
set -eu
count=${1:-2000}
modes=${2:-empty plain tls tlsone dynamic nocert nocertquic}
image=${CDNCA_SCALE_IMAGE:-cdnca-native-runtime:wafdual}
container="cdnca-g8a-scale-cost-$$"
certs=$(mktemp -d /tmp/cdnca-g8a-scale-certs.XXXXXX)
cleanup() {
	docker rm -f "$container" >/dev/null 2>&1 || true
	case "$certs" in /tmp/cdnca-g8a-scale-certs.*) rm -rf -- "$certs" ;; esac
}
trap cleanup EXIT HUP INT TERM

repo_root=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
GOWORK=off go run "$repo_root/tests/scale/certgen/main.go" "$certs" "$count"
chmod 755 "$certs"

docker run --detach --name "$container" --cap-add SYS_PTRACE --memory 4g --entrypoint sh "$image" -c 'trap "exit 0" TERM; while :; do sleep 3600; done' >/dev/null
docker exec "$container" mkdir -p /var/tmp/cost
docker cp "$certs" "$container:/var/tmp/cost/certs"
docker exec "$container" chmod -R a+rX /var/tmp/cost
docker exec --env N="$count" --env MODES="$modes" "$container" sh -c '
set -eu
bin=/usr/local/openresty/bin/openresty
root=/var/tmp/cost
# 最后一个支持 TLS 校验的模式保持运行，供下面的客户端检查。
KEEP=""; for m in $MODES; do case $m in dynamic|nocert) KEEP=$m ;; esac; done
kib() { awk -v k="$2" "\$1==k{print \$2}" "$1" 2>/dev/null || echo 0; }
measure() {
	name=$1; dir=$root/$name; mkdir -p "$dir/logs"
	start=$(date +%s)
	if ! "$bin" -p "$dir/" -c "$dir/nginx.conf" -t -q 2>"$dir/t.err"; then
		echo "{\"case\":\"$name\",\"error\":\"$(tail -1 "$dir/t.err" | tr -d \"\\\"\")\"}"; return
	fi
	"$bin" -p "$dir/" -c "$dir/nginx.conf"
	n=0; while [ ! -s "$dir/nginx.pid" ] && [ $n -lt 3000 ]; do sleep 0.2; n=$((n + 1)); done
	pid=$(cat "$dir/nginx.pid"); sleep 2
	worker=""
	for stat in /proc/[0-9]*/stat; do
		set -- $(cat "$stat" 2>/dev/null || true)
		[ "${4:-}" = "$pid" ] && worker=$1 && break
	done
	ready=$(( $(date +%s) - start ))
	echo "{\"case\":\"$name\",\"servers\":$N,\"ready_seconds\":$ready,\"master_rss_kib\":$(kib /proc/$pid/status VmRSS:),\"master_pss_kib\":$(kib /proc/$pid/smaps_rollup Pss:),\"worker_rss_kib\":$(kib /proc/$worker/status VmRSS:),\"worker_pss_kib\":$(kib /proc/$worker/smaps_rollup Pss:),\"cgroup_kib\":$(( $(cat /sys/fs/cgroup/memory.current) / 1024 ))}"
	[ "$name" = "$KEEP" ] || "$bin" -p "$dir/" -c "$dir/nginx.conf" -s stop
	sleep 1
}
head="worker_processes 1; error_log logs/error.log warn; pid nginx.pid; events { worker_connections 1024; } http { access_log off;"
gen() {
	mode=$1; dir=$root/$mode; mkdir -p "$dir"
	{
		echo "$head"
		case $mode in
		empty) echo "server { listen 80; server_name _; location / { return 200 ok; } }" ;;
		nocert|nocertquic)
			quic=""; [ $mode = nocertquic ] && quic=" listen 443 quic reuseport;"
			echo "server { listen 443 ssl default_server;$quic server_name _; ssl_certificate $root/certs/0.crt; ssl_certificate_key $root/certs/0.key;"
			echo "  ssl_certificate_by_lua_block {"
			echo "    local ssl = require \"ngx.ssl\"; local name = ssl.server_name(); local i = name and name:match(\"^s(%d+)%.example\$\")"
			echo "    if not i then return ngx.exit(ngx.ERROR) end"
			echo "    local f = io.open(\"$root/certs/\" .. i .. \".crt\"); if not f then return ngx.exit(ngx.ERROR) end; local c = f:read(\"*a\"); f:close()"
			echo "    f = io.open(\"$root/certs/\" .. i .. \".key\"); local k = f:read(\"*a\"); f:close()"
			echo "    ssl.clear_certs(); assert(ssl.set_der_cert(ssl.cert_pem_to_der(c))); assert(ssl.set_der_priv_key(ssl.priv_key_pem_to_der(k)))"
			echo "  }"
			echo "  location / { return 421; } }"
			q=""; [ $mode = nocertquic ] && q=" listen 443 quic;"
			i=0; while [ $i -lt $N ]; do echo "server { listen 443 ssl;$q server_name s$i.example; location / { return 200 \"site=s$i sni=\$ssl_server_name\"; } }"; i=$((i + 1)); done ;;
		dynamic)
			i=0; while [ $i -lt $N ]; do echo "server { listen 80; server_name s$i.example; location / { return 200 ok; } }"; i=$((i + 1)); done
			echo "server { listen 443 ssl default_server; server_name _; ssl_certificate $root/certs/0.crt; ssl_certificate_key $root/certs/0.key;"
			echo "  ssl_certificate_by_lua_block {"
			echo "    local ssl = require \"ngx.ssl\"; local name = ssl.server_name(); local i = name and name:match(\"^s(%d+)%.example\$\")"
			echo "    if not i then return ngx.exit(ngx.ERROR) end"
			echo "    local f = io.open(\"$root/certs/\" .. i .. \".crt\"); if not f then return ngx.exit(ngx.ERROR) end; local c = f:read(\"*a\"); f:close()"
			echo "    f = io.open(\"$root/certs/\" .. i .. \".key\"); local k = f:read(\"*a\"); f:close()"
			echo "    ssl.clear_certs(); assert(ssl.set_der_cert(ssl.cert_pem_to_der(c))); assert(ssl.set_der_priv_key(ssl.priv_key_pem_to_der(k)))"
			echo "  }"
			echo "  location / { return 200 \"sni=\$ssl_server_name\"; } }" ;;
		*)
			i=0; while [ $i -lt $N ]; do
				case $mode in
				plain) echo "server { listen 80; server_name s$i.example; location / { return 200 ok; } }" ;;
				tls) echo "server { listen 443 ssl; server_name s$i.example; ssl_certificate $root/certs/$i.crt; ssl_certificate_key $root/certs/$i.key; location / { return 200 ok; } }" ;;
				tlsone) echo "server { listen 443 ssl; server_name s$i.example; ssl_certificate $root/certs/0.crt; ssl_certificate_key $root/certs/0.key; location / { return 200 ok; } }" ;;
				esac
				i=$((i + 1))
			done ;;
		esac
		echo "}"
	} >"$dir/nginx.conf"
}
for mode in $MODES; do gen $mode; measure $mode; done
'
# 动态证书正确性：容器内用 OpenResty cosocket 对首、中、末站点做 TLS 握手，核对 SNI 回显。
docker exec --env N="$count" "$container" sh -c '
cat >/var/tmp/cost/client.conf <<EOF
worker_processes 1; error_log /var/tmp/cost/client.err warn; pid /var/tmp/cost/client.pid; daemon off; master_process off;
events {} http { init_worker_by_lua_block { ngx.timer.at(0, function()
  for _, i in ipairs({0, math.floor($N / 2), $N - 1}) do
    local sock = ngx.socket.tcp(); sock:settimeout(5000)
    assert(sock:connect("127.0.0.1", 443))
    local session, err = sock:sslhandshake(nil, "s" .. i .. ".example", false)
    if not session then ngx.log(ngx.ERR, "TLSCHECK site ", i, " handshake failed: ", err) else
      sock:send("GET / HTTP/1.0\r\nHost: s" .. i .. ".example\r\n\r\n"); local body = sock:receive("*a") or ""
      ngx.log(ngx.WARN, "TLSCHECK site ", i, " ok body=", body:match("site=%S+ sni=[%w%.]+") or body:match("sni=[%w%.]+") or "?") end
    sock:close()
  end
  os.exit(0) end) } }
EOF
timeout 60 /usr/local/openresty/bin/openresty -p /var/tmp/cost/ -c /var/tmp/cost/client.conf 2>/dev/null || true
grep -o "TLSCHECK.*" /var/tmp/cost/client.err | sed "s/, context.*//"
'
