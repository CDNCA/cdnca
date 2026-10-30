#!/bin/sh
# G8-b 内存对比：N 个 HTTPS 站点在三种证书形态下的 master/worker 内存，空闲时测一次、对全部 N 个站点
# 做一次校验证书链与主机名的 TLS 握手（容器内 OpenResty cosocket，verify=true）后再测一次。
#   empty           1 个 server（基线）
#   plain           N 个 listen 80 server（无 TLS 对照）
#   tls             N 个 listen 443 ssl，每站独立 ssl_certificate（现状）
#   luaplaceholder  N 个 listen 443 ssl，每站写同一张占位证书 + ssl_certificate_by_lua 按 SNI 读本地文件
#   nativemap       N 个 listen 443 ssl 不写证书；default server 用原生变量证书 + map $ssl_server_name，
#                   ssl_certificate_cache max=N（全部站点都热时的上界）
# 用法：tests/scale/cert-lazy-mem.sh [N] ["模式 ..."]（默认 N=1000）。1 个容器（--rm），用完即删。
set -eu
count=${1:-1000}
modes=${2:-empty plain tls luaplaceholder nativemap}
image=${CDNCA_SCALE_IMAGE:-cdnca-native-runtime:wafdual}
container="cdnca-g8b-certlazy-mem-$$"
work=$(mktemp -d /tmp/cdnca-g8b-certlazy-mem.XXXXXX)
cleanup() {
	docker rm -f "$container" >/dev/null 2>&1 || true
	case "$work" in /tmp/cdnca-g8b-certlazy-mem.*) rm -rf -- "$work" ;; esac
}
trap cleanup EXIT HUP INT TERM
root=/var/tmp/lazymem
repo_root=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
mkdir -p "$work/certs" "$work/conf"
GOWORK=off go run "$repo_root/tests/scale/certgen/main.go" "$work/certs" "$count"
i=0; while [ $i -lt "$count" ]; do cat "$work/certs/$i.crt"; i=$((i + 1)); done >"$work/conf/bundle.pem"
cat >"$work/conf/cert.lua" <<'EOF'
local ssl = require "ngx.ssl"
local name = ssl.server_name()
local id = name and name:match("^s(%d+)%.example$")
if not id then return ngx.exit(ngx.ERROR) end
local function slurp(p) local f = io.open(p); if not f then return nil end; local s = f:read("*a"); f:close(); return s end
local c, k = slurp("/var/tmp/lazymem/certs/" .. id .. ".crt"), slurp("/var/tmp/lazymem/certs/" .. id .. ".key")
if not c or not k then return ngx.exit(ngx.ERROR) end
ssl.clear_certs()
assert(ssl.set_cert(assert(ssl.parse_pem_cert(c))))
assert(ssl.set_priv_key(assert(ssl.parse_pem_priv_key(k))))
EOF
head="worker_processes 1; error_log logs/error.log warn; pid nginx.pid; events { worker_connections 1024; } http { access_log off;"
for mode in $modes; do
	awk -v n="$count" -v mode="$mode" -v root="$root" -v head="$head" 'BEGIN {
		print head
		ph = "ssl_certificate " root "/certs/0.crt; ssl_certificate_key " root "/certs/0.key;"
		lua = "ssl_certificate_by_lua_file " root "/conf/cert.lua;"
		if (mode == "empty") { print "server { listen 80; server_name _; location / { return 200 ok; } }"; print "}"; exit }
		if (mode == "nativemap") {
			printf "map_hash_max_size %d; map $ssl_server_name $lazy_cert { hostnames; default \"\";\n", (n < 1024 ? 2048 : 4 * n)
			for (i = 0; i < n; i++) printf "  s%d.example %s/certs/%d;\n", i, root, i
			print "}"
			print "server { listen 443 ssl default_server; server_name _; ssl_reject_handshake on; ssl_certificate $lazy_cert.crt; ssl_certificate_key $lazy_cert.key;"
			printf "  ssl_certificate_cache max=%d valid=1h; location / { return 421; } }\n", n
		}
		if (mode == "luaplaceholder") print "server { listen 443 ssl default_server; server_name _; " ph " " lua " location / { return 421; } }"
		for (i = 0; i < n; i++) {
			if (mode == "plain") pre = "listen 80;"
			else if (mode == "tls") pre = "listen 443 ssl; ssl_certificate " root "/certs/" i ".crt; ssl_certificate_key " root "/certs/" i ".key;"
			else if (mode == "luaplaceholder") pre = "listen 443 ssl; " ph " " lua
			else pre = "listen 443 ssl;"
			printf "server { %s server_name s%d.example; location / { return 200 \"site=s%d\\n\"; } }\n", pre, i, i
		}
		print "}"
	}' >"$work/conf/$mode.conf"
done
cat >"$work/conf/client.conf" <<EOF
worker_processes 1; error_log $root/client.err warn; pid $root/client.pid; daemon off; master_process off;
events {} http { lua_ssl_trusted_certificate $root/conf/bundle.pem; lua_ssl_verify_depth 1;
init_worker_by_lua_block { ngx.timer.at(0, function()
  local ok, fail, first = 0, 0, nil
  local t0 = ngx.now()
  for i = 0, $count - 1 do
    local sock = ngx.socket.tcp(); sock:settimeout(5000)
    local host = "s" .. i .. ".example"
    local good, err = sock:connect("127.0.0.1", 443)
    if good then good, err = sock:sslhandshake(nil, host, true) end
    if good then
      sock:send("GET / HTTP/1.0\r\nHost: " .. host .. "\r\n\r\n")
      local body = sock:receive("*a") or ""
      if body:find("site=" .. host:match("^s%d+") .. "\n", 1, true) then ok = ok + 1 else good, err = nil, "wrong body" end
    end
    if not good then fail = fail + 1; first = first or (host .. ": " .. tostring(err)) end
    sock:close()
  end
  ngx.update_time()
  ngx.log(ngx.WARN, "HANDSHAKES ok=", ok, " fail=", fail, " seconds=", string.format("%.1f", ngx.now() - t0), " first_fail=", tostring(first))
  os.exit(0) end) } }
EOF
cat >"$work/conf/inner.sh" <<'EOF'
set -eu
bin=/usr/local/openresty/bin/openresty; root=/var/tmp/lazymem
kib() { awk -v k="$2" '$1==k{print $2}' "$1" 2>/dev/null || echo 0; }
snap() { # 阶段 master worker
	echo "\"${1}_master_rss_kib\":$(kib /proc/$2/status VmRSS:),\"${1}_worker_rss_kib\":$(kib /proc/$3/status VmRSS:),\"${1}_worker_pss_kib\":$(kib /proc/$3/smaps_rollup Pss:),\"${1}_cgroup_kib\":$(( $(cat /sys/fs/cgroup/memory.current) / 1024 ))"
}
for mode in $MODES; do
	dir=$root/run/$mode; mkdir -p "$dir/logs"
	if ! "$bin" -p "$dir/" -c "$root/conf/$mode.conf" -t -q 2>"$dir/t.err"; then
		echo "{\"case\":\"$mode\",\"error\":\"$(grep -m1 emerg "$dir/t.err" | tr -d '"')\"}"; continue
	fi
	tcpu=$(sh -c "\"$bin\" -p \"$dir/\" -c \"$root/conf/$mode.conf\" -t -q 2>/dev/null; times" | tail -1 | awk '{print $1 "+" $2}')
	"$bin" -p "$dir/" -c "$root/conf/$mode.conf"
	n=0; while [ ! -s "$dir/nginx.pid" ] && [ $n -lt 3000 ]; do sleep 0.2; n=$((n + 1)); done
	pid=$(cat "$dir/nginx.pid"); sleep 2; worker=""
	for stat in /proc/[0-9]*/stat; do
		set -- $(cat "$stat" 2>/dev/null || true)
		[ "${4:-}" = "$pid" ] && worker=$1 && break
	done
	line="{\"case\":\"$mode\",\"servers\":$N,\"t_cpu_user+sys\":\"$tcpu\",$(snap idle "$pid" "$worker")"
	case $mode in tls|luaplaceholder|nativemap)
		rm -f $root/client.err
		timeout 600 "$bin" -p "$root/" -c "$root/conf/client.conf" 2>/dev/null || true
		hs=$(grep -o 'HANDSHAKES.*' $root/client.err | sed 's/, context.*//')
		sleep 1
		line="$line,\"handshake\":\"$hs\",$(snap after "$pid" "$worker")" ;;
	esac
	echo "$line}"
	errs=$(grep -c -E '\[(alert|emerg|crit|error)\]' "$dir/logs/error.log" || true)
	[ "$errs" = 0 ] || { echo "  error.log $errs 条："; grep -E '\[(alert|emerg|crit|error)\]' "$dir/logs/error.log" | sed -E 's/^[0-9\/ :]+//; s/, client: .*//' | sort | uniq -c | head -3; }
	"$bin" -p "$dir/" -c "$root/conf/$mode.conf" -s stop; sleep 1
done
EOF
chmod -R a+rX "$work"
docker run --detach --rm --name "$container" --cap-add SYS_PTRACE --memory 4g --entrypoint sh "$image" -c 'trap "exit 0" TERM; while :; do sleep 3600; done' >/dev/null
docker exec "$container" mkdir -p $root
docker cp "$work/certs" "$container:$root/certs"
docker cp "$work/conf" "$container:$root/conf"
docker exec "$container" chmod -R a+rX $root
docker exec --env N="$count" --env MODES="$modes" "$container" sh $root/conf/inner.sh
