#!/bin/sh
# Runs inside the node runtime container (see run.sh). Prints one result
# line per check: "RESULT <name> <data>".
set -u
B=/pocbin
mkdir -p /tmp/poc/logs /run/cdnca /plugins
chown nobody /run/cdnca
cp /pocbin/plugin.wasm /plugins/plugin.wasm

start_host() {
  rm -f /run/cdnca/plugin.sock
  su -s /bin/sh nobody -c "$B/host -socket /run/cdnca/plugin.sock -plugin /plugins/plugin.wasm \
    -pool 8 -timeout 20ms -memory-mib 64 >>/run/cdnca/host.log 2>&1 &"
  for _ in $(seq 1 50); do [ -S /run/cdnca/plugin.sock ] && return 0; sleep 0.1; done
  echo "host did not start"; cat /run/cdnca/host.log; return 1
}
hdr() { wget -S -q -O /dev/null "http://127.0.0.1:8080$1" 2>&1 | awk -v h="$2" 'tolower($1)==tolower(h)":"{print $2}' | tr -d '\r'; }
code() { wget -S -q -O /dev/null "http://127.0.0.1:8080$1" 2>&1 | awk '$1 ~ /^HTTP\//{print $2}' | tail -1; }
stats() { wget -q -O - http://127.0.0.1:8080/stats; }
bench() { $B/bench -url "http://127.0.0.1:8080$1" -n "$2" -c "$3"; }

/usr/local/openresty/nginx/sbin/nginx -V 2>&1 | head -1
/usr/local/openresty/nginx/sbin/nginx -p /tmp/poc -c /poc/nginx.conf || { cat /tmp/poc/error.log; exit 1; }
sleep 0.5

# ---- load
t0=$(date +%s%N); start_host; t1=$(date +%s%N)
echo "RESULT load_ms $(( (t1 - t0) / 1000000 )) $(grep 'plugin loaded' /run/cdnca/host.log | tail -1 | sed 's/.*plugin loaded: //')"
echo "RESULT host_rss_kib_after_load $(ps -o rss= -p "$(pgrep -f "$B/host")" 2>/dev/null || awk '/VmRSS/{print $2}' /proc/$(pgrep -f "$B/host")/status)"
echo "RESULT allow header=$(hdr /p/hello x-plugin-seen) x-plugin=$(hdr /p/hello x-plugin)"
echo "RESULT deny status=$(code /p/deny)"

# ---- latency: baseline vs plugin
echo "RESULT bench_base $(bench /base 20000 16)"
echo "RESULT bench_plugin $(bench /p/hello 20000 16)"

# ---- timeout: /loop spins; the call must end at the deadline and the next
# request must be served normally.
echo "RESULT loop status=$(code /p/loop) x-plugin=$(hdr /p/loop x-plugin)"
echo "RESULT after_loop x-plugin=$(hdr /p/hello x-plugin)"
# loop flood mixed with normal traffic
($B/bench -url http://127.0.0.1:8080/p/loop -n 200 -c 4 > /tmp/poc/loopflood.txt) &
echo "RESULT bench_plugin_during_loop_flood $(bench /p/hello 5000 16)"
wait
echo "RESULT loop_flood $(cat /tmp/poc/loopflood.txt)"

# ---- trap
echo "RESULT trap x-plugin=$(hdr /p/trap x-plugin)"
echo "RESULT after_trap x-plugin=$(hdr /p/hello x-plugin)"

# ---- memory cap (64 MiB linear memory)
echo "RESULT stats_before_oom $(stats)"
echo "RESULT oom x-plugin=$(hdr /p/oom x-plugin)"
sleep 0.3
echo "RESULT stats_after_oom $(stats)"
echo "RESULT after_oom x-plugin=$(hdr /p/hello x-plugin)"
echo "RESULT host_rss_kib_after_oom $(awk '/VmRSS/{print $2}' /proc/$(pgrep -f "$B/host")/status)"
echo "RESULT stats $(stats)"

# ---- crash isolation: kill -9 the host; nginx keeps serving (fail open)
nginx_workers_before=$(pgrep -f 'nginx: worker' | sort | tr '\n' ' ')
pkill -9 -f "$B/host"; sleep 0.2
echo "RESULT host_killed status=$(code /p/hello) x-plugin=$(hdr /p/hello x-plugin)"
echo "RESULT bench_host_down $(bench /p/hello 5000 16)"
nginx_workers_after=$(pgrep -f 'nginx: worker' | sort | tr '\n' ' ')
echo "RESULT nginx_workers_unchanged $([ "$nginx_workers_before" = "$nginx_workers_after" ] && echo yes || echo no) ($nginx_workers_after)"
t0=$(date +%s%N); start_host; t1=$(date +%s%N)
echo "RESULT restart_ms $(( (t1 - t0) / 1000000 )) x-plugin=$(hdr /p/hello x-plugin)"

# ---- reload: bad file keeps LKG; removal unloads
cp /plugins/plugin.wasm /tmp/poc/good.wasm
echo "not wasm" > /plugins/plugin.wasm; pkill -HUP -f "$B/host"; sleep 0.5
echo "RESULT bad_reload x-plugin=$(hdr /p/hello x-plugin) log=$(grep -c 'reload rejected' /run/cdnca/host.log)"
rm /plugins/plugin.wasm; pkill -HUP -f "$B/host"; sleep 0.5
echo "RESULT unload x-plugin=$(hdr /p/hello x-plugin)"
cp /tmp/poc/good.wasm /plugins/plugin.wasm; pkill -HUP -f "$B/host"; sleep 0.5
echo "RESULT reinstall x-plugin=$(hdr /p/hello x-plugin)"

# ---- option ②b: in-process Lua sandbox
echo "RESULT lua_ok $(wget -q -O - http://127.0.0.1:8080/lua/ok)"
echo "RESULT lua_escape $(wget -q -O - http://127.0.0.1:8080/lua/escape)"
echo "RESULT lua_loop $(wget -q -O - http://127.0.0.1:8080/lua/loop)"
# C-function bomb: the hook cannot stop string.rep; measure the stall it
# causes for a concurrent request on the same worker set.
($B/bench -url http://127.0.0.1:8080/lua/cbomb -n 4 -c 2 > /tmp/poc/cbomb.txt) &
sleep 0.05
echo "RESULT base_during_lua_cbomb $(bench /base 2000 4)"
wait
echo "RESULT lua_cbomb $(cat /tmp/poc/cbomb.txt) $(wget -q -T 10 -O - http://127.0.0.1:8080/lua/cbomb | head -c 200)"
echo "RESULT nginx_worker_killed_by_signal9 $(grep -c "exited on signal 9" /tmp/poc/error.log)"
echo "RESULT nginx_errors $(grep -c -E 'crit|alert|emerg' /tmp/poc/error.log)"
grep -E 'alert|emerg|crit' /tmp/poc/error.log | head -5
echo "RESULT plugin_unavailable_reasons"; grep -o "plugin host: .*, client" /tmp/poc/error.log | sed "s/, client//" | sort | uniq -c | head
echo "---- host.log"; tail -20 /run/cdnca/host.log
