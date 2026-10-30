#!/bin/sh
# ADR 0009 §8.5 item 2: ssl_client_hello_by_lua / ssl_certificate_by_lua on
# one shared TLS server, compared between TCP (h1/h2) and QUIC (h3) on the
# same port of the real OpenResty 1.31.1.1 runtime (patch chain 01-23).
. "$(dirname -- "$0")/lib.sh"
build_probe
cp -R "${poc_dir}/quic" "${work}/quic"
start_container
probe certs -out /poc/certs
nginx_start quic
sleep 0.5
in_c 'openresty -v 2>&1' | sed 's/^/runtime: /'
U=https://127.0.0.1:8443
r() { _p=$1; _path=$2; shift 2; probe get -url "${U}${_path}" -proto "${_p}" -bodymax 2000 "$@" 2>/dev/null | tail -1; }
# control requests use their own SNI so they never show up in a site's counters
reset() { r h1 /reset -sni ctl.test >/dev/null; }
hits() { r h1 /hits -sni ctl.test | jq -r '.body'; }
hit() { printf '%s\n' "$1" | sed -n "s/^$2=//p" | head -1; } # hits-text key

for proto in h1 h2 h3; do
  reset
  line="$(r ${proto} / -sni a.test)"
  check "${proto}-STATUS" 200 "$(printf '%s' "${line}" | jq '.status')" "${proto} a.test"
  check "${proto}-CERT" a.test "$(printf '%s' "${line}" | jq -r '.peer_cn')" "按 SNI 动态证书（不是占位 fallback.invalid）"
  echo "  ${proto}: $(printf '%s' "${line}" | jq -c '{proto,alpn,tls,body}')"
  h="$(hits)"
  transport=tcp; [ "${proto}" = h3 ] && transport=quic
  check "${proto}-HELLO-HOOK" 1 "$(hit "${h}" "a.test|${transport}|hello")" "client hello 回调在 ${transport} 上触发 1 次"
  check "${proto}-CERT-HOOK" 1 "$(hit "${h}" "a.test|${transport}|cert")" "证书回调触发，ngx.ctx 从 client hello 带到证书阶段"
done
check H3-ALTSVC 'h3=":8443"; ma=60' "$(r h2 / -sni a.test | jq -r '.headers["Alt-Svc"]')" "按站点在 header_filter 加 Alt-Svc"
check H3-NO-ALTSVC null "$(r h2 / -sni b.test | jq -r '.headers["Alt-Svc"]')" "未宣告站点不加 Alt-Svc"

echo "== wildcard and rejection, per transport"
for proto in h2 h3; do
  check "${proto}-WILDCARD" wild.w.test "$(r ${proto} / -sni x.w.test | jq -r '.peer_cn')" "通配 *.w.test 命中"
  check "${proto}-WILDCARD-DEEP" wild.w.test "$(r ${proto} / -sni y.x.w.test | jq -r '.peer_cn')" "多级子域落到最长通配"
  reset
  line="$(r ${proto} / -sni w.test)"
  check "${proto}-WILDCARD-APEX" true "$(printf '%s' "${line}" | jq 'has("err")')" "*.w.test 不匹配 w.test，握手被拒"
  line="$(r ${proto} / -sni unknown.test)"
  check "${proto}-UNKNOWN-SNI" true "$(printf '%s' "${line}" | jq 'has("err")')" "未知 SNI 握手被拒: $(printf '%s' "${line}" | jq -r '.err' | cut -c1-90)"
  check "${proto}-UNKNOWN-FAST" true "$(printf '%s' "${line}" | jq '.ms < 2000')" "拒绝即时返回（$(printf '%s' "${line}" | jq '.ms') ms），不是超时"
  line="$(r ${proto} / -sni '' -host a.test)"
  check "${proto}-NO-SNI" true "$(printf '%s' "${line}" | jq 'has("err")')" "无 SNI 握手被拒"
  transport=tcp; [ "${proto}" = h3 ] && transport=quic
  check "${proto}-REJECT-COUNT" 3 "$(hit "$(hits)" "reject|${transport}")" "三次拒绝都发生在 client hello 阶段"
done

echo "== per-site protocols (clienthello.set_protocols)"
check TCP-TLS12-ONLY-12 "TLS 1.2" "$(r h2 / -sni tls12.test | jq -r '.tls')" "tls12 站点 TCP 只协商 1.2"
check TCP-TLS12-ONLY-REJECT13 true "$(r h2 / -sni tls12.test -tlsmin 1.3 | jq 'has("err")')" "tls12 站点拒绝只支持 1.3 的客户端"
check TCP-TLS13-ONLY-REJECT12 true "$(r h2 / -sni tls13.test -tlsmax 1.2 | jq 'has("err")')" "tls13 站点拒绝 1.2 客户端"
check QUIC-TLS13-ONLY "TLS 1.3" "$(r h3 / -sni tls13.test | jq -r '.tls')" "tls13 站点 QUIC 正常"
line="$(r h3 / -sni tls12.test)"
check QUIC-TLS12-ONLY-FAILS true "$(printf '%s' "${line}" | jq 'has("err")')" "只开 1.2 的站点在 QUIC 上必然握手失败（QUIC 要求 1.3）: $(printf '%s' "${line}" | jq -r '.err' | cut -c1-80)"

echo "== yielding Lua (ngx.sleep 0.2 s in client hello and certificate)"
for proto in h2 h3; do
  line="$(r ${proto} / -sni slow.test)"
  check "${proto}-YIELD" "200 slow.test" "$(printf '%s' "${line}" | jq -r '"\(.status) \(.peer_cn)"')" "两个 SSL 阶段都 yield 后握手完成（$(printf '%s' "${line}" | jq '.ms') ms）"
done

echo "== certificate rotation without reload"
r h1 /rotate?v=v1 -sni ctl.test >/dev/null
probe get -url "${U}/" -proto h3 -sni rot.test -n 3 -sleep 1.5s >"${work}/rot-h3.jsonl" 2>"${work}/rot-h3.err" &
p3=$!
probe get -url "${U}/" -proto h2 -sni rot.test -n 3 -sleep 1.5s >"${work}/rot-h2.jsonl" 2>"${work}/rot-h2.err" &
p2=$!
sleep 0.6
r h1 /rotate?v=v2 -sni ctl.test >/dev/null
wait "${p3}" "${p2}" || true
for proto in h2 h3; do
  check "${proto}-ROT-INFLIGHT" "rot.test-v1,rot.test-v1,rot.test-v1" \
    "$(jq -r '.peer_cn' "${work}/rot-${proto}.jsonl" | paste -sd, -)" "在途连接保持旧证书、请求不断（同一连接 3 次请求）"
  check "${proto}-ROT-NEWCONN" rot.test-v2 "$(r ${proto} / -sni rot.test | jq -r '.peer_cn')" "新连接立即拿到新证书，不 reload"
done

echo "== session resumption: which hooks run"
for proto in h2 h3; do
  reset
  probe get -url "${U}/" -proto "${proto}" -sni b.test -n 2 -newconn >"${work}/res-${proto}.jsonl" 2>/dev/null
  transport=tcp; [ "${proto}" = h3 ] && transport=quic
  h="$(hits)"
  check "${proto}-RESUMED" "false,true" "$(jq -r '.resumed // false' "${work}/res-${proto}.jsonl" | paste -sd, -)" "第二个连接用会话票据恢复"
  check "${proto}-RESUME-HELLO" 2 "$(hit "${h}" "b.test|${transport}|hello")" "client hello 回调每个连接都触发（含恢复）"
  check "${proto}-RESUME-CERT" 1 "$(hit "${h}" "b.test|${transport}|cert")" "恢复的连接不触发证书回调"
done

echo "== SNI and Host disagree"
line="$(r h2 / -sni a.test -host b.test)"
echo "  h2 sni=a.test host=b.test: $(printf '%s' "${line}" | jq -c '{status,body}')"
line="$(r h3 / -sni a.test -host b.test)"
echo "  h3 sni=a.test host=b.test: $(printf '%s' "${line}" | jq -c '{status,body}')"
check FALLBACK-NEVER-SERVED 0 "$(cat "${work}"/rot-*.jsonl "${work}"/res-*.jsonl | grep -c fallback.invalid || true)" "占位证书从未下发"
in_c 'grep -c "\[alert\]\|\[crit\]\|\[emerg\]" /poc/quic/logs/error.log || true' | sed 's/^/error.log alert|crit|emerg lines: /'
finish
