#!/bin/sh
# ADR 0009 §8.5 item 3: per-pool origin TLS trust on one dynamic upstream with
# proxy_ssl_verify_by_lua + lua-resty-openssl, including the cross-tenant
# reverse cases and upstream keepalive reuse across pools.
. "$(dirname -- "$0")/lib.sh"
build_probe
cp -R "${poc_dir}/origintls" "${work}/origintls"
start_container
probe certs -out /poc/certs
o=/poc/certs/origin
docker exec -d "${container}" /poc/probe tlsorigin \
  -listen "127.0.0.1:9441|$o/a-good.crt|$o/a-good.key|a-good" \
  -listen "127.0.0.1:9442|$o/a-noint.crt|$o/a-noint.key|a-noint" \
  -listen "127.0.0.1:9443|$o/a-expired.crt|$o/a-expired.key|a-expired" \
  -listen "127.0.0.1:9444|$o/a-wrongname.crt|$o/a-wrongname.key|a-wrongname" \
  -listen "127.0.0.1:9445|$o/b-good.crt|$o/b-good.key|b-good" \
  -listen "127.0.0.1:9446|$o/b-evil.crt|$o/b-evil.key|b-evil" \
  -listen "127.0.0.1:9447|$o/a-multi.crt|$o/a-multi.key|a-multi"
nginx_start origintls
sleep 0.5
in_c 'openresty -v 2>&1' | sed 's/^/runtime: /'
r() { probe get -url "http://127.0.0.1:8080$1" -bodymax 300 2>/dev/null | tail -1; } # path
# every case starts on a fresh worker (no cached upstream connection), so the
# request below really handshakes with that origin
outcome() { nginx_reload origintls; line="$(r "$1")"; printf '%s %s' "$(printf '%s' "${line}" | jq '.status')" \
  "$(printf '%s' "${line}" | jq -r '.body' | sed -n 's/^label=\([^ ]*\).*/\1/p' | grep . || echo -)"; }

echo "== per-pool trust, Lua chain verification (/chain/)"
check CHAIN-A-OK "200 a-good" "$(outcome '/chain/?pool=a')" "A 的源站，A 的根，带中间证书"
check CHAIN-B-OK "200 b-good" "$(outcome '/chain/?pool=b')" "B 的源站，B 的根"
check CHAIN-EVIL-REJECT "502 -" "$(outcome '/chain/?pool=b_evil')" "反向：A 的 CA 给 B 的域名签的证书，B 的池拒绝"
check CHAIN-A-TRUST-ON-B "502 -" "$(outcome '/chain/?pool=a_on_b')" "反向：A 的根不能校验通过 B 的真实源站"
check CHAIN-NO-INTERMEDIATE "502 -" "$(outcome '/chain/?pool=a_noint')" "源站不发中间证书 → 拒绝（与 nginx 静态信任库同语义）"
check CHAIN-EXPIRED "502 -" "$(outcome '/chain/?pool=a_exp')" "过期证书拒绝"
check CHAIN-WRONG-NAME "502 -" "$(outcome '/chain/?pool=a_name')" "链有效但域名不符 → nginx 自己的主机名检查拒绝"
check CHAIN-YIELD "200 a-good" "$(outcome '/chain/?pool=a_slow')" "校验回调里 ngx.sleep 让出后继续"
nginx_reload origintls
line="$(r '/chain/?pool=b')"
check CHAIN-PEER-CHAIN "calls=1,ok=1,chain_len_2=1" "$(printf '%s' "${line}" | jq -r '.headers["X-Verify"]')" "新连接校验一次；回调里拿到源站发来的整条链（叶+中间=2）"
check CHAIN-REAL-SNI "origin-b.internal" "$(printf '%s' "${line}" | jq -r '.body' | sed -n 's/.*sni=\([^ ]*\).*/\1/p')" "keepalive 键带 #trust 时，源站收到的 SNI 仍是真实域名"
in_c 'grep -c "upstream SSL certificate verify error" /poc/origintls/logs/error.log' | sed 's/^/error.log "certificate verify error" lines: /'
in_c 'grep -c "upstream SSL certificate does not match" /poc/origintls/logs/error.log' | sed 's/^/error.log "does not match" lines: /'

echo "== variants that must not be used"
check LEAF-ONLY-FAILS "502 -" "$(outcome '/leaf/?pool=a')" "只用叶证书（不取对端链）连正常源站也失败"
check MERGED-ACCEPTS-EVIL "200 b-evil" "$(outcome '/merged/?pool=b_evil')" "反模式：各租户根并入节点级信任库，A 签的 B 域名证书被接受"
check VERIFYOFF-ACCEPTS-EVIL "200 b-evil" "$(outcome '/verifyoff/?pool=b_evil')" "proxy_ssl_verify off 时 Lua 判了拒绝也没人执行"

echo "== upstream connection reuse across pools"
# pair LOCATION FIRST SECOND: "<status1>|<status2>|<X-Verify of 2nd>|same-conn|new-conn"
pair() {
  nginx_reload origintls
  first="$(r "/$1/?pool=$2")"; second="$(r "/$1/?pool=$3")"
  c1="$(printf '%s' "${first}" | jq -r '.body' | sed -n 's/.*conn=//p')"
  c2="$(printf '%s' "${second}" | jq -r '.body' | sed -n 's/.*conn=//p')"
  printf '%s|%s|%s|%s' "$(printf '%s' "${first}" | jq '.status')" "$(printf '%s' "${second}" | jq '.status')" \
    "$(printf '%s' "${second}" | jq -r '.headers["X-Verify"]')" "$([ -n "${c1}" ] && [ "${c1}" = "${c2}" ] && echo same-conn || echo new-conn)"
}
# leak_a / leak_b: same address and SNI, trust A / trust B; the origin is A-signed for B's name
check KA-TRUSTKEY "200|502|calls=1,rejected=1,chain_len_2=1|new-conn" "$(pair chain leak_a leak_b)" "推荐：键含信任锚，B 的请求新建连接并被拒"
check KA-TRUSTKEY-REUSE "200|200|none|same-conn" "$(pair chain a a)" "推荐配置下同池仍复用连接"
check KA-SNIKEY-LEAK "200|200|none|same-conn" "$(pair snikey leak_a leak_b)" "缺陷：键只含 SNI，A 信任下校验过的连接给了 B 的池，B 的请求未经校验到达 A 签的源站"
check KA-DEFAULT-LEAK "200|200|none|same-conn" "$(pair default leak_a leak_b)" "缺陷：upstream 不写 keepalive 0 时 nginx 1.31 默认 keepalive（按 sockaddr）串用"
check KA-NGINX-LEAK "200|200|none|same-conn" "$(pair nginxka leak_a leak_b)" "缺陷：nginx keepalive 模块按 sockaddr 缓存，同样串用"
sni_second() { # location: SNI the origin saw for the second pool's request
  nginx_reload origintls
  r "/$1/?pool=sni_one" >/dev/null
  r "/$1/?pool=sni_two" | jq -r '.body' | sed -n 's/.*sni=\([^ ]*\).*/\1/p'
}
check KA-SNI-TRUSTKEY "two.internal" "$(sni_second chain)" "推荐配置：同地址不同 SNI 不串连接"
check KA-SNI-DEFAULT "one.internal" "$(sni_second default)" "缺陷：默认 keepalive 把 one.internal 的连接给了 two.internal 的请求（错的虚拟主机）"
finish
