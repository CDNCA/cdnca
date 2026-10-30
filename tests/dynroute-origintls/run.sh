#!/bin/sh
# Dynamic routing D5b acceptance on a real OpenResty: per-pool origin TLS
# (edge/openresty/dynroute/cdnca_origintls.lua) and the upstream reuse key.
# One --rm --network none container on the node runtime image.
#   tests/dynroute-origintls/run.sh
#   CDNCA_D5B_IMAGE  node runtime image (default cdnca-native-runtime:edge-golden,
#                    built from edge/openresty/native/Dockerfile --target runtime)
#   CDNCA_D5B_WRAP   command prefix (the shared machine's queue script)
# Certificates, mock HTTPS origins and the client are tests/dynroute-poc/probe
# (fresh keys every run). CA sets go to a content-addressed object directory
# read through cdnca_site.object(), as the agent will place them.
set -eu
here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH='' cd -- "${here}/../.." && pwd)
image=${CDNCA_D5B_IMAGE:-cdnca-native-runtime:edge-golden}
wrap=${CDNCA_D5B_WRAP:-}
docker image inspect "${image}" >/dev/null 2>&1 || { echo "BLOCKED: ${image} missing" >&2; exit 69; }
arch=$(docker image inspect "${image}" --format '{{.Architecture}}')
work=$(mktemp -d /tmp/cdnca-d5b-origintls.XXXXXX)
container="cdnca-d5b-origintls-$$"
# The container (root) creates certs/, objects/ and logs/ in the bind mount: on
# Linux they are root's, so hand them back before removing the work directory.
cleanup() {
	docker exec "${container}" chmod -R a+rwX /t >/dev/null 2>&1 || true
	docker rm -f "${container}" >/dev/null 2>&1 || true
	rm -rf "${work}"
}
trap cleanup EXIT INT TERM

GOWORK=off GOPROXY=off CGO_ENABLED=0 GOOS=linux GOARCH="${arch}" \
	go -C "${repo_root}/tests/dynroute-poc/probe" build -trimpath -o "${work}/probe" .
mkdir -p "${work}/lua/dynroute" "${work}/objects" "${work}/index"
for name in cdnca_site.lua cdnca_origintls.lua; do
	cp "${repo_root}/edge/openresty/dynroute/${name}" "${work}/lua/dynroute/${name}"
done
cp "${here}/nginx.conf" "${here}/fixtures.lua" "${work}/"
chmod -R a+rwX "${work}"
${wrap} docker run -d --rm --name "${container}" --network none -v "${work}:/t" \
	--entrypoint sh "${image}" -c 'sleep 3600' >/dev/null
in_c() { docker exec "${container}" sh -c "$1"; }

in_c '/t/probe certs -out /t/certs >/dev/null'
o=/t/certs/origin
# Object store layout of cdnca_site (sha256/<2>/<2>/<64>); the system bundle
# of this run is tenant A's root alone (so "system" trusts A, not B).
in_c "set -e; cd /t
put() { d=\$(sha256sum \"\$1\" | cut -c1-64); mkdir -p objects/sha256/\$(echo \$d | cut -c1-2)/\$(echo \$d | cut -c3-4)
  cp \"\$1\" objects/sha256/\$(echo \$d | cut -c1-2)/\$(echo \$d | cut -c3-4)/\$d; echo \$d; }
A=\$(put $o/caA.crt); B=\$(put $o/caB.crt)
M=\$(printf 'not stored' | sha256sum | cut -c1-64)
printf '{\"A\":\"%s\",\"B\":\"%s\",\"missing\":\"%s\"}' \$A \$B \$M > anchors.json
cp $o/caA.crt certs/system.crt; cp certs/edge/ca.crt certs/placeholder.crt; mkdir -p logs"
docker exec -d "${container}" /t/probe tlsorigin \
	-listen "127.0.0.1:9441|$o/a-good.crt|$o/a-good.key|a-good" \
	-listen "127.0.0.1:9442|$o/a-noint.crt|$o/a-noint.key|a-noint" \
	-listen "127.0.0.1:9443|$o/a-expired.crt|$o/a-expired.key|a-expired" \
	-listen "127.0.0.1:9444|$o/a-wrongname.crt|$o/a-wrongname.key|a-wrongname" \
	-listen "127.0.0.1:9445|$o/b-good.crt|$o/b-good.key|b-good" \
	-listen "127.0.0.1:9446|$o/b-evil.crt|$o/b-evil.key|b-evil" \
	-listen "127.0.0.1:9447|$o/a-multi.crt|$o/a-multi.key|a-multi"
in_c 'openresty -p /t/ -c nginx.conf' || { in_c 'tail -20 /t/logs/error.log'; exit 1; }
sleep 0.5
in_c 'openresty -v 2>&1' | sed 's/^/runtime: /'

failures=0
check() { # name expected actual note
	if [ "$2" = "$3" ]; then printf 'PASS %s %s  %s\n' "$1" "$3" "$4"
	else printf 'FAIL %s expected=%s actual=%s  %s\n' "$1" "$2" "$3" "$4"; failures=$((failures + 1)); fi
}
reload() { in_c 'openresty -p /t/ -c nginx.conf -s reload'; sleep 1; }
get() { docker exec "${container}" /t/probe get -url "http://127.0.0.1:8080/x?$1" -bodymax 300 ${2:+-host "$2"} 2>/dev/null | tail -1; }
sni_of() { field "$1" .body | sed -n 's/.*sni=\([^ ]*\).*/\1/p'; }
field() { printf '%s' "$1" | jq -r "$2"; }
label() { field "$1" '.body' | sed -n 's/^label=\([^ ]*\).*/\1/p' | grep . || echo -; }
conn() { field "$1" '.body' | sed -n 's/.*conn=//p'; }
# outcome QUERY: "<status> <origin label>" on a fresh worker (new handshake)
outcome() { reload; line=$(get "$1"); printf '%s %s' "$(field "${line}" .status)" "$(label "${line}")"; }
outcome_host() { reload; line=$(get "$1" "$2"); printf '%s %s' "$(field "${line}" .status)" "$(label "${line}")"; }
# pair Q1 Q2: "<status1>|<status2>|<verify calls of 2nd>|same-conn|new-conn"
pair() {
	reload; first=$(get "$1"); second=$(get "$2")
	c1=$(conn "${first}"); c2=$(conn "${second}")
	printf '%s|%s|%s|%s' "$(field "${first}" .status)" "$(field "${second}" .status)" \
		"$(field "${second}" '.headers["X-Verify-Calls"]')" "$([ -n "${c1}" ] && [ "${c1}" = "${c2}" ] && echo same-conn || echo new-conn)"
}

echo "== per-pool trust anchor: whole chain against the pool's CA set"
check TRUST-A "200 a-good" "$(outcome pool=a)" "A 的源站、A 的 CA 集（叶+中间）"
check TRUST-B "200 b-good" "$(outcome pool=b)" "B 的源站、B 的 CA 集"
check EVIL-REJECT "502 -" "$(outcome pool=b_evil)" "反向：A 的 CA 给 B 的域名签的证书，B 的池拒绝"
check A-ON-B "502 -" "$(outcome pool=a_on_b)" "反向：A 的 CA 集校验 B 的真实源站"
check NO-INTERMEDIATE "502 -" "$(outcome pool=a_noint)" "源站不发中间证书 → 拒绝"
check EXPIRED "502 -" "$(outcome pool=a_exp)" "过期 → 拒绝"
check WRONG-NAME "502 -" "$(outcome pool=a_name)" "链有效但域名与 SNI 不符 → nginx 主机名检查拒绝"
check MISSING-OBJECT "502 -" "$(outcome pool=missing)" "CA 集对象不在对象库 → 拒绝（不放行）"
check SYSTEM-A "200 a-good" "$(outcome pool=sys_a)" "system 锚：节点系统 CA 包（本次=A 的根）"
check SYSTEM-B "502 -" "$(outcome pool=sys_b)" "system 锚不信任 B 的根"
reload; line=$(get pool=b)
check REAL-SNI "origin-b.internal" "$(field "${line}" .body | sed -n 's/.*sni=\([^ ]*\).*/\1/p')" "复用键带信任锚，源站收到的 SNI 仍是真实域名"
check VERIFY-ONCE "1" "$(field "${line}" '.headers["X-Verify-Calls"]')" "新连接校验一次"
check KEY "https|origin-b.internal|sha256:$(jq -r .B "${work}/anchors.json")|-" "$(field "${line}" '.headers["X-Key"]')" "复用键 = edgesite.KeepaliveKey"

echo "== upstream reuse: same origin IP and SNI, different trust anchors"
check KA-TRUST-SPLIT "200|502|1|new-conn" "$(pair pool=leak_a pool=leak_b)" "两池共用源站 IP+SNI、信任锚不同：B 新建连接并重新校验（被拒），不复用 A 校验过的连接"
check KA-TRUST-SPLIT-REVERSE "502|200|1|new-conn" "$(pair pool=leak_b pool=leak_a)" "反序：B 的失败不影响 A 新建并通过"
check KA-SAME-TRUST-REUSE "200|200|0|same-conn" "$(pair pool=a pool=a2)" "同 SNI 同信任锚的两池复用同一连接（不重复握手）"
check KA-AUTH-SPLIT "200|200|1|new-conn" "$(pair pool=a pool=a_auth)" "回源鉴权身份不同：不复用"
check KA-OFF "200|200|1|new-conn" "$(pair pool=a_noka pool=a_noka)" "keepalive_idle_timeout_ms=0：不复用"
check KA-SNIKEY-LEAK "200|200|0|same-conn" "$(pair 'pool=leak_a&mode=snikey' 'pool=leak_b&mode=snikey')" "对照（缺陷形态）：键只含 SNI 时 B 未经校验复用 A 的连接"
sni_second() { reload; get "pool=sni_one" >/dev/null; field "$(get pool=sni_two)" .body | sed -n 's/.*sni=\([^ ]*\).*/\1/p'; }
check KA-SNI-SPLIT "two.internal" "$(sni_second)" "同地址不同 SNI 不串连接"

echo "== sni_mode (f16): custom / origin_host / visitor_host"
reload; line=$(get pool=mode_custom visitor.test)
check MODE-CUSTOM "200 two.internal" "$(field "${line}" .status) $(sni_of "${line}")" "custom：发配置的 sni，与访客 Host 无关"
check MODE-CUSTOM-KEY "https|two.internal|sha256:$(jq -r .A "${work}/anchors.json")|-" "$(field "${line}" '.headers["X-Key"]')" "复用键含 SNI"
reload; line=$(get pool=mode_origin visitor.test)
check MODE-ORIGIN "200 one.internal" "$(field "${line}" .status) $(sni_of "${line}")" "origin_host：发端点主机名（连接地址仍是 IP）"
reload; line=$(get pool=mode_visitor one.internal)
check MODE-VISITOR "200 one.internal" "$(field "${line}" .status) $(sni_of "${line}")" "visitor_host：发访客 Host"
check MODE-VISITOR-KEY "https|one.internal|sha256:$(jq -r .A "${work}/anchors.json")|-" "$(field "${line}" '.headers["X-Key"]')" "复用键含本次请求的 SNI"
reload; line=$(get pool=mode_visitor two.internal)
check MODE-VISITOR-2 "200 two.internal" "$(field "${line}" .status) $(sni_of "${line}")" "visitor_host：另一个访客 Host"
check MODE-VISITOR-NAME "502 -" "$(outcome_host pool=mode_visitor three.internal)" "visitor_host：证书不含访客 Host → 主机名检查拒绝"
check MODE-VISITOR-TRUST "200 b-good" "$(outcome_host pool=mode_visitor_b origin-b.internal)" "visitor_host 也按池信任锚校验"
visitor_pair() { # first host, second host: "<sni1>|<sni2>|<verify calls of 2nd>|same-conn|new-conn"
	reload; first=$(get pool=mode_visitor "$1"); second=$(get pool=mode_visitor "$2")
	c1=$(conn "${first}"); c2=$(conn "${second}")
	printf '%s|%s|%s|%s' "$(sni_of "${first}")" "$(sni_of "${second}")" "$(field "${second}" '.headers["X-Verify-Calls"]')" \
		"$([ -n "${c1}" ] && [ "${c1}" = "${c2}" ] && echo same-conn || echo new-conn)"
}
check KA-VISITOR-SPLIT "one.internal|two.internal|1|new-conn" "$(visitor_pair one.internal two.internal)" "同地址同池、访客 Host 不同：不串连接，第二个新建并校验"
check KA-VISITOR-REUSE "one.internal|one.internal|0|same-conn" "$(visitor_pair one.internal one.internal)" "同访客 Host：复用"
mode_cross() { reload; first=$(get pool=mode_visitor one.internal); second=$(get pool=mode_custom one.internal)
	printf '%s|%s' "$(sni_of "${second}")" "$([ "$(conn "${first}")" = "$(conn "${second}")" ] && echo same-conn || echo new-conn)"; }
check KA-MODE-CROSS "two.internal|new-conn" "$(mode_cross)" "访客 Host one 的连接不给 custom SNI two 的池"

in_c 'grep -c "cdnca origin tls: origin certificate rejected" /t/logs/error.log' | sed 's/^/error.log rejected lines: /'
in_c 'grep -E "\[(alert|crit|emerg)\]" /t/logs/error.log | head -5' || true
echo "RESULT dynroute-origintls failures=${failures}"
[ "${failures}" -eq 0 ]
