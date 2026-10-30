#!/bin/sh
# ADR 0011 RI-01 PoC-2: per-transaction audit sampling of grey-zone
# transactions (score > 0, below the threshold) by the last hex digit of the
# request id, only parts A + H, and its cost. Four rule sets, same CRS:
#   off         SecAuditEngine Off                         (cost floor)
#   relevant    RelevantOnly, as RenderDynamicWAFRules today
#   sample-off  RelevantOnly + phase 5 ctl:auditEngine=Off for unsampled grey,
#               ctl:auditLogParts=-B for sampled grey
#   sample-on   Engine Off + phase 5 ctl:auditEngine=On for sampled grey / blocked
#   N (default 3200 per traffic class)  REQUESTS (default 2000)  ROUNDS (default 3)
. "$(dirname -- "$0")/../lib.sh"
n_each="${N:-3200}"
requests="${REQUESTS:-2000}"
rounds="${ROUNDS:-3}"
build_probe
extract_crs
mkdir -p "${work}/gen"
crs_includes() { for f in $(ls "${work}/crs/rules" | grep '^REQUEST-.*\.conf$' | sort); do echo "Include /poc/crs/rules/${f}"; done; }
variant() { # name engine [extra rules file]
  { sed "s/__ENGINE__/$2/; s/__LOG__/$1/" "${here}/head.conf"; crs_includes; [ -n "${3:-}" ] && cat "${here}/$3"; true; } >"${work}/gen/$1.conf"
}
variant off Off
variant relevant RelevantOnly
variant sample-off RelevantOnly sample-off.rules
variant sample-on Off sample-on.rules
start_container
in_c 'openresty -v 2>&1' | sed 's/^/runtime: /'
nginx_start nginx.conf
grey="/g?q=1%27%20OR%20%271%27%3D%271"
strong="/b?q=%3Cscript%3Ealert(1)%3C/script%3E%27%20OR%20%271%27%3D%271"
clean="/c?q=world"
for port in 8081 8082 8083 8084; do
  check "CLASS-CLEAN-${port}" 200 "$(status "${port}" "${clean}")" "干净请求放行"
  check "CLASS-GREY-${port}" 200 "$(status "${port}" "${grey}")" "灰区（一条 CRITICAL，5 < 阈值 10）放行"
  check "CLASS-STRONG-${port}" 403 "$(status "${port}" "${strong}")" "强载荷（≥ 10）拦截"
done
in_c 'rm -f /poc/logs/audit-*.log'
nginx_stop nginx.conf; nginx_start nginx.conf

echo "== records written for ${n_each} clean + ${n_each} grey + ${n_each} blocked requests"
for port in 8081 8082 8083 8084; do
  probe get -url "http://127.0.0.1:${port}${clean}" -host a.test -n "${n_each}" -summary >/dev/null
  probe get -url "http://127.0.0.1:${port}${grey}" -host a.test -n "${n_each}" -summary >/dev/null
  probe get -url "http://127.0.0.1:${port}${strong}" -host a.test -n "${n_each}" -summary >/dev/null
done
nginx_stop nginx.conf
count() { in_c "cat /poc/logs/audit-$1.log 2>/dev/null | grep -c '\"/$2?' || true"; }
for v in off relevant sample-off sample-on; do
  bytes="$(in_c "[ -f /poc/logs/audit-${v}.log ] && wc -c </poc/logs/audit-${v}.log || echo 0" | tr -d ' ')"
  printf '%-10s clean=%s grey=%s blocked=%s bytes=%s\n' "${v}" "$(count "${v}" c)" "$(count "${v}" g)" "$(count "${v}" b)" "${bytes}"
done | tee "${work}/counts.txt"
row() { grep "^$1 " "${work}/counts.txt"; }
field() { row "$1" | tr ' ' '\n' | sed -n "s/^$2=//p"; }
check OFF-NONE "0/0/0" "$(field off clean)/$(field off grey)/$(field off blocked)" "Engine Off：不写"
check RELEVANT-ALL-HITS "0/${n_each}/${n_each}" "$(field relevant clean)/$(field relevant grey)/$(field relevant blocked)" "现状 RelevantOnly：带 auditlog 的规则命中即写（灰区 100% 写），不只看状态码"
for v in sample-off sample-on; do
  g="$(field "${v}" grey)"
  lo=$((n_each / 16 * 6 / 10)); hi=$((n_each / 16 * 14 / 10))
  check "${v}-GREY-SAMPLED" yes "$([ "${g}" -ge "${lo}" ] && [ "${g}" -le "${hi}" ] && echo yes || echo no)" "灰区抽样 ${g}/${n_each}（期望约 1/16 = $((n_each / 16))，容差 ±40%）"
  check "${v}-BLOCKED-ALL" "${n_each}" "$(field "${v}" blocked)" "拦截事务全写"
  check "${v}-CLEAN-NONE" 0 "$(field "${v}" clean)" "干净请求不写"
done
check SAMPLE-KEY-DIGIT 0 "$(in_c "grep '\"/g?' /poc/logs/audit-sample-on.log" | jq -r .transaction.unique_id | grep -vc '0$' || true)" "被抽中的灰区事务 unique_id 末位都是 0"
sample_line="$(in_c "grep '\"/g?' /poc/logs/audit-sample-on.log | head -1")"
check SAMPLE-NO-HEADERS null "$(printf '%s' "${sample_line}" | jq -c '.transaction.request.headers // null')" "抽样记录不含请求头（-B）"
check SAMPLE-HAS-RULE-AND-VAR yes "$(printf '%s' "${sample_line}" | jq -r '.transaction.messages[] | select(.details.ruleId=="942100") | .details.data' | grep -q 'ARGS:q' && echo yes || echo no)" "H 部分 data 有规则号与变量名（ARGS:q）"
echo "sample record ($(printf '%s' "${sample_line}" | wc -c | tr -d ' ') bytes), messages:"
printf '%s' "${sample_line}" | jq -c '.transaction.messages[] | {ruleId: .details.ruleId, match: .details.match, data: .details.data}' | cut -c1-200 | sed 's/^/  /'
check SAMPLE-VALUE-IN-MATCH yes "$(printf '%s' "${sample_line}" | jq -r '.transaction.messages[].details.data' | grep -q "1' OR" && echo yes || echo no)" "注意：data 里带参数值原文，agent 解析时要当场丢弃"

echo "== cost: grey-zone request, ${requests} sequential, 1 worker (interleaved rounds)"
in_c 'rm -f /poc/logs/audit-*.log'
nginx_start nginx.conf
for round in $(seq 1 "${rounds}"); do
  for port in 8081 8082 8083 8084; do
    case "${port}" in 8081) label=off ;; 8082) label=relevant ;; 8083) label=sample-off ;; *) label=sample-on ;; esac
    for path in "${grey}" "${clean}"; do
      kind=grey; [ "${path}" = "${clean}" ] && kind=clean
      probe get -url "http://127.0.0.1:${port}${path}" -host a.test -n 200 -summary >/dev/null
      printf 'round %s %-10s %-5s %s\n' "${round}" "${label}" "${kind}" "$(probe get -url "http://127.0.0.1:${port}${path}" -host a.test -n "${requests}" -summary)"
    done
  done
done
finish
