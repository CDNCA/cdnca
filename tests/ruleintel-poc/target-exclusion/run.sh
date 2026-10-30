#!/bin/sh
# ADR 0011 RI-01 PoC-1: can a per-request (rule, parameter) exclusion come
# from the transaction ID (context t=,<rule>:<param>,...) through
# ctl:ruleRemoveTargetById, without a reload? Real OWASP CRS 4.30.0 on
# libmodsecurity 3.0.17 + ModSecurity-nginx 1.0.4, OpenResty 1.31.1.1.
#   1 literal ctl:ruleRemoveTargetById (baseline)          gen/static.conf
#   2 the parameter name from a macro (%{tx.x})            gen/macro.conf    (must not load)
#   3 the parameter name as a regex                        gen/regex.conf
#   4 alternative A: rendered hooks, one per (rule, param), switched by t= in the
#     transaction ID; flat and grouped by rule family      gen/hooks*.conf
#   cost: clean request, CRS only vs 4096 flat hooks vs 4096 grouped hooks
#   PAIRS (default 4096)  REQUESTS (default 2000)  ROUNDS (default 3)
. "$(dirname -- "$0")/../lib.sh"
pairs_total="${PAIRS:-4096}"
requests="${REQUESTS:-2000}"
rounds="${ROUNDS:-3}"
build_probe
extract_crs
mkdir -p "${work}/gen"
gen="${work}/gen"
crs_includes() { for f in $(ls "${work}/crs/rules" | grep '^REQUEST-.*\.conf$' | sort); do echo "Include /poc/crs/rules/${f}"; done; }
detection() { cat "${here}/base.conf"; echo "SecRuleEngine DetectionOnly"; crs_includes; }
detection >"${gen}/detect.conf"
start_container
in_c 'openresty -v 2>&1' | sed 's/^/runtime: /'

echo "== which CRS rules the probe fires on parameter q (detection only, PL1)"
nginx_start nginx-detect.conf
sqli="1%27%20OR%20%271%27%3D%271"
probe get -url "http://127.0.0.1:8080/discover?q=${sqli}" -host a.test -raw >/dev/null 2>&1
fired="$(in_c "grep 'ModSecurity: Warning' /poc/logs/error.log | grep '\"/discover' | grep -o '\[id \"[0-9]*\"\]' | grep -o '[0-9]*' | sort -u | grep -v '^949\|^980\|^5[0-9]\{4\}\$' | paste -sd' ' -")"
echo "fired: ${fired}"
in_c "grep 'ModSecurity: Warning' /poc/logs/error.log | grep '\"/discover' | grep -o '\[id \"[0-9]*\"\].*\[data \"[^]]*\]' | sed 's/\[file[^]]*\]//; s/\[line[^]]*\]//; s/\[rev[^]]*\]//' | cut -c1-160" | sed 's/^/  /'
[ -n "${fired}" ] || { echo "BLOCKED: probe fired no CRS rule" >&2; exit 1; }
nginx_stop nginx-detect.conf

n=51100
# variant rule files: base + the variant's exclusion rules + CRS
variant() { # name, exclusion rules on stdin
  { cat "${here}/base.conf"; cat; crs_includes; } >"${gen}/$1.conf"
}
for id in ${fired}; do printf 'SecAction "id:%d,phase:1,pass,nolog,t:none,ctl:ruleRemoveTargetById=%s;ARGS:q"\n' "$((n = n + 1))" "${id}"; done | variant static
for id in ${fired}; do printf 'SecAction "id:%d,phase:1,pass,nolog,t:none,setvar:tx.cdnca_p=q,ctl:ruleRemoveTargetById=%s;ARGS:%%{tx.cdnca_p}"\n' "$((n = n + 1))" "${id}"; done | variant macro
for id in ${fired}; do printf 'SecAction "id:%d,phase:1,pass,nolog,t:none,ctl:ruleRemoveTargetById=%s;ARGS:/q/"\n' "$((n = n + 1))" "${id}"; done | variant regex
# alternative A: the (rule, param) pairs (real ones for q first, then
# synthetic p0..p31 on CRS request rule ids) rendered as hooks
all_ids="$(cat "${work}"/crs/rules/REQUEST-9*.conf | grep -o 'id:9[0-9]\{5\}' | cut -d: -f2 | sort -u | grep -v '^90[01]\|^949')"
{
  for id in ${fired}; do echo "${id} q"; done
  for id in ${all_ids}; do i=0; while [ "${i}" -lt 32 ]; do echo "${id} p${i}"; i=$((i + 1)); done; done
} | head -n "${pairs_total}" | sort -k1,1 -s >"${gen}/pairs.txt"
echo "pairs: $(wc -l <"${gen}/pairs.txt" | tr -d ' ') over $(cut -d' ' -f1 "${gen}/pairs.txt" | sort -u | wc -l | tr -d ' ') rules"
n=60000
while read -r id p; do
  n=$((n + 1))
  printf 'SecRule TX:cdnca_tex "@contains ,%s:%s," "id:%d,phase:1,pass,nolog,t:none,ctl:ruleRemoveTargetById=%s;ARGS:%s"\n' "${id}" "${p}" "${n}" "${id}" "${p}"
done <"${gen}/pairs.txt" | variant hooks
n=70000
last=""
while read -r id p; do
  fam="$(printf '%s' "${id}" | cut -c1-4)"
  if [ "${fam}" != "${last}" ]; then
    [ -n "${last}" ] && printf 'SecMarker "CDNCA-TEX-%s"\n' "${last}"
    n=$((n + 1)); printf 'SecRule TX:cdnca_tex "!@contains ,%s" "id:%d,phase:1,pass,nolog,t:none,skipAfter:CDNCA-TEX-%s"\n' "${fam}" "${n}" "${fam}"
    last="${fam}"
  fi
  n=$((n + 1))
  printf 'SecRule TX:cdnca_tex "@contains ,%s:%s," "id:%d,phase:1,pass,nolog,t:none,ctl:ruleRemoveTargetById=%s;ARGS:%s"\n' "${id}" "${p}" "${n}" "${id}" "${p}"
done <"${gen}/pairs.txt" >"${gen}/grouped.rules"
printf 'SecMarker "CDNCA-TEX-%s"\n' "${last}" >>"${gen}/grouped.rules"
variant hooks-grouped <"${gen}/grouped.rules"
echo "grouped: $(grep -c skipAfter "${gen}/grouped.rules") family guards"
: | variant noex
chmod -R a+rwX "${work}"

echo "== 2: parameter name from a macro"
macro_t="$(in_c 'openresty -p /poc/ -c nginx-macro.conf -t 2>&1' || true)"
printf '%s\n' "${macro_t}" | grep -i 'modsecurity\|emerg' | head -2 | cut -c1-240 | sed 's/^/  /'
check MACRO-REJECTED yes "$(printf '%s' "${macro_t}" | grep -q 'test is successful' && echo no || echo yes)" "ctl:ruleRemoveTargetById 的参数名写宏，规则文件加载失败（扫描器不接受 %{}）"

nginx_start nginx.conf
ctx() { printf 'X-Poc-Ctx:t=%s' "$1"; }
echo "== 1 / 3: literal and regex targets"
check STATIC-Q 200 "$(status 8081 "/s?q=${sqli}")" "字面量 ARGS:q：q 上的命中被移除"
check STATIC-R 403 "$(status 8081 "/s?r=${sqli}")" "字面量 ARGS:q：同一载荷在参数 r 上仍拦截（只移除目标，不移除规则）"
check REGEX-Q 403 "$(status 8083 "/s?q=${sqli}")" "ARGS:/q/ 被当作字面量名，不匹配 q，仍拦截"
check CASE-Q 403 "$(status 8081 "/s?Q=${sqli}")" "参数名大小写不同（Q）不移除：展开集合时按原样精确比较"

echo "== 4: alternative A, hooks switched by the transaction ID (no reload)"
tq=",$(printf '%s:q,' ${fired})"
for port in 8084 8085; do
  label=flat; [ "${port}" = 8085 ] && label=grouped
  check "HOOK-${label}-OFF" 403 "$(status "${port}" "/h?q=${sqli}")" "${label}：上下文无排除 → 拦截"
  check "HOOK-${label}-ON" 200 "$(status "${port}" "/h?q=${sqli}" -H "$(ctx "${tq}")")" "${label}：t= 列出 (规则,q) → 放行"
  check "HOOK-${label}-OTHER-PARAM" 403 "$(status "${port}" "/h?r=${sqli}" -H "$(ctx "${tq}")")" "${label}：同一上下文，载荷在 r 上 → 拦截"
  check "HOOK-${label}-OFF-AGAIN" 403 "$(status "${port}" "/h?q=${sqli}")" "${label}：下一个请求去掉 t= → 拦截（事务级，不残留）"
  check "HOOK-${label}-OTHER-RULE" 403 "$(status "${port}" "/h?q=${sqli}" -H "$(ctx ",942200:q,")")" "${label}：t= 只列 (942200,q)，命中的是别的规则 → 拦截（按规则号精确匹配）"
done
json_status="$(probe get -url "http://127.0.0.1:8084/j" -host a.test -method POST -body "{\"q\":\"1' OR '1'='1\"}" -H 'Content-Type:application/json' -H "$(ctx ",$(printf '%s:json.q,' ${fired})")" 2>/dev/null | tail -1 | jq -r .status)"
check HOOK-JSON-NAME-UNRENDERED 403 "${json_status}" "JSON 叶子名为 json.q：钩子只渲染了 q，不放行（JSON 参数要按 json.<路径> 渲染）"
check HOOK-UNRENDERED-PAIR 403 "$(status 8084 "/h?zz=${sqli}" -H "$(ctx ",$(printf '%s:zz,' ${fired})")")" "t= 里有、但没渲染进钩子的对（zz）无效：新对要等下一次渲染 + reload"
echo "== spoofing"
check SPOOF-ARG 403 "$(status 8084 "/h?q=${sqli}&cdnca_tex=${tq}")" "客户端参数 cdnca_tex 不影响 TX 变量"

echo "== cost: clean request /c?q=world, ${requests} sequential, 1 worker (interleaved rounds)"
for round in $(seq 1 "${rounds}"); do
  for port in 8086 8084 8085; do
    case "${port}" in 8086) label="CRS only" ;; 8084) label="${pairs_total} flat hooks" ;; *) label="${pairs_total} grouped hooks" ;; esac
    probe get -url "http://127.0.0.1:${port}/c?q=world" -host a.test -n 200 -summary >/dev/null
    printf 'round %s %-22s %s\n' "${round}" "${label}:" "$(probe get -url "http://127.0.0.1:${port}/c?q=world" -host a.test -n "${requests}" -summary)"
    printf 'round %s %-22s %s\n' "${round}" "${label} + t=:" "$(probe get -url "http://127.0.0.1:${port}/c?q=world" -host a.test -n "${requests}" -summary -H "$(ctx "${tq}")")"
  done
done
echo "== memory (master VmRSS, kB)"
nginx_stop nginx.conf
for conf in noex hooks hooks-grouped; do
  sed "s#__RULES__#/poc/gen/${conf}.conf#" "${here}/nginx-one.conf" >"${work}/one.conf"
  nginx_start one.conf
  echo "${conf}: $(in_c "grep VmRSS /proc/\$(cat /poc/logs/one.pid)/status | awk '{print \$2}'")"
  nginx_stop one.conf
done
in_c 'grep -c "ModSecurity: Warning" /poc/logs/error.log' | sed 's/^/modsecurity warnings logged: /'
finish
