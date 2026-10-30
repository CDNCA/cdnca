#!/bin/sh
# ADR 0009 §8.5 item 5: managed WAF (ModSecurity v3.0.17 + ModSecurity-nginx
# 1.0.4 + OWASP CRS 4.30.0) on one shared server: phase order against the Lua
# phases, what ModSecurity can see of Lua's work, per-site paranoia /
# threshold / mode and ctl:ruleRemoveById exclusions decided per request
# (data, no reload), compared request by request with v7's one-rule-set-per-site.
#   MODSECURITY_RUNTIME  libmodsecurity + connector built for nginx 1.31.1
#                        (default: scripts/security/modsecurity-runtime.sh)
#   CRS_SOURCE           coreruleset-4.30.0 source tarball
. "$(dirname -- "$0")/lib.sh"
runtime="${MODSECURITY_RUNTIME:-$(sh "${repo_root}/scripts/security/modsecurity-runtime.sh")}"
crs_tar="${CRS_SOURCE:-${HOME}/.cache/cdnca-modsecurity/src/coreruleset-4.30.0-src.tar.gz}"
[ -f "${runtime}/modules/ngx_http_modsecurity_module.so" ] || { echo "BLOCKED: no ModSecurity runtime at ${runtime}" >&2; exit 69; }
[ -f "${crs_tar}" ] || { echo "BLOCKED: no CRS source ${crs_tar}" >&2; exit 69; }
build_probe
mkdir -p "${work}/crs" "${work}/modsec/gen"
tar xzf "${crs_tar}" -C "${work}/crs" --strip-components=1 coreruleset-4.30.0/rules
cp "${poc_dir}"/modsec/* "${work}/modsec/"
gen="${work}/modsec/gen"
crs_includes() { for f in $(ls "${work}/crs/rules" | grep '^REQUEST-.*\.conf$' | sort); do echo "Include /poc/crs/rules/${f}"; done; }
# one data-driven exclusion rule per CRS request rule id (not the init and
# blocking-evaluation rules): removes that rule iff the site context lists it
crs_ids="$(cat "${work}"/crs/rules/REQUEST-9*.conf | grep -o 'id:9[0-9]\{5\}' | cut -d: -f2 | sort -u | grep -v '^90[01]\|^949')"
n=52000
for id in ${crs_ids}; do
  n=$((n + 1))
  printf 'SecRule TX:cdnca_exclude "@contains ,%s," "id:%d,phase:1,pass,nolog,t:none,ctl:ruleRemoveById=%s"\n' "${id}" "${n}" "${id}"
done >"${gen}/exclusion-rules.conf"
echo "data-driven exclusion rules: $(wc -l <"${gen}/exclusion-rules.conf" | tr -d ' ') (one per CRS request rule id)"
# same rules grouped by rule family: one guard per family skips the family's
# per-id rules when no id of that family is excluded
n=53000
for fam in $(printf '%s\n' ${crs_ids} | cut -c1-4 | sort -u); do
  n=$((n + 1))
  printf 'SecRule TX:cdnca_exclude "!@contains ,%s" "id:%d,phase:1,pass,nolog,t:none,skipAfter:END-EX-%s"\n' "${fam}" "${n}" "${fam}"
  for id in $(printf '%s\n' ${crs_ids} | grep "^${fam}"); do
    n=$((n + 1))
    printf 'SecRule TX:cdnca_exclude "@contains ,%s," "id:%d,phase:1,pass,nolog,t:none,ctl:ruleRemoveById=%s"\n' "${id}" "${n}" "${id}"
  done
  printf 'SecMarker "END-EX-%s"\n' "${fam}"
done >"${gen}/exclusion-rules-grouped.conf"
echo "grouped: $(grep -c skipAfter "${gen}/exclusion-rules-grouped.conf") family guards"
{ cat "${work}/modsec/base.conf" "${work}/modsec/dynamic-head.conf" "${gen}/exclusion-rules.conf"; crs_includes; } >"${gen}/dynamic.conf"
{ cat "${work}/modsec/base.conf" "${work}/modsec/dynamic-head.conf" "${gen}/exclusion-rules-grouped.conf"; crs_includes; } >"${gen}/dynamic-grouped.conf"
{ cat "${work}/modsec/base.conf" "${work}/modsec/dynamic-head.conf"; crs_includes; } >"${gen}/dynamic-noex.conf"
# v7 site rules (renderManagedWAFSite shape): settings before CRS
site_rules() { # pl thr mode site_ids api_ids [removed id ranges of disabled sets]
  [ "$3" = detect ] && echo "SecRuleEngine DetectionOnly"
  echo "SecAction \"id:20001,phase:1,pass,nolog,t:none,setvar:tx.blocking_paranoia_level=$1,setvar:tx.detection_paranoia_level=$1,setvar:tx.inbound_anomaly_score_threshold=$2\""
  [ -n "$4" ] && echo "SecAction \"id:20002,phase:1,pass,nolog,t:none,$(for i in $(echo "$4" | tr , ' '); do printf 'ctl:ruleRemoveById=%s,' "$i"; done | sed 's/,$//')\""
  [ -n "${6:-}" ] && echo "SecRuleRemoveById $6"
  [ -n "$5" ] && echo "SecRule REQUEST_FILENAME \"@beginsWith /api/\" \"id:20003,phase:1,pass,nolog,t:none,t:urlDecodeUni,t:normalizePath,$(for i in $(echo "$5" | tr , ' '); do printf 'ctl:ruleRemoveById=%s,' "$i"; done | sed 's/,$//')\""
  return 0
}
# v7 nginx instance with COUNT site servers on 8091..: "faithful" = CRS once at
# http level, per-site file with the site rules only (each server's rule set
# is child rules + the parent's rules appended as shared_ptr, rules.h append);
# "standalone" = every site file carries base + CRS itself
v7_instance() { # mode count
  dir="${work}/v7-$1-$2"; mkdir -p "${dir}/logs" "${dir}/gen"
  { cat "${work}/modsec/base.conf"; crs_includes; } >"${dir}/gen/node.conf"
  {
    echo "load_module /usr/local/openresty/modsecurity/modules/ngx_http_modsecurity_module.so;"
    echo "worker_processes 1; pid logs/nginx.pid; error_log logs/error.log info; events { worker_connections 256; }"
    echo "http { access_log off;"
    [ "$1" = faithful ] && echo "  modsecurity_rules_file /poc/v7-$1-$2/gen/node.conf;"
    i=0
    while [ "${i}" -lt "$2" ]; do
      case "${i}" in
        0) site_rules 1 5 block "${sqli_ids:-}" "${xss_ids:-}" ;;
        2) site_rules 1 5 detect "" "" ;;
        3) site_rules 1 5 block "" "" "942000-942999" ;; # d: the sqli set disabled
        *) site_rules 2 3 block "" "" ;;
      esac >"${dir}/gen/site-${i}.conf"
      if [ "$1" = standalone ]; then
        { cat "${work}/modsec/base.conf"; cat "${dir}/gen/site-${i}.conf"; crs_includes; } >"${dir}/gen/site-${i}.full"
        mv "${dir}/gen/site-${i}.full" "${dir}/gen/site-${i}.conf"
      fi
      echo "  server { listen 127.0.0.1:$((8091 + i)); modsecurity on; modsecurity_rules_file /poc/v7-$1-$2/gen/site-${i}.conf; location / { proxy_pass http://127.0.0.1:9000; } }"
      i=$((i + 1))
    done
    echo "}"
  } >"${dir}/nginx.conf"
  chmod -R a+rwX "${dir}"
}
start_container -v "${runtime}:/usr/local/openresty/modsecurity:ro"
in_c 'openresty -v 2>&1' | sed 's/^/runtime: /'
nginx_start modsec
sleep 1
set_policy() { in_c "wget -q -O - 'http://127.0.0.1:8090/set?host=$1&policy=$(printf '%s' "$2" | jq -sRr @uri)'" >/dev/null; }
ALL=sqli,xss
set_policy a.test "pl=1;thr=5;mode=block;sets=${ALL};ex="
set_policy b.test "pl=2;thr=3;mode=block;sets=${ALL};ex="
set_policy c.test "pl=1;thr=5;mode=detect;sets=${ALL};ex="
set_policy d.test "pl=1;thr=5;mode=block;sets=xss;ex="
# req PORT HOST PATH [POST-BODY] -> status
# requests go out byte for byte (probe -raw: no client-side path normalisation)
req() { # port host path [form body] -> status
  if [ -n "${4:-}" ]; then
    probe get -url "http://127.0.0.1:$1$3" -host "$2" -raw -method POST -body "$4" 2>/dev/null
  else
    probe get -url "http://127.0.0.1:$1$3" -host "$2" -raw 2>/dev/null
  fi | tail -1 | jq -r '.status // "error"'
}
# rule ids CRS matched for a request (detection-only site c), identified by a unique path
fired() { # path-with-query
  req 8080 c.test "$1" >/dev/null
  path="${1%%\?*}"
  in_c "grep 'ModSecurity: Warning' /poc/modsec/logs/error.log | grep '\"${path}' | grep -o '\[id \"[0-9]*\"\]' | grep -o '[0-9]*' | sort -u | grep -v '^949\|^980\|^5[0-9]\{4\}\$' | paste -sd, -"
}

echo "== which CRS rules fire (site c = detection only, PL1)"
sqli_ids="$(fired "/d-sqli?id=1%27%20OR%20%271%27%3D%271")"
xss_ids="$(fired "/api/d-xss?q=%3Cscript%3Ealert(1)%3C/script%3E")"
echo "SQLi probe fired: ${sqli_ids}"
echo "XSS probe fired: ${xss_ids}"
check DISCOVERY "yes" "$([ -n "${sqli_ids}" ] && [ -n "${xss_ids}" ] && echo yes || echo no)" "探测载荷在 PL1 命中 CRS 规则"
# PL2-only probe: fires at PL2 and not at PL1
set_policy c.test "pl=2;thr=5;mode=detect;sets=${ALL};ex="
pl2_path=""
for candidate in "/d-pl2a?q=%2541%2541" "/d-pl2b?q=a%27%27b%27%27c" "/d-pl2c?q=~%60%40%23%24%25%5E%26*()-_%3D%2B%5B%5D%7B%7D%7C" "/d-pl2d?q=1;2;3;4;5;6"; do
  at2="$(fired "${candidate}")"
  set_policy c.test "pl=1;thr=5;mode=detect;sets=${ALL};ex="
  at1="$(fired "$(printf '%s' "${candidate}" | sed 's/d-pl2/e-pl2/')")"
  set_policy c.test "pl=2;thr=5;mode=detect;sets=${ALL};ex="
  echo "candidate ${candidate}: PL2 fired [${at2}] PL1 fired [${at1}]"
  if [ -n "${at2}" ] && [ -z "${at1}" ] && [ -z "${pl2_path}" ]; then pl2_path="$(printf '%s' "${candidate}" | sed 's/d-pl2/pl2/')"; fi
done
set_policy c.test "pl=1;thr=5;mode=detect;sets=${ALL};ex="
echo "PL2-only probe: ${pl2_path:-none found}"

echo "== same policies on both shapes"
# site a excludes the SQLi probe's rules everywhere and the XSS probe's rules under /api/
v7_instance faithful 4
nginx_start v7-faithful-4
set_policy a.test "pl=1;thr=5;mode=block;sets=${ALL};ex==${sqli_ids}|/api/=${xss_ids}"
sqli="/q?id=1%27%20OR%20%271%27%3D%271"
xss="q=%3Cscript%3Ealert(1)%3C/script%3E"
# columns: expected status on a (exclusions) b (PL2, thr 3) c (detection only) d (PL1, sqli set off)
corpus="clean|/hello?q=world|200|200|200|200
sqli-get|${sqli}|200|403|200|200
sqli-post|/form|200|403|200|200
xss-api|/api/x?${xss}|200|403|200|403
xss-other|/x?${xss}|403|403|200|403
xss-api-traversal|/api/../x?${xss}|403|403|200|403
xss-api-encoded|/%61pi/x?${xss}|200|403|200|403"
[ -n "${pl2_path}" ] && corpus="${corpus}
pl2-only|${pl2_path}|200|403|200|200"
printf '%s\n' "${corpus}" | while IFS='|' read -r name path ea eb ec ed; do
  body=""; [ "${name}" = sqli-post ] && body="id=1' OR '1'='1"
  for site in a b c d; do
    port=$((8090 + $(printf '%s' "${site}" | tr abcd 1234)))
    expected="$(eval echo "\${e${site}}")"
    v7="$(req "${port}" "${site}.test" "${path}" "${body}")"
    dyn="$(req 8080 "${site}.test" "${path}" "${body}")"
    grouped="$(req 8085 "${site}.test" "${path}" "${body}")"
    check "EQ-${name}-${site}" "${expected}/${expected}/${expected}" "${v7}/${dyn}/${grouped}" "v7 每站规则集 / 共享 server / 共享 server 分组排除"
  done
done 2>&1 | tee "${work}/eq.txt"
failures=$((failures + $(grep -c '^FAIL' "${work}/eq.txt" || true)))
in_c 'openresty -p /poc/v7-faithful-4/ -c nginx.conf -s stop' || true

echo "== policy change takes effect on the next request (no reload)"
set_policy a.test "pl=1;thr=5;mode=block;sets=${ALL};ex=/api/=${xss_ids}"
check LIVE-REMOVE-EXCLUSION 403 "$(req 8080 a.test "${sqli}")" "去掉 SQLi 排除后下一个请求即拦截"
set_policy a.test "pl=1;thr=5;mode=block;sets=${ALL};ex==${sqli_ids}|/api/=${xss_ids}"
check LIVE-RESTORE-EXCLUSION 200 "$(req 8080 a.test "${sqli}")" "恢复排除后下一个请求即放行"
set_policy b.test "pl=1;thr=1000;mode=block;sets=${ALL};ex="
check LIVE-THRESHOLD 200 "$(req 8080 b.test "${sqli}")" "阈值调到 1000 后放行（只计分）"
set_policy b.test "pl=2;thr=3;mode=block;sets=${ALL};ex="
check LIVE-THRESHOLD-BACK 403 "$(req 8080 b.test "${sqli}")" "阈值恢复后拦截"

echo "== isolation and failure modes"
for i in 1 2 3 4 5 6; do printf '%s %s\n' "$(req 8080 a.test "${sqli}")" "$(req 8080 b.test "${sqli}")"; done >"${work}/interleave.txt"
check INTERLEAVE "200 403" "$(sort -u "${work}/interleave.txt" | paste -sd, -)" "a/b 交替 6 轮：a 的排除不泄漏给 b（ctl 只作用于本事务）"
check FAIL-CLOSED 500 "$(req 8080 broken.test /hello)" "站点没有 WAF 上下文时拒绝（不是放行）"
check SPOOF-HEADER 403 "$(probe get -url "http://127.0.0.1:8080${sqli}" -host b.test -raw -H "X-Poc-Server-Rewrite: x" \
  -H "X-Cdnca-Waf-Ctx: s=a.test;pl=1;thr=5;mode=block;ex=,${sqli_ids},;|0" 2>/dev/null | tail -1 | jq -r '.status')" "客户端伪造上下文头无效（上下文只在事务 ID 里，由 Lua 写）"
check NO-LEAK-TO-ORIGIN "leaked_ctx=" "$(in_c "wget -q -O - --header 'Host: a.test' 'http://127.0.0.1:8080/hello'" | grep -o 'leaked_ctx=[^ ]*')" "Lua 设的请求头不送到源站"

echo "== phase order and visibility"
req 8080 a.test /trace >/dev/null
trace="$(in_c "grep -E 'TRACE1|TRACE2|POC-ACCESS uri=/trace' /poc/modsec/logs/error.log | tail -3")"
printf '%s\n' "${trace}" | sed 's/.*\(TRACE[12][^]]*\).*/  \1/; s/.*\(POC-ACCESS[^,]*\).*/  \1/' | cut -c1-200
check SEES-SERVER-REWRITE-HEADER yes "$(printf '%s' "${trace}" | grep -q 'srvrw=set-in-server-rewrite' && echo yes || echo no)" "server_rewrite_by_lua 设的头 ModSecurity phase 1 可见"
check NOT-SEES-REWRITE-HEADER yes "$(printf '%s' "${trace}" | grep 'TRACE1' | grep -q 'rw=set-in-rewrite' && echo no || echo yes)" "rewrite_by_lua（默认 postpone 到阶段末尾）在 ModSecurity phase 1 之后"
check SEES-TXID yes "$(printf '%s' "${trace}" | grep 'TRACE1' | grep -q 'uid=s=a.test;pl=1' && echo yes || echo no)" "modsecurity_transaction_id 取到 server_rewrite_by_lua 写的变量"
check ORDER-P2-BEFORE-ACCESS "TRACE1,TRACE2,POC-ACCESS" "$(printf '%s\n' "${trace}" | grep -o 'TRACE1\|TRACE2\|POC-ACCESS' | paste -sd, -)" "ModSecurity phase 1 (rewrite) → phase 2 (preaccess) → access_by_lua"
req 8080 a.test "/exec-sqli?id=1%27%20OR%20%271%27%3D%271" >/dev/null
check EXEC-ONE-TRANSACTION 1 "$(in_c "grep -c 'EXECTRACE' /poc/modsec/logs/error.log")" "ngx.exec 进命名 location 后不重跑 ModSecurity（上下文按 pool cleanup 找回）"

echo "== cost of the data-driven exclusion rules (clean request on a.test, 2000 sequential, 1 worker)"
# three interleaved rounds (the host runs other jobs; compare within a round)
for round in 1 2 3; do
  for port in 8084 8080 8085; do
    probe get -url "http://127.0.0.1:${port}/hello?q=world" -host a.test -n 200 -summary >/dev/null
    case "${port}" in 8084) label="no exclusion rules" ;; 8080) label="398 flat exclusion rules" ;; *) label="48 groups + 398 rules" ;; esac
    printf 'round %s %-26s %s\n' "${round}" "${label}:" "$(probe get -url "http://127.0.0.1:${port}/hello?q=world" -host a.test -n 2000 -summary)"
  done
done
echo "== memory: nginx master VmRSS with 3 vs 21 site servers (per extra site = delta / 18)"
in_c 'openresty -p /poc/modsec/ -c nginx.conf -s stop'; sleep 1
rss() { in_c "grep VmRSS /proc/\$(cat /poc/$1/logs/nginx.pid)/status | awk '{print \$2}'"; }
for mode in faithful standalone; do
  v7_instance "${mode}" 3; v7_instance "${mode}" 21
  nginx_start "v7-${mode}-3"; sleep 1; small="$(rss "v7-${mode}-3")"
  in_c "openresty -p /poc/v7-${mode}-3/ -c nginx.conf -s stop"; sleep 1
  nginx_start "v7-${mode}-21"; sleep 1; big="$(rss "v7-${mode}-21")"
  in_c "openresty -p /poc/v7-${mode}-21/ -c nginx.conf -s stop"; sleep 1
  echo "v7 ${mode}: 3 sites ${small} kB, 21 sites ${big} kB, per extra site $(( (big - small) / 18 )) kB"
done
mkdir -p "${work}/dyn-only/logs"
# main config up to (not including) the two cost-baseline servers, then close http{}
sed '/# same, without the per-rule exclusion rules/,$d' "${work}/modsec/nginx.conf" >"${work}/dyn-only/nginx.conf"
echo "}" >>"${work}/dyn-only/nginx.conf"
chmod -R a+rwX "${work}/dyn-only"
nginx_start dyn-only; sleep 1
echo "shared server (any number of sites): master VmRSS $(rss dyn-only) kB"
finish
