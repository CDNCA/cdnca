#!/bin/sh
# ADR 0011 RI-01 PoC-3: grey-zone challenge chain on real CRS:
#   node rule deny,status:<code> -> error_page <code> = @cdnca_waf_challenge
#   -> Lua challenge (JS page for GET, 307 + cookie for POST) -> the client
#   repeats the same request with the cookie -> g=1 -> passed to the origin.
# Checks the status code choice (418 / 599), what the named location sees,
# that ModSecurity runs once per request, POST 307 keeps method and body,
# API-class requests are not challenged, strong payloads stay blocked,
# a forged / foreign cookie does not pass, and the cost.
#   REQUESTS (default 2000)  ROUNDS (default 3)
. "$(dirname -- "$0")/../lib.sh"
requests="${REQUESTS:-2000}"
rounds="${ROUNDS:-3}"
build_probe
extract_crs
mkdir -p "${work}/gen"
crs_includes() { for f in $(ls "${work}/crs/rules" | grep '^REQUEST-.*\.conf$' | sort); do echo "Include /poc/crs/rules/${f}"; done; }
for code in 418 599; do
  { cat "${here}/head.conf"; crs_includes; sed "s/__CODE__/${code}/" "${here}/rules.conf"; } >"${work}/gen/challenge-${code}.conf"
done
# site with the grey-zone challenge off: the context rules and the grey pass rule only
{ cat "${here}/head.conf"; crs_includes; sed '/id:51310/,/cdnca_b "@streq 1"/d' "${here}/rules.conf"; } >"${work}/gen/nochallenge.conf"
start_container
in_c 'openresty -v 2>&1' | sed 's/^/runtime: /'
config_test="$(in_c 'mkdir -p /poc/logs && openresty -p /poc/ -c nginx.conf -t 2>&1' || true)"
printf '%s\n' "${config_test}" | grep -v 'syntax is ok' | sed 's/^/  /'
check CONFIG-OK yes "$(printf '%s' "${config_test}" | grep -q 'test is successful' && echo yes || echo no)" "error_page 418/599 = @named 与规则加载通过"
nginx_start nginx.conf
grey="/g?q=1%27%20OR%20%271%27%3D%271"
strong="/b?q=%3Cscript%3Ealert(1)%3C/script%3E%27%20OR%20%271%27%3D%271"
html='Accept:text/html,application/xhtml+xml'
# one request -> JSON line
get() { port="$1"; path="$2"; shift 2; probe get -url "http://127.0.0.1:${port}${path}" -host a.test -bodymax 400 "$@" 2>/dev/null | tail -1; }
st() { printf '%s' "$1" | jq -r '.status // "error"'; }
hdr() { printf '%s' "$1" | jq -r --arg k "$2" '.headers[$k] // ""'; }
body() { printf '%s' "$1" | jq -r '.body // ""'; }
txstarts() { in_c "grep -c 'TXSTART' /poc/logs/error.log" || true; }

for port in 8081 8082; do
  code=418; [ "${port}" = 8082 ] && code=599
  echo "== challenge code ${code}: browser GET in the grey zone"
  before="$(txstarts)"
  first="$(get "${port}" "${grey}" -H "${html}")"
  after="$(txstarts)"
  check "GET-${code}-CHALLENGED" 200/challenge "$(st "${first}")/$(hdr "${first}" X-Cdnca-Waf)" "灰区浏览器 GET → 挑战页（状态改写为 200，不暴露 ${code}）"
  check "GET-${code}-NAMED-SEES-METHOD" GET "$(hdr "${first}" X-Poc-Challenge-Method)" "命名 location 里方法仍是原始 GET"
  check "GET-${code}-NAMED-SEES-TXID" yes "$(hdr "${first}" X-Poc-Txid | grep -q '^g=0;b=1;|' && echo yes || echo no)" "命名 location 能读到事务 ID 上下文（g=0）"
  check "GET-${code}-ONE-TRANSACTION" 1 "$((after - before))" "error_page 跳命名 location 后 ModSecurity 不再建第二个事务"
  cookie="$(body "${first}" | sed -n 's/.*data-cookie="\([^;"]*\).*/\1/p')"
  second="$(get "${port}" "${grey}" -H "${html}" -H "Cookie:${cookie}")"
  check "GET-${code}-RETRY-PASSES" 200 "$(st "${second}")" "带挑战 cookie 重发同一 GET → 放行"
  check "GET-${code}-RETRY-AT-ORIGIN" yes "$(body "${second}" | grep -q '^origin method=GET' && echo yes || echo no)" "重发请求到达源站"
done
in_c "grep -o 'ModSecurity: Access denied with code [0-9]*' /poc/logs/error.log | sort | uniq -c" | sed 's/^/  /'

echo "== POST (form) in the grey zone: 307 keeps method and body"
form="q=1' OR '1'='1&other=x"
p1="$(get 8081 /form -method POST -body "${form}" -H "${html}")"
check POST-307 307 "$(st "${p1}")" "表单 POST → 307 + Set-Cookie"
check POST-307-LOCATION /form "$(hdr "${p1}" Location)" "Location 指回同一 URL"
pcookie="$(hdr "${p1}" Set-Cookie | cut -d';' -f1)"
p2="$(get 8081 /form -method POST -body "${form}" -H "${html}" -H "Cookie:${pcookie}")"
check POST-REPEAT-PASSES 200 "$(st "${p2}")" "浏览器按 307 带 cookie 重发同一 POST → 放行"
check POST-REPEAT-BODY "origin method=POST len=${#form}" "$(body "${p2}" | sed 's/ body=.*//')" "源站收到原方法与完整请求体"
check POST-OTHER-ADDR 307 "$(st "$(get 8081 /form -method POST -body "${form}" -H "${html}" -H "Cookie:${pcookie}x")")" "伪造/篡改 cookie → 再次挑战"

echo "== who is not challenged"
check API-JSON-PASS 200 "$(st "$(get 8081 /api -method POST -body "{\"q\":\"1' OR '1'='1\"}" -H 'Content-Type:application/json' -H 'Accept:application/json')")" "API 类（JSON 体）灰区 → 放行，不挑战"
check API-AUTH-PASS 200 "$(st "$(get 8081 "${grey}" -H 'Authorization:Bearer x')")" "带 Authorization 的 GET 灰区 → 放行"
check XHR-PASS 200 "$(st "$(get 8081 "${grey}" -H 'X-Requested-With:XMLHttpRequest')")" "XHR 灰区 → 放行"
check STRONG-BLOCK 403 "$(st "$(get 8081 "${strong}" -H "${html}")")" "强载荷（≥ 阈值）→ 403，不给挑战"
check STRONG-BLOCK-WITH-COOKIE 403 "$(st "$(get 8081 "${strong}" -H "${html}" -H "Cookie:${cookie}")")" "过了挑战也不放宽强分拦截"
check CLEAN-NO-CHALLENGE 200 "$(st "$(get 8081 /c?q=world -H "${html}")")" "干净请求 → 直接放行"
check NOCHALLENGE-GREY-PASS 200 "$(st "$(get 8083 "${grey}" -H "${html}")")" "站点关灰区挑战（无 51310）→ 灰区放行（现状）"
check HEAD-CHALLENGED 200 "$(st "$(get 8081 "${grey}" -method HEAD -H "${html}")")" "HEAD 灰区 → 挑战（200，无 body）"

echo "== cost: browser GET, ${requests} sequential, 1 worker (interleaved rounds)"
for round in $(seq 1 "${rounds}"); do
  for kind in clean grey-challenge grey-cookie grey-nochallenge; do
    case "${kind}" in
      clean) port=8081; path=/c?q=world; extra="" ;;
      grey-challenge) port=8081; path="${grey}"; extra="" ;;
      grey-cookie) port=8081; path="${grey}"; extra="Cookie:${cookie}" ;;
      *) port=8083; path="${grey}"; extra="" ;;
    esac
    set -- -H "${html}"; [ -n "${extra}" ] && set -- "$@" -H "${extra}"
    probe get -url "http://127.0.0.1:${port}${path}" -host a.test -n 200 -summary "$@" >/dev/null
    printf 'round %s %-17s %s\n' "${round}" "${kind}" "$(probe get -url "http://127.0.0.1:${port}${path}" -host a.test -n "${requests}" -summary "$@")"
  done
done
finish
