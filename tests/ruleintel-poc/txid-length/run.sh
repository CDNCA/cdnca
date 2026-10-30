#!/bin/sh
# ADR 0011 RI-01 PoC-4: how long can modsecurity_transaction_id be?
# Lua writes a c3-shaped context of a given length; ModSecurity reports the
# UNIQUE_ID length it got, whether the tail is intact, whether the context
# rule parses it (wide: t= up to 65535 chars, PCRE's largest bounded repeat; narrow: up to 2000, today's
# dynamicWAFContextRule bound), the error-log line and audit unique_id, and
# the cost of long IDs.
#   LENGTHS (default "128 1024 2048 2300 4096 8192 16384 32768 65536 65700")
#   REQUESTS (default 2000)  ROUNDS (default 3)
. "$(dirname -- "$0")/../lib.sh"
lengths="${LENGTHS:-128 1024 2048 2300 4096 8192 16384 32768 65536 65700}"
requests="${REQUESTS:-2000}"
rounds="${ROUNDS:-3}"
build_probe
mkdir -p "${work}/gen"
sed 's/__MAX__/65535/' "${here}/rules.conf" >"${work}/gen/wide.conf"
sed 's/__MAX__/2000/' "${here}/rules.conf" >"${work}/gen/narrow.conf"
start_container
in_c 'openresty -v 2>&1' | sed 's/^/runtime: /'
nginx_start nginx.conf

# the last ModSecurity log line of a rule msg for the newest request
last_msg() { in_c "grep -o \"$1 [0-9]*\" /poc/logs/error.log | tail -1 | cut -d' ' -f2"; }
printf '%-7s %-6s %-7s %-6s %-6s %-9s %s\n' want port status uidlen tlen auditlen errline
for len in ${lengths}; do
  for port in 8081 8082; do
    in_c ': >/poc/logs/audit.log; : >/poc/logs/error.log'
    code="$(status "${port}" /x -H "X-Poc-Len:${len}")"
    uid="$(last_msg UIDLEN)"; tl="$(last_msg TLEN)"
    audit="$(in_c "tail -1 /poc/logs/audit.log" | jq -r '.transaction.unique_id | length' 2>/dev/null || echo -)"
    errline="$(in_c "grep 'UIDRAW' /poc/logs/error.log | tail -1 | wc -c" | tr -d ' ')"
    printf '%-7s %-6s %-7s %-6s %-6s %-9s %s\n' "${len}" "${port}" "${code}" "${uid:--}" "${tl:--}" "${audit:--}" "${errline}"
  done
done | tee "${work}/table.txt"
row() { awk -v l="$1" -v p="$2" '$1==l && $2==p' "${work}/table.txt"; }
col() { row "$1" "$2" | awk -v c="$3" '{print $c}'; }
for len in ${lengths}; do
  check "LEN-${len}-RECEIVED" "${len}" "$(col "${len}" 8081 4)" "ModSecurity 收到的 UNIQUE_ID 长度 = Lua 写入长度（尾部 request id 完整，未截断）"
  check "LEN-${len}-AUDIT" "${len}" "$(col "${len}" 8081 6)" "审计记录 unique_id 全长"
done
check NARROW-2048 200 "$(col 2048 8082 3)" "现有 2000 字符上限规则：2048 字节上下文能解析"
check NARROW-2300-REJECT 501 "$(col 2300 8082 3)" "现有 2000 字符上限规则：t= 超 2000 → 解析失败（生产为 500 fail closed）"
check WIDE-65536 200 "$(col 65536 8081 3)" "t= 上限放到 65535 后 64 KiB 上下文能解析（线性字符类，不触 PCRE 上限）"
check WIDE-65700-REJECT 501 "$(col 65700 8081 3)" "t= 超 65535（PCRE 有界重复上限）→ 解析失败"
check ERRLOG-TRUNCATED yes "$(e="$(col 8192 8081 7)"; [ "${e}" -gt 0 ] && [ "${e}" -lt 8192 ] && echo yes || echo no)" "error.log 单行被截断（NGX_MAX_ERROR_STR 4096）：日志里看不到完整事务 ID"

echo "== cost: request with a context of N bytes, ${requests} sequential, 1 worker (interleaved rounds)"
in_c 'sed -i "s/^SecAuditEngine On/SecAuditEngine Off/; s/,log,t:none,t:length,/,nolog,t:none,t:length,/g; s/,log,t:none,msg:.UIDRAW/,nolog,t:none,msg:'"'"'UIDRAW/" /poc/gen/wide.conf'
nginx_stop nginx.conf; nginx_start nginx.conf
[ "${rounds}" -gt 0 ] && for round in $(seq 1 "${rounds}"); do
  for len in 128 2048 8192 32768; do
    probe get -url "http://127.0.0.1:8081/x" -host a.test -n 200 -summary -H "X-Poc-Len:${len}" >/dev/null
    printf 'round %s len %-6s %s\n' "${round}" "${len}" "$(probe get -url "http://127.0.0.1:8081/x" -host a.test -n "${requests}" -summary -H "X-Poc-Len:${len}")"
  done
done
finish
