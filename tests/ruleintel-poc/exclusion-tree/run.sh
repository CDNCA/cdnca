#!/bin/sh
# ri-03d: automatic exclusions without one location per site (ri-03c: the
# per-site location costs about 4-5.5 ms reload and 150-210 KiB per process
# per site). Plan A: one tier location for every site; the node rules carry
# a hook tree (gen.py): per site one rule with its ctl:ruleRemoveTargetById,
# grouped by the last two hex digits of the site ID (16 x 16 skipAfter
# guards). Plan B: Lua drops the excluded argument before ModSecurity
# (ngx.req.set_uri_args), checked for whether ModSecurity sees the change.
# Plan C (chosen, RI-03d): buckets of BUCKET sites (default 128), one
# location each (tier file + one rule per site), Lua maps site -> bucket.
#   MODES (default "a c")  BUCKET (default 128)
# Real OWASP CRS 4.30.0, libmodsecurity 3.0.17 + ModSecurity-nginx 1.0.4,
# OpenResty 1.31.1.1.
#   SITES (default "0 1000 10000")  TARGETS per site (default 32)
#   REQUESTS (default 2000)  ROUNDS (default 3)
. "$(dirname -- "$0")/../lib.sh"
site_counts="${SITES:-0 1000 10000}"
per_site="${TARGETS:-32}"
requests="${REQUESTS:-2000}"
rounds="${ROUNDS:-3}"
build_probe
extract_crs
gen="${work}/gen"
mkdir -p "${gen}"
printf 'SecAction "id:39000,phase:1,pass,nolog,t:none,setvar:tx.blocking_paranoia_level=1,setvar:tx.detection_paranoia_level=1"\n' >"${gen}/tier.conf"
cat "${work}"/crs/rules/REQUEST-9[1-4]*.conf | grep -o 'id:9[0-9]\{5\}' | cut -d: -f2 | sort -u | grep -v '^949' | head -n "${per_site}" >"${gen}/ids.txt"
python3 "${here}/gen.py" "${gen}" "${per_site}" "${gen}/ids.txt" ${site_counts}
hot=$(sed -n 1p "${gen}/n$(echo ${site_counts} | awk '{print $NF}')/sites.txt")
# MODES: a = node-wide hook tree, c = bucket locations (gen.py)
port=8100
configs=""
for mode in ${MODES:-a c}; do
  for count in ${site_counts}; do
    port=$((port + 1))
    name="${mode}${count}"
    configs="${configs} ${name}:${port}:n${count}"
    buckets=/dev/null; locations="/poc/gen/empty.conf"; hooks=""
    if [ "${mode}" = c ]; then
      buckets="/poc/gen/n${count}/buckets.txt"; locations="/poc/gen/${name}.locations.conf"
      sed "s#__ORIGIN__#$((port + 1000))#g" "${gen}/n${count}/locations.conf" >"${gen}/${name}.locations.conf"
    else
      hooks="Include /poc/gen/n${count}/hooks.conf"
    fi
    sed -e "s#__NAME__#${name}#g" -e "s#__PORT__#${port}#g" -e "s#__ORIGIN__#$((port + 1000))#g" \
      -e "s#__BUCKETS__#${buckets}#g" -e "s#__LOCATIONS__#${locations}#g" \
      -e "s#/poc/gen/${name}/node.conf#/poc/gen/${name}.node.conf#" "${here}/nginx.conf" >"${work}/${name}.conf"
    { cat "${here}/base.conf"; [ -n "${hooks}" ] && echo "${hooks}"
      for f in $(ls "${work}/crs/rules" | grep '^REQUEST-.*\.conf$' | sort); do echo "Include /poc/crs/rules/${f}"; done; } >"${gen}/${name}.node.conf"
  done
done
: >"${gen}/empty.conf"
for count in ${site_counts}; do
  echo "n${count}: hooks.conf $(wc -l <"${gen}/n${count}/hooks.conf") lines $(du -k "${gen}/n${count}/hooks.conf" | cut -f1) KiB; buckets $(ls "${gen}/n${count}/b" | wc -l) of <= ${BUCKET:-128} sites"
done
start_container
in_c 'openresty -v 2>&1' | sed 's/^/runtime: /'
echo "sites with ${per_site} exclusions each; 1 worker per instance"

echo "== configuration test, start and reload (RSS kB)"
for entry in ${configs}; do
  name="${entry%%:*}"
  in_c "mkdir -p /poc/logs"
  timing="$(in_c "set -e; t0=\$(cut -d' ' -f1 /proc/uptime); openresty -p /poc/ -c ${name}.conf -t >/poc/${name}.t 2>&1 || { tail -3 /poc/${name}.t; exit 1; }
    t1=\$(cut -d' ' -f1 /proc/uptime); openresty -p /poc/ -c ${name}.conf; until [ -s /poc/logs/${name}.pid ]; do sleep 0.05; done
    m=\$(cat /poc/logs/${name}.pid); until [ -n \"\$(cat /proc/\$m/task/\$m/children)\" ]; do sleep 0.05; done; sleep 2
    w=\$(cat /proc/\$m/task/\$m/children | tr -d ' '); t2=\$(cut -d' ' -f1 /proc/uptime); kill -HUP \$m
    while [ \"\$(cat /proc/\$m/task/\$m/children | tr -d ' ')\" = \"\$w\" ] || [ -z \"\$(cat /proc/\$m/task/\$m/children | tr -d ' ')\" ]; do sleep 0.05; done
    t3=\$(cut -d' ' -f1 /proc/uptime); sleep 3; w=\$(cat /proc/\$m/task/\$m/children | tr -d ' ')
    echo \"test \$t0 \$t1 reload \$t2 \$t3 master \$(awk '/VmRSS/{print \$2}' /proc/\$m/status) worker \$(awk '/VmRSS/{print \$2}' /proc/\$w/status)\"")" || { echo "${timing}"; exit 1; }
  echo "${timing}" | awk -v n="${name}" '{printf "%s: test %d ms, reload (HUP until a new worker) %d ms, master RSS %d kB, worker RSS %d kB\n", n, ($3-$2)*1000, ($6-$5)*1000, $8, $10}'
done

sqli="1%27%20OR%20%271%27%3D%271"
cold=00000000-0000-4000-8000-999999999999
for mode in ${MODES:-a c}; do
  last="$(echo ${configs} | tr ' ' '\n' | grep "^${mode}" | tail -1)"
  lname="${last%%:*}"; rest="${last#*:}"; lport="${rest%%:*}"; set_dir="${rest#*:}"
  sites="${gen}/${set_dir}/sites.txt"
  other="$(sed -n 2p "${sites}")"
  twin="$(grep "${hot#"${hot%??}"}\$" "${sites}" | sed -n 2p)"
  cousin="$(grep "${hot#"${hot%?}"}\$" "${sites}" | grep -v "${hot#"${hot%??}"}\$" | sed -n 1p)"
  echo "== correctness on ${lname}"
  check "${mode}-HOT-EXCLUDED" 200 "$(status "${lport}" "/h?q=${sqli}" -H "X-Poc-Site:${hot}")" "本站排除 (942100,q)：q 上命中被移除"
  check "${mode}-HOT-OTHER-PARAM" 403 "$(status "${lport}" "/h?r=${sqli}" -H "X-Poc-Site:${hot}")" "本站同一载荷在 r 上：拦截"
  check "${mode}-OTHER-SITE" 403 "$(status "${lport}" "/h?q=${sqli}" -H "X-Poc-Site:${other}")" "别的站（同桶，有自己的排除）：q 上拦截，不串站"
  [ -n "${twin}" ] && check "${mode}-SAME-BUCKET" 403 "$(status "${lport}" "/h?q=${sqli}" -H "X-Poc-Site:${twin}")" "末两位相同的别站：拦截"
  [ -n "${cousin}" ] && check "${mode}-SAME-L1" 403 "$(status "${lport}" "/h?q=${sqli}" -H "X-Poc-Site:${cousin}")" "末位相同的别站：拦截"
  check "${mode}-COLD-SITE" 403 "$(status "${lport}" "/h?q=${sqli}" -H "X-Poc-Site:${cold}")" "无排除的冷站：拦截"
  check "${mode}-SPOOF-ARG" 403 "$(status "${lport}" "/h?q=${sqli}&s=${hot}")" "客户端参数不影响站点选择"
  check "${mode}-HOT-AGAIN-COLD" 403 "$(status "${lport}" "/h?q=${sqli}" -H "X-Poc-Site:${cold}")" "热站请求之后冷站：事务级，不残留"
  check "${mode}-B-SET-URI-ARGS" 403 "$(status "${lport}" "/b?q=${sqli}" -H "X-Poc-Site:${cold}")" "方案 B：Lua set_uri_args 去掉 q 后 ModSecurity 仍按 r->unparsed_uri 看到 q：仍拦截"
done

echo "== cost: clean request /c?q=world&p1_1=a, ${requests} sequential (interleaved rounds)"
for round in $(seq 1 "${rounds}"); do
  for entry in ${configs}; do
    name="${entry%%:*}"; rest="${entry#*:}"; p="${rest%%:*}"; set_dir="${rest#*:}"
    for kind in hot first last cold; do
      site="${hot}"
      [ "${kind}" = last ] && site="$(sort "${gen}/${set_dir}/sites.txt" | tail -1)"
      [ "${kind}" = first ] && site="$(sort "${gen}/${set_dir}/sites.txt" | head -1)"
      [ "${kind}" = cold ] && site=00000000-0000-4000-8000-999999999999
      [ -n "${site}" ] || continue
      grep -q "^${site}\$" "${gen}/${set_dir}/sites.txt" || [ "${kind}" = cold ] || continue
      probe get -url "http://127.0.0.1:${p}/c?q=world&p1_1=a" -host a.test -n 200 -summary -H "X-Poc-Site:${site}" >/dev/null
      printf 'round %s %-7s %-5s %s\n' "${round}" "${name}" "${kind}" \
        "$(probe get -url "http://127.0.0.1:${p}/c?q=world&p1_1=a" -host a.test -n "${requests}" -summary -H "X-Poc-Site:${site}")"
    done
  done
done
finish
