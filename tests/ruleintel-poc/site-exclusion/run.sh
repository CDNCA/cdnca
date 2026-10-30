#!/bin/sh
# ADR 0011 RI-03: automatic exclusions grouped by
# site instead of the per-request t= list. A site with exclusions in force
# gets one named location whose rule file is the tier file plus its own
# SecRuleUpdateTargetById lines (static, merged with the http-level CRS);
# Lua finds it by site ID in one table lookup and ngx.exec()s there. A
# request only pays for its own site's exclusions; other sites' blocks are
# never evaluated. Real OWASP CRS 4.30.0, libmodsecurity 3.0.17 +
# ModSecurity-nginx 1.0.4, OpenResty 1.31.1.1.
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
crs_includes() { for f in $(ls "${work}/crs/rules" | grep '^REQUEST-.*\.conf$' | sort); do echo "Include /poc/crs/rules/${f}"; done; }
{ cat "${here}/base.conf"; crs_includes; } >"${gen}/node.conf"
printf 'SecAction "id:39000,phase:1,pass,nolog,t:none,setvar:tx.blocking_paranoia_level=1,setvar:tx.detection_paranoia_level=1"\n' >"${gen}/tier.conf"
# the exclusion rules: the probe's real hit (942100, q) first on the hot
# site, then synthetic names on CRS request rule IDs
ids="$(cat "${work}"/crs/rules/REQUEST-9[1-4]*.conf | grep -o 'id:9[0-9]\{5\}' | cut -d: -f2 | sort -u | grep -v '^949' | head -n "${per_site}")"
hot=$(python3 -c 'import hashlib; h = hashlib.sha256(b"1").hexdigest(); print("%s-%s-4%s-8%s-%s" % (h[:8], h[8:12], h[13:16], h[17:20], h[20:32]))')
port=8100
configs=""
for count in ${site_counts}; do
  port=$((port + 1))
  configs="${configs} n${count}:${port}"
  sed -e "s#__NAME__#n${count}#g" -e "s#__PORT__#${port}#g" -e "s#__ORIGIN__#$((port + 1000))#g" "${here}/nginx.conf" >"${work}/n${count}.conf"
done
# per site: the tier file plus per_site SecRuleUpdateTargetById lines; site 1
# (hot) excludes (942100, q) first; one named location per site
IDS="${ids}" python3 - "${gen}" "${per_site}" ${site_counts} <<'PY'
import hashlib, os, sys
gen, per_site, counts = sys.argv[1], int(sys.argv[2]), [int(c) for c in sys.argv[3:]]
ids = os.environ["IDS"].split()
for position, count in enumerate(counts):
    origin = 9101 + position + 1000
    name = "n%d" % count
    os.makedirs(os.path.join(gen, name, "sites"), exist_ok=True)
    with open(os.path.join(gen, name, "sites.txt"), "w") as listing, open(os.path.join(gen, name, "locations.conf"), "w") as locations:
        for index in range(1, count + 1):
            # random looking IDs as real ones (the named location scan
            # compares names byte by byte); site 1 is the hot one
            h = hashlib.sha256(b"%d" % index).hexdigest()
            site = "%s-%s-4%s-8%s-%s" % (h[:8], h[8:12], h[13:16], h[17:20], h[20:32])
            lines = ["Include /poc/gen/tier.conf"]
            pairs = [(rule, "p%d_%d" % (index, n)) for n, rule in enumerate(ids)]
            if index == 1:
                pairs = [("942100", "q")] + pairs[1:]
            lines += ['SecRuleUpdateTargetById %s "!ARGS:%s"' % pair for pair in pairs[:per_site]]
            with open(os.path.join(gen, name, "sites", site + ".conf"), "w") as out:
                out.write("\n".join(lines) + "\n")
            listing.write(site + "\n")
            locations.write("    location @cdnca_waf_s%s { modsecurity on; modsecurity_rules_file /poc/gen/%s/sites/%s.conf; "
                            "proxy_pass http://127.0.0.1:%d; }\n" % (site, name, site, origin))
PY
chmod -R a+rwX "${work}"
start_container
in_c 'openresty -v 2>&1' | sed 's/^/runtime: /'
echo "sites with ${per_site} exclusions each; 1 worker per instance; exclusion files: $(du -sh "${gen}" | cut -f1)"

echo "== configuration test and start (parse + merge time, RSS kB)"
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
last="${configs##* }"
lport="${last##*:}"
echo "== correctness on ${last%%:*}"
check HOT-EXCLUDED 200 "$(status "${lport}" "/h?q=${sqli}" -H "X-Poc-Site:${hot}")" "本站排除 (942100,q)：q 上命中被移除"
check HOT-OTHER-PARAM 403 "$(status "${lport}" "/h?r=${sqli}" -H "X-Poc-Site:${hot}")" "本站同一载荷在 r 上：拦截"
check OTHER-SITE 403 "$(status "${lport}" "/h?q=${sqli}" -H "X-Poc-Site:$(sed -n 2p "${gen}/${last%%:*}/sites.txt")")" "别的站（有自己的排除块）：q 上拦截，不串站"
check COLD-SITE 403 "$(status "${lport}" "/h?q=${sqli}" -H "X-Poc-Site:00000000-0000-4000-8000-999999999999")" "无排除的冷站走档位 location：拦截"
check SPOOF-ARG 403 "$(status "${lport}" "/h?q=${sqli}&s=${hot}")" "客户端参数不影响站点选择"

echo "== cost: clean request /c?q=world&p1_1=a, ${requests} sequential (interleaved rounds)"
for round in $(seq 1 "${rounds}"); do
  for entry in ${configs}; do
    name="${entry%%:*}"; p="${entry##*:}"
    for kind in hot first last cold; do
      site="${hot}"
      [ "${kind}" = last ] && site="$(sort "${gen}/${name}/sites.txt" | tail -1)"
      [ "${kind}" = first ] && site="$(sort "${gen}/${name}/sites.txt" | head -1)"
      [ "${kind}" = cold ] && site=00000000-0000-4000-8000-999999999999
      [ -n "${site}" ] || continue
      probe get -url "http://127.0.0.1:${p}/c?q=world&p1_1=a" -host a.test -n 200 -summary -H "X-Poc-Site:${site}" >/dev/null
      printf 'round %s %-7s %-5s %s\n' "${round}" "${name}" "${kind}" \
        "$(probe get -url "http://127.0.0.1:${p}/c?q=world&p1_1=a" -host a.test -n "${requests}" -summary -H "X-Poc-Site:${site}")"
    done
  done
done
finish
