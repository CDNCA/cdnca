#!/bin/sh
# Semantic equivalence of libmodsecurity patch 02 (hashed SecRuleRemoveById
# ids, edge/openresty/modsecurity/patches/02-*): the same rule sets and
# requests on the baseline engine and on the patched engine must keep exactly
# the same rules ($modsecurity_rule_ids of patch 01) and statuses.
# Removal forms: single ids, ranges, mixed and duplicate lists, ids before
# and after the rule, 1000 ids that match no rule, SecRuleRemoveByTag,
# SecRuleRemoveByMsg, ctl:ruleRemoveById (id and range), ctl:ruleRemoveByTag,
# a chain parent, a deny rule, and the server -> location merge path.
# Locations proxy like the node does (a static alias location skips phase 2
# in ModSecurity-nginx 1.0.4 on both engines; not what the node runs) and
# SecRequestBodyAccess is On as on the node (Off skips phase 2 entirely).
#   tests/modsecurity-patches/rule-remove-equiv.sh <baseline engine dir> [patched engine dir]
# Engine dirs come from scripts/security/modsecurity-runtime.sh (the patched
# one is built from this tree when omitted). Prints RESULT failures=N.
set -eu
here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
repo=$(CDPATH='' cd -- "${here}/../.." && pwd)
. "${repo}/edge/openresty/runtime.env"
base=$1
patched=${2:-$(sh "${repo}/scripts/security/modsecurity-runtime.sh")}
work=$(mktemp -d /tmp/cdnca-ms-equiv.XXXXXX); trap '[ -n "${KEEP:-}" ] || rm -rf "${work}"' EXIT
t="${work}/t"; mkdir -p "${t}"

# 100 logged rules 1000-1099 on ARGS:x=a; tag t<i%4>, msg m<i%3>; 1098 is a
# chain parent, 1099 (phase 2) denies. Rule 900 removes at run time on y=.
{
  printf 'SecRuleEngine On\nSecRequestBodyAccess On\nSecResponseBodyAccess Off\nSecAuditEngine Off\n'
  printf 'SecRule ARGS:y "@streq id" "id:900,phase:1,pass,nolog,ctl:ruleRemoveById=1060,ctl:ruleRemoveById=1070-1075"\n'
  printf 'SecRule ARGS:y "@streq tag" "id:901,phase:1,pass,nolog,ctl:ruleRemoveByTag=t1"\n'
  printf 'SecRule ARGS:y "@streq deny" "id:902,phase:1,pass,nolog,ctl:ruleRemoveById=1099"\n'
  i=1000; while [ $i -le 1097 ]; do
    printf 'SecRule ARGS:x "@streq a" "id:%s,phase:1,pass,log,tag:'"'"'t%s'"'"',msg:'"'"'m%s'"'"'"\n' $i $((i % 4)) $((i % 3))
    i=$((i + 1)); done
  printf 'SecRule ARGS:x "@streq a" "id:1098,phase:2,pass,log,chain,tag:'"'"'t2'"'"',msg:'"'"'m2'"'"'"\n  SecRule ARGS:z "@streq b" "t:none"\n'
  printf 'SecRule ARGS:x "@streq a" "id:1099,phase:2,deny,status:403,log,tag:'"'"'t3'"'"',msg:'"'"'m0'"'"'"\n'
} >"${t}/base.conf"
# case name: extra directives (before = in front of the rules, else after)
cases='none:
single:SecRuleRemoveById 1005 1010 1099
range:SecRuleRemoveById 1020-1030
mixed:SecRuleRemoveById 1001 1040-1045 1050 1001 1050|SecRuleRemoveById 1046 1046-1047 1098
before:SecRuleRemoveById 1002 1033-1034 1099
edges:SecRuleRemoveById 999 1000 1097-1097 1100 1099-2000
fake:FAKE1000 1011 1062-1063
tag:SecRuleRemoveByTag t1
msg:SecRuleRemoveByMsg m2
tagmsgid:SecRuleRemoveByTag t0|SecRuleRemoveByMsg m1|SecRuleRemoveById 1002 1005-1008'
locs=''
printf '%s\n' "${cases}" | while IFS=: read -r name extra; do
  { if [ "${name}" = before ]; then printf '%s\n' "${extra}"; cat "${t}/base.conf"; else cat "${t}/base.conf"
      printf '%s\n' "${extra}" | tr '|' '\n' | while read -r line; do
        case "${line}" in FAKE1000*) seq 700001 701000 | paste -sd' ' - | fold -w 250 -s | sed 's/^/SecRuleRemoveById /'
          echo "SecRuleRemoveById ${line#FAKE1000 }"; seq 701001 701010 | paste -sd' ' - | sed 's/^/SecRuleRemoveById /' ;;
          ?*) echo "${line}" ;; esac; done; fi; } >"${t}/${name}.conf"
done
names=$(printf '%s\n' "${cases}" | cut -d: -f1 | tr '\n' ' ')
{
  echo 'load_module /ms/modules/ngx_http_modsecurity_module.so;'
  echo 'worker_processes 1; daemon on; pid /tmp/n.pid; error_log /tmp/n.err warn; events {}'
  echo 'http { log_format r "$request_uri $status $modsecurity_rule_ids"; access_log /tmp/r.log r;'
  echo "  modsecurity_rules 'SecUnicodeMapFile /ms/unicode.mapping 20127';"
  echo '  server { listen 127.0.0.1:8080;'
  for n in ${names}; do echo "    location /${n}/ { modsecurity on; modsecurity_rules_file /t/${n}.conf; proxy_pass http://127.0.0.1:8082/; }"; done
  echo '  }'
  echo '  server { listen 127.0.0.1:8081; modsecurity on; modsecurity_rules_file /t/base.conf;'
  echo "    location /merge/ { modsecurity_rules 'SecRuleRemoveById 1007 1080-1082 1099'; proxy_pass http://127.0.0.1:8082/; }"
  echo "    location /mergetag/ { modsecurity_rules 'SecRuleRemoveByTag t3'; proxy_pass http://127.0.0.1:8082/; }"
  echo '  }'
  echo '  server { listen 127.0.0.1:8082; access_log off; location / { return 200 ok; } }'
  echo '}'
} >"${t}/nginx.conf"
{
  echo 'set -u; mkdir -p /tmp/logs; openresty -c /t/nginx.conf -p /tmp/ || { cat /tmp/n.err; exit 1; }; sleep 0.5'
  echo "for q in 'x=a' 'x=a&z=b' 'x=a&y=id' 'x=a&y=tag' 'x=a&y=deny' 'x=c'; do"
  echo "  for n in ${names}; do curl -s -o /dev/null \"http://127.0.0.1:8080/\$n/a?\$q\"; done"
  echo "  for n in merge mergetag; do curl -s -o /dev/null \"http://127.0.0.1:8081/\$n/a?\$q\"; done"
  echo 'done; sleep 0.3; cat /tmp/r.log; grep -E "\[(emerg|alert|crit|error)\]" /tmp/n.err | grep -v "ModSecurity: Access denied" >&2 || true'
} >"${t}/drive.sh"
run() { docker run --rm --network none -v "${t}:/t:ro" -v "$1:/ms:ro" -e LD_LIBRARY_PATH=/ms/lib \
  --entrypoint sh "${OPENRESTY_IMAGE}" /t/drive.sh; }
run "${base}" >"${work}/a.log"
run "${patched}" >"${work}/b.log"
failures=0
check() { if [ "$2" = "$3" ]; then echo "PASS $1"; else echo "FAIL $1 expected=[$2] actual=[$3]"; failures=$((failures + 1)); fi; }
check REQUESTS 72 "$(wc -l <"${work}/a.log" | tr -d ' ')"
if diff -u "${work}/a.log" "${work}/b.log" >"${work}/diff"; then echo "PASS EQUIVALENT baseline=patched lines=$(wc -l <"${work}/a.log" | tr -d ' ')"
else echo "FAIL EQUIVALENT"; head -40 "${work}/diff"; failures=$((failures + 1)); fi
# The cases must exercise removal (else equality proves nothing): count kept
# rules per case on the patched engine.
kept() { awk -v u="$1" '$1 == u { n = gsub(/,[0-9]+/, "", $3); print $2 " " n }' "${work}/b.log"; }
has() { awk -v u="$1" -v id=",$2," '$1 == u { print (index($3, id) ? "kept" : "removed") }' "${work}/b.log"; }
check none "403 99" "$(kept '/none/a?x=a')"
check chain-on "403 100" "$(kept '/none/a?x=a&z=b')"
check no-match "200 0" "$(kept '/none/a?x=c')"
check single "200 96" "$(kept '/single/a?x=a')"
check range "403 88" "$(kept '/range/a?x=a')"
check mixed "403 89" "$(kept '/mixed/a?x=a&z=b')"
check before "200 95" "$(kept '/before/a?x=a')"
check edges "200 96" "$(kept '/edges/a?x=a')"
check fake "403 96" "$(kept '/fake/a?x=a')"
check fake-1011 removed "$(has '/fake/a?x=a' 1011)"
check tag "403 74" "$(kept '/tag/a?x=a')"
check msg "403 66" "$(kept '/msg/a?x=a')"
check tagmsgid "403 47" "$(kept '/tagmsgid/a?x=a')"
check ctl-id "403 92" "$(kept '/none/a?x=a&y=id')"
check ctl-id-1060 removed "$(has '/none/a?x=a&y=id' 1060)"
check ctl-tag "403 74" "$(kept '/none/a?x=a&y=tag')"
check ctl-deny "200 98" "$(kept '/none/a?x=a&y=deny')"
check merge "200 94" "$(kept '/merge/a?x=a')"
check merge-1007 removed "$(has '/merge/a?x=a' 1007)"
check mergetag "200 74" "$(kept '/mergetag/a?x=a')"
echo "RESULT failures=${failures}"
[ "${failures}" -eq 0 ]
