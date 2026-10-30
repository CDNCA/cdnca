#!/bin/sh
# Real-OpenResty test of the WAF attack evidence in the security log (ge-waf
# S4): policy_id, detector, matched fragment, User-Agent and request body
# excerpt of a bound policy's block, rendered by edgeconfig with the fixed
# security log format (cmd/security-location).
#   WAF_EVIDENCE_IMAGE  OpenResty image (default the pinned node release, runtime.env)
set -eu
repo_root="$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)"
. "${repo_root}/edge/openresty/runtime.env"
image="${WAF_EVIDENCE_IMAGE:-${OPENRESTY_IMAGE}}"
work="${WAF_EVIDENCE_WORK:-$(mktemp -d "${TMPDIR:-/tmp}/cdnca-waf-evidence.XXXXXX")}"
mkdir -p "${work}"
container="cdnca-ge-waf-evidence-$(basename "${work}" | tr 'A-Z.' 'a-z-')"
cleanup() { docker rm -f "${container}" >/dev/null 2>&1 || true; [ -n "${KEEP:-}" ] || rm -rf -- "${work}"; }
trap cleanup EXIT INT TERM
mkdir -p "${work}/lua" "${work}/logs"
cp "${repo_root}/edge/openresty/lua/cdnca_waf.lua" "${work}/lua/cdnca_waf.lua"
site=5ee00000-0000-4000-8000-0000000000e1
policy=6ee00000-0000-4000-8000-0000000000e2
cat <<JSON | GOWORK="${repo_root}/go.work" go -C "${repo_root}/libs/edgeconfig" run ./cmd/security-location "${site}" >"${work}/render.txt"
[{"kind":"waf","policy_id":"${policy}","policy_version":1,"binding_revision":1,"runtime_sha256":"$(printf '%064d' 0)",
  "enabled":true,"default_action":"allow","rules":[
   {"rule_id":"7ee00000-0000-4000-8000-0000000000e3","match":{"inspect":[{"target":"body","key":"q","operator":"detect","values":["sqli"]}]},
    "action":"block","flow":"stop"},
   {"rule_id":"7ee00000-0000-4000-8000-0000000000e4","match":{"inspect":[{"target":"user_agent","operator":"contains","values":["nikto"]}]},
    "action":"log","flow":"continue"}]}]
JSON
for part in 0 1 2 3; do : >"${work}/part${part}.txt"; done
awk -v W="${work}" 'BEGIN{n=0} /^=====$/{n++; next} {print > (W "/part" n ".txt")}' "${work}/render.txt"
cat >"${work}/nginx.conf" <<EOF2
worker_processes 1;
error_log logs/error.log warn;
pid logs/nginx.pid;
events { worker_connections 256; }
http {
  lua_package_path "\$prefix/lua/?.lua;;";
  client_body_temp_path /tmp/evidence-body;
$(cat "${work}/part0.txt")
$(cat "${work}/part2.txt")
  server { listen 127.0.0.1:18095;
$(cat "${work}/part3.txt")
    location / {
$(cat "${work}/part1.txt")
      content_by_lua_block { ngx.say("origin") }
    } }
}
EOF2
chmod -R a+rwX "${work}"
docker run -d --rm --name "${container}" --network none -v "${work}:/w" --entrypoint sh "${image}" -c 'sleep 600' >/dev/null
docker exec "${container}" openresty -p /w/ -c nginx.conf
docker exec "${container}" sh -c "printf 'POST / HTTP/1.1\r\nHost: e.test\r\nUser-Agent: sqlmap/1.7\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 24\r\nConnection: close\r\n\r\nq=1%%27+or+%%271%%27%%3D%%271' | nc -w 3 127.0.0.1 18095 >/dev/null 2>&1 || true"
docker exec "${container}" sh -c "printf 'GET /x HTTP/1.1\r\nHost: e.test\r\nUser-Agent: Mozilla nikto scan\r\nConnection: close\r\n\r\n' | nc -w 3 127.0.0.1 18095 >/dev/null 2>&1 || true"
sleep 1
log="${work}/logs/security.jsonl"
fail=0
check() { if grep -q -- "$2" "${log}"; then echo "PASS $1"; else echo "FAIL $1 (missing $2)"; fail=1; fi; }
check "policy_id" "\"policy_id\":\"${policy}\""
check "detector sqli" '"detector":"sqli"'
check "matched fragment with key" "\"matched\":\"q=1' or '1'='1\""
check "user agent" '"user_agent":"sqlmap/1.7"'
check "body excerpt" '"request_body_excerpt":"q=1%27+or+%271%27%3D%271"'
check "log rule matched fragment" '"matched":"Mozilla nikto scan"'
check "block action" '"action":"block"'
python3 -c "import json,sys; [json.loads(l) for l in open(sys.argv[1])]" "${log}" && echo "PASS lines are JSON" || { echo "FAIL lines are not JSON"; fail=1; }
if grep -E '\[(error|crit|alert|emerg)\]' "${work}/logs/error.log"; then fail=1; fi
[ "${fail}" = 0 ]
