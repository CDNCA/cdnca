#!/bin/sh
# CC temporary bans of the client itself are queued for the
# Agent's kernel ban (DDoS protection cc_kernel_ban) and drained by
# kernel_bans() once each; a ban of a count_by bucket (target count_key) is
# not queued (it is not a client). Real OpenResty, no network.
#
# Usage: edge/openresty/ccv2/kernel_ban_test.sh
set -eu

repo_root="$(CDPATH='' cd -- "$(dirname -- "$0")/../../.." && pwd)"
# shellcheck disable=SC1091
. "${repo_root}/edge/openresty/runtime.env"
engine="${CC_ENGINE:-${repo_root}/edge/openresty/ccv2/engine.lua}"

workdir="$(mktemp -d "${TMPDIR:-/tmp}/cdnca-ge-ddos-ccban.XXXXXX")"
container="cdnca-ge-ddos-ccban-$(basename "${workdir}" | tr -cd 'A-Za-z0-9')"
cleanup() {
  docker rm -f "${container}" >/dev/null 2>&1 || true
  rm -rf -- "${workdir}"
}
trap cleanup EXIT HUP INT TERM
fail() { echo "FAIL: $*" >&2; exit 1; }

tenant="018f1000-0000-7000-8000-000000000001"
uuid() { printf '018f1000-0000-7000-8000-%012d' "$1"; }
entry_id() { printf '%s\0%s\0%s\0%s\0%s' "${tenant}" "$1" localhost "$2" http | sha256sum | awk '{print substr($1,1,32)}'; }

# site <n> <port> <rules json>: one CC v2 policy, its registry entry and server.
registry=""
servers=""
site() {
  site_id="$(uuid "$1")"
  policy_id="$(uuid "$(( $1 + 100 ))")"
  binding_id="$(uuid "$(( $1 + 200 ))")"
  publication_id="$(uuid "$(( $1 + 300 ))")"
  mkdir -p "${workdir}/security/${site_id}"
  printf '{"schema_version":"cdnca.edge.cc/v2","tenant_scope_id":"%s","site_id":"%s","policy_id":"%s","policy_version":1,"binding_id":"%s","binding_revision":1,"publication_id":"%s","enabled":true,"trusted_proxies":[],"allowlist":[],"rules":%s}' \
    "${tenant}" "${site_id}" "${policy_id}" "${binding_id}" "${publication_id}" "$3" >"${workdir}/security/${site_id}/cc.compiled.json"
  sha="$(sha256sum "${workdir}/security/${site_id}/cc.compiled.json" | awk '{print $1}')"
  entry="$(entry_id "${site_id}" "$2")"
  item="{\"entry_id\":\"${entry}\",\"tenant_scope_id\":\"${tenant}\",\"site_id\":\"${site_id}\",\"hostname\":\"localhost\",\"listen_port\":$2,\"protocol\":\"http\",\"policy_id\":\"${policy_id}\",\"policy_version\":1,\"binding_id\":\"${binding_id}\",\"binding_revision\":1,\"publication_id\":\"${publication_id}\",\"source_sha256\":\"$(printf 'a%.0s' $(seq 64))\",\"compiled_path\":\"security/${site_id}/cc.compiled.json\",\"compiled_sha256\":\"${sha}\"}"
  registry="${registry:+${registry},}${item}"
  servers="${servers}
  server {
    listen $2;
    server_rewrite_by_lua_block { return require(\"cc\").access(\"${entry}\") }
    log_by_lua_block { require(\"cc\").log() }
    location / { return 200 'ok\n'; }
  }"
}
rule() { # n priority match count_by limit action
  printf '{"rule_id":"%s","priority":%s,"flow":"stop","match":%s,"dimension":"client_ip"%s,"limit":%s,"action":%s}' \
    "$(uuid "$1")" "$2" "$3" "$4" "$5" "$6"
}
any='{"path":{"kind":"prefix","value":"/"}}'
fixed3='{"algorithm":"fixed_window","requests":3,"window_seconds":60}'

# Registry entries must be ordered by port.
site 1 18201 "[$(rule 11 1 "${any}" '' "${fixed3}" '{"kind":"temporary_ban","ban_seconds":120}')]"
site 2 18202 "[$(rule 21 1 "${any}" ',"count_by":[{"key":"uri_path"}]' "${fixed3}" '{"kind":"temporary_ban","ban_seconds":120,"target":"count_key"}')]"

cat >"${workdir}/nginx.conf" <<EOF
worker_processes 1;
error_log logs/error.log info;
pid nginx.pid;
events { worker_connections 64; }
http {
  lua_package_path '/usr/local/share/cdnca/security/?.lua;;';
  lua_shared_dict cdnca_cc_v2_state 4m;
  set_real_ip_from 127.0.0.1;
  real_ip_header X-Real-IP;
  init_by_lua_block {
    local file = assert(io.open("/runtime/registry.json", "rb"))
    local registry = file:read("*a")
    file:close()
    require("cc").init({state_dict="cdnca_cc_v2_state", release_root="/runtime", registry_json=registry})
  }
  server {
    listen 18299;
    location = /cc-kernel-bans {
      default_type text/plain;
      content_by_lua_block { for _, line in ipairs(require("cc").kernel_bans()) do ngx.say(line) end }
    }
  }
  ${servers}
}
EOF
printf '{"schema_version":"cdnca.edge.cc-registry/v1","config_version_id":"kernel-ban","entries":[%s]}' "${registry}" >"${workdir}/registry.json"
mkdir -p "${workdir}/logs"

docker run -d --rm --name "${container}" --network none --cpus 1 --memory 128m --pids-limit 64 \
  --volume "${engine}:/usr/local/share/cdnca/security/cc.lua:ro" \
  --volume "${workdir}:/runtime" --workdir /runtime \
  "${OPENRESTY_IMAGE}" openresty -g 'daemon off;' -p /runtime/ -c nginx.conf >/dev/null

ready=""
for _ in $(seq 1 100); do
  if docker exec "${container}" curl -fsS -o /dev/null http://127.0.0.1:18299/cc-kernel-bans 2>/dev/null; then ready=1; break; fi
  sleep 0.1
done
if [ -z "${ready}" ]; then
  cat "${workdir}/logs/error.log" >&2 2>/dev/null || true
  fail "cc.lua did not start"
fi

if ! docker exec -i -e TENANT="${tenant}" -e SITE1="$(uuid 1)" "${container}" sh -eu <<'INNER'
fail() { echo "FAIL: $*" >&2; exit 1; }
req() { curl -sS -o /dev/null -w '%{http_code}' -H "X-Real-IP: $2" "http://127.0.0.1:$1$3"; }
expect() { test "$3" = "$2" || fail "$1: want $2, got $3"; }
drain() { curl -fsS http://127.0.0.1:18299/cc-kernel-bans; }

test -z "$(drain)" || fail "queue not empty at start"
for n in 1 2 3; do expect "client ${n}" 200 "$(req 18201 198.51.100.7 /)"; done
expect "client over limit" 429 "$(req 18201 198.51.100.7 /)"
expect "client banned" 429 "$(req 18201 198.51.100.7 /)"
lines="$(drain)"
test "$(printf '%s\n' "${lines}" | grep -c .)" = 1 || fail "one ban, one line: ${lines}"
case "${lines}" in
  "${TENANT}|${SITE1}|198.51.100.7|"*) ;;
  *) fail "line = ${lines}" ;;
esac
until="${lines##*|}"
now="$(date +%s)"
test $((until - now)) -ge 115 && test $((until - now)) -le 121 || fail "until ${until} vs now ${now}"
test -z "$(drain)" || fail "drained twice"
echo "ok   client ban queued once with its end"

for n in 1 2 3; do expect "bucket ${n}" 200 "$(req 18202 203.0.113.${n} /p)"; done
expect "bucket over limit" 429 "$(req 18202 203.0.113.4 /p)"
test -z "$(drain)" || fail "a count_key ban was queued for the kernel"
echo "ok   bucket (count_key) ban not queued"
INNER
then
  cat "${workdir}/logs/error.log" >&2 2>/dev/null || true
  fail "kernel ban queue"
fi
echo "PASS cc kernel ban queue"
